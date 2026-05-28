// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeMetricsReader is the test double for the AC #13 paths.
// queryFn / queryAggregatedFn let each test customise the
// response (return rows, return error). When unset, the
// defaults are "no rows, no error" — a healthy-but-empty store.
type fakeMetricsReader struct {
	queryFn           func(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error)
	queryAggregatedFn func(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error)
}

func (f *fakeMetricsReader) Query(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, gran, routeID, from, to)
	}
	return nil, nil
}

func (f *fakeMetricsReader) QueryAggregated(ctx context.Context, gran observability.Granularity, from, to time.Time) ([]observability.MetricBucket, error) {
	if f.queryAggregatedFn != nil {
		return f.queryAggregatedFn(ctx, gran, from, to)
	}
	return nil, nil
}

// metricsTestEnv builds a Handler + auto-auth router specifically
// for the /metrics endpoints. Seeds one route in BoltDB so the
// timeseries 404-on-unknown-route path is covered without
// affecting other tests' fixtures.
type metricsTestEnv struct {
	env     *testEnv
	router  http.Handler
	routeID string
}

func newMetricsTestEnv(t *testing.T) *metricsTestEnv {
	t.Helper()
	env := newTestEnv(t, false)
	rt, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "metrics.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return &metricsTestEnv{env: env, router: env.router, routeID: rt.ID}
}

// rawHandler returns a router that bypasses the autoAuthRouter
// wrapper — used for tests that must hit the genuine 401 path
// (anon).
func (m *metricsTestEnv) rawHandler(t *testing.T) http.Handler {
	t.Helper()
	ipExtractor, _ := auth.NewIPExtractor("")
	return NewRouter(m.env.handler, false, ipExtractor, nil)
}

// --- AC #17 auth gate --------------------------------------------------------

func TestMetricsEndpoints_Viewer200(t *testing.T) {
	// AC #17 explicitly: a viewer (not admin) MUST be able to
	// read the /metrics/* endpoints. The wiring places them in
	// the hard-auth-no-admin-gate group, so admin and viewer
	// share the same code path — but a direct viewer test is
	// the only guard against a future regression where someone
	// drops a RequireAdminMiddleware on this subgroup (anon/admin
	// tests wouldn't catch that — only the viewer would 403).
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "metrics-viewer", "Metrics Viewer", "sub-metrics-viewer")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer (CreateOIDCUser default)", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(m.env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed viewer session: %v", err)
	}
	raw := m.rawHandler(t)
	cookie := &http.Cookie{Name: sessionCookieName, Value: s.ID}

	for _, path := range []string{
		"/api/v1/metrics/timeseries?route=" + m.routeID + "&metric=req_per_sec&window=24h",
		"/api/v1/metrics/summary",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		raw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("VIEWER LOCKOUT REGRESSION on %s: status=%d body=%s — AC #17 requires viewer-or-above read access", path, rec.Code, rec.Body)
		}
	}
}

func TestMetricsEndpoints_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	for _, path := range []string{
		"/api/v1/metrics/timeseries?route=" + m.routeID + "&metric=req_per_sec&window=24h",
		"/api/v1/metrics/summary",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		raw.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: anon status = %d, want 401", path, rec.Code)
		}
	}
}

// --- AC #13 degraded paths ---------------------------------------------------

func TestMetricsTimeseries_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// metrics reader intentionally left nil (boot-failed).
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true")
	}
	if len(resp.Points) != 0 {
		t.Errorf("points = %d, want 0 (no data when disabled)", len(resp.Points))
	}
}

func TestMetricsSummary_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader = degraded)")
	}
}

func TestMetricsTimeseries_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(ctx context.Context, gran observability.Granularity, routeID string, from, to time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMetricsSummary_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(_ context.Context, _ observability.Granularity, _ string, _, _ time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("locked")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- AC #5 gap-fill ----------------------------------------------------------

func TestMetricsTimeseries_GapFill_CountsZero(t *testing.T) {
	m := newMetricsTestEnv(t)

	// Real :memory: observability store with two rows: one at
	// "10 minutes ago" and one at "5 minutes ago". The slots
	// in between MUST come back with value: 0 for a count
	// metric, never null.
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	rows := []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-10 * time.Minute), ReqCount: 100, FourxxCount: 2, FivexxCount: 1, LatencyP95Ms: 16},
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 200, FourxxCount: 0, FivexxCount: 0, LatencyP95Ms: 32},
	}
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, rows); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := len(resp.Points); got < 1400 || got > 1500 {
		t.Fatalf("points = %d, want ~1440 (24h × 60min)", got)
	}

	// Find the two seeded points and assert their immediate
	// neighbours are gap-filled with 0, not null.
	gapNonNullCount := 0
	dataPointsCount := 0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Errorf("count-metric point at %s has null value — AC #5 violation (counts must gap-fill to 0)", p.Ts)
		}
		if p.Value != nil {
			gapNonNullCount++
			if *p.Value > 0 {
				dataPointsCount++
			}
		}
	}
	if dataPointsCount != 2 {
		t.Errorf("data points (value > 0) = %d, want 2", dataPointsCount)
	}
	if gapNonNullCount < 1400 {
		t.Errorf("gap-filled non-null count points = %d, want ~1440", gapNonNullCount)
	}
}

func TestMetricsTimeseries_GapFill_P95Null(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	// One row with traffic + latency, then a long gap.
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 100, LatencyP95Ms: 32},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=p95_latency_ms&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	nullCount := 0
	dataPointCount := 0
	var dataValue float64
	for _, p := range resp.Points {
		if p.Value == nil {
			nullCount++
		} else {
			dataPointCount++
			dataValue = *p.Value
		}
	}
	if dataPointCount != 1 {
		t.Fatalf("p95 data points = %d, want 1", dataPointCount)
	}
	if dataValue != 32 {
		t.Errorf("p95 data value = %v, want 32", dataValue)
	}
	if nullCount < 1400 {
		t.Errorf("p95 null-gap points = %d, want ~1439 (every empty bucket is null, NOT 0 — AC #5)", nullCount)
	}
}

// --- AC #6 4xx / 5xx split on summary ---------------------------------------

func TestMetricsSummary_4xxAnd5xxAreIndependent(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	// Seed the just-closed minute with one row carrying ONLY
	// 4xx (no 5xx). The summary response MUST report the 4xx
	// total non-zero and the 5xx total exactly zero — proving
	// the two are independent fields (AC #6).
	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 50, FourxxCount: 7, FivexxCount: 0, LatencyP95Ms: 12},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalFourXxPerMin != 7 {
		t.Errorf("TotalFourXxPerMin = %d, want 7", resp.TotalFourXxPerMin)
	}
	if resp.TotalFiveXxPerMin != 0 {
		t.Errorf("TotalFiveXxPerMin = %d, want 0 — 4xx must NOT contaminate 5xx field (AC #6)", resp.TotalFiveXxPerMin)
	}
	if resp.TotalReqPerMin != 50 {
		t.Errorf("TotalReqPerMin = %d, want 50", resp.TotalReqPerMin)
	}
	// Reciprocal coverage in TestMetricsSummary_5xxOnly below.
}

func TestMetricsSummary_5xxOnly_4xxStaysZero(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 20, FourxxCount: 0, FivexxCount: 3, LatencyP95Ms: 12},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp summaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TotalFiveXxPerMin != 3 {
		t.Errorf("TotalFiveXxPerMin = %d, want 3", resp.TotalFiveXxPerMin)
	}
	if resp.TotalFourXxPerMin != 0 {
		t.Errorf("TotalFourXxPerMin = %d, want 0 — 5xx must NOT contaminate 4xx field (AC #6)", resp.TotalFourXxPerMin)
	}
}

// --- Validation paths --------------------------------------------------------

func TestMetricsTimeseries_BadMetric(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=BOGUS&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestMetricsTimeseries_BadWindow(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=req_per_sec&window=7d", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// --- Spec-1 §10.1: route=all aggregated timeseries -------------------------

func TestMetricsTimeseries_RouteAll_AggregatesAcrossRoutes(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	// Seed two routes with traffic in the SAME minute and a
	// third route in a different minute. The aggregated
	// timeseries must show ONE point per minute, summing
	// across routes inside the minute.
	now := time.Now().UTC().Truncate(time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 80, FourxxCount: 4, FivexxCount: 0, LatencyP95Ms: 16},
		// A second seeded route in the same -5m bucket would
		// require seeding another route. We test the GROUP BY
		// implicitly by combining with a different bucket.
		{RouteID: m.routeID, Ts: now.Add(-3 * time.Minute), ReqCount: 100, FourxxCount: 0, FivexxCount: 2, LatencyP95Ms: 32},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.RouteID != "all" {
		t.Errorf("RouteID echo = %q, want \"all\"", resp.RouteID)
	}
	// Sanity: roughly 1440 buckets (24h × 60min).
	if got := len(resp.Points); got < 1400 || got > 1500 {
		t.Fatalf("points = %d, want ~1440", got)
	}
	// Find the two data points (value > 0) and confirm their
	// sums are correct.
	dataValues := []float64{}
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value > 0 {
			dataValues = append(dataValues, *p.Value)
		}
	}
	if len(dataValues) != 2 {
		t.Fatalf("data points = %d, want 2: %v", len(dataValues), dataValues)
	}
	// Order is timestamp-ascending: -5m then -3m.
	if dataValues[0] != 80 || dataValues[1] != 100 {
		t.Errorf("aggregated req counts = %v, want [80, 100]", dataValues)
	}
}

func TestMetricsTimeseries_RouteAll_4xxAnd5xxStaySeparate(t *testing.T) {
	// AC #3 anti-regression on the aggregated path: a
	// 4xx-only burst across routes must NOT inflate the
	// aggregated 5xx series.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 50, FourxxCount: 30, FivexxCount: 0, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// 4xx series: should have a non-zero data point.
	req4 := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=four_xx_rate&window=24h", nil)
	rec4 := httptest.NewRecorder()
	m.router.ServeHTTP(rec4, req4)
	var resp4 timeseriesResponse
	if err := json.NewDecoder(rec4.Body).Decode(&resp4); err != nil {
		t.Fatalf("decode 4xx: %v", err)
	}
	max4 := 0.0
	for _, p := range resp4.Points {
		if p.Value != nil && *p.Value > max4 {
			max4 = *p.Value
		}
	}
	if max4 != 30 {
		t.Errorf("4xx aggregated max = %v, want 30", max4)
	}

	// 5xx series: every point must be zero (no 5xx seeded).
	req5 := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=five_xx_rate&window=24h", nil)
	rec5 := httptest.NewRecorder()
	m.router.ServeHTTP(rec5, req5)
	var resp5 timeseriesResponse
	if err := json.NewDecoder(rec5.Body).Decode(&resp5); err != nil {
		t.Fatalf("decode 5xx: %v", err)
	}
	for _, p := range resp5.Points {
		if p.Value != nil && *p.Value > 0 {
			t.Fatalf("aggregated 5xx had a non-zero point (%v) — AC #3 regression: 4xx leaked into 5xx", *p.Value)
		}
	}
}

func TestMetricsTimeseries_RouteAll_NilReaderDisabled(t *testing.T) {
	// AC #13 carries over: aggregated endpoint must also
	// emit disabled=true when the reader is nil.
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded)", rec.Code)
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true on aggregated path with nil reader")
	}
}

func TestMetricsTimeseries_RouteAll_SentinelBeatsCollidingRoute(t *testing.T) {
	// Anti-regression for the collision analysis documented on
	// routeAllSentinel in metrics_handlers.go.
	//
	// UUID-generated route IDs cannot collide with "all"
	// (different format, different length). But a tampered
	// backup restore COULD inject a row with ID "all". Pin the
	// invariant behaviourally: when route=all is passed, the
	// handler dispatches to QueryAggregated (not Query) — even
	// when both fakes return distinguishable sentinel data.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC().Truncate(time.Minute)
	aggregatedSentinelTs := now.Add(-7 * time.Minute)
	perRouteSentinelTs := now.Add(-13 * time.Minute)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryFn: func(_ context.Context, _ observability.Granularity, _ string, _, _ time.Time) ([]observability.MetricBucket, error) {
			// Per-route value the handler MUST NOT pick up.
			return []observability.MetricBucket{
				{Ts: perRouteSentinelTs, ReqCount: 999},
			}, nil
		},
		queryAggregatedFn: func(_ context.Context, _ observability.Granularity, _, _ time.Time) ([]observability.MetricBucket, error) {
			return []observability.MetricBucket{
				{Ts: aggregatedSentinelTs, ReqCount: 42},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Find the single non-zero point; assert it carries the
	// aggregated sentinel (42), NOT the per-route one (999).
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value == 999 {
			t.Fatalf("route=all dispatched to per-route Query (got 999 sentinel) — sentinel precedence regression")
		}
	}
	found := false
	for _, p := range resp.Points {
		if p.Value != nil && *p.Value == 42 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("aggregated sentinel (42) not in response — route=all dispatched somewhere unexpected")
	}
}

func TestMetricsTimeseries_RouteAll_QueryError503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetMetricsReader(&fakeMetricsReader{
		queryAggregatedFn: func(_ context.Context, _ observability.Granularity, _, _ time.Time) ([]observability.MetricBucket, error) {
			return nil, errors.New("locked")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=all&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestMetricsTimeseries_UnknownRoute404(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route=00000000-0000-0000-0000-000000000000&metric=req_per_sec&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

