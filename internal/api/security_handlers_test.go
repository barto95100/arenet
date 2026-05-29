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

// fakeWafEventReader is the test double for WafEventReader.
// Either return a fixed slice OR an error via the queryFn
// indirection — same pattern as fakeMetricsReader.
type fakeWafEventReader struct {
	queryFn func(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error)
}

func (f *fakeWafEventReader) QueryWafEvents(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

// --- /api/v1/security/events: auth gate ------------------------------------

func TestSecurityEvents_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityEvents_Viewer200(t *testing.T) {
	// AC #12 explicitly: a viewer (not admin) must be able to
	// read the /security/events endpoint. Wiring lives in the
	// hard-auth-no-admin group; this is the direct anti-
	// regression against a future RequireAdmin landing on that
	// subgroup (mirror of L.2's TestMetricsEndpoints_Viewer200).
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "security-viewer", "Security Viewer", "sub-security-viewer")
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /security/events: status=%d body=%s — AC #12 requires viewer-or-above read access", rec.Code, rec.Body)
	}
}

// --- AC #13 degraded paths --------------------------------------------------

func TestSecurityEvents_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// reader intentionally not set → nil → disabled response.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp securityEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader = degraded)")
	}
	if len(resp.Events) != 0 {
		t.Errorf("events = %d, want 0 (no data when disabled)", len(resp.Events))
	}
}

func TestSecurityEvents_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		queryFn: func(_ context.Context, _ observability.WafEventFilter) ([]observability.WafEvent, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- Validation -------------------------------------------------------------

func TestSecurityEvents_InvalidLimit_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{})

	cases := []string{"abc", "0", "-5", "1.5"}
	for _, raw := range cases {
		t.Run("limit="+raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/security/events?limit="+raw, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("limit=%q status = %d, want 400", raw, rec.Code)
			}
		})
	}
}

func TestSecurityEvents_LimitClampedAt100(t *testing.T) {
	// The handler MUST clamp limit > 100 to 100 (defence-in-
	// depth on top of the storage-layer cap). Verified by
	// recording the filter passed to the fake reader.
	m := newMetricsTestEnv(t)
	var observed observability.WafEventFilter
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		queryFn: func(_ context.Context, f observability.WafEventFilter) ([]observability.WafEvent, error) {
			observed = f
			return nil, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events?limit=500", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.Limit != securityEventsLimitCap {
		t.Errorf("filter.Limit = %d, want %d (handler clamps limit > cap)", observed.Limit, securityEventsLimitCap)
	}
}

// --- Filters ---------------------------------------------------------------

func TestSecurityEvents_RouteAndCategoryFiltersPassed(t *testing.T) {
	m := newMetricsTestEnv(t)
	var observed observability.WafEventFilter
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		queryFn: func(_ context.Context, f observability.WafEventFilter) ([]observability.WafEvent, error) {
			observed = f
			return nil, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events?route=r-a&category=SQLi&limit=20", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.RouteID != "r-a" {
		t.Errorf("filter.RouteID = %q, want r-a", observed.RouteID)
	}
	if observed.Category != "SQLi" {
		t.Errorf("filter.Category = %q, want SQLi", observed.Category)
	}
	if observed.Limit != 20 {
		t.Errorf("filter.Limit = %d, want 20", observed.Limit)
	}
}

// --- Happy path: events serialize correctly ---------------------------------

func TestSecurityEvents_EventsRoundTrip(t *testing.T) {
	m := newMetricsTestEnv(t)
	now := time.Now().UTC().Truncate(time.Second)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		queryFn: func(_ context.Context, _ observability.WafEventFilter) ([]observability.WafEvent, error) {
			return []observability.WafEvent{
				{
					ID: 42, Ts: now, RouteID: "r-a", RuleID: "942100",
					Category: "SQLi", Severity: 2, SrcIP: "1.2.3.4",
					RequestMethod: "GET", RequestPath: "/?id=1'+OR+1=1",
					PayloadSample: "id=1' OR 1=1",
				},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp securityEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("events = %d, want 1", len(resp.Events))
	}
	got := resp.Events[0]
	if got.ID != 42 || got.RouteID != "r-a" || got.RuleID != "942100" || got.Category != "SQLi" ||
		got.Severity != 2 || got.SrcIP != "1.2.3.4" || got.RequestMethod != "GET" ||
		got.RequestPath != "/?id=1'+OR+1=1" || got.PayloadSample != "id=1' OR 1=1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// --- /metrics/timeseries: waf_block_rate metric ----------------------------

func TestMetricsTimeseries_WafBlockRate(t *testing.T) {
	// Step M.2 — the new metric must route through the
	// existing timeseries handler unchanged. Gap-fill = 0
	// for missing buckets (count metric, not p95).
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	now := time.Now().UTC().Truncate(time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: now.Add(-5 * time.Minute), ReqCount: 100, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 7, LatencyP95Ms: 0},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=waf_block_rate&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp timeseriesResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	dataPoints := 0
	var seenVal float64
	gapZeros := 0
	for _, p := range resp.Points {
		if p.Value == nil {
			t.Errorf("waf_block_rate point at %s has null value — count metrics gap-fill to 0, not null", p.Ts)
		} else if *p.Value > 0 {
			dataPoints++
			seenVal = *p.Value
		} else {
			gapZeros++
		}
	}
	if dataPoints != 1 {
		t.Fatalf("data points (value > 0) = %d, want 1", dataPoints)
	}
	if seenVal != 7 {
		t.Errorf("seeded waf_block_count = 7, response value = %v", seenVal)
	}
	if gapZeros < 1400 {
		t.Errorf("gap-filled zero points = %d, want ~1439 (count metric, 24h window)", gapZeros)
	}
}

func TestMetricsTimeseries_WafBlockRate_BadMetric_StillRejected(t *testing.T) {
	// Anti-regression on the enum extension: the validation
	// message must mention the new metric so an operator
	// gets a useful error if they typo it.
	m := newMetricsTestEnv(t)
	obsStore, _ := observability.Open(context.Background(), ":memory:")
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/metrics/timeseries?route="+m.routeID+"&metric=waf_block&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (waf_block is not the right enum value)", rec.Code)
	}
}

// --- /metrics/summary: WAF fields independence (AC #3) ---------------------

func TestMetricsSummary_WafFields_IndependentFrom4xx5xx(t *testing.T) {
	// AC #3 anti-regression on the summary endpoint: a
	// WAF-only burst must leave TotalFourXxPerMin /
	// TotalFiveXxPerMin at 0, and the symmetric case
	// (4xx-only / 5xx-only) must leave TotalWafBlockedPerMin
	// at 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	// Seed the just-closed minute with WAF-only activity.
	// req_count IS incremented per AC #3 (a WAF block
	// counts as a request). 4xx/5xx stay 0.
	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 30, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 30, LatencyP95Ms: 8},
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
	if resp.TotalWafBlockedPerMin != 30 {
		t.Errorf("TotalWafBlockedPerMin = %d, want 30", resp.TotalWafBlockedPerMin)
	}
	if resp.TotalFourXxPerMin != 0 {
		t.Errorf("TotalFourXxPerMin = %d, want 0 — WAF-only burst must NOT inflate 4xx (AC #3)", resp.TotalFourXxPerMin)
	}
	if resp.TotalFiveXxPerMin != 0 {
		t.Errorf("TotalFiveXxPerMin = %d, want 0 — WAF-only burst must NOT inflate 5xx (AC #3)", resp.TotalFiveXxPerMin)
	}
	// AC #3 verified at the top-5 row level too.
	if len(resp.TopRoutes) != 1 || resp.TopRoutes[0].WafBlockedPerMin != 30 ||
		resp.TopRoutes[0].FourxxPerMin != 0 || resp.TopRoutes[0].FivexxPerMin != 0 {
		t.Errorf("top-route row leaked counters: %+v", resp.TopRoutes)
	}
}

func TestMetricsSummary_4xx5xxBurst_DoesNotInflateWaf(t *testing.T) {
	// Reciprocal AC #3 check on the summary: 4xx/5xx burst
	// → TotalWafBlockedPerMin stays at 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 50, FourxxCount: 10, FivexxCount: 5, WafBlockCount: 0, LatencyP95Ms: 16},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.TotalWafBlockedPerMin != 0 {
		t.Errorf("TotalWafBlockedPerMin = %d, want 0 — L counters must NOT inflate WAF total (AC #3 reciprocal)", resp.TotalWafBlockedPerMin)
	}
}

// --- /metrics/summary: WafBlocksByCategory aggregation ----------------------

func TestMetricsSummary_WafBlocksByCategory(t *testing.T) {
	// Step M.2 — the summary endpoint queries the WAF event
	// log for the just-closed minute and groups by category.
	// Test pins both the aggregation logic and the
	// reader-interface contract.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	// Seed a bucket row so the summary doesn't early-return
	// (the WAF-event aggregation runs AFTER the bucket-side
	// loop, but the response still surfaces categories even
	// when bucket counts are zero — operator wants the
	// signal as long as events exist).
	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 5, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 5, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}

	// Seed waf_events in the just-closed minute spanning 3
	// categories.
	if err := obsStore.InsertWafEventBatch(context.Background(), []observability.WafEvent{
		{Ts: prevMinute.Add(15 * time.Second), RouteID: m.routeID, RuleID: "942100", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevMinute.Add(20 * time.Second), RouteID: m.routeID, RuleID: "942200", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.2", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevMinute.Add(25 * time.Second), RouteID: m.routeID, RuleID: "941100", Category: "XSS", Severity: 3, SrcIP: "2.2.2.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevMinute.Add(30 * time.Second), RouteID: m.routeID, RuleID: "932100", Category: "RCE", Severity: 2, SrcIP: "3.3.3.1", RequestMethod: "POST", RequestPath: "/", PayloadSample: ""},
		{Ts: prevMinute.Add(35 * time.Second), RouteID: m.routeID, RuleID: "932200", Category: "RCE", Severity: 2, SrcIP: "3.3.3.2", RequestMethod: "POST", RequestPath: "/", PayloadSample: ""},
	}); err != nil {
		t.Fatalf("seed events: %v", err)
	}

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
	if resp.WafBlocksByCategory == nil {
		t.Fatalf("WafBlocksByCategory is nil; expected map (possibly empty)")
	}
	if got := resp.WafBlocksByCategory["SQLi"]; got != 2 {
		t.Errorf("SQLi count = %d, want 2", got)
	}
	if got := resp.WafBlocksByCategory["XSS"]; got != 1 {
		t.Errorf("XSS count = %d, want 1", got)
	}
	if got := resp.WafBlocksByCategory["RCE"]; got != 2 {
		t.Errorf("RCE count = %d, want 2", got)
	}
	if got := resp.WafBlocksByCategory["LFI"]; got != 0 {
		t.Errorf("LFI count = %d, want 0", got)
	}
}

func TestMetricsSummary_WafEventsReader_NilLeavesMapEmpty(t *testing.T) {
	// When the WAF event reader is nil (boot-failed
	// observability with partial degraded mode somehow),
	// the summary STILL returns successfully with an empty
	// WafBlocksByCategory map. Operator gets honest zeros,
	// not 500.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	// Intentionally do NOT call SetWafEventReader — leave it nil.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp summaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.WafBlocksByCategory == nil {
		t.Errorf("WafBlocksByCategory = nil, want empty map")
	}
	if len(resp.WafBlocksByCategory) != 0 {
		t.Errorf("WafBlocksByCategory has %d entries with nil reader, want 0", len(resp.WafBlocksByCategory))
	}
}

// --- M.2 amendment: TopAttackedRoute -----------------------------------------

// TestMetricsSummary_TopAttackedRoute_SortsAcrossAllRoutesByWafBlocks is the
// load-bearing test for the M.2 amendment: TopAttackedRoute must
// be computed across ALL routes, NOT filtered to the traffic-
// ranked top-5. The motivating scenario — a low-traffic auth/
// admin surface taking a targeted attack — would be invisible
// in the dashboard headline if the ranking were constrained to
// the traffic top-5. This is exactly the case that matters on
// an internet-exposed proxy.
func TestMetricsSummary_TopAttackedRoute_SortsAcrossAllRoutesByWafBlocks(t *testing.T) {
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	// Seed a SECOND route — the low-traffic "admin" surface
	// that takes the WAF heat. m.routeID is the high-traffic
	// route created by newMetricsTestEnv.
	adminRoute, err := m.env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "admin.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:2", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		WAFMode:   "block",
	})
	if err != nil {
		t.Fatalf("seed admin route: %v", err)
	}

	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		// High-traffic "main" route — 10000 req, zero WAF.
		// Would dominate TopRoutes (sorted by traffic).
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 10000, FourxxCount: 5, FivexxCount: 0, WafBlockCount: 0, LatencyP95Ms: 8},
		// Low-traffic "admin" route — 50 req, but 50 WAF
		// blocks (every request was an attack). MUST become
		// TopAttackedRoute despite being way down the
		// traffic ranking.
		{RouteID: adminRoute.ID, Ts: prevMinute, ReqCount: 50, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 50, LatencyP95Ms: 4},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
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

	// TopRoutes is sorted by traffic: main route comes first.
	if len(resp.TopRoutes) == 0 || resp.TopRoutes[0].RouteID != m.routeID {
		t.Fatalf("TopRoutes[0] = %+v, want main route at top by traffic", resp.TopRoutes)
	}

	// TopAttackedRoute is the LOAD-BEARING field — must be the
	// admin route despite being lower in traffic.
	if resp.TopAttackedRoute == nil {
		t.Fatal("TopAttackedRoute is nil; expected the admin route to dominate by WAF count")
	}
	if resp.TopAttackedRoute.RouteID != adminRoute.ID {
		t.Errorf("TopAttackedRoute.RouteID = %q (host=%q), want admin route %q (50 WAF blocks > main route's 0) — sorting must be across ALL routes, not constrained to TopRoutes",
			resp.TopAttackedRoute.RouteID, resp.TopAttackedRoute.Host, adminRoute.ID)
	}
	if resp.TopAttackedRoute.WafBlockedPerMin != 50 {
		t.Errorf("TopAttackedRoute.WafBlockedPerMin = %d, want 50", resp.TopAttackedRoute.WafBlockedPerMin)
	}
}

func TestMetricsSummary_TopAttackedRoute_NilWhenNoWafActivity(t *testing.T) {
	// When no route had a WAF block in the window, the field
	// is JSON null — honest "nothing here" rather than
	// arbitrarily picking a route with 0 blocks.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	prevMinute := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1m, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevMinute, ReqCount: 100, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 0, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/metrics/summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	// Capture the body bytes BEFORE Decode consumes them,
	// so the wire-shape sanity check below sees the actual
	// payload.
	bodyBytes := rec.Body.Bytes()
	var resp summaryResponse
	_ = json.Unmarshal(bodyBytes, &resp)
	if resp.TopAttackedRoute != nil {
		t.Errorf("TopAttackedRoute = %+v, want nil (no WAF activity in window)", resp.TopAttackedRoute)
	}
	// Sanity on the JSON wire shape: the field MUST serialize
	// as `null`, not omitted, so the frontend type can rely
	// on it being present. encoding/json may insert whitespace
	// after the colon depending on Go version + encoder
	// settings; check both the dense and the space variants.
	if !bytes_Contains(bodyBytes, []byte(`"topAttackedRoute":null`)) &&
		!bytes_Contains(bodyBytes, []byte(`"topAttackedRoute": null`)) {
		t.Errorf("wire JSON missing topAttackedRoute:null field — frontend expects the key always present.\nbody=%s", string(bodyBytes))
	}
}

// bytes_Contains is a tiny dep-free substring check. Avoids
// pulling bytes just for this one assertion site.
func bytes_Contains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
