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

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeWafEventReader is the test double for WafEventReader.
// Either return a fixed slice OR an error via the queryFn
// indirection — same pattern as fakeMetricsReader.
//
// M.2 amendment #2: also satisfies AggregateWafEventsByRule
// via aggregateFn. Defaults to no rows + no error so callers
// that don't exercise the aggregate path don't have to set it.
type fakeWafEventReader struct {
	queryFn          func(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error)
	aggregateFn      func(ctx context.Context, filter observability.WafEventAggregateFilter) ([]observability.WafEventRuleAggregate, error)
	aggregateCatFn   func(ctx context.Context, filter observability.WafEventCategoryFilter) ([]observability.WafEventCategoryAggregate, error)
	aggregateRouteFn func(ctx context.Context, from, to time.Time) (map[string]observability.WafEventRouteCounts, error)
	distinctIPFn     func(ctx context.Context, from, to time.Time) ([]string, error)
}

func (f *fakeWafEventReader) QueryWafEvents(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeWafEventReader) AggregateWafEventsByRule(ctx context.Context, filter observability.WafEventAggregateFilter) ([]observability.WafEventRuleAggregate, error) {
	if f.aggregateFn != nil {
		return f.aggregateFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeWafEventReader) AggregateWafEventsByCategory(ctx context.Context, filter observability.WafEventCategoryFilter) ([]observability.WafEventCategoryAggregate, error) {
	if f.aggregateCatFn != nil {
		return f.aggregateCatFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeWafEventReader) AggregateWafEventsByRoute(ctx context.Context, from, to time.Time) (map[string]observability.WafEventRouteCounts, error) {
	if f.aggregateRouteFn != nil {
		return f.aggregateRouteFn(ctx, from, to)
	}
	return nil, nil
}

func (f *fakeWafEventReader) DistinctWafEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if f.distinctIPFn != nil {
		return f.distinctIPFn(ctx, from, to)
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
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "security-viewer", "Security Viewer", "", "sub-security-viewer")
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
	// WAF-only burst must leave TotalFourXx /
	// TotalFiveXx at 0, and the symmetric case
	// (4xx-only / 5xx-only) must leave TotalWafBlocked
	// at 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	// Seed the 24h window with WAF-only activity.
	// req_count IS incremented per AC #3 (a WAF block
	// counts as a request). 4xx/5xx stay 0. Follow-up to
	// 579f695: WAF counts come from waf_event rows, not
	// the bucket WafBlockCount column.
	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 30, FourxxCount: 0, FivexxCount: 0, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}
	events := []observability.WafEvent{}
	for i := 0; i < 30; i++ {
		events = append(events, observability.WafEvent{
			Ts: prevHour.Add(time.Duration(i) * time.Second), RouteID: m.routeID,
			RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1",
			Action: "BLOCK", StatusCode: 403,
		})
	}
	if err := obsStore.InsertWafEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed waf_event: %v", err)
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
	if resp.TotalWafBlocked != 30 {
		t.Errorf("TotalWafBlocked = %d, want 30", resp.TotalWafBlocked)
	}
	if resp.TotalFourXx != 0 {
		t.Errorf("TotalFourXx = %d, want 0 — WAF-only burst must NOT inflate 4xx (AC #3)", resp.TotalFourXx)
	}
	if resp.TotalFiveXx != 0 {
		t.Errorf("TotalFiveXx = %d, want 0 — WAF-only burst must NOT inflate 5xx (AC #3)", resp.TotalFiveXx)
	}
	// AC #3 verified at the top-5 row level too.
	if len(resp.TopRoutes) != 1 || resp.TopRoutes[0].WafBlocked != 30 ||
		resp.TopRoutes[0].Fourxx != 0 || resp.TopRoutes[0].Fivexx != 0 {
		t.Errorf("top-route row leaked counters: %+v", resp.TopRoutes)
	}
}

func TestMetricsSummary_4xx5xxBurst_DoesNotInflateWaf(t *testing.T) {
	// Reciprocal AC #3 check on the summary: 4xx/5xx burst
	// → TotalWafBlocked stays at 0.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 50, FourxxCount: 10, FivexxCount: 5, WafBlockCount: 0, LatencyP95Ms: 16},
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
	if resp.TotalWafBlocked != 0 {
		t.Errorf("TotalWafBlocked = %d, want 0 — L counters must NOT inflate WAF total (AC #3 reciprocal)", resp.TotalWafBlocked)
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
	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 5, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 5, LatencyP95Ms: 8},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}

	// Seed waf_events in the just-closed minute spanning 3
	// categories.
	if err := obsStore.InsertWafEventBatch(context.Background(), []observability.WafEvent{
		{Ts: prevHour.Add(15 * time.Second), RouteID: m.routeID, RuleID: "942100", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevHour.Add(20 * time.Second), RouteID: m.routeID, RuleID: "942200", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.2", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevHour.Add(25 * time.Second), RouteID: m.routeID, RuleID: "941100", Category: "XSS", Severity: 3, SrcIP: "2.2.2.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: prevHour.Add(30 * time.Second), RouteID: m.routeID, RuleID: "932100", Category: "RCE", Severity: 2, SrcIP: "3.3.3.1", RequestMethod: "POST", RequestPath: "/", PayloadSample: ""},
		{Ts: prevHour.Add(35 * time.Second), RouteID: m.routeID, RuleID: "932200", Category: "RCE", Severity: 2, SrcIP: "3.3.3.2", RequestMethod: "POST", RequestPath: "/", PayloadSample: ""},
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

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		// High-traffic "main" route — 10000 req, zero WAF.
		// Would dominate TopRoutes (sorted by traffic).
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 10000, FourxxCount: 5, FivexxCount: 0, LatencyP95Ms: 8},
		// Low-traffic "admin" route — 50 req. WAF blocks
		// seeded as waf_event rows below (follow-up to
		// 579f695: bucket WafBlockCount is no longer read
		// by the summary handler).
		{RouteID: adminRoute.ID, Ts: prevHour, ReqCount: 50, FourxxCount: 0, FivexxCount: 0, LatencyP95Ms: 4},
	}); err != nil {
		t.Fatalf("seed bucket: %v", err)
	}
	// 50 WAF blocks on the admin route (every request was
	// an attack). The handler reads these via
	// AggregateWafEventsByRoute so the admin route becomes
	// TopAttackedRoute despite low traffic.
	events := []observability.WafEvent{}
	for i := 0; i < 50; i++ {
		events = append(events, observability.WafEvent{
			Ts: prevHour.Add(time.Duration(i) * time.Second), RouteID: adminRoute.ID,
			RuleID: "942100", Category: "SQLi", SrcIP: "1.1.1.1",
			Action: "BLOCK", StatusCode: 403,
		})
	}
	if err := obsStore.InsertWafEventBatch(context.Background(), events); err != nil {
		t.Fatalf("seed waf_event: %v", err)
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
	if resp.TopAttackedRoute.WafBlocked != 50 {
		t.Errorf("TopAttackedRoute.WafBlocked = %d, want 50", resp.TopAttackedRoute.WafBlocked)
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

	prevHour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	if err := obsStore.InsertBatch(context.Background(), observability.Granularity1h, []observability.MetricBucket{
		{RouteID: m.routeID, Ts: prevHour, ReqCount: 100, FourxxCount: 0, FivexxCount: 0, WafBlockCount: 0, LatencyP95Ms: 8},
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

// --- M.2 amendment #2: /api/v1/security/events/by-rule ----------------------

func TestSecurityEventsByRule_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?route="+m.routeID+"&window=24h", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityEventsByRule_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?route="+m.routeID+"&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp securityEventsByRuleResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader = degraded)")
	}
}

func TestSecurityEventsByRule_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		aggregateFn: func(_ context.Context, _ observability.WafEventAggregateFilter) ([]observability.WafEventRuleAggregate, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?route="+m.routeID+"&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestSecurityEventsByRule_MissingRoute_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing route)", rec.Code)
	}
}

func TestSecurityEventsByRule_BadWindow_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{})

	for _, w := range []string{"", "7d", "bogus", "1h"} {
		t.Run("window="+w, func(t *testing.T) {
			url := "/api/v1/security/events/by-rule?route=" + m.routeID
			if w != "" {
				url += "&window=" + w
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("window=%q status = %d, want 400", w, rec.Code)
			}
		})
	}
}

func TestSecurityEventsByRule_WindowMapping_24hAnd30d(t *testing.T) {
	// Pin the window→time-range mapping: 24h passes a
	// ~24h-ago `From`, 30d passes ~30d-ago. The handler
	// uses time.Now() so the test compares with a tolerance.
	m := newMetricsTestEnv(t)
	var observed observability.WafEventAggregateFilter
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		aggregateFn: func(_ context.Context, f observability.WafEventAggregateFilter) ([]observability.WafEventRuleAggregate, error) {
			observed = f
			return nil, nil
		},
	})

	for _, tc := range []struct {
		window  string
		wantAgo time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
	} {
		t.Run("window="+tc.window, func(t *testing.T) {
			now := time.Now().UTC()
			req := httptest.NewRequest(http.MethodGet,
				"/api/v1/security/events/by-rule?route="+m.routeID+"&window="+tc.window, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			// Filter passed to the reader must have From ≈ now-window.
			delta := observed.From.Sub(now.Add(-tc.wantAgo))
			if delta < -5*time.Second || delta > 5*time.Second {
				t.Errorf("filter.From offset from expected = %v; want ≈0 (delta from now-%v)", delta, tc.wantAgo)
			}
		})
	}
}

func TestSecurityEventsByRule_HappyPath_AggregateRoundTrip(t *testing.T) {
	// End-to-end: real :memory: store seeded with events
	// spanning multiple rules, AggregateWafEventsByRule
	// flows through the handler, response shape verified.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetMetricsReader(obsStore)
	m.env.handler.SetWafEventReader(obsStore)

	now := time.Now().UTC()
	if err := obsStore.InsertWafEventBatch(context.Background(), []observability.WafEvent{
		{Ts: now.Add(-2 * time.Hour), RouteID: m.routeID, RuleID: "942100", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: now.Add(-90 * time.Minute), RouteID: m.routeID, RuleID: "942100", Category: "SQLi", Severity: 2, SrcIP: "1.1.1.2", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
		{Ts: now.Add(-1 * time.Hour), RouteID: m.routeID, RuleID: "941100", Category: "XSS", Severity: 3, SrcIP: "2.2.2.1", RequestMethod: "GET", RequestPath: "/", PayloadSample: ""},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?route="+m.routeID+"&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp securityEventsByRuleResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Rows) != 2 {
		t.Fatalf("rows = %d, want 2 (942100 + 941100)", len(resp.Rows))
	}
	// Ordered by count DESC: 942100 (2) first, 941100 (1) second.
	if resp.Rows[0].RuleID != "942100" || resp.Rows[0].Count != 2 || resp.Rows[0].Category != "SQLi" {
		t.Errorf("row[0] = %+v, want 942100/SQLi/2", resp.Rows[0])
	}
	if resp.Rows[1].RuleID != "941100" || resp.Rows[1].Count != 1 || resp.Rows[1].Category != "XSS" {
		t.Errorf("row[1] = %+v, want 941100/XSS/1", resp.Rows[1])
	}
}

func TestSecurityEventsByRule_TimeWindowFiltersOutStale(t *testing.T) {
	// The spec §5.4 drift this amendment fixes: on a 24h
	// window, events older than 24h must NOT appear in the
	// aggregate. Seed events 25h old + 1h old; query 24h;
	// expect only the 1h-old.
	m := newMetricsTestEnv(t)
	obsStore, err := observability.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = obsStore.Close() })
	m.env.handler.SetWafEventReader(obsStore)

	now := time.Now().UTC()
	if err := obsStore.InsertWafEventBatch(context.Background(), []observability.WafEvent{
		{Ts: now.Add(-25 * time.Hour), RouteID: m.routeID, RuleID: "stale", Category: "SQLi"},
		{Ts: now.Add(-1 * time.Hour), RouteID: m.routeID, RuleID: "recent", Category: "SQLi"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/security/events/by-rule?route="+m.routeID+"&window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp securityEventsByRuleResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Rows) != 1 {
		t.Fatalf("rows = %d, want 1 (only the 1h-old event)", len(resp.Rows))
	}
	if resp.Rows[0].RuleID != "recent" {
		t.Errorf("row[0].RuleID = %q, want %q — stale event leaked past the 24h window", resp.Rows[0].RuleID, "recent")
	}
}

// --- /api/v1/security/auth-failures (Step Q.2) ------------------------------

// fakeAuthFailureReader satisfies AuthFailureReader for the
// handler-level tests. queryFn controls the response (events,
// partial flag, error). nil queryFn defaults to (nil, false, nil)
// — empty result, no error.
type fakeAuthFailureReader struct {
	queryFn func(ctx context.Context, actions []string, from, to time.Time, limit int) ([]audit.Event, bool, error)
}

func (f *fakeAuthFailureReader) QueryByActionRange(ctx context.Context, actions []string, from, to time.Time, limit int) ([]audit.Event, bool, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, actions, from, to, limit)
	}
	return nil, false, nil
}

func TestSecurityAuthFailures_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityAuthFailures_Viewer200(t *testing.T) {
	// AC #12 mirror: viewer MUST read the auth-failures endpoint.
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "authfail-viewer", "Auth Failures Viewer", "", "sub-authfail-viewer")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(m.env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed viewer session: %v", err)
	}
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /security/auth-failures: status=%d body=%s — AC #12 requires viewer-or-above read access", rec.Code, rec.Body)
	}
}

func TestSecurityAuthFailures_NilReader_DisabledResponse(t *testing.T) {
	// AC #14: nil reader → 200 with disabled=true, empty
	// timeseries/recent. Same shape as the M /security/events
	// degraded path.
	m := newMetricsTestEnv(t)
	// Intentionally do NOT call SetAuthFailureReader.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp securityAuthFailuresResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (nil reader = degraded)")
	}
	if len(resp.Timeseries) != 0 || len(resp.Recent) != 0 {
		t.Errorf("disabled response leaked data: timeseries=%d recent=%d", len(resp.Timeseries), len(resp.Recent))
	}
}

func TestSecurityAuthFailures_ScanError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return nil, false, errors.New("audit bucket unreadable")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestSecurityAuthFailures_MissingWindow_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing window)", rec.Code)
	}
}

func TestSecurityAuthFailures_InvalidWindow_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=7d", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (window=7d is not 24h/30d)", rec.Code)
	}
}

func TestSecurityAuthFailures_PassesAuthFailureActionsToReader(t *testing.T) {
	// Verify the handler passes the canonical action set to
	// the reader. Anti-regression against a future refactor
	// that drops one of the four actions.
	m := newMetricsTestEnv(t)
	var observedActions []string
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, actions []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			observedActions = actions
			return nil, false, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	want := audit.AuthFailureActions()
	if len(observedActions) != len(want) {
		t.Fatalf("len(observedActions) = %d, want %d (%v)", len(observedActions), len(want), want)
	}
	have := map[string]struct{}{}
	for _, a := range observedActions {
		have[a] = struct{}{}
	}
	for _, a := range want {
		if _, ok := have[a]; !ok {
			t.Errorf("auth-failure action %q missing from handler request", a)
		}
	}
}

func TestSecurityAuthFailures_TimeseriesGapFill(t *testing.T) {
	// Seed 3 events at t-1m, t-2m, t-5m (all within the 24h
	// window). Expect a dense 1440-point timeseries with 0s
	// in the empty minutes.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC()
	events := []audit.Event{
		{Action: audit.ActionLoginFailure, Timestamp: now.Add(-1 * time.Minute), IP: "1.2.3.4"},
		{Action: audit.ActionLoginFailure, Timestamp: now.Add(-2 * time.Minute), IP: "1.2.3.4"},
		{Action: audit.ActionLoginFailure, Timestamp: now.Add(-5 * time.Minute), IP: "5.6.7.8"},
	}
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return events, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAuthFailuresResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 24h window → 1440 minutes of buckets.
	if len(resp.Timeseries) != 1440 {
		t.Errorf("len(timeseries) = %d, want 1440 (24h × 60m gap-filled)", len(resp.Timeseries))
	}
	// Total event count across all points must equal the seeded count.
	total := 0
	nonZero := 0
	for _, p := range resp.Timeseries {
		total += p.Value
		if p.Value > 0 {
			nonZero++
		}
	}
	if total != len(events) {
		t.Errorf("sum(timeseries.value) = %d, want %d (seeded count)", total, len(events))
	}
	// Three events in three distinct minutes → three non-zero buckets.
	if nonZero != 3 {
		t.Errorf("non-zero bucket count = %d, want 3", nonZero)
	}
}

func TestSecurityAuthFailures_RecentFeedSortedDesc(t *testing.T) {
	// The fake returns events in reverse-chronological order
	// (mirroring QueryByActionRange's contract); the handler
	// must preserve that ordering in the `recent` projection.
	m := newMetricsTestEnv(t)
	now := time.Now().UTC()
	events := []audit.Event{
		{Action: audit.ActionLoginFailure, Timestamp: now.Add(-1 * time.Minute), IP: "10.0.0.1", ActorUsernameSnapshot: "admin"},
		{Action: audit.ActionUnlockFailure, Timestamp: now.Add(-5 * time.Minute), IP: "10.0.0.2", ActorUsernameSnapshot: "root"},
		{Action: audit.ActionOIDCLoginRejected, Timestamp: now.Add(-10 * time.Minute), IP: "10.0.0.3", ActorUsernameSnapshot: ""},
	}
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return events, false, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAuthFailuresResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Recent) != 3 {
		t.Fatalf("len(recent) = %d, want 3", len(resp.Recent))
	}
	if resp.Recent[0].SrcIP != "10.0.0.1" || resp.Recent[2].SrcIP != "10.0.0.3" {
		t.Errorf("recent feed not preserved in ts-desc order: %+v", resp.Recent)
	}
	if resp.Recent[0].Action != audit.ActionLoginFailure {
		t.Errorf("recent[0].Action = %q, want %q", resp.Recent[0].Action, audit.ActionLoginFailure)
	}
	if resp.Recent[0].Username != "admin" {
		t.Errorf("recent[0].Username = %q, want %q", resp.Recent[0].Username, "admin")
	}
}

func TestSecurityAuthFailures_PartialFlagPropagates(t *testing.T) {
	// Reader signals partial=true → response.partial=true.
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return []audit.Event{}, true, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/auth-failures?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp securityAuthFailuresResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Partial {
		t.Errorf("partial = false in response, want true (reader signalled cap-hit)")
	}
}

// --- /api/v1/security/throttle-events (Step Q.3) ----------------------------

// fakeThrottleEventReader satisfies ThrottleEventReader. queryFn
// + aggregateFn default to (nil, nil) so callers only set what
// the test cares about — same shape as fakeWafEventReader.
type fakeThrottleEventReader struct {
	queryFn      func(ctx context.Context, filter observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error)
	aggregateFn  func(ctx context.Context, filter observability.ThrottleEventAggregateFilter) ([]observability.ThrottleEventIPAggregate, error)
	distinctIPFn func(ctx context.Context, from, to time.Time) ([]string, error)
}

func (f *fakeThrottleEventReader) QueryThrottleEvents(ctx context.Context, filter observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeThrottleEventReader) AggregateThrottleEventsByIP(ctx context.Context, filter observability.ThrottleEventAggregateFilter) ([]observability.ThrottleEventIPAggregate, error) {
	if f.aggregateFn != nil {
		return f.aggregateFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeThrottleEventReader) DistinctThrottleEventSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if f.distinctIPFn != nil {
		return f.distinctIPFn(ctx, from, to)
	}
	return nil, nil
}

// fakeDecisionReader satisfies DecisionReader. Step N.3 mirror
// of fakeThrottleEventReader. Default returns (nil, nil) so
// tests that don't care about the crowdsec arm can wire the
// reader as a no-op present-reader (avoids triggering the
// partial flag).
type fakeDecisionReader struct {
	queryFn      func(ctx context.Context, filter observability.DecisionEventFilter) ([]observability.DecisionEvent, error)
	distinctIPFn func(ctx context.Context, from, to time.Time) ([]string, error)
}

func (f *fakeDecisionReader) QueryDecisionEvents(ctx context.Context, filter observability.DecisionEventFilter) ([]observability.DecisionEvent, error) {
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeDecisionReader) DistinctDecisionSrcIPs(ctx context.Context, from, to time.Time) ([]string, error) {
	if f.distinctIPFn != nil {
		return f.distinctIPFn(ctx, from, to)
	}
	return nil, nil
}

func TestSecurityThrottleEvents_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityThrottleEvents_Viewer200(t *testing.T) {
	// AC #12 mirror: viewer MUST read /throttle-events.
	m := newMetricsTestEnv(t)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "throttle-viewer", "Throttle Viewer", "", "sub-throttle-viewer")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(m.env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed viewer session: %v", err)
	}
	raw := m.rawHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /security/throttle-events: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestSecurityThrottleEvents_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// Intentionally do NOT call SetThrottleEventReader.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp securityThrottleEventsResponse
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

func TestSecurityThrottleEvents_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		queryFn: func(_ context.Context, _ observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestSecurityThrottleEvents_InvalidLimit_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{})
	cases := []string{"abc", "0", "-5", "1.5"}
	for _, raw := range cases {
		t.Run("limit="+raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events?limit="+raw, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("limit=%q status = %d, want 400", raw, rec.Code)
			}
		})
	}
}

func TestSecurityThrottleEvents_InvalidTier_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{})
	cases := []string{"0", "3", "-1", "abc"}
	for _, raw := range cases {
		t.Run("tier="+raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events?tier="+raw, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("tier=%q status = %d, want 400 (tier must be 1 or 2)", raw, rec.Code)
			}
		})
	}
}

func TestSecurityThrottleEvents_LimitClampedAtCap(t *testing.T) {
	m := newMetricsTestEnv(t)
	var observed observability.ThrottleEventFilter
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		queryFn: func(_ context.Context, f observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error) {
			observed = f
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events?limit=500", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.Limit != securityThrottleEventsLimitCap {
		t.Errorf("filter.Limit = %d, want %d", observed.Limit, securityThrottleEventsLimitCap)
	}
}

func TestSecurityThrottleEvents_FiltersPassed(t *testing.T) {
	m := newMetricsTestEnv(t)
	var observed observability.ThrottleEventFilter
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		queryFn: func(_ context.Context, f observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error) {
			observed = f
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events?srcIp=10.0.0.5&tier=2&limit=25", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.SrcIP != "10.0.0.5" {
		t.Errorf("filter.SrcIP = %q, want 10.0.0.5", observed.SrcIP)
	}
	if observed.Tier != 2 {
		t.Errorf("filter.Tier = %d, want 2", observed.Tier)
	}
	if observed.Limit != 25 {
		t.Errorf("filter.Limit = %d, want 25", observed.Limit)
	}
}

func TestSecurityThrottleEvents_PayloadShape(t *testing.T) {
	// Verify the wire shape per AC #7.
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)
	until := ts.Add(15 * time.Minute)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		queryFn: func(_ context.Context, _ observability.ThrottleEventFilter) ([]observability.ThrottleEvent, error) {
			return []observability.ThrottleEvent{
				{
					ID:                   42,
					Ts:                   ts,
					Tier:                 1,
					SrcIP:                "1.2.3.4",
					AttemptedUsername:    "admin",
					BlockedUntil:         until,
					BlockDurationSeconds: 900,
				},
			}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/throttle-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityThrottleEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(resp.Events))
	}
	e := resp.Events[0]
	if e.ID != 42 || e.Tier != 1 || e.SrcIP != "1.2.3.4" || e.AttemptedUsername != "admin" || e.BlockDurationSeconds != 900 {
		t.Errorf("event field mismatch: %+v", e)
	}
	if e.Ts != ts.Format(time.RFC3339) {
		t.Errorf("event.Ts = %q, want %q", e.Ts, ts.Format(time.RFC3339))
	}
	if e.BlockedUntil != until.Format(time.RFC3339) {
		t.Errorf("event.BlockedUntil = %q, want %q", e.BlockedUntil, until.Format(time.RFC3339))
	}
}

// --- /api/v1/security/attackers-summary (Step Q.3) --------------------------

// installAttackerReaders is a helper that injects all FOUR
// readers expected by the attackers-summary handler (Step N.3
// extended the original Q.3 trio with a crowdsec arm). Each
// reader is configurable via its distinct-IP function; pass
// nil for "no rows" / "skip this source".
func installAttackerReaders(t *testing.T, m *metricsTestEnv, wafIPs, throttleIPs []string, auditIPs []string, crowdsecIPs []string) {
	t.Helper()
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return wafIPs, nil
		},
	})
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return throttleIPs, nil
		},
	})
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			out := make([]audit.Event, 0, len(auditIPs))
			for _, ip := range auditIPs {
				out = append(out, audit.Event{Action: audit.ActionLoginFailure, IP: ip})
			}
			return out, false, nil
		},
	})
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return crowdsecIPs, nil
		},
	})
}

func TestSecurityAttackersSummary_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityAttackersSummary_AllReadersNil_Disabled(t *testing.T) {
	// AC #14: ALL three readers missing → disabled=true.
	m := newMetricsTestEnv(t)
	// Intentionally do NOT set any reader.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode)", rec.Code)
	}
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Disabled {
		t.Errorf("disabled = false, want true (no readers configured)")
	}
	if resp.UniqueIps != 0 {
		t.Errorf("uniqueIps = %d in disabled response, want 0", resp.UniqueIps)
	}
}

func TestSecurityAttackersSummary_InvalidWindow_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	installAttackerReaders(t, m, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=7d", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSecurityAttackersSummary_MissingWindow_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	installAttackerReaders(t, m, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestSecurityAttackersSummary_UnionWithOverlap(t *testing.T) {
	// Critical test for D6.A union correctness. Seed three
	// sources with overlapping IPs and verify:
	//   - uniqueIps = size of the SET union (not sum)
	//   - byBucketSource = per-source SIZES (not the union)
	//
	// WAF: 1.1.1.1, 2.2.2.2, 3.3.3.3 (3 IPs)
	// THROTTLE: 2.2.2.2, 4.4.4.4         (2 IPs, 2.2.2.2 also in WAF)
	// AUDIT:   3.3.3.3, 5.5.5.5         (2 IPs, 3.3.3.3 also in WAF)
	// UNION: {1,2,3,4,5} = 5 unique
	m := newMetricsTestEnv(t)
	installAttackerReaders(t,
		m,
		[]string{"1.1.1.1", "2.2.2.2", "3.3.3.3"},
		[]string{"2.2.2.2", "4.4.4.4"},
		[]string{"3.3.3.3", "5.5.5.5"},
		nil, // crowdsec arm intentionally empty in this 3-source test; the 4-source case is TestSecurityAttackersSummary_UnionAcrossFourSources
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAttackersSummaryResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.UniqueIps != 5 {
		t.Errorf("uniqueIps = %d, want 5 (union of overlapping sets)", resp.UniqueIps)
	}
	if resp.ByBucketSource.WAF != 3 {
		t.Errorf("byBucketSource.waf = %d, want 3", resp.ByBucketSource.WAF)
	}
	if resp.ByBucketSource.Throttle != 2 {
		t.Errorf("byBucketSource.throttle = %d, want 2", resp.ByBucketSource.Throttle)
	}
	// Audit dedupes empty IPs (none here) AND the in-handler
	// map dedupes duplicates within audit (none here).
	if resp.ByBucketSource.Audit != 2 {
		t.Errorf("byBucketSource.audit = %d, want 2", resp.ByBucketSource.Audit)
	}
}

func TestSecurityAttackersSummary_DuplicatesInOneSource_DeduplicatedForBreakdown(t *testing.T) {
	// The audit source dedupes within itself (multiple
	// auth-failure events from the same IP → ONE IP in the
	// audit breakdown count, ONE entry in the union). WAF
	// and Throttle distinct-IP queries return already-
	// distinct slices at the storage layer (SELECT DISTINCT),
	// so the test simulates that contract.
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			// Same IP 5 times → 1 unique
			return []audit.Event{
				{Action: audit.ActionLoginFailure, IP: "9.9.9.9"},
				{Action: audit.ActionLoginFailure, IP: "9.9.9.9"},
				{Action: audit.ActionLoginFailure, IP: "9.9.9.9"},
				{Action: audit.ActionUnlockFailure, IP: "9.9.9.9"},
				{Action: audit.ActionOIDCLoginRejected, IP: "9.9.9.9"},
			}, false, nil
		},
	})
	m.env.handler.SetWafEventReader(&fakeWafEventReader{})
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{})
	m.env.handler.SetDecisionReader(&fakeDecisionReader{}) // 4th reader present-but-empty so partial does not fire

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.ByBucketSource.Audit != 1 {
		t.Errorf("byBucketSource.audit = %d, want 1 (5 events from same IP → 1 unique)", resp.ByBucketSource.Audit)
	}
	if resp.UniqueIps != 1 {
		t.Errorf("uniqueIps = %d, want 1", resp.UniqueIps)
	}
}

func TestSecurityAttackersSummary_EmptyIPsIgnored(t *testing.T) {
	// Audit events with empty IP (per spec §8.5 — IP
	// extractor failed) must NOT contribute to the union
	// or per-source counts.
	m := newMetricsTestEnv(t)
	m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
		queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
			return []audit.Event{
				{Action: audit.ActionLoginFailure, IP: ""},
				{Action: audit.ActionLoginFailure, IP: "8.8.8.8"},
			}, false, nil
		},
	})
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"", "7.7.7.7"}, nil
		},
	})
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{})
	m.env.handler.SetDecisionReader(&fakeDecisionReader{}) // 4th reader present-but-empty

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	// Union should be {7.7.7.7, 8.8.8.8} = 2; empty strings ignored.
	if resp.UniqueIps != 2 {
		t.Errorf("uniqueIps = %d, want 2 (empty IPs filtered)", resp.UniqueIps)
	}
}

func TestSecurityAttackersSummary_PartialReaders_NoDisabledFlag(t *testing.T) {
	// Four-state contract pinning (subset-nil branch — Step
	// N.3 extended the original Q.3 three-state to four):
	//   - disabled MUST stay false (ALL FOUR nil is the only
	//     disabled trigger).
	//   - partial MUST be true (subset is down, signal is
	//     honest-but-narrower).
	//   - the union still reflects the readers that DID
	//     respond.
	// AC #14 wording per §3.4 + N AC #15, aligned with Q.2's
	// partial flag convention.
	m := newMetricsTestEnv(t)
	m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return []string{"1.2.3.4"}, nil
		},
	})
	// WAF + audit + crowdsec readers intentionally NOT set.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Disabled {
		t.Errorf("disabled = true with one reader present, want false")
	}
	if !resp.Partial {
		t.Errorf("partial = false with a subset of readers nil, want true")
	}
	if resp.UniqueIps != 1 {
		t.Errorf("uniqueIps = %d, want 1 (throttle reader contributed)", resp.UniqueIps)
	}
	if resp.ByBucketSource.Throttle != 1 ||
		resp.ByBucketSource.WAF != 0 ||
		resp.ByBucketSource.Audit != 0 ||
		resp.ByBucketSource.CrowdSec != 0 {
		t.Errorf("byBucketSource mismatch: %+v", resp.ByBucketSource)
	}
}

func TestSecurityAttackersSummary_PartialFlagFires_OnAnySingleNilReader(t *testing.T) {
	// Explicit pinning of the partial-flag trigger across
	// each individual reader being nil. FOUR sub-cases —
	// one reader missing at a time (N.3 extended Q.3's 3
	// readers to 4), the other three wired with a single IP
	// each. Verify `partial=true` in every case and the
	// union/breakdown reflect what we DID get.
	cases := []struct {
		name         string
		setupSkip    string // which reader to leave nil: "waf" | "throttle" | "audit" | "crowdsec"
		wantWAF      int
		wantThr      int
		wantAudit    int
		wantCrowdSec int
		wantUnique   int
	}{
		{name: "waf-nil", setupSkip: "waf", wantThr: 1, wantAudit: 1, wantCrowdSec: 1, wantUnique: 3},
		{name: "throttle-nil", setupSkip: "throttle", wantWAF: 1, wantAudit: 1, wantCrowdSec: 1, wantUnique: 3},
		{name: "audit-nil", setupSkip: "audit", wantWAF: 1, wantThr: 1, wantCrowdSec: 1, wantUnique: 3},
		{name: "crowdsec-nil", setupSkip: "crowdsec", wantWAF: 1, wantThr: 1, wantAudit: 1, wantUnique: 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newMetricsTestEnv(t)
			if tc.setupSkip != "waf" {
				m.env.handler.SetWafEventReader(&fakeWafEventReader{
					distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
						return []string{"7.7.7.7"}, nil
					},
				})
			}
			if tc.setupSkip != "throttle" {
				m.env.handler.SetThrottleEventReader(&fakeThrottleEventReader{
					distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
						return []string{"8.8.8.8"}, nil
					},
				})
			}
			if tc.setupSkip != "audit" {
				m.env.handler.SetAuthFailureReader(&fakeAuthFailureReader{
					queryFn: func(_ context.Context, _ []string, _, _ time.Time, _ int) ([]audit.Event, bool, error) {
						return []audit.Event{{Action: audit.ActionLoginFailure, IP: "9.9.9.9"}}, false, nil
					},
				})
			}
			if tc.setupSkip != "crowdsec" {
				m.env.handler.SetDecisionReader(&fakeDecisionReader{
					distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
						return []string{"6.6.6.6"}, nil
					},
				})
			}

			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			var resp securityAttackersSummaryResponse
			_ = json.NewDecoder(rec.Body).Decode(&resp)

			if resp.Disabled {
				t.Errorf("disabled = true with one reader missing; want false (only ALL-nil → disabled)")
			}
			if !resp.Partial {
				t.Errorf("partial = false with reader %q missing; want true", tc.setupSkip)
			}
			if resp.ByBucketSource.WAF != tc.wantWAF {
				t.Errorf("waf = %d, want %d", resp.ByBucketSource.WAF, tc.wantWAF)
			}
			if resp.ByBucketSource.Throttle != tc.wantThr {
				t.Errorf("throttle = %d, want %d", resp.ByBucketSource.Throttle, tc.wantThr)
			}
			if resp.ByBucketSource.Audit != tc.wantAudit {
				t.Errorf("audit = %d, want %d", resp.ByBucketSource.Audit, tc.wantAudit)
			}
			if resp.ByBucketSource.CrowdSec != tc.wantCrowdSec {
				t.Errorf("crowdsec = %d, want %d", resp.ByBucketSource.CrowdSec, tc.wantCrowdSec)
			}
			if resp.UniqueIps != tc.wantUnique {
				t.Errorf("uniqueIps = %d, want %d", resp.UniqueIps, tc.wantUnique)
			}
		})
	}
}

func TestSecurityAttackersSummary_AllPresent_NeitherFlag(t *testing.T) {
	// Four-state contract pinning (all-present branch — Step
	// N.3 extended the original Q.3 three-state from 3 to 4
	// readers): when EVERY reader is wired (waf + throttle +
	// audit + crowdsec), neither `disabled` nor `partial` is
	// set. The dashboard relies on this to decide whether to
	// show the "data incomplete" hint.
	m := newMetricsTestEnv(t)
	installAttackerReaders(t,
		m,
		[]string{"1.1.1.1"},
		[]string{"2.2.2.2"},
		[]string{"3.3.3.3"},
		[]string{"4.4.4.4"},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Disabled {
		t.Errorf("disabled = true with all readers present, want false")
	}
	if resp.Partial {
		t.Errorf("partial = true with all readers present, want false")
	}
	if resp.UniqueIps != 4 {
		t.Errorf("uniqueIps = %d, want 4 (one IP per source, no overlap)", resp.UniqueIps)
	}
}

func TestSecurityAttackersSummary_ReaderError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetWafEventReader(&fakeWafEventReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// --- /api/v1/security/decisions (Step N.3) ----------------------------------

func TestSecurityDecisions_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestSecurityDecisions_Viewer200(t *testing.T) {
	// AC #N.20 (mirror of Q.3's AC #12): viewer MUST read
	// /security/decisions.
	m := newMetricsTestEnv(t)
	m.env.handler.SetDecisionReader(&fakeDecisionReader{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "decisions-viewer", "Decisions Viewer", "", "sub-decisions-viewer")
	if err != nil {
		t.Fatalf("seed viewer: %v", err)
	}
	if viewer.Role != auth.UserRoleViewer {
		t.Fatalf("seed-viewer role = %q; want viewer", viewer.Role)
	}
	sessionStore := auth.NewSessionStore(m.env.store.DB())
	s, err := sessionStore.Create(ctx, viewer.ID, false, "127.0.0.1", "test/1")
	if err != nil {
		t.Fatalf("seed viewer session: %v", err)
	}
	raw := m.rawHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /security/decisions: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestSecurityDecisions_NilReader_DisabledResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK)", rec.Code)
	}
	var resp securityDecisionsResponse
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

func TestSecurityDecisions_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		queryFn: func(_ context.Context, _ observability.DecisionEventFilter) ([]observability.DecisionEvent, error) {
			return nil, errors.New("disk full")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestSecurityDecisions_InvalidLimit_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetDecisionReader(&fakeDecisionReader{})
	cases := []string{"abc", "0", "-5", "1.5"}
	for _, raw := range cases {
		t.Run("limit="+raw, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions?limit="+raw, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("limit=%q status = %d, want 400", raw, rec.Code)
			}
		})
	}
}

func TestSecurityDecisions_LimitClampedAtCap(t *testing.T) {
	m := newMetricsTestEnv(t)
	var observed observability.DecisionEventFilter
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		queryFn: func(_ context.Context, f observability.DecisionEventFilter) ([]observability.DecisionEvent, error) {
			observed = f
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions?limit=500", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.Limit != securityDecisionsLimitCap {
		t.Errorf("filter.Limit = %d, want %d", observed.Limit, securityDecisionsLimitCap)
	}
}

func TestSecurityDecisions_FiltersPassed(t *testing.T) {
	m := newMetricsTestEnv(t)
	var observed observability.DecisionEventFilter
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		queryFn: func(_ context.Context, f observability.DecisionEventFilter) ([]observability.DecisionEvent, error) {
			observed = f
			return nil, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions?scope=range&srcIp=185.142.86.0/24&scenario=crowdsecurity/http-probing&limit=25&onlyActive=true", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if observed.Scope != "range" {
		t.Errorf("filter.Scope = %q, want range", observed.Scope)
	}
	if observed.Value != "185.142.86.0/24" {
		t.Errorf("filter.Value = %q, want 185.142.86.0/24 (srcIp query param maps to Value field)", observed.Value)
	}
	if observed.Scenario != "crowdsecurity/http-probing" {
		t.Errorf("filter.Scenario = %q, want crowdsecurity/http-probing", observed.Scenario)
	}
	if observed.Limit != 25 {
		t.Errorf("filter.Limit = %d, want 25", observed.Limit)
	}
	if !observed.OnlyActive {
		t.Error("filter.OnlyActive = false, want true (onlyActive=true query param)")
	}
}

func TestSecurityDecisions_PayloadShape(t *testing.T) {
	// Pin the wire shape promised by the Step Q.4 mock UI's
	// "185.142.86.0/24 · SQLi · auto"-style rows: {scope,
	// value, scenario, type} columns must round-trip
	// verbatim from the storage layer.
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 5, 29, 14, 0, 0, 0, time.UTC)
	exp := ts.Add(24 * time.Hour)
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		queryFn: func(_ context.Context, _ observability.DecisionEventFilter) ([]observability.DecisionEvent, error) {
			return []observability.DecisionEvent{
				{
					ID:              7,
					UUID:            "uuid-185-range",
					Ts:              ts,
					Scope:           "range",
					Value:           "185.142.86.0/24",
					Type:            "ban",
					Scenario:        "crowdsecurity/http-probing",
					ExpiresAt:       exp,
					DurationSeconds: 86400,
				},
			}, nil
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/decisions", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityDecisionsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("len(events) = %d, want 1", len(resp.Events))
	}
	e := resp.Events[0]
	if e.ID != 7 || e.UUID != "uuid-185-range" || e.Scope != "range" ||
		e.Value != "185.142.86.0/24" || e.Type != "ban" ||
		e.Scenario != "crowdsecurity/http-probing" || e.DurationSeconds != 86400 {
		t.Errorf("event field mismatch: %+v", e)
	}
	if e.Ts != ts.Format(time.RFC3339) {
		t.Errorf("event.Ts = %q, want %q", e.Ts, ts.Format(time.RFC3339))
	}
	if e.ExpiresAt != exp.Format(time.RFC3339) {
		t.Errorf("event.ExpiresAt = %q, want %q", e.ExpiresAt, exp.Format(time.RFC3339))
	}
}

// --- /api/v1/security/attackers-summary 4th-source extension (Step N.3) ----

func TestSecurityAttackersSummary_UnionAcrossFourSources(t *testing.T) {
	// Step N.3 extension: the union now spans 4 sources.
	//
	// WAF:      1.1.1.1, 2.2.2.2
	// THROTTLE: 3.3.3.3
	// AUDIT:    4.4.4.4
	// CROWDSEC: 5.5.5.5, 2.2.2.2 (overlaps WAF)
	// UNION:    {1,2,3,4,5} = 5 unique
	m := newMetricsTestEnv(t)
	installAttackerReaders(t,
		m,
		[]string{"1.1.1.1", "2.2.2.2"},
		[]string{"3.3.3.3"},
		[]string{"4.4.4.4"},
		[]string{"5.5.5.5", "2.2.2.2"},
	)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp securityAttackersSummaryResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.UniqueIps != 5 {
		t.Errorf("uniqueIps = %d, want 5 (union of 4 overlapping sources)", resp.UniqueIps)
	}
	if resp.ByBucketSource.WAF != 2 {
		t.Errorf("waf = %d, want 2", resp.ByBucketSource.WAF)
	}
	if resp.ByBucketSource.Throttle != 1 {
		t.Errorf("throttle = %d, want 1", resp.ByBucketSource.Throttle)
	}
	if resp.ByBucketSource.Audit != 1 {
		t.Errorf("audit = %d, want 1", resp.ByBucketSource.Audit)
	}
	if resp.ByBucketSource.CrowdSec != 2 {
		t.Errorf("crowdsec = %d, want 2", resp.ByBucketSource.CrowdSec)
	}
	if resp.Disabled || resp.Partial {
		t.Errorf("disabled=%v partial=%v; want both false with all 4 readers wired", resp.Disabled, resp.Partial)
	}
}

func TestSecurityAttackersSummary_CrowdSecReaderError_503(t *testing.T) {
	// Any of the 4 readers returning an error → 503.
	// Validates the crowdsec arm's error path (Step N.3
	// extension to Q.3's TestSecurityAttackersSummary_ReaderError_503).
	m := newMetricsTestEnv(t)
	m.env.handler.SetDecisionReader(&fakeDecisionReader{
		distinctIPFn: func(_ context.Context, _, _ time.Time) ([]string, error) {
			return nil, errors.New("crowdsec mirror lost lapi connection")
		},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/attackers-summary?window=24h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}
