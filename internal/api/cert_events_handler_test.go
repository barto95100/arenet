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
)

// fakeCertEventReader is the test double for CertEventReader.
// Either queryFn / countFn return a fixed slice/count OR an
// error — same pattern as fakeWafEventReader.
//
// capturedFilter records the most recent CertEventFilter the
// handler passed in so the test can assert query-string-to-
// filter parameter mapping (limit, since, until, levels,
// search).
type fakeCertEventReader struct {
	queryFn        func(ctx context.Context, filter observability.CertEventFilter) ([]observability.CertEvent, error)
	countFn        func(ctx context.Context, filter observability.CertEventFilter) (int64, error)
	capturedFilter observability.CertEventFilter
	// Phase 5 — aggregate fake. aggregateFn returns the slice the
	// handler is supposed to ship; capturedAggregateFilter records
	// the filter the handler computed from the query string for
	// parameter-mapping assertions.
	aggregateFn              func(ctx context.Context, filter observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error)
	capturedAggregateFilter  observability.CertEventAggregateFilter
}

func (f *fakeCertEventReader) QueryCertEvents(ctx context.Context, filter observability.CertEventFilter) ([]observability.CertEvent, error) {
	f.capturedFilter = filter
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeCertEventReader) CountCertEvents(ctx context.Context, filter observability.CertEventFilter) (int64, error) {
	if f.countFn != nil {
		return f.countFn(ctx, filter)
	}
	// Default: count == events returned by Query (HasMore = false).
	if f.queryFn != nil {
		evts, _ := f.queryFn(ctx, filter)
		return int64(len(evts)), nil
	}
	return 0, nil
}

func (f *fakeCertEventReader) AggregateCertEvents(ctx context.Context, filter observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error) {
	f.capturedAggregateFilter = filter
	if f.aggregateFn != nil {
		return f.aggregateFn(ctx, filter)
	}
	return nil, nil
}

// --- /api/v1/observability/cert-events: auth gate --------------------------

func TestCertEvents_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestCertEvents_Viewer200(t *testing.T) {
	// Mirrors TestSecurityEvents_Viewer200: AC #12 viewer-or-
	// above read access. Cert events are operationally
	// equivalent (lifecycle data, no operator action surface);
	// blocking viewers would break the Activity log page.
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "cert-events-viewer", "Cert Events Viewer", "", "sub-cert-events-viewer")
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /observability/cert-events: status=%d body=%s", rec.Code, rec.Body)
	}
}

// --- AC #13 degraded path --------------------------------------------------

func TestCertEvents_NilReader_DegradedResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// reader intentionally not set → nil → degraded response.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp certEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false, want true (reader is nil)")
	}
	if len(resp.Events) != 0 {
		t.Errorf("Events len = %d, want 0", len(resp.Events))
	}
	if resp.Total != 0 || resp.HasMore {
		t.Errorf("Total/HasMore = %d/%v, want 0/false", resp.Total, resp.HasMore)
	}
}

// --- Happy path ------------------------------------------------------------

func TestCertEvents_HappyPath_RoundTrip(t *testing.T) {
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{
		queryFn: func(_ context.Context, _ observability.CertEventFilter) ([]observability.CertEvent, error) {
			return []observability.CertEvent{
				{
					ID: 1, Ts: ts, Level: observability.CertEventLevelInfo,
					Type:   observability.CertEventTypeObtained,
					Domain: "*.example.com", Issuer: "Let's Encrypt",
					Challenge: "DNS-01", Renewal: true,
				},
				{
					ID: 2, Ts: ts.Add(-time.Hour), Level: observability.CertEventLevelError,
					Type:   observability.CertEventTypeFailed,
					Domain: "test.local", Error: "subject does not qualify",
				},
			}, nil
		},
		countFn: func(_ context.Context, _ observability.CertEventFilter) (int64, error) {
			return 2, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body)
	}
	var resp certEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true, want false (reader is wired)")
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if resp.HasMore {
		t.Errorf("HasMore = true, want false (Total == len(Events))")
	}
	if len(resp.Events) != 2 {
		t.Fatalf("Events len = %d, want 2", len(resp.Events))
	}
	// Field round-trip on the first row.
	first := resp.Events[0]
	if first.Domain != "*.example.com" || first.Issuer != "Let's Encrypt" {
		t.Errorf("first row: %+v", first)
	}
	if first.Level != "INFO" || first.EventType != "cert_obtained" {
		t.Errorf("first row level/type: %+v", first)
	}
	if !first.Renewal {
		t.Errorf("first row Renewal = false, want true")
	}
	if first.Challenge != "DNS-01" {
		t.Errorf("first row Challenge = %q, want DNS-01", first.Challenge)
	}
	// Second row carries Error verbatim.
	if resp.Events[1].Error != "subject does not qualify" {
		t.Errorf("second row Error = %q", resp.Events[1].Error)
	}
}

// TestCertEvents_HasMore_TrueWhenCountExceedsEvents pins the
// hasMore derivation: when total > len(events), the response
// signals "there are more rows beyond this page".
func TestCertEvents_HasMore_TrueWhenCountExceedsEvents(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{
		queryFn: func(_ context.Context, _ observability.CertEventFilter) ([]observability.CertEvent, error) {
			// Returned 100 rows (= limit cap).
			out := make([]observability.CertEvent, 100)
			for i := range out {
				out[i] = observability.CertEvent{ID: int64(i), Domain: "x"}
			}
			return out, nil
		},
		countFn: func(_ context.Context, _ observability.CertEventFilter) (int64, error) {
			return 250, nil // 250 total, only 100 returned.
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	var resp certEventsResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Total != 250 {
		t.Errorf("Total = %d, want 250", resp.Total)
	}
	if !resp.HasMore {
		t.Errorf("HasMore = false, want true (250 > 100)")
	}
}

// --- Query parameter parsing -----------------------------------------------

func TestCertEvents_LimitClamp(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?limit=5000", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (silent clamp)", rec.Code)
	}
	if r.capturedFilter.Limit != certEventsLimitCap {
		t.Errorf("filter.Limit = %d, want %d (cap)", r.capturedFilter.Limit, certEventsLimitCap)
	}
}

func TestCertEvents_LimitDefault_WhenMissing(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if r.capturedFilter.Limit != certEventsDefaultLimit {
		t.Errorf("filter.Limit = %d, want %d (default)", r.capturedFilter.Limit, certEventsDefaultLimit)
	}
}

func TestCertEvents_InvalidLimit_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})

	for _, bad := range []string{"abc", "-5", "0"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?limit="+bad, nil)
		rec := httptest.NewRecorder()
		m.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q status = %d, want 400", bad, rec.Code)
		}
	}
}

func TestCertEvents_SinceUntilParsing(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	since := "2026-06-01T00:00:00Z"
	until := "2026-06-06T12:00:00Z"
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?since="+since+"&until="+until, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body = %s", rec.Code, rec.Body)
	}
	wantSince, _ := time.Parse(time.RFC3339, since)
	wantUntil, _ := time.Parse(time.RFC3339, until)
	if !r.capturedFilter.From.Equal(wantSince) {
		t.Errorf("filter.From = %v, want %v", r.capturedFilter.From, wantSince)
	}
	if !r.capturedFilter.To.Equal(wantUntil) {
		t.Errorf("filter.To = %v, want %v", r.capturedFilter.To, wantUntil)
	}
}

func TestCertEvents_InvalidSince_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?since=not-a-date", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCertEvents_ReversedSinceUntil_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})
	// since > until → 400.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?since=2026-06-06T12:00:00Z&until=2026-06-01T00:00:00Z", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (until <= since)", rec.Code)
	}
}

func TestCertEvents_LevelFilter_Single(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?level=ERROR", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(r.capturedFilter.Levels) != 1 || r.capturedFilter.Levels[0] != observability.CertEventLevelError {
		t.Errorf("filter.Levels = %v, want [ERROR]", r.capturedFilter.Levels)
	}
}

func TestCertEvents_LevelFilter_Multi(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?level=INFO,ERROR", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(r.capturedFilter.Levels) != 2 {
		t.Fatalf("filter.Levels len = %d, want 2", len(r.capturedFilter.Levels))
	}
}

func TestCertEvents_InvalidLevel_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events?level=DEBUG", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCertEvents_SearchPassThrough(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?search=let%27s%20encrypt", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if r.capturedFilter.Search != "let's encrypt" {
		t.Errorf("filter.Search = %q, want %q", r.capturedFilter.Search, "let's encrypt")
	}
}

func TestCertEvents_SearchTrimsWhitespace(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?search=%20%20cert%20%20", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if r.capturedFilter.Search != "cert" {
		t.Errorf("filter.Search = %q, want %q (trimmed)", r.capturedFilter.Search, "cert")
	}
}

// --- Cert.B domain + type filter passthrough -------------------------------

// TestCertEvents_DomainFilterPassThrough pins that ?domain= reaches
// the storage filter as exact-match. Cert.B (2026-06-23) uses this
// for the /certs drill-down which fetches the last N events for a
// specific hostname without the substring imprecision of `search`.
func TestCertEvents_DomainFilterPassThrough(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?domain=vault.example.com", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if r.capturedFilter.Domain != "vault.example.com" {
		t.Errorf("filter.Domain = %q, want %q",
			r.capturedFilter.Domain, "vault.example.com")
	}
}

func TestCertEvents_DomainFilterTrimsWhitespace(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?domain=%20%20example.com%20%20", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if r.capturedFilter.Domain != "example.com" {
		t.Errorf("filter.Domain = %q, want %q (trimmed)",
			r.capturedFilter.Domain, "example.com")
	}
}

func TestCertEvents_DomainFilter_EmptyPassesThroughAsNoFilter(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?domain=", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if r.capturedFilter.Domain != "" {
		t.Errorf("filter.Domain = %q, want \"\" (empty = no filter)",
			r.capturedFilter.Domain)
	}
}

// TestCertEvents_TypeFilter_cert_failed pins that ?type=cert_failed
// reaches the storage filter — primary use case for the /certs
// stale-failure badge in Cert.B (operator wants "did this domain
// have any cert_failed event in the last N hours").
func TestCertEvents_TypeFilter_cert_failed(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?type=cert_failed", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if r.capturedFilter.Type != "cert_failed" {
		t.Errorf("filter.Type = %q, want cert_failed", r.capturedFilter.Type)
	}
}

// TestCertEvents_DomainAndTypeCombined pins that the two filters
// compose : domain + type, both forwarded to storage.
func TestCertEvents_DomainAndTypeCombined(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?domain=auth.example.com&type=cert_failed&limit=5", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if r.capturedFilter.Domain != "auth.example.com" {
		t.Errorf("filter.Domain = %q, want auth.example.com", r.capturedFilter.Domain)
	}
	if r.capturedFilter.Type != "cert_failed" {
		t.Errorf("filter.Type = %q, want cert_failed", r.capturedFilter.Type)
	}
	if r.capturedFilter.Limit != 5 {
		t.Errorf("filter.Limit = %d, want 5", r.capturedFilter.Limit)
	}
}

// TestCertEvents_TypeFilter_UnknownPassesThrough — defensive contract :
// the handler does NOT return 400 for an unrecognised type token.
// Future certmagic versions may emit new event types we don't yet
// know about ; the storage layer filters as a literal string so an
// unknown type cleanly returns 0 rows rather than blocking the call.
func TestCertEvents_TypeFilter_UnknownPassesThrough(t *testing.T) {
	m := newMetricsTestEnv(t)
	r := &fakeCertEventReader{}
	m.env.handler.SetCertEventReader(r)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events?type=cert_future_event_type", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (unknown type passes through)", rec.Code)
	}
	if r.capturedFilter.Type != "cert_future_event_type" {
		t.Errorf("filter.Type = %q, want pass-through", r.capturedFilter.Type)
	}
}

// --- Query error path ------------------------------------------------------

func TestCertEvents_QueryError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{
		queryFn: func(_ context.Context, _ observability.CertEventFilter) ([]observability.CertEvent, error) {
			return nil, errors.New("simulated db error")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestCertEvents_CountError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{
		queryFn: func(_ context.Context, _ observability.CertEventFilter) ([]observability.CertEvent, error) {
			return []observability.CertEvent{}, nil
		},
		countFn: func(_ context.Context, _ observability.CertEventFilter) (int64, error) {
			return 0, errors.New("simulated count error")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

// --- HasCertEventReader getter --------------------------------------------

func TestHasCertEventReader_NilWhenUnset(t *testing.T) {
	env := newTestEnv(t, false)
	if env.handler.HasCertEventReader() {
		t.Errorf("HasCertEventReader = true without setter, want false")
	}
}

func TestHasCertEventReader_TrueAfterSetter(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertEventReader(&fakeCertEventReader{})
	if !env.handler.HasCertEventReader() {
		t.Errorf("HasCertEventReader = false after setter, want true")
	}
}

// --- Phase 5 — /observability/cert-events/aggregate ----------------------

func TestCertEventsAggregate_NilReader_Degraded(t *testing.T) {
	m := newMetricsTestEnv(t)
	// reader intentionally not wired → AC #13 degraded mode.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events/aggregate", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded, not 5xx)", rec.Code)
	}
	var resp certEventsAggregateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false, want true (reader is nil)")
	}
	if len(resp.Buckets) != 0 {
		t.Errorf("Buckets len = %d, want 0", len(resp.Buckets))
	}
}

func TestCertEventsAggregate_HappyPath_DefaultWindow30dInterval1d(t *testing.T) {
	m := newMetricsTestEnv(t)
	bucketStart := time.Now().UTC().Add(-24 * time.Hour).Truncate(time.Hour)
	fake := &fakeCertEventReader{
		aggregateFn: func(_ context.Context, _ observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error) {
			return []observability.CertEventBucket{
				{BucketStart: bucketStart, Issued: 3, Renewed: 1, Failed: 2},
			}, nil
		},
	}
	m.env.handler.SetCertEventReader(fake)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events/aggregate", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	var resp certEventsAggregateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true, want false (reader is wired)")
	}
	if len(resp.Buckets) != 1 {
		t.Fatalf("Buckets len = %d, want 1", len(resp.Buckets))
	}
	if got := resp.Buckets[0]; got.Issued != 3 || got.Renewed != 1 || got.Failed != 2 {
		t.Errorf("bucket counts mismatch: got issued=%d renewed=%d failed=%d, want 3/1/2",
			got.Issued, got.Renewed, got.Failed)
	}

	// Default-window assertion: handler must have asked for 30d
	// at 1d granularity per the brief defaults.
	gotFilter := fake.capturedAggregateFilter
	gotWindow := gotFilter.To.Sub(gotFilter.From)
	if gotWindow != 30*24*time.Hour {
		t.Errorf("default window = %s, want 720h (30d)", gotWindow)
	}
	if gotFilter.Interval != 24*time.Hour {
		t.Errorf("default interval = %s, want 24h", gotFilter.Interval)
	}
}

func TestCertEventsAggregate_CustomWindowAndInterval(t *testing.T) {
	m := newMetricsTestEnv(t)
	fake := &fakeCertEventReader{
		aggregateFn: func(_ context.Context, _ observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error) {
			return []observability.CertEventBucket{}, nil
		},
	}
	m.env.handler.SetCertEventReader(fake)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events/aggregate?window=7d&interval=1h", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	gotFilter := fake.capturedAggregateFilter
	gotWindow := gotFilter.To.Sub(gotFilter.From)
	if gotWindow != 7*24*time.Hour {
		t.Errorf("window = %s, want 168h (7d)", gotWindow)
	}
	if gotFilter.Interval != time.Hour {
		t.Errorf("interval = %s, want 1h", gotFilter.Interval)
	}
}

func TestCertEventsAggregate_ClampsExcessiveWindow(t *testing.T) {
	// 365d > 90d cap → handler must silently clamp to 90d.
	m := newMetricsTestEnv(t)
	fake := &fakeCertEventReader{
		aggregateFn: func(_ context.Context, _ observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error) {
			return []observability.CertEventBucket{}, nil
		},
	}
	m.env.handler.SetCertEventReader(fake)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events/aggregate?window=365d", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body)
	}
	gotWindow := fake.capturedAggregateFilter.To.Sub(fake.capturedAggregateFilter.From)
	if gotWindow != 90*24*time.Hour {
		t.Errorf("window = %s, want clamped to 90d (2160h)", gotWindow)
	}
}

func TestCertEventsAggregate_RejectsBadWindow(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events/aggregate?window=not-a-duration", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (bad window format)", rec.Code)
	}
}

func TestCertEventsAggregate_RejectsBadInterval(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/observability/cert-events/aggregate?interval=garbage", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (bad interval format)", rec.Code)
	}
}

func TestCertEventsAggregate_StoreError_503(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCertEventReader(&fakeCertEventReader{
		aggregateFn: func(_ context.Context, _ observability.CertEventAggregateFilter) ([]observability.CertEventBucket, error) {
			return nil, errors.New("sqlite EBUSY")
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events/aggregate", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
}

func TestCertEventsAggregate_AnonReturns401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/cert-events/aggregate", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anon status = %d, want 401", rec.Code)
	}
}
