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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// Step Z.1 — rate-limit events handler tests. Mirror of
// country_block_events_handler_test.go shape: degraded path
// (nil reader → 200 + degraded:true), filter parameter
// mapping, RFC 3339 since/until parsing.

type fakeRateLimitEventReader struct {
	queryFn        func(ctx context.Context, filter observability.RateLimitEventFilter) ([]observability.RateLimitEvent, error)
	countFn        func(ctx context.Context, from, to time.Time) (int64, error)
	capturedFilter observability.RateLimitEventFilter
}

func (f *fakeRateLimitEventReader) QueryRateLimitEvents(
	ctx context.Context,
	filter observability.RateLimitEventFilter,
) ([]observability.RateLimitEvent, error) {
	f.capturedFilter = filter
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func (f *fakeRateLimitEventReader) CountRateLimitEventsByWindow(
	ctx context.Context, from, to time.Time,
) (int64, error) {
	if f.countFn != nil {
		return f.countFn(ctx, from, to)
	}
	return 0, nil
}

func TestRateLimitEvents_NilReader_DegradedResponse(t *testing.T) {
	m := newMetricsTestEnv(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/rate-limit-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (degraded is OK, not 5xx)", rec.Code)
	}
	var resp rateLimitEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false; want true (reader is nil)")
	}
	if len(resp.Events) != 0 {
		t.Errorf("Events len = %d; want 0", len(resp.Events))
	}
}

func TestRateLimitEvents_HappyPath_RoundTrip(t *testing.T) {
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)
	m.env.handler.SetRateLimitEventReader(&fakeRateLimitEventReader{
		queryFn: func(_ context.Context, _ observability.RateLimitEventFilter) ([]observability.RateLimitEvent, error) {
			return []observability.RateLimitEvent{
				{
					ID: 1, Ts: ts, RouteID: "route-a", Zone: "route-route-a",
					RemoteIP: "203.0.113.5", WaitMs: 1500,
				},
				{
					ID: 2, Ts: ts.Add(-time.Minute), RouteID: "route-b", Zone: "route-route-b",
					RemoteIP: "203.0.113.6", WaitMs: 800,
				},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/rate-limit-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body)
	}
	var resp rateLimitEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true; want false (reader is wired)")
	}
	if len(resp.Events) != 2 {
		t.Fatalf("expected 2 events; got %d", len(resp.Events))
	}
	first := resp.Events[0]
	if first.RouteID != "route-a" || first.RemoteIP != "203.0.113.5" ||
		first.Zone != "route-route-a" || first.WaitMs != 1500 {
		t.Errorf("first row mismatch: %+v", first)
	}
	if !strings.HasPrefix(first.Ts, "2026-06-18T12:00:00") {
		t.Errorf("ts = %q; want RFC 3339 starting 2026-06-18T12:00:00", first.Ts)
	}
}

func TestRateLimitEvents_FilterMapping(t *testing.T) {
	m := newMetricsTestEnv(t)
	reader := &fakeRateLimitEventReader{}
	m.env.handler.SetRateLimitEventReader(reader)

	since := "2026-06-17T00:00:00Z"
	until := "2026-06-18T00:00:00Z"
	url := "/api/v1/security/rate-limit-events?" +
		"limit=50&route=r-x&remoteIp=1.2.3.4&" +
		"since=" + since + "&until=" + until

	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body)
	}

	got := reader.capturedFilter
	if got.Limit != 50 {
		t.Errorf("Limit = %d; want 50", got.Limit)
	}
	if got.RouteID != "r-x" {
		t.Errorf("RouteID = %q; want r-x", got.RouteID)
	}
	if got.RemoteIP != "1.2.3.4" {
		t.Errorf("RemoteIP = %q; want 1.2.3.4", got.RemoteIP)
	}
	wantSince := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
	if !got.From.Equal(wantSince) {
		t.Errorf("From = %v; want %v", got.From, wantSince)
	}
	wantUntil := time.Date(2026, 6, 18, 0, 0, 0, 0, time.UTC)
	if !got.To.Equal(wantUntil) {
		t.Errorf("To = %v; want %v", got.To, wantUntil)
	}
}

func TestRateLimitEvents_LimitClamp_Cap(t *testing.T) {
	m := newMetricsTestEnv(t)
	reader := &fakeRateLimitEventReader{}
	m.env.handler.SetRateLimitEventReader(reader)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/rate-limit-events?limit=999999", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (clamp is silent)", rec.Code)
	}
	if reader.capturedFilter.Limit != rateLimitEventsLimitCap {
		t.Errorf("Limit = %d; want %d (silent clamp)", reader.capturedFilter.Limit, rateLimitEventsLimitCap)
	}
}

func TestRateLimitEvents_BadLimit_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetRateLimitEventReader(&fakeRateLimitEventReader{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/security/rate-limit-events?limit=abc", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestRateLimitEvents_ReversedTimeBounds_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetRateLimitEventReader(&fakeRateLimitEventReader{})

	url := "/api/v1/security/rate-limit-events?since=2026-06-18T12:00:00Z&until=2026-06-18T11:00:00Z"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}
