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

// W.5 — country-block events handler tests. Mirror of
// cert_events_handler_test.go shape: degraded path (nil
// reader → 200 + degraded:true), filter parameter mapping,
// RFC 3339 since/until parsing, limit clamp.

// fakeCountryBlockEventReader is the test double for the
// W.5 CountryBlockEventReader. Captures the filter so
// tests can assert query-string → filter parameter mapping.
type fakeCountryBlockEventReader struct {
	queryFn        func(ctx context.Context, filter observability.CountryBlockEventFilter) ([]observability.CountryBlockEvent, error)
	capturedFilter observability.CountryBlockEventFilter
}

func (f *fakeCountryBlockEventReader) QueryCountryBlockEvents(
	ctx context.Context,
	filter observability.CountryBlockEventFilter,
) ([]observability.CountryBlockEvent, error) {
	f.capturedFilter = filter
	if f.queryFn != nil {
		return f.queryFn(ctx, filter)
	}
	return nil, nil
}

func TestCountryBlockEvents_NilReader_DegradedResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// Reader intentionally not set → nil → degraded response.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/country-block-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (degraded is OK, not 5xx)", rec.Code)
	}
	var resp countryBlockEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false; want true (reader is nil)")
	}
	if len(resp.Events) != 0 {
		t.Errorf("Events len = %d; want 0", len(resp.Events))
	}
	if resp.Total != 0 || resp.HasMore {
		t.Errorf("Total/HasMore = %d/%v; want 0/false", resp.Total, resp.HasMore)
	}
}

func TestCountryBlockEvents_HappyPath_RoundTrip(t *testing.T) {
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	m.env.handler.SetCountryBlockEventReader(&fakeCountryBlockEventReader{
		queryFn: func(_ context.Context, _ observability.CountryBlockEventFilter) ([]observability.CountryBlockEvent, error) {
			return []observability.CountryBlockEvent{
				{
					ID: 1, Ts: ts, RouteID: "route-a", SrcIP: "203.0.113.5",
					Country: "RU", Mode: "deny", StatusCode: 451, Reason: "deny-match",
				},
				{
					ID: 2, Ts: ts.Add(-time.Hour), RouteID: "route-b", SrcIP: "203.0.113.6",
					Country: "FR", Mode: "allow", StatusCode: 403, Reason: "allow-miss",
				},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/country-block-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (body=%s)", rec.Code, rec.Body)
	}
	var resp countryBlockEventsResponse
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
	if first.RouteID != "route-a" || first.SrcIP != "203.0.113.5" ||
		first.Country != "RU" || first.Mode != "deny" ||
		first.StatusCode != 451 || first.Reason != "deny-match" {
		t.Errorf("first row mismatch: %+v", first)
	}
	// RFC 3339 ts formatting (no decoder-side parsing — the
	// API contract is the string representation).
	if !strings.HasPrefix(first.Ts, "2026-06-08T12:00:00") {
		t.Errorf("ts = %q; want RFC 3339 starting 2026-06-08T12:00:00", first.Ts)
	}
}

func TestCountryBlockEvents_FilterMapping(t *testing.T) {
	m := newMetricsTestEnv(t)
	reader := &fakeCountryBlockEventReader{}
	m.env.handler.SetCountryBlockEventReader(reader)

	since := "2026-06-01T00:00:00Z"
	until := "2026-06-08T00:00:00Z"
	url := "/api/v1/observability/country-block-events?" +
		"limit=50&route=r-x&srcIp=1.2.3.4&country=RU&mode=deny&" +
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
	if got.SrcIP != "1.2.3.4" {
		t.Errorf("SrcIP = %q; want 1.2.3.4", got.SrcIP)
	}
	if got.Country != "RU" {
		t.Errorf("Country = %q; want RU", got.Country)
	}
	if got.Mode != "deny" {
		t.Errorf("Mode = %q; want deny", got.Mode)
	}
	wantSince := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	if !got.From.Equal(wantSince) {
		t.Errorf("From = %v; want %v", got.From, wantSince)
	}
	wantUntil := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	if !got.To.Equal(wantUntil) {
		t.Errorf("To = %v; want %v", got.To, wantUntil)
	}
}

func TestCountryBlockEvents_LimitValidation(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCountryBlockEventReader(&fakeCountryBlockEventReader{})

	cases := []struct {
		name  string
		url   string
		wantS int
	}{
		{"negative limit", "/api/v1/observability/country-block-events?limit=-1", http.StatusBadRequest},
		{"non-integer limit", "/api/v1/observability/country-block-events?limit=abc", http.StatusBadRequest},
		{"valid limit", "/api/v1/observability/country-block-events?limit=10", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.url, nil)
			rec := httptest.NewRecorder()
			m.router.ServeHTTP(rec, req)
			if rec.Code != tc.wantS {
				t.Errorf("status = %d; want %d (body=%s)", rec.Code, tc.wantS, rec.Body)
			}
		})
	}
}

func TestCountryBlockEvents_UntilBeforeSince_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetCountryBlockEventReader(&fakeCountryBlockEventReader{})

	url := "/api/v1/observability/country-block-events?" +
		"since=2026-06-08T00:00:00Z&until=2026-06-01T00:00:00Z"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (reversed time bounds)", rec.Code)
	}
}

func TestHasCountryBlockEventReader_BootSignal(t *testing.T) {
	m := newMetricsTestEnv(t)
	if m.env.handler.HasCountryBlockEventReader() {
		t.Error("nil-initial state: HasCountryBlockEventReader = true; want false")
	}
	m.env.handler.SetCountryBlockEventReader(&fakeCountryBlockEventReader{})
	if !m.env.handler.HasCountryBlockEventReader() {
		t.Error("post-Set state: HasCountryBlockEventReader = false; want true")
	}
}
