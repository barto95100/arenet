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

	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/geo"
)

// stubGeoBus is a minimal GeoEventReader for handler tests:
// SnapshotLimited returns a canned slice; Stats returns the
// canned BusStats. The test reads capturedLimit to assert the
// limit-parsing path.
type stubGeoBus struct {
	events        []geo.GeoEvent
	stats         geo.BusStats
	capturedLimit int
}

func (s *stubGeoBus) SnapshotLimited(limit int) []geo.GeoEvent {
	s.capturedLimit = limit
	out := s.events
	if limit < len(out) {
		out = out[:limit]
	}
	return out
}

func (s *stubGeoBus) Stats() geo.BusStats { return s.stats }

func TestGeoEvents_Anon401(t *testing.T) {
	m := newMetricsTestEnv(t)
	raw := m.rawHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon status = %d, want 401", rec.Code)
	}
}

func TestGeoEvents_Viewer200(t *testing.T) {
	// Mirrors TestCertEvents_Viewer200 — geo events are
	// operationally equivalent (observability data, no
	// operator action surface). AC #17 carry-forward.
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoBus(&stubGeoBus{})

	ctx := context.Background()
	viewer, err := newTestUserStore(t, m.env).CreateOIDCUser(ctx, "geo-events-viewer", "Geo Events Viewer", "sub-geo-events-viewer")
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

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: s.ID})
	rec := httptest.NewRecorder()
	raw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("VIEWER LOCKOUT REGRESSION on /observability/geo-events: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestGeoEvents_NilBus_DegradedResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// bus intentionally not set → nil → degraded response.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (degraded mode is OK, not 5xx)", rec.Code)
	}
	var resp geoEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false, want true (bus is nil)")
	}
	if len(resp.Events) != 0 {
		t.Errorf("Events len = %d, want 0", len(resp.Events))
	}
	if resp.Total != 0 {
		t.Errorf("Total = %d, want 0", resp.Total)
	}
}

func TestGeoEvents_HappyPath_ReturnsEvents(t *testing.T) {
	m := newMetricsTestEnv(t)
	ts := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	bus := &stubGeoBus{
		events: []geo.GeoEvent{
			{Timestamp: ts, Category: geo.CategoryWAF, SourceIP: "8.8.8.8", SourceCountry: "US"},
			{Timestamp: ts.Add(time.Second), Category: geo.CategoryAuth, SourceIP: "1.1.1.1", SourceCountry: "AU"},
		},
	}
	m.env.handler.SetGeoBus(bus)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body)
	}
	var resp geoEventsResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true, want false (bus + lookup present)")
	}
	if resp.Total != 2 {
		t.Errorf("Total = %d, want 2", resp.Total)
	}
	if len(resp.Events) != 2 {
		t.Errorf("Events len = %d, want 2", len(resp.Events))
	}
	if resp.Events[0].SourceCountry != "US" || resp.Events[1].SourceCountry != "AU" {
		t.Errorf("event order broken: %+v", resp.Events)
	}
}

func TestGeoEvents_LimitDefault100(t *testing.T) {
	m := newMetricsTestEnv(t)
	bus := &stubGeoBus{}
	m.env.handler.SetGeoBus(bus)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if bus.capturedLimit != geoEventsDefaultLimit {
		t.Errorf("captured limit = %d, want %d (default)", bus.capturedLimit, geoEventsDefaultLimit)
	}
}

func TestGeoEvents_LimitClampedAtCap(t *testing.T) {
	m := newMetricsTestEnv(t)
	bus := &stubGeoBus{}
	m.env.handler.SetGeoBus(bus)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events?limit=99999", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if bus.capturedLimit != geoEventsLimitCap {
		t.Errorf("captured limit = %d, want %d (cap)", bus.capturedLimit, geoEventsLimitCap)
	}
}

func TestGeoEvents_LimitInvalid400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoBus(&stubGeoBus{})

	for _, raw := range []string{"abc", "-1", "0"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events?limit="+raw, nil)
		rec := httptest.NewRecorder()
		m.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%q got status %d, want 400; body=%s", raw, rec.Code, rec.Body)
		}
	}
}

func TestGeoEvents_DegradedGeoIP_FlagsResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoBus(&stubGeoBus{})
	m.env.handler.SetGeoIPDegraded(true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/geo-events", nil)
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"degraded":true`) {
		t.Errorf("expected degraded:true in body, got %s", body)
	}
}
