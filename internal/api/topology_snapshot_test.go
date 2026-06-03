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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/api/topology"
	"github.com/barto95100/arenet/internal/storage"
)

// fakeRouteLister implements SnapshotRouteLister with canned
// values for the snapshot handler tests.
type fakeRouteLister struct {
	routes []storage.Route
	err    error
}

func (f *fakeRouteLister) ListRoutes(ctx context.Context) ([]storage.Route, error) {
	return f.routes, f.err
}

// silentLogger discards all log output for tests.
func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestSnapshotHandler_GET_EmptyRoutes(t *testing.T) {
	h := NewSnapshotHandler(&fakeRouteLister{routes: nil}, nil, nil, silentLogger())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology/snapshot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type: got %q, want application/json", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control: got %q, want no-store", got)
	}
	var resp topology.SnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Routes == nil {
		t.Errorf("Routes: nil, want empty slice (JSON-empty-as-[])")
	}
	if len(resp.Routes) != 0 {
		t.Errorf("Routes: got %d, want 0", len(resp.Routes))
	}
	// GeneratedAt is whatever now() returned — verify it's
	// non-zero and parses as a recent timestamp.
	if resp.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt: zero, want non-zero")
	}
	if time.Since(resp.GeneratedAt) > 5*time.Second {
		t.Errorf("GeneratedAt too old: %v ago", time.Since(resp.GeneratedAt))
	}
}

func TestSnapshotHandler_GET_PopulatedRoutes(t *testing.T) {
	routes := []storage.Route{
		{
			ID:         "r1",
			Host:       "api.example",
			LBPolicy:   "round_robin",
			TLSEnabled: true,
			WAFMode:    "block",
			Aliases:    []string{"alt.example"},
			Upstreams:  []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
		},
		{
			ID:        "r2",
			Host:      "app.example",
			LBPolicy:  "weighted_round_robin",
			Upstreams: []storage.Upstream{{URL: "http://10.0.0.2:80", Weight: 1}},
		},
	}
	h := NewSnapshotHandler(&fakeRouteLister{routes: routes}, nil, nil, silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology/snapshot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var resp topology.SnapshotResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(resp.Routes) != 2 {
		t.Fatalf("Routes: got %d, want 2", len(resp.Routes))
	}
	if resp.Routes[0].ID != "r1" || resp.Routes[1].ID != "r2" {
		t.Errorf("Routes order: got [%s, %s]", resp.Routes[0].ID, resp.Routes[1].ID)
	}
	// Wire-shape sanity: route 0 carries the aliases + tls + waf;
	// route 0's single upstream gets the full traffic share (1.0
	// fairness, ReqPerSec equal to route ReqPerSec which is 0
	// without a populated window).
	r0 := resp.Routes[0]
	if !r0.TLSEnabled || r0.WAFLevel != "block" {
		t.Errorf("route 0 tls/waf: got tls=%v waf=%q", r0.TLSEnabled, r0.WAFLevel)
	}
	if len(r0.Aliases) != 1 || r0.Aliases[0] != "alt.example" {
		t.Errorf("route 0 aliases: got %v", r0.Aliases)
	}
	if len(r0.Upstreams) != 1 {
		t.Fatalf("route 0 upstreams: got %d, want 1", len(r0.Upstreams))
	}
	if r0.Upstreams[0].ID != "r1-0" {
		t.Errorf("upstream id: got %q, want r1-0", r0.Upstreams[0].ID)
	}
	if r0.Upstreams[0].FairnessRatio != 1.0 {
		t.Errorf("single-upstream fairness: got %v, want 1.0", r0.Upstreams[0].FairnessRatio)
	}
	// Status field is present and well-formed (StatusUnknown
	// when no prober is wired).
	if r0.Upstreams[0].Status != topology.StatusUnknown {
		t.Errorf("status without prober: got %q, want %q", r0.Upstreams[0].Status, topology.StatusUnknown)
	}
}

func TestSnapshotHandler_GET_StoreError(t *testing.T) {
	h := NewSnapshotHandler(
		&fakeRouteLister{err: errors.New("bolt: closed")},
		nil, nil, silentLogger(),
	)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology/snapshot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status on store error: got %d, want 500", rec.Code)
	}
}

func TestSnapshotHandler_NonGETMethod(t *testing.T) {
	h := NewSnapshotHandler(&fakeRouteLister{}, nil, nil, silentLogger())
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/v1/topology/snapshot", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: got %d, want 405", method, rec.Code)
		}
		if got := rec.Header().Get("Allow"); got != http.MethodGet {
			t.Errorf("%s Allow header: got %q, want GET", method, got)
		}
	}
}

func TestSnapshotHandler_MetricsViewWired(t *testing.T) {
	// When a non-nil MetricsView is provided, the route reqPerSec
	// reflects the aggregator's value.
	window := topology.NewSlidingWindow()
	window.Push("r1", 100, 5, 42)
	routes := []storage.Route{{
		ID:        "r1",
		Host:      "api.example",
		LBPolicy:  "round_robin",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.1:80", Weight: 1}},
	}}
	h := NewSnapshotHandler(&fakeRouteLister{routes: routes}, window, nil, silentLogger())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/topology/snapshot", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", rec.Code)
	}
	var resp topology.SnapshotResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Routes[0].ReqPerSec != 100 {
		t.Errorf("route reqPerSec: got %v, want 100 (window aggregate)", resp.Routes[0].ReqPerSec)
	}
	if resp.Routes[0].P99LatencyMs != 42 {
		t.Errorf("route p99 (window p95): got %d, want 42", resp.Routes[0].P99LatencyMs)
	}
}

func TestNewSnapshotHandler_NilStore_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil store: want panic, got none")
		}
	}()
	_ = NewSnapshotHandler(nil, nil, nil, silentLogger())
}

func TestNewSnapshotHandler_NilLogger_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("nil logger: want panic, got none")
		}
	}()
	_ = NewSnapshotHandler(&fakeRouteLister{}, nil, nil, nil)
}
