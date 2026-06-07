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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/storage"
)

// stubServerPositionStore is the test double for the
// position store. Records Save calls + returns canned
// records / errors as configured.
type stubServerPositionStore struct {
	mu     sync.Mutex
	getRec storage.ServerPositionRecord
	getErr error
	putErr error
	putRec storage.ServerPositionRecord
	puts   int
}

func (s *stubServerPositionStore) GetServerPosition(_ context.Context) (storage.ServerPositionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getRec, s.getErr
}

func (s *stubServerPositionStore) PutServerPosition(_ context.Context, rec storage.ServerPositionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.putErr != nil {
		return s.putErr
	}
	s.putRec = rec
	s.puts++
	return nil
}

func (s *stubServerPositionStore) putCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts
}

// stubRedetector returns either a canned ServerPosition or
// an error.
type stubRedetector struct {
	pos *geo.ServerPosition
	err error
}

func (s stubRedetector) Redetect() (*geo.ServerPosition, error) {
	return s.pos, s.err
}

// --- GET ----------------------------------------------------------------

func TestGetServerPosition_FromStore_ReturnsPersisted(t *testing.T) {
	env := newTestEnv(t, false)
	rec := storage.ServerPositionRecord{
		Lat: 48.8566, Lon: 2.3522,
		City: "Paris", Country: "FR",
		Mode: "manual",
		// DetectedAt → wire's "detectedAt"
		DetectedAt: time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC),
	}
	env.handler.SetServerPositionStore(&stubServerPositionStore{getRec: rec})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/server-position", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Lat != 48.8566 || resp.Lon != 2.3522 {
		t.Errorf("lat/lon mismatch: %+v", resp)
	}
	if resp.Mode != "manual" {
		t.Errorf("Mode = %q, want manual", resp.Mode)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true, want false (store has row)")
	}
}

func TestGetServerPosition_StoreEmpty_FallsBackToBootDetected(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})
	env.handler.SetBootDetectedPosition(&geo.ServerPosition{
		Lat: 51.5074, Lon: -0.1278,
		City: "London", Country: "GB",
		Mode: geo.ServerPositionModeAuto, SourceIP: "203.0.113.1",
		DetectedAt: time.Now().UTC(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/server-position", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Country != "GB" || resp.Mode != "auto" {
		t.Errorf("fallback mismatch: %+v", resp)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true, want false (boot auto-detect available)")
	}
}

func TestGetServerPosition_NoStoreNoBoot_DegradedResponse(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})
	// No boot-detected position.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/server-position", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 even in degraded mode", w.Code, w.Body)
	}
	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false, want true (no row, no boot pos)")
	}
	if resp.Lat != 0 || resp.Lon != 0 {
		t.Errorf("expected zero lat/lon in degraded shape, got %+v", resp)
	}
}

func TestGetServerPosition_NilStore_StillReturnsBootPosition(t *testing.T) {
	// Tests the defensive path: handler had its store
	// cleared (or never set) but still has the boot auto-
	// detect — GET should surface it instead of 500ing.
	env := newTestEnv(t, false)
	env.handler.SetBootDetectedPosition(&geo.ServerPosition{
		Lat: 35.6762, Lon: 139.6503, Mode: "auto", City: "Tokyo", Country: "JP",
		DetectedAt: time.Now().UTC(),
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/server-position", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", w.Code)
	}
	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Country != "JP" {
		t.Errorf("boot fallback failed: %+v", resp)
	}
}

func TestGetServerPosition_Anon_401(t *testing.T) {
	env := newTestEnv(t, false)
	rawRouter := buildRawRouter(t, env)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/observability/server-position", nil)
	w := httptest.NewRecorder()
	rawRouter.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", w.Code)
	}
}

// --- PUT ----------------------------------------------------------------

func TestPutServerPosition_HappyPath_SavesAndReturns200(t *testing.T) {
	env := newTestEnv(t, false)
	stub := &stubServerPositionStore{getErr: storage.ErrNotFound}
	env.handler.SetServerPositionStore(stub)

	body := `{"lat": 45.7640, "lon": 4.8357, "city": "Lyon", "country": "FR"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if stub.putCount() != 1 {
		t.Errorf("put calls = %d, want 1", stub.putCount())
	}
	if stub.putRec.Mode != "manual" {
		t.Errorf("persisted Mode=%q, want manual", stub.putRec.Mode)
	}
	if stub.putRec.City != "Lyon" || stub.putRec.Country != "FR" {
		t.Errorf("persisted city/country mismatch: %+v", stub.putRec)
	}
	// SourceIP empty for manual override per spec §5.2.
	if stub.putRec.SourceIP != "" {
		t.Errorf("manual SourceIP should be empty, got %q", stub.putRec.SourceIP)
	}

	// Audit event recorded.
	gotAudits := env.audit.Events()
	if len(gotAudits) == 0 || gotAudits[len(gotAudits)-1].Action != audit.ActionServerPositionUpdated {
		t.Errorf("expected ActionServerPositionUpdated in audit log, got %+v", gotAudits)
	}
}

func TestPutServerPosition_LatOutOfRange_400(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})

	for _, body := range []string{
		`{"lat": 91, "lon": 0, "city": "X", "country": "FR"}`,
		`{"lat": -91, "lon": 0, "city": "X", "country": "FR"}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s → status=%d, want 400", body, w.Code)
		}
	}
}

func TestPutServerPosition_LonOutOfRange_400(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})

	for _, body := range []string{
		`{"lat": 0, "lon": 181, "city": "X", "country": "FR"}`,
		`{"lat": 0, "lon": -181, "city": "X", "country": "FR"}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("body=%s → status=%d, want 400", body, w.Code)
		}
	}
}

func TestPutServerPosition_EmptyCityCountry_Accepted(t *testing.T) {
	// Spec §5.2: "city and country are operator-supplied
	// display strings; empty allowed."
	env := newTestEnv(t, false)
	stub := &stubServerPositionStore{getErr: storage.ErrNotFound}
	env.handler.SetServerPositionStore(stub)

	body := `{"lat": 0, "lon": 0, "city": "", "country": ""}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("empty city/country rejected: status=%d body=%s", w.Code, w.Body)
	}
}

func TestPutServerPosition_BoundaryLat_Accepted(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})

	for _, body := range []string{
		`{"lat": 90, "lon": 0, "city": "X", "country": "F"}`,
		`{"lat": -90, "lon": 0, "city": "X", "country": "F"}`,
		`{"lat": 0, "lon": 180, "city": "X", "country": "F"}`,
		`{"lat": 0, "lon": -180, "city": "X", "country": "F"}`,
	} {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("boundary body=%s status=%d body=%s", body, w.Code, w.Body)
		}
	}
}

func TestPutServerPosition_BadJSON_400(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status=%d, want 400", w.Code)
	}
}

func TestPutServerPosition_Anon_401(t *testing.T) {
	env := newTestEnv(t, false)
	rawRouter := buildRawRouter(t, env)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position",
		strings.NewReader(`{"lat":0,"lon":0,"city":"","country":""}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rawRouter.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", w.Code)
	}
}

func TestPutServerPosition_NilStore_503(t *testing.T) {
	env := newTestEnv(t, false)
	// store intentionally not set.

	body := `{"lat": 0, "lon": 0, "city": "X", "country": "FR"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/observability/server-position", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", w.Code)
	}
}

// --- POST :redetect -----------------------------------------------------

func TestRedetectServerPosition_HappyPath_SavesAuto(t *testing.T) {
	env := newTestEnv(t, false)
	stub := &stubServerPositionStore{getErr: storage.ErrNotFound}
	env.handler.SetServerPositionStore(stub)
	env.handler.SetServerPositionRedetector(stubRedetector{
		pos: &geo.ServerPosition{
			Lat: 48.8566, Lon: 2.3522,
			City: "Paris", Country: "FR",
			Mode: geo.ServerPositionModeAuto, SourceIP: "203.0.113.42",
			DetectedAt: time.Now().UTC(),
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observability/server-position:redetect", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body)
	}
	if stub.putCount() != 1 {
		t.Errorf("put calls = %d, want 1 (redetect persists)", stub.putCount())
	}
	if stub.putRec.Mode != "auto" {
		t.Errorf("persisted Mode=%q, want auto", stub.putRec.Mode)
	}

	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.City != "Paris" || resp.Country != "FR" || resp.Mode != "auto" {
		t.Errorf("response mismatch: %+v", resp)
	}
	if resp.SourceIP != "203.0.113.42" {
		t.Errorf("SourceIP not surfaced: %+v", resp)
	}
}

func TestRedetectServerPosition_DetectFails_DegradedResponse(t *testing.T) {
	env := newTestEnv(t, false)
	stub := &stubServerPositionStore{getErr: storage.ErrNotFound}
	env.handler.SetServerPositionStore(stub)
	env.handler.SetServerPositionRedetector(stubRedetector{err: errors.New("ipify timeout")})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observability/server-position:redetect", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; spec §5.3 returns degraded shape on failure", w.Code, w.Body)
	}
	if stub.putCount() != 0 {
		t.Errorf("put calls = %d on failure, want 0 (no state change → no persist)", stub.putCount())
	}

	var resp serverPositionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Degraded {
		t.Errorf("Degraded = false on detect failure, want true")
	}
}

func TestRedetectServerPosition_NilRedetector_503(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetServerPositionStore(&stubServerPositionStore{getErr: storage.ErrNotFound})
	// redetector intentionally not set.

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observability/server-position:redetect", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", w.Code)
	}
}

func TestRedetectServerPosition_Anon_401(t *testing.T) {
	env := newTestEnv(t, false)
	rawRouter := buildRawRouter(t, env)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/observability/server-position:redetect", nil)
	w := httptest.NewRecorder()
	rawRouter.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", w.Code)
	}
}

func TestRedetectServerPosition_OverwritesPreviousManual(t *testing.T) {
	// Operator had a manual override; redetect overwrites
	// with auto. Audit emits a before/after diff.
	env := newTestEnv(t, false)
	prev := storage.ServerPositionRecord{
		Lat: 0, Lon: 0, Mode: "manual", City: "Original", Country: "XX",
	}
	stub := &stubServerPositionStore{getRec: prev}
	env.handler.SetServerPositionStore(stub)
	env.handler.SetServerPositionRedetector(stubRedetector{
		pos: &geo.ServerPosition{
			Lat: 35.6762, Lon: 139.6503,
			City: "Tokyo", Country: "JP",
			Mode: geo.ServerPositionModeAuto, SourceIP: "198.51.100.7",
			DetectedAt: time.Now().UTC(),
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/observability/server-position:redetect", nil)
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d", w.Code)
	}
	if stub.putRec.Country != "JP" || stub.putRec.Mode != "auto" {
		t.Errorf("redetect did not overwrite: %+v", stub.putRec)
	}
}

// --- Helpers ------------------------------------------------------------

// buildRawRouter constructs a router WITHOUT the auto-auth
// wrapper for the 401-path tests (mirror of the
// metricsTestEnv.rawHandler shape, but for /observability
// paths that newMetricsTestEnv doesn't seed routes for).
func buildRawRouter(t *testing.T, env *testEnv) http.Handler {
	t.Helper()
	ipExtractor, err := auth.NewIPExtractor("")
	if err != nil {
		t.Fatalf("ip extractor: %v", err)
	}
	return NewRouter(env.handler, false, ipExtractor, nil, nil, nil, nil)
}
