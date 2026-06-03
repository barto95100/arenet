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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/auth"
)

// TestHealthz_Returns200WithStatusOK exercises GET /healthz end-to-end
// through the full chi.Router built by NewRouter (Step H.3). The test
// also implicitly verifies that the endpoint is reachable WITHOUT
// authentication — the assertion would fail with 401/403 if /healthz
// had been mounted inside one of the auth-gated subgroups.
func TestHealthz_Returns200WithStatusOK(t *testing.T) {
	h := newTestHandler(t, &fakeAuditAppender{}, &bytes.Buffer{})
	ipExtractor, err := auth.NewIPExtractor("")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}
	router := NewRouter(h, false, ipExtractor, nil, nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}

	var body healthzResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Status != "ok" {
		t.Errorf("status = %q; want \"ok\"", body.Status)
	}
	// uptime_seconds is captured via time.Since on a startTime set in
	// NewHandler. In a fast unit test the elapsed time is typically
	// 0; the only invariant we can assert is non-negative.
	if body.UptimeSeconds < 0 {
		t.Errorf("uptime_seconds = %d; want >= 0", body.UptimeSeconds)
	}
}
