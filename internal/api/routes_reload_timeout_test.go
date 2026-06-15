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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #R-CADDY-ADMIN-DEADLOCK callsite regression — POST /routes
// and PUT /routes/{id} handlers BOTH surface the new
// caddymgr.ReloadFromStore timeout error (context deadline
// exceeded, prefixed "caddy reload timed out after 25s") as
// a clean HTTP 500 with a JSON error body. Pre-fix the
// handler would have hung indefinitely on a blocked
// caddy.Load; post-fix the operator sees an actionable 500.
//
// The 11 callsites that call ReloadFromStore all follow the
// same shape (audit pass in commit body):
//   1. h.logger.Error(...) with the err
//   2. roll back the storage mutation
//   3. writeError(w, http.StatusInternalServerError,
//      "caddy reload failed: "+err.Error())
//
// Sample the POST + PUT routes paths (the two most operator-
// visible) — the other 9 callsites use the same writeError
// pattern verified by audit, so a regression there would
// surface as a 500 too (just attributed to a different
// rollback shape).

// timeoutErr mirrors what caddymgr.ReloadFromStore now
// returns on a select-fired timeout. We hand-craft it here
// rather than importing caddymgr because the api package
// only sees ReloadFromStore through the CaddyReloader
// interface; the fakeReloader.SetNextErr seam lets us prime
// any error shape.
func timeoutErr() error {
	return fmt.Errorf("caddy reload timed out after 25s: %w", context.DeadlineExceeded)
}

func TestCreateRoute_CaddyReloadTimeout_Returns500WithErrorBody(t *testing.T) {
	env := newTestEnv(t, false)
	env.caddy.SetNextErr(timeoutErr())

	body := `{"host":"timeout.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on reload timeout; body=%s", rec.Code, rec.Body)
	}

	// Body must be JSON with an "error" field containing the
	// timeout message. The frontend's ApiError parser reads
	// this exact shape (lib/api/client.ts errBody.error
	// extraction).
	var bodyResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bodyResp); err != nil {
		t.Fatalf("response body not JSON: %v\nbody=%s", err, rec.Body.String())
	}
	msg, _ := bodyResp["error"].(string)
	if !strings.Contains(msg, "caddy reload failed") {
		t.Errorf("error body missing rollback prefix: got %q", msg)
	}
	if !strings.Contains(msg, "timed out") {
		t.Errorf("error body missing timeout signal: got %q", msg)
	}

	// Storage MUST have been rolled back — the create handler
	// deletes the just-inserted row on reload failure. A
	// missing rollback would leave the operator with a
	// phantom route in the DB that Caddy never knew about.
	routes, _ := env.store.ListRoutes(context.Background())
	for _, r := range routes {
		if r.Host == "timeout.local" {
			t.Errorf("phantom route survived reload-timeout rollback: %+v", r)
		}
	}
}

func TestUpdateRoute_CaddyReloadTimeout_Returns500WithErrorBody(t *testing.T) {
	env := newTestEnv(t, false)

	// Seed an existing route via the happy-path POST so we
	// have a stable ID to PUT against.
	seed := `{"host":"existing.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	seedReq := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(seed))
	seedReq.Header.Set("Content-Type", "application/json")
	seedRec := httptest.NewRecorder()
	env.router.ServeHTTP(seedRec, seedReq)
	if seedRec.Code != http.StatusCreated {
		t.Fatalf("seed POST status = %d body=%s", seedRec.Code, seedRec.Body)
	}
	var seedBody map[string]any
	_ = json.Unmarshal(seedRec.Body.Bytes(), &seedBody)
	id, _ := seedBody["id"].(string)
	if id == "" {
		t.Fatalf("seed POST did not return an id; body=%s", seedRec.Body)
	}

	// Now prime the next reload (the PUT's reload) to fail
	// with the timeout error shape.
	env.caddy.SetNextErr(timeoutErr())

	body := `{"host":"existing.local","upstreams":[{"url":"http://127.0.0.1:9999","weight":1}],"lbPolicy":"round_robin","tlsEnabled":false,"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on reload timeout; body=%s", rec.Code, rec.Body)
	}

	var bodyResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bodyResp); err != nil {
		t.Fatalf("response body not JSON: %v\nbody=%s", err, rec.Body.String())
	}
	msg, _ := bodyResp["error"].(string)
	if !strings.Contains(msg, "caddy reload failed") {
		t.Errorf("error body missing rollback prefix: got %q", msg)
	}
	if !strings.Contains(msg, "timed out") {
		t.Errorf("error body missing timeout signal: got %q", msg)
	}

	// Storage rollback : the upstream URL must still be the
	// seeded :9000 (not the attempted :9999). The PUT handler
	// uses UpdateRoute with the previous shape on reload
	// failure.
	routes, _ := env.store.ListRoutes(context.Background())
	for _, r := range routes {
		if r.ID == id {
			if len(r.Upstreams) == 0 || r.Upstreams[0].URL != "http://127.0.0.1:9000" {
				t.Errorf("update reload-timeout rollback failed; upstream = %+v", r.Upstreams)
			}
		}
	}
}
