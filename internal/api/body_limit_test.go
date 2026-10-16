// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// bodyLimit must cap the body so a handler that reads it sees an error
// past the limit — the body never grows into the heap unbounded (F4/F31).
func TestBodyLimit_Middleware_CapsTheRead(t *testing.T) {
	var readErr error
	h := bodyLimit(1024)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(strings.Repeat("A", 4096)))
	h.ServeHTTP(httptest.NewRecorder(), r)
	if readErr == nil {
		t.Fatal("a body past the cap must make the read fail; got nil error (unbounded)")
	}
}

// A login body past the /auth cap is refused before it is decoded into
// memory. Without the cap the oversized-but-valid JSON would decode and
// answer 401 (bad credentials); with it the read fails first and the
// handler answers 400.
func TestLogin_OversizedBody_Refused(t *testing.T) {
	env, token := setupTestEnv(t)
	_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

	huge := `{"username":"admin","password":"` + strings.Repeat("A", int(maxAuthBodyBytes)+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized login body: status=%d, want 400 (capped before decode); body=%s", rec.Code, rec.Body)
	}

	// Non-regression: a normal small login body is NOT capped (it reaches
	// the credential check and fails with 401, not 400-from-the-cap).
	ok := `{"username":"admin","password":"wrong-but-15-chars"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(ok))
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	env.router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("a normal login body must reach the credential check: status=%d, want 401", rec2.Code)
	}
}

// geo/lookup-batch caps the IP COUNT only after decoding; the body cap
// must refuse an oversized payload before the array is materialised (F31).
func TestGeoLookupBatch_OversizedBody_Refused(t *testing.T) {
	env := newTestEnv(t, false)

	huge := `{"ips":["` + strings.Repeat("1.2.3.4\",\"", int(maxGeoBatchBodyBytes)/10+200) + `1.2.3.4"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized geo-batch body: status=%d, want 400 (capped before decode); body len=%d", rec.Code, len(huge))
	}
	// Distinguish "refused by the body cap" from "decoded, then rejected
	// by the post-decode IP-count check" — both are 400, but only the
	// former means the giant array never hit the heap. The count check's
	// message says "too many"; the cap's does not.
	if strings.Contains(rec.Body.String(), "too many") {
		t.Errorf("geo-batch decoded the whole array before refusing it — the body cap did not fire (F31): %s", rec.Body)
	}
}
