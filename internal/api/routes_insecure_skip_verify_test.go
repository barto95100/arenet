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

// #R-PROXMOX-HTTPS-LOOP commit 1b — API wire layer for
// InsecureSkipVerify.
//
// Smoke gap caught: commit 1 shipped the storage struct field
// only. The wire (routeRequest) had no InsecureSkipVerify, and
// updateRoute uses dec.DisallowUnknownFields() — so any PUT
// that echoed the field (e.g. from a GET→PUT roundtrip in the
// future frontend) returned 400 "invalid JSON body" before
// reaching the storage layer.
//
// These tests pin:
//   1. POST→GET roundtrip with InsecureSkipVerify:true on an
//      https pool returns true on the wire response.
//   2. PUT WITHOUT the key preserves the previously stored
//      value (same UX as healthCheck / countryBlock).
//   3. PUT WITH explicit false replaces (clears) the stored
//      value.
//   4. POST WITHOUT the key defaults to false (strict).
//   5. Self-heal on http-only upstreams: setting true is
//      silently normalised to false (mirror of the
//      RedirectToHTTPS self-heal at routes.go:1273-1275).

// jsonBodyHTTPS builds a POST/PUT body using an https upstream.
// When iskvJSON is "true" / "false", the insecureSkipVerify key
// is injected; "" omits it (tests the absent path).
func jsonBodyHTTPS(host, iskvJSON string) string {
	tail := ""
	if iskvJSON != "" {
		tail = `,"insecureSkipVerify":` + iskvJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"https://192.168.1.60:8006","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

// jsonBodyHTTP — http-only pool variant for the self-heal test.
func jsonBodyHTTP(host, iskvJSON string) string {
	tail := ""
	if iskvJSON != "" {
		tail = `,"insecureSkipVerify":` + iskvJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.10:8123","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_InsecureSkipVerify_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyHTTPS("pve.example.com", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}

	// Wire response must echo the flag (no omitempty — see
	// handler.go routeResponse).
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.InsecureSkipVerify {
		t.Errorf("response InsecureSkipVerify = false; want true (roundtrip)")
	}

	// Storage carries the same value.
	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].InsecureSkipVerify {
		t.Errorf("storage InsecureSkipVerify = false; want true")
	}
}

func TestCreateRoute_InsecureSkipVerify_Defaults_False(t *testing.T) {
	// POST without the insecureSkipVerify key — strict default
	// (false) must persist. Operator must opt in to bypass
	// cert validation.
	env := newTestEnv(t, false)
	body := jsonBodyHTTPS("pve.default.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].InsecureSkipVerify {
		t.Errorf("storage InsecureSkipVerify = true on default; want false (strict)")
	}
}

func TestUpdateRoute_InsecureSkipVerify_NilPreservesPrevious(t *testing.T) {
	// PUT without the key MUST preserve the stored value — same
	// UX as healthCheck / countryBlock. This is the case that
	// the commit 1 gap broke (PUT returned 400 before even
	// reaching this branch).
	env := newTestEnv(t, false)

	createBody := jsonBodyHTTPS("pve.preserve.local", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// PUT WITHOUT the insecureSkipVerify key — preserve path.
	putBody := jsonBodyHTTPS("pve.preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200 (preserve path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify dropped to false after PUT-without-key; want preserved true")
	}
}

func TestUpdateRoute_InsecureSkipVerify_PresentReplacesWithFalse(t *testing.T) {
	// PUT WITH explicit false MUST clear the previously stored
	// true. Pins that the pointer dereference path is wired
	// (i.e. the *bool is not collapsed into a "nil OR false →
	// preserve" mistake).
	env := newTestEnv(t, false)

	createBody := jsonBodyHTTPS("pve.replace.local", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	putBody := jsonBodyHTTPS("pve.replace.local", "false")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify stayed true after PUT explicit false; want cleared")
	}
}

func TestCreateRoute_InsecureSkipVerify_HTTPOnly_NormalisesToFalse(t *testing.T) {
	// HTTP-only upstream pool + insecureSkipVerify:true is
	// meaningless (no transport.tls block emitted by the
	// caddymgr builder). The API silently normalises to false
	// + warn-log — same self-heal shape as RedirectToHTTPS
	// auto-clearing when TLSEnabled flips false (routes.go:
	// 1273-1275). Pins that the dead config doesn't persist.
	env := newTestEnv(t, false)
	body := jsonBodyHTTP("ha.normalise.local", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201 (silent normalisation, not rejection)",
			rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true on http-only pool; want normalised to false")
	}
}

func TestUpdateRoute_InsecureSkipVerify_HTTPOnly_NormalisesToFalse(t *testing.T) {
	// Same self-heal on PUT path: a previously stored true on
	// an https pool that the operator just switched to http
	// must normalise to false (the operator didn't restate the
	// flag, but the http upstream makes it meaningless).
	env := newTestEnv(t, false)

	// 1. Create with https + true.
	createBody := jsonBodyHTTPS("pve.switch.local", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// 2. PUT without insecureSkipVerify (preserve-on-nil) but
	// switch the pool to http-only — the preserved true must
	// be self-healed back to false.
	putBody := jsonBodyHTTP("pve.switch.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200 (self-heal succeeds)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true on http-only switched pool; want self-healed to false")
	}
}
