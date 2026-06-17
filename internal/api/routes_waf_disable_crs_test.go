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

// Step X.1 (2026-06-17) — API wire layer for Route.WAFDisableCRS.
//
// Mirrors the UploadStreamingMode wire-layer tests verbatim — the
// two fields share the exact same nil-pointer-preserve-on-omit /
// explicit-false-replace semantic by design (ADR D2). When that
// shape ever changes the tests fail in lockstep, surfacing the
// drift instantly.
//
// Covers :
//   1. POST→GET roundtrip with wafDisableCRS:true echoes the
//      flag on the response and persists in storage.
//   2. POST without the key defaults to false (CRS loaded —
//      pre-X.1 byte-equivalent).
//   3. PUT WITHOUT the key preserves the previously stored
//      value (preserve-on-omit).
//   4. PUT WITH explicit false REPLACES (clears) the value.

func jsonBodyWithDisableCRS(host, disableCRSJSON string) string {
	tail := ""
	if disableCRSJSON != "" {
		tail = `,"wafDisableCRS":` + disableCRSJSON
	}
	// wafMode "detect" so the caddymgr emit actually consults
	// WAFDisableCRS (mode "off" short-circuits before the flag is
	// read). The Step I.4 contract decouples the two : disable
	// CRS is silent until WAFMode flips on.
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"detect"%s}`,
		host, tail,
	)
}

func TestCreateRoute_WAFDisableCRS_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithDisableCRS("nas.lan", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}

	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.WAFDisableCRS {
		t.Errorf("response WAFDisableCRS = false; want true (roundtrip)")
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].WAFDisableCRS {
		t.Errorf("storage WAFDisableCRS = false; want true")
	}
}

func TestCreateRoute_WAFDisableCRS_Defaults_False(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithDisableCRS("api.default.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].WAFDisableCRS {
		t.Errorf("storage WAFDisableCRS = true on default; want false (pre-X.1 byte-equivalent)")
	}
}

func TestUpdateRoute_WAFDisableCRS_NilPreservesPrevious(t *testing.T) {
	// PUT without the key MUST preserve the stored value.
	// Mirror of TestUpdateRoute_UploadStreamingMode_NilPreservesPrevious.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithDisableCRS("nas.preserve.local", "true")
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

	// PUT WITHOUT the wafDisableCRS key — preserve path.
	putBody := jsonBodyWithDisableCRS("nas.preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200 (preserve path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].WAFDisableCRS {
		t.Errorf("WAFDisableCRS dropped to false after PUT-without-key; want preserved true")
	}
}

func TestUpdateRoute_WAFDisableCRS_PresentReplacesWithFalse(t *testing.T) {
	// PUT WITH explicit false MUST clear the previously stored
	// true. This is the only way an operator can re-enable CRS
	// from the API after toggling it off.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithDisableCRS("nas.replace.local", "true")
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

	// PUT WITH explicit false — replace path.
	putBody := jsonBodyWithDisableCRS("nas.replace.local", "false")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200", putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].WAFDisableCRS {
		t.Errorf("WAFDisableCRS = true after explicit PUT false; want re-enabled (false)")
	}
}
