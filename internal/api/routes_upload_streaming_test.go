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

// Phase 4.5 — API wire layer for Route.UploadStreamingMode.
//
// Mirrors the InsecureSkipVerify wire-layer tests:
//   1. POST→GET roundtrip with uploadStreamingMode:true echoes
//      the flag on the response and persists in storage
//   2. POST without the key defaults to false
//   3. PUT WITHOUT the key preserves the previously stored
//      value (preserve-on-omit)
//   4. PUT WITH explicit false REPLACES (clears) the value

func jsonBodyWithStreaming(host, streamingJSON string) string {
	tail := ""
	if streamingJSON != "" {
		tail = `,"uploadStreamingMode":` + streamingJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_UploadStreamingMode_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithStreaming("registry.local", "true")
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
	if !resp.UploadStreamingMode {
		t.Errorf("response UploadStreamingMode = false; want true (roundtrip)")
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].UploadStreamingMode {
		t.Errorf("storage UploadStreamingMode = false; want true")
	}
}

func TestCreateRoute_UploadStreamingMode_Defaults_False(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithStreaming("api.default.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].UploadStreamingMode {
		t.Errorf("storage UploadStreamingMode = true on default; want false")
	}
}

func TestUpdateRoute_UploadStreamingMode_NilPreservesPrevious(t *testing.T) {
	// PUT without the key MUST preserve the stored value. The
	// Lesson 8 preserve-on-omit invariant — same UX as
	// InsecureSkipVerify / healthCheck / countryBlock.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithStreaming("registry.preserve.local", "true")
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

	// PUT WITHOUT the uploadStreamingMode key — preserve path.
	putBody := jsonBodyWithStreaming("registry.preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200 (preserve path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].UploadStreamingMode {
		t.Errorf("UploadStreamingMode dropped to false after PUT-without-key; want preserved true")
	}
}

func TestUpdateRoute_UploadStreamingMode_PresentReplacesWithFalse(t *testing.T) {
	// PUT WITH explicit false MUST clear the previously stored
	// true. Pins that the *bool pointer dereference path is
	// wired correctly.
	env := newTestEnv(t, false)

	createBody := jsonBodyWithStreaming("registry.replace.local", "true")
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

	putBody := jsonBodyWithStreaming("registry.replace.local", "false")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].UploadStreamingMode {
		t.Errorf("UploadStreamingMode still true after PUT with explicit false; want cleared")
	}
}
