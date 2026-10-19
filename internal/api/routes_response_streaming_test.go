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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// v2.77 (issue #317) — API wire layer for Route.ResponseStreamingMode.
// Literal-JSON wire test (per the "test the wire, not the struct" lesson):
// the camelCase `responseStreamingMode` must round-trip POST→response→
// storage, default false, and preserve-on-omit at PUT.

func jsonBodyWithResponseStreaming(host, streamingJSON string) string {
	tail := ""
	if streamingJSON != "" {
		tail = `,"responseStreamingMode":` + streamingJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_ResponseStreamingMode_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithResponseStreaming("ha.local", "true")
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
	if !resp.ResponseStreamingMode {
		t.Errorf("response responseStreamingMode = false; want true (camelCase wire roundtrip)")
	}
	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].ResponseStreamingMode {
		t.Errorf("storage ResponseStreamingMode = false; want true")
	}
}

func TestCreateRoute_ResponseStreamingMode_Defaults_False(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithResponseStreaming("plain.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].ResponseStreamingMode {
		t.Errorf("storage ResponseStreamingMode = true on default; want false")
	}
}

func TestUpdateRoute_ResponseStreamingMode_NilPreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)

	createBody := jsonBodyWithResponseStreaming("preserve.local", "true")
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

	// PUT WITHOUT the responseStreamingMode key — must preserve true.
	putBody := jsonBodyWithResponseStreaming("preserve.local", "")
	preq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	preq.Header.Set("Content-Type", "application/json")
	prec := httptest.NewRecorder()
	env.router.ServeHTTP(prec, preq)
	if prec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", prec.Code, prec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].ResponseStreamingMode {
		t.Errorf("ResponseStreamingMode not preserved on PUT-without-key; want true")
	}
}
