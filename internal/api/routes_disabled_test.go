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

// Regression: the route enable/disable feature (v2.15.0) added a
// `disabled` field to the storage struct, topology, the dedicated
// /disable + /enable endpoints, and the frontend RouteRequest — but
// NOT to the API wire struct (routeRequest) used by createRoute and
// updateRoute. Both decode with dec.DisallowUnknownFields(), so any
// POST/PUT that carries "disabled":... (which the v2.15.0 frontend
// form now always sends) is rejected with 400 "unknown field
// \"disabled\"" before reaching the storage layer. This made it
// impossible to create OR edit a route from the UI. Same bug class
// as the InsecureSkipVerify wire gap.
//
// These tests pin:
//   1. POST with "disabled":true creates a route stored as disabled.
//   2. POST with "disabled":false (the frontend default) succeeds
//      and stores enabled — this is the exact payload that 400'd.
//   3. POST without the key defaults to enabled (disabled=false).
//   4. PUT with "disabled":true on an enabled route disables it.

// jsonBodyDisabled builds a POST/PUT body. When disabledJSON is
// "true"/"false" the disabled key is injected; "" omits it.
func jsonBodyDisabled(host, disabledJSON string) string {
	tail := ""
	if disabledJSON != "" {
		tail = `,"disabled":` + disabledJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.20:8080","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_Disabled_True_Stored(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyDisabled("dis.example.com", "true")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if !got[0].Disabled {
		t.Errorf("storage Disabled = false; want true (disabled:true on create)")
	}
}

func TestCreateRoute_Disabled_False_Succeeds(t *testing.T) {
	// This is the EXACT payload the v2.15.0 frontend sends on a
	// normal create ("disabled":false) — it must NOT 400.
	env := newTestEnv(t, false)
	body := jsonBodyDisabled("ena.example.com", "false")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201 (disabled:false must be accepted)",
			rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].Disabled {
		t.Errorf("storage Disabled = true; want false")
	}
}

func TestCreateRoute_Disabled_Absent_DefaultsEnabled(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyDisabled("def.example.com", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s; want 201", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].Disabled {
		t.Errorf("storage Disabled = true on default; want false (enabled)")
	}
}

func TestUpdateRoute_Disabled_True_Applies(t *testing.T) {
	env := newTestEnv(t, false)

	createBody := jsonBodyDisabled("upd.example.com", "false")
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

	putBody := jsonBodyDisabled("upd.example.com", "true")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s; want 200", putRec.Code, putRec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if !got[0].Disabled {
		t.Errorf("storage Disabled = false after PUT disabled:true; want true")
	}
}
