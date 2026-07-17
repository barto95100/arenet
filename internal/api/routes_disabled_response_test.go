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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// Regression (v2.17.1): the routeResponse serializer NEVER included the
// `disabled` field, even though the storage row and the /disable endpoint
// set it correctly. So GET /routes returned a disabled route with no
// `disabled` key → the frontend decoded it as undefined (falsy) → the
// 3-state control showed the route as Active, "disabled" never stuck, and
// the frontend last-HTTPS count (which reads !route.disabled) was
// systematically wrong. The whole class was invisible because no test ever
// asserted `disabled` round-trips through the RESPONSE (only the request/
// storage side was covered). These tests pin the response.

// getRouteJSON fetches GET /routes/{id} and returns the raw JSON body.
func getRouteJSON(t *testing.T, env *testEnv, id string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/routes/"+id, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET route status=%d body=%s", rec.Code, rec.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode route response: %v", err)
	}
	return m
}

func TestRouteResponse_Disabled_RoundTrips(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "dis.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		Disabled:  true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	m := getRouteJSON(t, env, created.ID)
	got, present := m["disabled"]
	if !present {
		t.Fatal(`response has no "disabled" key; the frontend reads it as undefined → shows Active`)
	}
	if got != true {
		t.Errorf(`response "disabled" = %v; want true`, got)
	}
}

func TestRouteResponse_DisabledFalse_ReadsAsEnabled(t *testing.T) {
	// A non-disabled route: with omitempty, "disabled" may be absent, which
	// the frontend correctly reads as not-disabled (undefined → falsy →
	// 'active'). So absent-or-false is acceptable here; the load-bearing
	// case is the true one above. This test guards that an enabled route is
	// NOT reported as disabled.
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "ena.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	m := getRouteJSON(t, env, created.ID)
	if v, ok := m["disabled"]; ok && v == true {
		t.Errorf(`enabled route reported disabled=true`)
	}
}
