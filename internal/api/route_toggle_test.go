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

// seedToggleRoute creates a route via the store and returns its ID.
// Named distinctly from other package seed helpers to avoid collisions.
func seedToggleRoute(t *testing.T, env *testEnv, host string, tls bool) string {
	t.Helper()
	r, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       host,
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: tls,
	})
	if err != nil {
		t.Fatalf("seed route: %v", err)
	}
	return r.ID
}

func TestRouteDisable_SetsDisabledAndReloads(t *testing.T) {
	env := newTestEnv(t, false)
	id := seedToggleRoute(t, env, "a.example.com", false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body)
	}
	got, err := env.store.GetRoute(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Disabled {
		t.Error("route not marked Disabled after /disable")
	}
}

func TestRouteDisable_Idempotent(t *testing.T) {
	env := newTestEnv(t, false)
	id := seedToggleRoute(t, env, "b.example.com", false)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("disable #%d status = %d; want 200", i, rec.Code)
		}
	}
}

func TestRouteEnable_ClearsDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	id := seedToggleRoute(t, env, "c.example.com", false)
	// disable then enable
	for _, action := range []string{"disable", "enable"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/"+action, nil)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d; want 200", action, rec.Code)
		}
	}
	got, _ := env.store.GetRoute(context.Background(), id)
	if got.Disabled {
		t.Error("route still Disabled after /enable")
	}
}

func TestRouteDisable_LastHttpsRouteHint(t *testing.T) {
	env := newTestEnv(t, false)
	id := seedToggleRoute(t, env, "only-tls.example.com", true) // sole TLS route

	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/disable", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body)
	}
	var resp struct {
		LastHTTPSRouteAffected bool `json:"lastHttpsRouteAffected"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.LastHTTPSRouteAffected {
		t.Error("disabling the only TLS route should report lastHttpsRouteAffected=true")
	}
}
