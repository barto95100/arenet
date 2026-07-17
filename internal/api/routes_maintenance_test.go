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
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func maintBody(host, extra string) string {
	return `{"host":"` + host + `","upstreams":[{"url":"http://u:1","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"` + extra + `}`
}

// The exact create-with-maintenance payload the frontend sends must NOT 400.
func TestCreateRoute_WithMaintenanceConfig(t *testing.T) {
	env := newTestEnv(t, false)
	body := maintBody("m.example.com", `,"maintenanceConfig":{"retryAfterSeconds":300,"bypassIps":["10.0.0.5"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (maintenanceConfig must be accepted)", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].MaintenanceConfig == nil || got[0].MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("stored MaintenanceConfig = %+v; want RetryAfterSeconds 300", got[0].MaintenanceConfig)
	}
}

func TestMaintenanceEndpoint_On_SetsConfig(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "on.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig == nil {
		t.Fatal("MaintenanceConfig nil after /maintenance; want defaults set")
	}
	if got.MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("default RetryAfterSeconds = %d; want 300", got.MaintenanceConfig.RetryAfterSeconds)
	}
}

func TestMaintenanceEndpoint_Off_ClearsConfig(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "off.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{RetryAfterSeconds: 300},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance/off", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig != nil {
		t.Errorf("MaintenanceConfig = %+v after /off; want nil (clear-on-off)", got.MaintenanceConfig)
	}
}

func TestUpdateRoute_PreservesMaintenanceOnEdit(t *testing.T) {
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host: "edit.example.com", Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}}, LBPolicy: storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{RetryAfterSeconds: 120, BypassIPs: []string{"10.0.0.1"}},
	})
	body := maintBody("edit.example.com", `,"maintenanceConfig":{"retryAfterSeconds":120,"bypassIps":["10.0.0.1"]}`)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig == nil || got.MaintenanceConfig.RetryAfterSeconds != 120 {
		t.Errorf("MaintenanceConfig after edit = %+v; want RetryAfterSeconds 120", got.MaintenanceConfig)
	}
	_ = json.Marshal // keep import
}
