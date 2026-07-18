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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// The 3 states (Active / Maintenance / Disabled) are MUTUALLY EXCLUSIVE.
// Every transition endpoint must establish exactly ONE clean state, never
// leave two flags set. v2.17.1 fixed the disable side (entering Disabled
// clears MaintenanceConfig). This pins the MIRROR: entering Maintenance
// must clear Disabled — otherwise a disabled route that's put into
// maintenance keeps Disabled=true, so routeState() (Disabled wins) still
// shows it disabled (the toast lied), and a later Enable resurrects
// maintenance instead of going Active.

func TestMaintenance_Enter_ClearsDisabled(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "dm.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		Disabled:  true, // route starts DISABLED
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// disabled -> maintenance
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("enter maintenance status=%d body=%s", rec.Code, rec.Body)
	}

	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.Disabled {
		t.Error("Disabled still true after entering maintenance; want false (states are exclusive — the control would still show Disabled)")
	}
	if got.MaintenanceConfig == nil {
		t.Error("MaintenanceConfig nil after entering maintenance; want set")
	}
}

func TestMaintenance_Enter_ThenEnable_GoesActive(t *testing.T) {
	// Full user scenario: disabled -> maintenance -> enable. After enable
	// the route must be ACTIVE (Disabled=false AND MaintenanceConfig=nil),
	// not resurrected into maintenance.
	env := newTestEnv(t, false)
	created, _ := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "dme.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		Disabled:  true,
	})

	// -> maintenance
	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/maintenance", nil)
	env.router.ServeHTTP(httptest.NewRecorder(), r1)
	// -> enable (active)
	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+created.ID+"/enable", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, r2)
	if rec.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", rec.Code, rec.Body)
	}

	got, _ := env.store.GetRoute(context.Background(), created.ID)
	if got.Disabled {
		t.Error("Disabled true after enable; want false")
	}
	if got.MaintenanceConfig != nil {
		t.Errorf("MaintenanceConfig = %+v after enable; want nil (route should be Active, not maintenance)", got.MaintenanceConfig)
	}
}
