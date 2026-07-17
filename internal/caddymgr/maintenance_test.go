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

package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestBuildConfigJSON_MaintenanceRoute is the Task 4 structural gate:
// a route with MaintenanceConfig set must emit a static_response 503
// (with Retry-After + the maintenance body) for everyone except the
// client_ip bypass allow-list.
//
// We deliberately do NOT call caddy.Validate in THIS file: this file
// sorts alphabetically BEFORE manager_test.go (and before
// managed_domain_emission_test.go), so a Validate call here would
// leak Caddy admin-endpoint global state into the alphabetically-
// later TestSyncRegistry_NotCalledOnReloadFailure (manager_test.go)
// and break it — the exact anti-pattern documented at
// managed_domain_emission_test.go:462-478 and manager_test.go:
// 1160-1166. The real caddy.Validate coverage for the maintenance
// shape lives in TestBuildConfigJSON_LoadsCleanly's canonical fixture
// (manager_test.go, route ID "r-maintenance"), which runs safely
// after the sync-registry test in the same file. This file sticks to
// buildConfigJSON + string/structural assertions only.
func TestBuildConfigJSON_MaintenanceRoute(t *testing.T) {
	// NOTE: buildConfigJSON is pure config generation — it emits the
	// arenet_routemetrics handler as a JSON string but never
	// PROVISIONS it, so no metrics.SetRegistry is needed here.
	// Crucially, we must NOT call metrics.SetRegistry: this test
	// sorts alphabetically BEFORE TestSyncRegistry_NotCalledOnReload
	// Failure, which relies on the process-global registry being nil
	// so the arenet_routemetrics Provision fails and its caddy.Load
	// is rejected. Setting the global here would let that Load
	// succeed and break the sync test (a real cross-test poisoning
	// caught during Task 4 implementation).
	routes := []storage.Route{{
		ID: "r1", Host: "maint.example.com", TLSEnabled: true,
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 300, BypassIPs: []string{"192.168.1.0/24"},
		},
	}}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	// buildConfigJSON emits via json.MarshalIndent (manager.go:2219),
	// so keys are followed by ": " (space) rather than compact ":".
	// Normalize whitespace before the substring checks so the
	// assertions don't depend on the marshaler's indent style.
	compact := strings.Join(strings.Fields(string(cfgJSON)), "")

	// 1. static_response 503 present.
	if !strings.Contains(compact, `"static_response"`) || !strings.Contains(compact, `"status_code":503`) {
		t.Error("no static_response 503 emitted for maintenance route")
	}
	// 2. Retry-After header present.
	if !strings.Contains(compact, `"Retry-After"`) || !strings.Contains(compact, `"300"`) {
		t.Error("no Retry-After: 300 header emitted")
	}
	// 3. client_ip bypass with the CIDR (NOT remote_ip).
	if !strings.Contains(compact, `"client_ip"`) || !strings.Contains(compact, `192.168.1.0/24`) {
		t.Error("no client_ip bypass with the CIDR")
	}
	if strings.Contains(compact, `"remote_ip"`) {
		t.Error("used remote_ip; want client_ip")
	}
}

// TestBuildConfigJSON_MaintenanceRoute_NoBypass covers the "no bypass
// IPs configured" path: the bypass inner route must be omitted
// entirely (an empty client_ip ranges matcher would be a no-op
// matcher, not "match nobody"), so ALL traffic — including the
// operator's own IP — hits the 503 until BypassIPs is populated.
func TestBuildConfigJSON_MaintenanceRoute_NoBypass(t *testing.T) {
	// See the note in TestBuildConfigJSON_MaintenanceRoute: no
	// metrics.SetRegistry here — buildConfigJSON is pure, and
	// setting the global registry would poison the later
	// TestSyncRegistry_NotCalledOnReloadFailure.
	routes := []storage.Route{{
		ID: "r2", Host: "maint2.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		MaintenanceConfig: &storage.MaintenanceConfig{
			RetryAfterSeconds: 60,
		},
	}}

	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	compact := strings.Join(strings.Fields(string(cfgJSON)), "")
	if strings.Contains(compact, `"client_ip"`) {
		t.Error("client_ip bypass emitted with no BypassIPs configured; want no bypass route at all")
	}
	if !strings.Contains(compact, `"static_response"`) || !strings.Contains(compact, `"status_code":503`) {
		t.Error("no static_response 503 emitted for maintenance route")
	}
}

// TestDefaultMaintenancePageHTML_MatchesInternalDefault pins the
// v2.17.1 Item E exported accessor: it must return the exact same
// HTML as the package-private arenetDefaultMaintenancePage used by
// resolveMaintenancePage's empty-stored-HTML fallback, and it must be
// non-empty so internal/api's GET handler has something real to
// surface to the frontend as the built-in default.
func TestDefaultMaintenancePageHTML_MatchesInternalDefault(t *testing.T) {
	got := DefaultMaintenancePageHTML()
	if got == "" {
		t.Fatal("DefaultMaintenancePageHTML() returned empty string")
	}
	if got != arenetDefaultMaintenancePage {
		t.Error("DefaultMaintenancePageHTML() does not match arenetDefaultMaintenancePage")
	}
}
