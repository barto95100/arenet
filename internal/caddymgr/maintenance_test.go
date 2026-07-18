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

// v2.18.0 — buildMaintenanceBody must substitute BOTH the per-route
// retry_after sentinel AND the global message sentinel. The message is
// operator free text: it MUST be HTML-escaped (so it can't inject
// markup into every 503), and its newlines rendered as <br> (so a
// multi-line message from the Settings textarea displays across lines
// rather than collapsing to one). An empty message substitutes to
// nothing (the built-in default's generic line then stands alone).
func TestBuildMaintenanceBody_SubstitutesMessage(t *testing.T) {
	html := `<p class="msg">{arenet.maintenance.message}</p><p>retry {arenet.maintenance.retry_after}s</p>`
	got := buildMaintenanceBody(html, 300, "Back at 14:00")
	if !strings.Contains(got, "Back at 14:00") {
		t.Errorf("message not substituted; body=%q", got)
	}
	if !strings.Contains(got, "retry 300s") {
		t.Errorf("retry_after not substituted; body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.message}") {
		t.Errorf("message sentinel left unsubstituted; body=%q", got)
	}
}

func TestBuildMaintenanceBody_EscapesMessageHTML(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, `<script>alert(1)</script> & "quoted"`)
	if strings.Contains(got, "<script>") {
		t.Errorf("message HTML not escaped — raw <script> in body: %q", got)
	}
	if !strings.Contains(got, "&lt;script&gt;") {
		t.Errorf("expected escaped script tag; body=%q", got)
	}
	if !strings.Contains(got, "&amp;") {
		t.Errorf("expected escaped ampersand; body=%q", got)
	}
}

func TestBuildMaintenanceBody_MessageNewlinesToBr(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, "line one\nline two")
	if !strings.Contains(got, "line one<br>line two") {
		t.Errorf("newline not rendered as <br>; body=%q", got)
	}
}

// v2.18.0 security — the message is operator free text substituted into
// the (placeholder-expanded) 503 body. A message of {env.SECRET} would
// otherwise leak a process-env secret into the public 503. The message
// has no documented placeholders of its own, so dangerous Caddy
// namespaces ({env.*}, {file.*}) must be neutralized.
func TestBuildMaintenanceBody_NeutralizesEnvPlaceholderInMessage(t *testing.T) {
	html := `<div>{arenet.maintenance.message}</div>`
	got := buildMaintenanceBody(html, 60, "leak: {env.ACME_DNS_API_TOKEN} and {file./etc/passwd}")
	if strings.Contains(got, "{env.ACME_DNS_API_TOKEN}") {
		t.Errorf("{env.*} in message survived — secret disclosure: %q", got)
	}
	if strings.Contains(got, "{file./etc/passwd}") {
		t.Errorf("{file.*} in message survived — file disclosure: %q", got)
	}
}

func TestBuildMaintenanceBody_EmptyMessageSubstitutesNothing(t *testing.T) {
	html := `<div>[{arenet.maintenance.message}]</div>`
	got := buildMaintenanceBody(html, 60, "")
	if !strings.Contains(got, "[]") {
		t.Errorf("empty message should substitute to nothing (leaving []); body=%q", got)
	}
	if strings.Contains(got, "{arenet.maintenance.message}") {
		t.Errorf("empty message left the sentinel unsubstituted; body=%q", got)
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
