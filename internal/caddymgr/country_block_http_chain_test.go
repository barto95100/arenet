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
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/storage"
)

// Step W follow-up — country-block on the HTTP chain.
//
// v1.6.0-step-w shipped country-block on the HTTPS chain
// only. The HTTP chain (arenet_http server, port :80)
// emitted a 301 redirect via buildRedirectRoute WITHOUT
// evaluating the gate first, so a non-allowed source
// country received a 301 confirming the host existed —
// then retried against the HTTPS chain (where the gate
// fired). Pre-redirect bypass; verified live via
// check-host.net returning 301 from 58 worldwide probes
// even with mode=allow countryList=["FR","PT"].
//
// Fix: prepend the country-block handler in
// buildRedirectRoute so a non-allowed source gets the
// configured status (403/451/444) on port 80 directly,
// stopping the request before any "host present" leak.

// --- buildRedirectRoute prepends country-block handler -----

func TestBuildRedirectRoute_PrependsCountryBlock_WhenModeNotOff(t *testing.T) {
	cb := countryblock.Config{
		Mode:        countryblock.ModeAllow,
		CountryList: []string{"FR", "PT"},
		StatusCode:  403,
	}
	r := buildRedirectRoute("route-uuid-1", "ha.example.com", cb, []string{"ha.example.com"})

	if len(r.Handle) != 2 {
		t.Fatalf("expected 2 handlers (country_block + static_response 301); got %d", len(r.Handle))
	}
	// Position #1 — country-block (W.3 chain-position
	// invariant carries over: the gate runs FIRST so a
	// block short-circuits before any downstream handler).
	if got := r.Handle[0]["handler"]; got != countryblock.HandlerName {
		t.Errorf("Handle[0].handler = %q; want %q", got, countryblock.HandlerName)
	}
	// Position #2 — the existing static_response 301 path.
	if got := r.Handle[1]["handler"]; got != "static_response" {
		t.Errorf("Handle[1].handler = %q; want static_response", got)
	}
	if got := r.Handle[1]["status_code"]; got != 301 {
		t.Errorf("Handle[1].status_code = %v; want 301 (redirect preserved on pass-through)", got)
	}
}

func TestBuildRedirectRoute_OmitsCountryBlock_WhenModeOff(t *testing.T) {
	// mode=off → the W.3 cheap-skip optimization applies on
	// the HTTP chain too. Zero per-request cost for routes
	// that don't use the feature.
	cases := []countryblock.Config{
		{}, // zero-value Mode==""
		{Mode: countryblock.ModeOff},
		{Mode: countryblock.ModeOff, CountryList: []string{"FR"}},
	}
	for _, cb := range cases {
		r := buildRedirectRoute("route-uuid-1", "ha.example.com", cb, []string{"ha.example.com"})
		if len(r.Handle) != 1 {
			t.Errorf("expected 1 handler when mode=off (just static_response); got %d for cb=%+v", len(r.Handle), cb)
			continue
		}
		if got := r.Handle[0]["handler"]; got != "static_response" {
			t.Errorf("expected sole handler to be static_response; got %q for cb=%+v", got, cb)
		}
	}
}

func TestBuildRedirectRoute_CountryBlockConfigPropagated(t *testing.T) {
	// Pin the round-trip: the cb config the caller passes
	// reaches the emitted handler JSON intact (mode +
	// countryList + statusCode all visible).
	cb := countryblock.Config{
		Mode:        countryblock.ModeDeny,
		CountryList: []string{"RU", "KP"},
		StatusCode:  451,
	}
	r := buildRedirectRoute("route-uuid-2", "blocked.example.com", cb, []string{"blocked.example.com"})

	cbHandler := r.Handle[0]
	if cbHandler["routeID"] != "route-uuid-2" {
		t.Errorf("routeID = %v; want route-uuid-2", cbHandler["routeID"])
	}
	config, ok := cbHandler["config"].(map[string]any)
	if !ok {
		t.Fatalf("config block is not a map: %T", cbHandler["config"])
	}
	if config["mode"] != "deny" {
		t.Errorf("config.mode = %v; want deny", config["mode"])
	}
	if config["statusCode"] != 451 {
		t.Errorf("config.statusCode = %v; want 451", config["statusCode"])
	}
	list, ok := config["countryList"].([]string)
	if !ok || len(list) != 2 {
		t.Errorf("config.countryList = %v; want 2-element []string", config["countryList"])
	}
}

// --- buildConfigJSON HTTP-chain integration ----------------

// TestBuildConfigJSON_CountryBlockOnHTTPChain — when a route
// has RedirectToHTTPS=true AND country_block on, the HTTP
// server's per-host route must carry BOTH handlers in
// order (country_block → static_response 301). This is the
// regression guard for the pre-redirect bypass that
// v1.6.0-step-w shipped with.
func TestBuildConfigJSON_CountryBlockOnHTTPChain(t *testing.T) {
	routes := []storage.Route{
		{
			ID:              "route-uuid-1",
			Host:            "gated.example.com",
			Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:        storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			WAFMode:         "off",
			CountryBlock: countryblock.Config{
				Mode:        countryblock.ModeAllow,
				CountryList: []string{"FR", "PT"},
				StatusCode:  403,
			},
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutesArr := extractServerRoutes(t, raw, "arenet_http")

	// Find the per-host redirect route for gated.example.com
	// (ACME challenges + other routes also live on arenet_http;
	// match by Match.Host).
	var redirectRoute map[string]any
	for _, ent := range httpRoutesArr {
		m := ent.(map[string]any)
		matches, ok := m["match"].([]any)
		if !ok || len(matches) == 0 {
			continue
		}
		first, _ := matches[0].(map[string]any)
		hosts, _ := first["host"].([]any)
		for _, h := range hosts {
			if h == "gated.example.com" {
				redirectRoute = m
				break
			}
		}
		if redirectRoute != nil {
			break
		}
	}
	if redirectRoute == nil {
		t.Fatalf("could not locate redirect route for gated.example.com in arenet_http routes:\n%s", raw)
	}

	handle, _ := redirectRoute["handle"].([]any)
	if len(handle) != 2 {
		t.Fatalf("redirect route handler chain length = %d; want 2 (country_block + static_response)\nfull route: %+v", len(handle), redirectRoute)
	}
	first, _ := handle[0].(map[string]any)
	second, _ := handle[1].(map[string]any)
	if first["handler"] != countryblock.HandlerName {
		t.Errorf("HTTP chain position #1 = %v; want %s (country-block runs FIRST on the HTTP redirect path)",
			first["handler"], countryblock.HandlerName)
	}
	if second["handler"] != "static_response" {
		t.Errorf("HTTP chain position #2 = %v; want static_response (301 redirect preserved on pass-through)", second["handler"])
	}
	if v, ok := second["status_code"].(float64); !ok || int(v) != 301 {
		t.Errorf("static_response status_code = %v; want 301 (HTTPS redirect intent preserved)", second["status_code"])
	}
}

// TestBuildConfigJSON_CountryBlockOffOnHTTPChain — when
// country_block is off, the HTTP redirect route MUST stay
// byte-equal to the pre-fix shape: a single
// static_response 301 handler. This pins the cheap-skip
// optimization on the HTTP chain (zero per-request cost
// for routes that don't use the feature).
func TestBuildConfigJSON_CountryBlockOffOnHTTPChain(t *testing.T) {
	routes := []storage.Route{
		{
			ID:              "route-uuid-1",
			Host:            "open.example.com",
			Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:        storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			WAFMode:         "off",
			// CountryBlock zero-value = off.
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutesArr := extractServerRoutes(t, raw, "arenet_http")
	for _, ent := range httpRoutesArr {
		m := ent.(map[string]any)
		matches, ok := m["match"].([]any)
		if !ok || len(matches) == 0 {
			continue
		}
		first, _ := matches[0].(map[string]any)
		hosts, _ := first["host"].([]any)
		for _, h := range hosts {
			if h != "open.example.com" {
				continue
			}
			handle, _ := m["handle"].([]any)
			if len(handle) != 1 {
				t.Errorf("off-mode HTTP redirect route handler chain length = %d; want 1 (cheap-skip omits country-block handler)",
					len(handle))
				return
			}
			h0, _ := handle[0].(map[string]any)
			if h0["handler"] != "static_response" {
				t.Errorf("off-mode sole handler = %v; want static_response", h0["handler"])
			}
			return
		}
	}
}

// TestBuildConfigJSON_CountryBlockOnHTTPSChain_Unchanged
// is the symmetric regression guard: the HTTPS-side
// per-route chain emit (subroute with the existing 8+
// handlers) MUST still carry country-block at chain
// position #2 as before. The HTTP-chain addition above
// is an EXTENSION, not a replacement.
func TestBuildConfigJSON_CountryBlockOnHTTPSChain_Unchanged(t *testing.T) {
	routes := []storage.Route{
		{
			ID:              "route-uuid-1",
			Host:            "gated.example.com",
			Upstreams:       []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:        storage.LBPolicyRoundRobin,
			TLSEnabled:      true,
			RedirectToHTTPS: true,
			WAFMode:         "off",
			CountryBlock: countryblock.Config{
				Mode:        countryblock.ModeDeny,
				CountryList: []string{"RU"},
				StatusCode:  403,
			},
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	out := string(raw)
	// Both server chains must reference the
	// arenet_country_block handler. A single occurrence
	// would mean only one side carries it.
	count := substringCount(out, `"arenet_country_block"`)
	if count != 2 {
		t.Errorf("expected 2 references to arenet_country_block (HTTP redirect + HTTPS subroute); got %d", count)
	}
}

// substringCount is a tiny helper. We avoid the regexp
// package to keep this test file dependency-free.
func substringCount(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}

// extractServerRoutes returns the apps.http.servers[name]
// .routes array from a buildConfigJSON output. Centralises
// the pointer-chase through the nested JSON envelope so the
// test cases above stay readable.
func extractServerRoutes(t *testing.T, raw []byte, serverName string) []any {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps, _ := top["apps"].(map[string]any)
	http, _ := apps["http"].(map[string]any)
	servers, _ := http["servers"].(map[string]any)
	srv, ok := servers[serverName].(map[string]any)
	if !ok {
		t.Fatalf("server %q not found in emitted config:\n%s", serverName, raw)
	}
	routesArr, _ := srv["routes"].([]any)
	return routesArr
}
