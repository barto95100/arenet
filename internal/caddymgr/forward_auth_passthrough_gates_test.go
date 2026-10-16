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

package caddymgr

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/metrics"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"
)

// passthroughFixtureRoute is the one route all three tests in this file
// emit: a forward-auth route whose provider declares an
// AuthPassthroughPrefix, fenced by every host-perimeter gate. opts picks
// whether CrowdSec is on (crowdsecConfig is unexported, so this stays in
// package).
func passthroughFixtureRoute() storage.Route {
	return storage.Route{
		ID:         "app",
		Host:       "app.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		WAFMode:    "off",
		TLSEnabled: true,
		AuthMode:   storage.RouteAuthForwardAuth,
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: "authentik",
		},
		IPFilter: &storage.IPFilter{Mode: "deny", CIDRs: []string{"10.0.0.0/8"}},
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeAllow,
			CountryList: []string{"FR"},
		},
		RateLimit: &storage.RouteRateLimit{Events: 100, Window: "1m"},
	}
}

const passthroughFixturePrefix = "/outpost.goauthentik.io"

func passthroughFixtureOpts(crowdSec bool) buildOpts {
	o := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authentik": {
				Name:                  "authentik",
				VerifyURL:             "http://127.0.0.1:9091",
				AuthRequestURI:        "/outpost.goauthentik.io/auth/caddy",
				AuthPassthroughPrefix: passthroughFixturePrefix,
			},
		},
	}
	if crowdSec {
		o.CrowdSec = crowdsecConfig{apiURL: "http://127.0.0.1:8080", apiKey: "test-key"}
	}
	return o
}

// A forward-auth route with an AuthPassthroughPrefix emits a SECOND
// route, before the main one, that proxies the IdP's own endpoint
// (Authentik's /outpost.goauthentik.io/*, oauth2-proxy's /oauth2/*)
// straight through with no forward_auth gate — correctly, because that
// endpoint is the thing doing the authenticating and cannot sit behind
// itself.
//
// The defect (scan F17): that passthrough route carried no gate AT ALL.
// The route's IP filter, country block, rate limit and CrowdSec gate —
// the operator's perimeter around the host — did not apply to the
// passthrough subtree. So a source the operator fenced out by IP, by
// country, or by reputation still reached the IdP endpoint on that host.
// It is the host's perimeter, not the app's auth, so lifting only the
// auth gate is right; lifting the perimeter is the bug.
//
// This proves the fix against the emitted Caddy JSON, not the builder's
// return value: a green unit test on buildAuthPassthroughRoute's slice
// would not see a caller that forgot to pass the gates.
func TestForwardAuthPassthrough_CarriesThePerimeterGates(t *testing.T) {
	raw, err := buildConfigJSON(
		[]storage.Route{passthroughFixtureRoute()}, passthroughFixtureOpts(true))
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	chain := passthroughHandlerChain(t, raw, passthroughFixturePrefix+"/*")

	// Everything the operator set on the host must stand in front of the
	// reverse_proxy to the IdP, in the same order the main chain uses:
	// rate limit, country block, IP filter, CrowdSec.
	wantBeforeProxy := []string{"rate_limit", "arenet_country_block", "ip_filter", "crowdsec"}
	proxyAt := indexOf(chain, "reverse_proxy")
	if proxyAt < 0 {
		t.Fatalf("passthrough route has no reverse_proxy; chain = %v", chain)
	}
	for _, want := range wantBeforeProxy {
		at := indexOf(chain, want)
		if at < 0 {
			t.Errorf("passthrough route is missing the %q gate — the operator's "+
				"perimeter does not cover the IdP endpoint; chain = %v", want, chain)
			continue
		}
		if at > proxyAt {
			t.Errorf("passthrough route runs %q AFTER reverse_proxy (at %d > %d); "+
				"a gate past the proxy never fires; chain = %v", want, at, proxyAt, chain)
		}
	}
}

// TestForwardAuthPassthrough_MirrorsTheMainChainGates is the drift guard.
//
// The passthrough's perimeter is built by perimeterGateHandlers; the main
// route builds the same gates inline, in a different place in the file.
// Two copies drift — a gate added to the main chain but not to the helper
// re-opens exactly this hole on the IdP endpoint. This asserts the two
// blocks are byte-for-token identical, so such a change cannot land green.
//
// Both blocks are read the same way — the handler names up to the first
// reverse_proxy — so the comparison needs no knowledge of which gates
// exist, only that whatever the main chain fences the host with, the
// passthrough fences it with too. The main chain's leading metrics
// handler is dropped; it is observability, not a gate.
func TestForwardAuthPassthrough_MirrorsTheMainChainGates(t *testing.T) {
	raw, err := buildConfigJSON(
		[]storage.Route{passthroughFixtureRoute()}, passthroughFixtureOpts(true))
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	routesArr := extractServerRoutes(t, raw, "arenet_https")

	var passthrough, main []string
	for _, r := range routesArr {
		rm, _ := r.(map[string]any)
		toks := rawSubrouteHandlerTokens(rm)
		if len(toks) == 0 {
			continue
		}
		if routeMatchesSinglePath(rm, passthroughFixturePrefix+"/*") {
			passthrough = gatesBeforeProxy(toks)
			continue
		}
		// The main catch-all route: host-only match, leads with metrics.
		if toks[0] == "arenet_routemetrics" {
			main = gatesBeforeProxy(toks[1:])
		}
	}

	if len(passthrough) == 0 {
		t.Fatal("did not find the passthrough route")
	}
	if len(main) == 0 {
		t.Fatal("did not find the main route's gate block")
	}
	// The main chain opens (after metrics) with exactly the passthrough's
	// perimeter gates, then adds the auth stage the passthrough omits (the
	// forward-auth gate is a subroute that lands in `main` after the
	// perimeter). So the passthrough must be the PREFIX of the main gate
	// block: every perimeter gate the host carries, the IdP endpoint
	// carries too, in the same order (the F17 drift guard); anything the
	// main chain adds beyond that prefix is auth, which is correctly
	// absent from the passthrough.
	if len(main) < len(passthrough) || !reflect.DeepEqual(passthrough, main[:len(passthrough)]) {
		t.Errorf("passthrough and main-chain perimeter gates have drifted apart:\n"+
			"  passthrough = %v\n  main chain  = %v\n"+
			"a perimeter gate on the host that the IdP endpoint does not also carry is the F17 hole",
			passthrough, main)
	}
}

// TestForwardAuthPassthrough_LoadsCleanly runs the real caddy.Validate on
// the emitted config so the gated passthrough route — a shape this
// codebase did not emit before — is proven loadable, not just
// shaped-right. CrowdSec is left off: its handler provisions by dialing
// LAPI, which a unit test must not do (see catchall_test.go); the other
// three gates carry the Validate.
func TestForwardAuthPassthrough_LoadsCleanly(t *testing.T) {
	metrics.SetRegistry(metrics.NewRegistry())
	t.Cleanup(metrics.ResetForTest)
	// arenet_country_block provisions only with a global lookup installed
	// (normally by cmd/arenet at boot); the harness must do the same
	// before caddy.Validate, exactly as TestBuildConfigJSON_CountryBlock…
	// does (manager_test.go).
	prev := countryblock.GlobalLookup()
	countryblock.SetGlobalLookup(noopLookup{})
	t.Cleanup(func() { countryblock.SetGlobalLookup(prev) })

	raw, err := buildConfigJSON(
		[]storage.Route{passthroughFixtureRoute()}, passthroughFixtureOpts(false))
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var parsed caddy.Config
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal config: %v\n%s", err, raw)
	}
	if err := caddy.Validate(&parsed); err != nil {
		t.Fatalf("caddy.Validate rejected the gated passthrough route: %v\n%s", err, raw)
	}
}

// rawSubrouteHandlerTokens returns the handler names of a route's
// subroute, unflattened (an ip-filter stays "subroute"). Empty when the
// route is not a single-subroute route.
func rawSubrouteHandlerTokens(route map[string]any) []string {
	handleArr, _ := route["handle"].([]any)
	if len(handleArr) != 1 {
		return nil
	}
	sub, _ := handleArr[0].(map[string]any)
	if sub["handler"] != "subroute" {
		return nil
	}
	inner, _ := sub["routes"].([]any)
	toks := make([]string, 0, len(inner))
	for _, ir := range inner {
		irm, _ := ir.(map[string]any)
		for _, h := range irm["handle"].([]any) {
			hm, _ := h.(map[string]any)
			if name, ok := hm["handler"].(string); ok {
				toks = append(toks, name)
			}
		}
	}
	return toks
}

// gatesBeforeProxy returns the prefix of toks up to the first
// reverse_proxy (forward_auth also emits as reverse_proxy, so the first
// one is always the boundary between the perimeter and the auth/proxy
// stage).
func gatesBeforeProxy(toks []string) []string {
	for i, tk := range toks {
		if tk == "reverse_proxy" {
			return toks[:i]
		}
	}
	return toks
}

// passthroughHandlerChain finds the emitted route whose single path
// matcher is pathPattern and returns the ordered list of handler names in
// its subroute, flattening the ip-filter subroute to the token
// "ip_filter" (its inner route carries a client_ip matcher and an error
// handler — see buildIPFilterRoute).
func passthroughHandlerChain(t *testing.T, raw []byte, pathPattern string) []string {
	t.Helper()
	routesArr := extractServerRoutes(t, raw, "arenet_https")

	for _, r := range routesArr {
		rm, _ := r.(map[string]any)
		if !routeMatchesSinglePath(rm, pathPattern) {
			continue
		}
		handleArr, _ := rm["handle"].([]any)
		if len(handleArr) != 1 {
			t.Fatalf("passthrough route handle has %d entries, want 1 (a subroute)", len(handleArr))
		}
		sub, _ := handleArr[0].(map[string]any)
		if sub["handler"] != "subroute" {
			t.Fatalf("passthrough route top handler is %v, want subroute", sub["handler"])
		}
		inner, _ := sub["routes"].([]any)
		chain := make([]string, 0, len(inner))
		for _, ir := range inner {
			irm, _ := ir.(map[string]any)
			ihandle, _ := irm["handle"].([]any)
			for _, h := range ihandle {
				hm, _ := h.(map[string]any)
				name, _ := hm["handler"].(string)
				if name == "subroute" && subrouteIsIPFilter(hm) {
					chain = append(chain, "ip_filter")
					continue
				}
				chain = append(chain, name)
			}
		}
		return chain
	}

	t.Fatalf("no route matched path %q in emitted config:\n%s", pathPattern, raw)
	return nil
}

// routeMatchesSinglePath reports whether the route's match set is exactly
// one matcher carrying pathPattern as its only path.
func routeMatchesSinglePath(route map[string]any, pathPattern string) bool {
	matchArr, _ := route["match"].([]any)
	for _, m := range matchArr {
		mm, _ := m.(map[string]any)
		paths, _ := mm["path"].([]any)
		for _, p := range paths {
			if s, _ := p.(string); s == pathPattern {
				return true
			}
		}
	}
	return false
}

// subrouteIsIPFilter reports whether a subroute handler is the one
// buildIPFilterRoute produces: an inner route with a client_ip matcher
// and an error handler.
func subrouteIsIPFilter(sub map[string]any) bool {
	inner, _ := sub["routes"].([]any)
	for _, ir := range inner {
		irm, _ := ir.(map[string]any)
		matchArr, _ := irm["match"].([]any)
		for _, m := range matchArr {
			mm, _ := m.(map[string]any)
			if _, ok := mm["client_ip"]; ok {
				return true
			}
			if not, ok := mm["not"].([]any); ok {
				for _, n := range not {
					nm, _ := n.(map[string]any)
					if _, ok := nm["client_ip"]; ok {
						return true
					}
				}
			}
		}
	}
	return false
}

func indexOf(xs []string, want string) int {
	for i, x := range xs {
		if x == want {
			return i
		}
	}
	return -1
}
