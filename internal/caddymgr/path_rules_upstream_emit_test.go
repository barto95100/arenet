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
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// emitPathSubrouteJSON emits the subroute for a route with the given path
// rules + a route proxy sentinel ("route-pool:80"), wiring a pathProxy
// closure that mirrors the manager.go call site: a rule with no upstream
// pool inherits the sentinel route proxy, a rule with an own pool gets its
// own reverse_proxy via buildReverseProxyHandler (sharing a sentinel
// handle_response). Returns the JSON string for substring assertions.
func emitPathSubrouteJSON(t *testing.T, rules []storage.PathRule) string {
	t.Helper()
	routeProxy := map[string]any{"handler": "reverse_proxy", "upstreams": []map[string]any{{"dial": "route-pool:80"}}}
	sharedHandleResponse := []map[string]any{{"handler": "copy_response"}}
	pathProxy := func(pr storage.PathRule) (map[string]any, error) {
		if len(pr.Upstreams) == 0 {
			return routeProxy, nil
		}
		return buildReverseProxyHandler(proxyPoolParams{
			Upstreams:          pr.Upstreams,
			LBPolicy:           pr.LBPolicy,
			HealthCheck:        pr.HealthCheck,
			UsesHTTPS:          poolUsesHTTPS(pr.Upstreams),
			InsecureSkipVerify: false,
		}, sharedHandleResponse, false)
	}
	sub, err := buildPathRulesSubroute(rules, routeProxy, func(c storage.BasicAuthRouteConfig) map[string]any {
		return map[string]any{"handler": "authentication"}
	}, pathProxy)
	if err != nil {
		t.Fatalf("buildPathRulesSubroute: %v", err)
	}
	b, err := json.Marshal(sub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestPathRulesSubroute_RuleWithOwnUpstream(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "api-a:8080") {
		t.Fatalf("path rule should proxy to its own upstream; got: %s", js)
	}
}

func TestPathRulesSubroute_RuleWithoutUpstreamUsesRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/docs",
		BasicAuth:  &storage.BasicAuthRouteConfig{Username: "u", PasswordHash: "$h"},
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("protection-only rule must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_CatchAllKeepsRoutePool(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/v1",
		Upstreams:  []storage.Upstream{{URL: "http://api-a:8080", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	// Both the path pool AND the route pool (catch-all) must appear.
	if !strings.Contains(js, "route-pool:80") {
		t.Fatalf("catch-all must keep the route pool; got: %s", js)
	}
}

func TestPathRulesSubroute_HTTPSPathPoolEmitsTransport(t *testing.T) {
	rules := []storage.PathRule{{
		PathPrefix: "/legacy",
		Upstreams:  []storage.Upstream{{URL: "https://old:8443", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "\"tls\"") {
		t.Fatalf("https path pool must emit a transport.tls block; got: %s", js)
	}
}

func TestPathRulesSubroute_IPBlockBeforeOwnUpstream(t *testing.T) {
	// fail-closed IP filter still gates BEFORE the path's own proxy.
	rules := []storage.PathRule{{
		PathPrefix: "/metrics",
		IPFilter:   &storage.IPFilter{Mode: storage.IPFilterModeAllow, CIDRs: []string{"10.0.0.0/8"}},
		Upstreams:  []storage.Upstream{{URL: "http://m:9090", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
	}}
	js := emitPathSubrouteJSON(t, rules)
	if !strings.Contains(js, "static_response") || !strings.Contains(js, "m:9090") {
		t.Fatalf("expected both the IP 403 block and the own upstream; got: %s", js)
	}
}
