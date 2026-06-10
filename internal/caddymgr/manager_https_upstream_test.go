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

	"github.com/barto95100/arenet/internal/storage"
)

// #R-PROXMOX-HTTPS-LOOP — buildConfigJSON emits
// transport.tls when the upstream pool uses https://.
//
// Pre-fix: a route with upstreams=[https://192.168.1.60:8006]
// produced {"dial":"192.168.1.60:8006"} with NO transport
// block. Caddy spoke plain HTTP toward the upstream → the
// HTTPS-only Proxmox port returned 301 → Caddy faithfully
// re-proxied → infinite redirect loop.
//
// Post-fix: the same route emits transport.tls (verify cert
// by default; skip verify when InsecureSkipVerify=true).
//
// These tests dig into the emitted JSON to assert the
// transport block shape rather than substring-match the raw
// bytes — same approach as httpRoutesFromConfig used by the
// existing manager tests.

// extractRouteReverseProxy returns the reverse_proxy handler
// map for the named host from a built Caddy config.
func extractRouteReverseProxy(t *testing.T, raw []byte, host string) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, srv := range servers {
		srvMap := srv.(map[string]any)
		routesRaw, ok := srvMap["routes"].([]any)
		if !ok {
			continue
		}
		for _, rt := range routesRaw {
			rtMap := rt.(map[string]any)
			matchesRaw, ok := rtMap["match"].([]any)
			if !ok {
				continue
			}
			for _, m := range matchesRaw {
				mMap := m.(map[string]any)
				hostsRaw, ok := mMap["host"].([]any)
				if !ok {
					continue
				}
				for _, h := range hostsRaw {
					if h.(string) != host {
						continue
					}
					// Found the route; dig into its subroute
					// handle to extract the reverse_proxy
					// handler.
					handles := rtMap["handle"].([]any)
					for _, h := range handles {
						hm := h.(map[string]any)
						if hm["handler"].(string) != "subroute" {
							continue
						}
						innerRoutes := hm["routes"].([]any)
						for _, ir := range innerRoutes {
							irMap := ir.(map[string]any)
							innerHandles := irMap["handle"].([]any)
							for _, ih := range innerHandles {
								ihm := ih.(map[string]any)
								if ihm["handler"] == "reverse_proxy" {
									return ihm
								}
							}
						}
					}
				}
			}
		}
	}
	t.Fatalf("no reverse_proxy handler found for host %q", host)
	return nil
}

func TestBuildConfigJSON_HTTPUpstream_NoTransportTLS(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-http",
			Host: "ha.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.10:8123", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "ha.example.com")
	if _, has := rp["transport"]; has {
		t.Errorf("transport block emitted for HTTP-only upstream; want absent\nreverse_proxy=%+v", rp)
	}
}

func TestBuildConfigJSON_HTTPSUpstream_EmitsTransportTLS_StrictVerify(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-https-strict",
			Host: "pve.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://192.168.1.60:8006", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
			// InsecureSkipVerify defaults false → strict
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "pve.example.com")
	transport, has := rp["transport"].(map[string]any)
	if !has {
		t.Fatalf("transport block absent for HTTPS upstream; want present\nreverse_proxy=%+v", rp)
	}
	if transport["protocol"] != "http" {
		t.Errorf("transport.protocol = %v; want \"http\" (HTTP/1.1 over TLS)", transport["protocol"])
	}
	tlsCfg, has := transport["tls"].(map[string]any)
	if !has {
		t.Fatalf("transport.tls block absent; want present (empty {} = strict default)")
	}
	if _, hasSkip := tlsCfg["insecure_skip_verify"]; hasSkip {
		t.Errorf("transport.tls carries insecure_skip_verify on a strict route; want absent\ntls=%+v", tlsCfg)
	}
}

func TestBuildConfigJSON_HTTPSUpstream_InsecureSkipVerifyTrue_EmitsFlag(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-https-insecure",
			Host: "pve.local",
			Upstreams: []storage.Upstream{
				{URL: "https://192.168.1.60:8006", Weight: 1},
			},
			LBPolicy:           storage.LBPolicyRoundRobin,
			InsecureSkipVerify: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "pve.local")
	transport := rp["transport"].(map[string]any)
	tlsCfg := transport["tls"].(map[string]any)
	if v, _ := tlsCfg["insecure_skip_verify"].(bool); !v {
		t.Errorf("transport.tls.insecure_skip_verify = %v; want true\ntls=%+v", tlsCfg["insecure_skip_verify"], tlsCfg)
	}
}

func TestBuildConfigJSON_HTTPSUpstreamPool_AllHTTPS_EmitsTransportTLS(t *testing.T) {
	// A 2-element all-https pool — transport.tls emits once
	// for the whole reverse_proxy handler (per-handler, not
	// per-upstream).
	routes := []storage.Route{
		{
			ID:   "r-pool-https",
			Host: "cluster.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://10.0.0.20:8006", Weight: 1},
				{URL: "https://10.0.0.21:8006", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "cluster.example.com")
	if _, has := rp["transport"]; !has {
		t.Errorf("transport block absent for all-https pool; want present\nreverse_proxy=%+v", rp)
	}
	// Both upstreams emitted (sanity — pool didn't shrink).
	if got := len(rp["upstreams"].([]any)); got != 2 {
		t.Errorf("upstreams length = %d; want 2", got)
	}
}

// NOTE: a caddy.Validate-level test for the HTTPS upstream
// (TestBuildConfigJSON_LoadsCleanly_HTTPSUpstream) was
// drafted and then dropped because caddy.Validate on the
// fixture left global state (Caddy admin endpoint, tls.cache
// maintenance) that poisoned the next test in alphabetical
// order (TestSyncRegistry_NotCalledOnReloadFailure in
// manager_test.go) — t.Cleanup with caddy.Stop wasn't
// sufficient to fully reset.
//
// The shape pins in this file already lock the contract
// well: an unknown `transport`/`tls` sub-key would have been
// caught at Caddy v2's Provision time in
// TestBuildConfigJSON_LoadsCleanly (manager_test.go:981)
// because forward_auth's fixture already emits the SAME
// {"protocol":"http","tls":{...}} block shape (see
// manager.go:2298-2302 forward_auth precedent + the
// caddy.Validate coverage at manager_test.go:2349 +
// 2546+ for forward_auth HTTPS VerifyURL fixtures). The
// route-level emission re-uses that shape verbatim, so the
// risk of an unknown-key surprise on transport.tls for the
// route path is already covered by existing tests.

func TestBuildConfigJSON_HTTPSUpstream_PreservesDialFormat(t *testing.T) {
	// Sanity: the dial host:port should still be just
	// host:port, no scheme leakage. Confirms the scheme-
	// handling adds transport.tls but doesn't pollute the
	// upstream object.
	routes := []storage.Route{
		{
			ID:   "r-dial-shape",
			Host: "pve.example.com",
			Upstreams: []storage.Upstream{
				{URL: "https://192.168.1.60:8006", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "pve.example.com")
	upstreams := rp["upstreams"].([]any)
	upstream := upstreams[0].(map[string]any)
	if dial := upstream["dial"].(string); dial != "192.168.1.60:8006" {
		t.Errorf("dial = %q; want %q (scheme should NOT leak into the dial field)", dial, "192.168.1.60:8006")
	}
}
