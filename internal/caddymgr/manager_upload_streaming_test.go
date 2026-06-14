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

// Phase 4.5 caddymgr tests — UploadStreamingMode wiring into
// the generated Caddy config:
//   - reverse_proxy.flush_interval = -1 when enabled
//   - arenet_waf.skip_body_inspection = true when enabled
//   - both fields ABSENT when the route opts out

func TestBuildConfigJSON_UploadStreamingMode_EmitsFlushInterval(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-registry",
			Host: "registry.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.50:5000", Weight: 1},
			},
			LBPolicy:            storage.LBPolicyRoundRobin,
			UploadStreamingMode: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "registry.example.com")

	fi, has := rp["flush_interval"]
	if !has {
		t.Fatalf("flush_interval absent on streaming route; want -1\nreverse_proxy=%+v", rp)
	}
	// JSON unmarshal turns the int -1 into float64; check
	// both for forward-compat with a future encoder switch.
	switch v := fi.(type) {
	case float64:
		if v != -1 {
			t.Errorf("flush_interval = %v; want -1", v)
		}
	case int:
		if v != -1 {
			t.Errorf("flush_interval = %v; want -1", v)
		}
	default:
		t.Errorf("flush_interval has unexpected type %T = %v", fi, fi)
	}
}

func TestBuildConfigJSON_UploadStreamingMode_AbsentByDefault(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-api",
			Host: "api.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.20:8080", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
			// UploadStreamingMode defaults false
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "api.example.com")

	if _, has := rp["flush_interval"]; has {
		t.Errorf("flush_interval emitted on non-streaming route; want absent\nreverse_proxy=%+v", rp)
	}
}

// extractArenetWAF returns the arenet_waf handler map for the
// named host from a built Caddy config, or nil if no WAF
// handler is present (route has WAFMode=off).
func extractArenetWAF(t *testing.T, raw []byte, host string) map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	for _, srv := range servers {
		srvMap := srv.(map[string]any)
		routesRaw, _ := srvMap["routes"].([]any)
		for _, rt := range routesRaw {
			rtMap := rt.(map[string]any)
			matchesRaw, _ := rtMap["match"].([]any)
			for _, m := range matchesRaw {
				mMap := m.(map[string]any)
				hostsRaw, _ := mMap["host"].([]any)
				for _, h := range hostsRaw {
					if h.(string) != host {
						continue
					}
					handles := rtMap["handle"].([]any)
					for _, hh := range handles {
						hm := hh.(map[string]any)
						if hm["handler"] != "subroute" {
							continue
						}
						innerRoutes := hm["routes"].([]any)
						for _, ir := range innerRoutes {
							irMap := ir.(map[string]any)
							innerHandles := irMap["handle"].([]any)
							for _, ih := range innerHandles {
								ihm := ih.(map[string]any)
								if ihm["handler"] == "arenet_waf" {
									return ihm
								}
							}
						}
					}
				}
			}
		}
	}
	return nil
}

func TestBuildConfigJSON_UploadStreamingMode_WAFGetsSkipBodyInspection(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-registry-waf",
			Host: "registry.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.50:5000", Weight: 1},
			},
			LBPolicy:            storage.LBPolicyRoundRobin,
			WAFMode:             "detect",
			UploadStreamingMode: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	waf := extractArenetWAF(t, raw, "registry.example.com")
	if waf == nil {
		t.Fatalf("arenet_waf handler absent; want present for WAFMode=detect")
	}
	if got, _ := waf["skip_body_inspection"].(bool); !got {
		t.Errorf("arenet_waf.skip_body_inspection = %v; want true\nwaf=%+v", waf["skip_body_inspection"], waf)
	}
}

func TestBuildConfigJSON_WAFOn_NoStreaming_OmitsSkipBodyInspection(t *testing.T) {
	routes := []storage.Route{
		{
			ID:   "r-api-waf",
			Host: "api.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.20:8080", Weight: 1},
			},
			LBPolicy: storage.LBPolicyRoundRobin,
			WAFMode:  "detect",
			// UploadStreamingMode defaults false
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	waf := extractArenetWAF(t, raw, "api.example.com")
	if waf == nil {
		t.Fatalf("arenet_waf handler absent; want present for WAFMode=detect")
	}
	if _, has := waf["skip_body_inspection"]; has {
		t.Errorf("arenet_waf.skip_body_inspection emitted on non-streaming route; want absent\nwaf=%+v", waf)
	}
}

func TestBuildConfigJSON_UploadStreamingMode_WAFOff_NoWAFHandler(t *testing.T) {
	// Coverage of the combination {WAFMode=off, UploadStreamingMode=true}:
	// flush_interval still emitted on reverse_proxy, no WAF
	// handler is built (WAFMode=off short-circuits in
	// buildWAFHandler), so there's nothing to receive
	// skip_body_inspection. The toggle silently degrades
	// to "Caddy streaming only" — operator gets the Caddy
	// half of the protection without surprise.
	routes := []storage.Route{
		{
			ID:   "r-files",
			Host: "files.example.com",
			Upstreams: []storage.Upstream{
				{URL: "http://10.0.0.30:8081", Weight: 1},
			},
			LBPolicy:            storage.LBPolicyRoundRobin,
			WAFMode:             "off",
			UploadStreamingMode: true,
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	rp := extractRouteReverseProxy(t, raw, "files.example.com")
	if _, has := rp["flush_interval"]; !has {
		t.Errorf("flush_interval absent on WAF=off + streaming route; want -1")
	}
	if waf := extractArenetWAF(t, raw, "files.example.com"); waf != nil {
		t.Errorf("WAF handler emitted for WAFMode=off; want absent\nwaf=%+v", waf)
	}
}
