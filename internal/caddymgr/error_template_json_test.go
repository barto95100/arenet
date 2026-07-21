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

// NOTE: this file keeps only pure JSON-shape assertions. The real
// caddy.Validate empirical gate that provisions these handle_response
// blocks is the package's single canonical Validate test,
// TestBuildConfigJSON_LoadsCleanly in manager_test.go — its fixture
// route is a reverse_proxy, so it already provisions the emitted blocks.
// The project convention is ONE caddy.Validate call per package (a
// second call leaks Caddy admin-endpoint / metrics global state into
// alphabetically-later tests — see the external_cert_emit_test.go and
// manager_test.go headers), so we deliberately do NOT add a competing
// Validate call here.

import (
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// findReverseProxyHandleResponse digs the reverse_proxy handler's
// handle_response slice out of an emitted config for the given host.
// Mirrors the traversal in error_pages_test.go (route → subroute →
// reverse_proxy).
func findReverseProxyHandleResponse(t *testing.T, raw []byte) []any {
	t.Helper()
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	srv := servers["arenet_http"].(map[string]any)
	for _, r := range srv["routes"].([]any) {
		rMap := r.(map[string]any)
		handlers, ok := rMap["handle"].([]any)
		if !ok {
			continue
		}
		for _, h := range handlers {
			hMap := h.(map[string]any)
			if hMap["handler"] != "subroute" {
				continue
			}
			subroutes, ok := hMap["routes"].([]any)
			if !ok {
				continue
			}
			for _, sr := range subroutes {
				srMap := sr.(map[string]any)
				subHandlers, ok := srMap["handle"].([]any)
				if !ok {
					continue
				}
				for _, sh := range subHandlers {
					shMap := sh.(map[string]any)
					if shMap["handler"] != "reverse_proxy" {
						continue
					}
					if hr, ok := shMap["handle_response"].([]any); ok {
						return hr
					}
				}
			}
		}
	}
	t.Fatal("no reverse_proxy handle_response found")
	return nil
}

func jsonProxyRoute() []storage.Route {
	return []storage.Route{{
		ID:        "r-json",
		Host:      "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9099", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}}
}

// TestBuildConfigJSON_ErrorResponse_PreserveJSON pins the preserve-JSON
// contract: a reverse-proxy route emits TWO ordered handle_response
// blocks —
//
//	[0] outer match = status AND Content-Type application/json* →
//	    copy_response (a JSON error of any path is sent verbatim);
//	[1] outer match = status only, with inner routes in order:
//	    [path /api/* → copy_response] then [→ branded error handler].
//
// The path decision + branding fallback MUST share block [1]'s inner
// routes: a status-only block "wins" for every error and its inner
// routes fall through (routes.go wrapRoute), so the trailing match-less
// error route is the guaranteed branding fallback. Two separate
// status-only outer blocks would drop non-matching responses (spec §6
// E1, caught by the live smoke).
func TestBuildConfigJSON_ErrorResponse_PreserveJSON(t *testing.T) {
	raw, err := buildConfigJSON(jsonProxyRoute(), buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	hr := findReverseProxyHandleResponse(t, raw)
	if len(hr) != 2 {
		t.Fatalf("handle_response len = %d; want 2 (json passthrough, then api-path/branding)", len(hr))
	}

	// Block [0] — application/json* response passthrough with copy_response.
	b := hr[0].(map[string]any)
	bMatch := b["match"].(map[string]any)
	ct := bMatch["headers"].(map[string]any)["Content-Type"].([]any)
	if len(ct) != 1 || ct[0].(string) != "application/json*" {
		t.Errorf("block[0] Content-Type match = %v; want [application/json*]", ct)
	}
	bInner := b["routes"].([]any)[0].(map[string]any)
	if bInner["handle"].([]any)[0].(map[string]any)["handler"] != "copy_response" {
		t.Errorf("block[0] inner handler = %v; want copy_response", bInner["handle"])
	}

	// Block [1] — status-only outer; inner route 0 = /api/* copy_response,
	// inner route 1 = branded error handler (fall-through).
	ac := hr[1].(map[string]any)
	if _, hasHeaders := ac["match"].(map[string]any)["headers"]; hasHeaders {
		t.Errorf("block[1] outer match must be status-only (no headers), got %v", ac["match"])
	}
	acRoutes := ac["routes"].([]any)
	if len(acRoutes) != 2 {
		t.Fatalf("block[1] inner routes = %d; want 2 (api-path copy, then error fallback)", len(acRoutes))
	}
	apiRoute := acRoutes[0].(map[string]any)
	paths := apiRoute["match"].([]any)[0].(map[string]any)["path"].([]any)
	if len(paths) != 1 || paths[0].(string) != "/api/*" {
		t.Errorf("block[1] route0 path = %v; want [/api/*]", paths)
	}
	if apiRoute["handle"].([]any)[0].(map[string]any)["handler"] != "copy_response" {
		t.Errorf("block[1] route0 handler = %v; want copy_response", apiRoute["handle"])
	}
	fallback := acRoutes[1].(map[string]any)
	if _, hasMatch := fallback["match"]; hasMatch {
		t.Errorf("block[1] route1 (branding fallback) must have NO match (catch-all), got %v", fallback["match"])
	}
	errHandler := fallback["handle"].([]any)[0].(map[string]any)
	if errHandler["handler"] != "error" {
		t.Errorf("block[1] route1 handler = %v; want error", errHandler["handler"])
	}
	if errHandler["status_code"] != "{http.reverse_proxy.status_code}" {
		t.Errorf("block[1] error.status_code = %v; want the reverse_proxy placeholder", errHandler["status_code"])
	}

	// Both outer blocks gate on the same status-code list, and 401/407
	// stay OUT of it (the Www-Authenticate / Proxy-Authenticate
	// passthrough contract must survive the restructure).
	for i, blk := range hr {
		codes := blk.(map[string]any)["match"].(map[string]any)["status_code"].([]any)
		set := map[int]bool{}
		for _, sc := range codes {
			set[int(sc.(float64))] = true
		}
		if set[401] || set[407] {
			t.Errorf("block %d status_code contains 401/407, must pass through verbatim: %v", i, codes)
		}
		for _, want := range []int{400, 403, 404, 409, 422, 500, 502, 503} {
			if !set[want] {
				t.Errorf("block %d status_code missing %d: %v", i, want, codes)
			}
		}
	}
}
