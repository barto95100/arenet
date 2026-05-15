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

func TestBuildConfigJSON_TestRoute(t *testing.T) {
	routes := []storage.Route{
		{ID: "fixture", Host: "test.local", UpstreamURL: "http://127.0.0.1:9999"},
	}

	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, raw)
	}

	for _, sub := range []string{
		`"listen"`,
		`":8080"`,
		`"host"`,
		`"test.local"`,
		`"reverse_proxy"`,
		`"127.0.0.1:9999"`,
		`"automatic_https"`,
		`"internal"`,
	} {
		if !strings.Contains(string(raw), sub) {
			t.Errorf("config JSON missing %q\n%s", sub, raw)
		}
	}
}

// httpRoutesFromConfig digs into the parsed JSON to extract the arenet_http
// server's route slice — keeps assertions readable in the catch-all test.
func httpRoutesFromConfig(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	server := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["arenet_http"].(map[string]any)
	rawRoutes := server["routes"].([]any)
	routes := make([]map[string]any, len(rawRoutes))
	for i, r := range rawRoutes {
		routes[i] = r.(map[string]any)
	}
	return routes
}

func TestBuildConfigJSON_CatchAllAppended(t *testing.T) {
	routes := []storage.Route{
		{ID: "a", Host: "a.local", UpstreamURL: "http://127.0.0.1:9001"},
		{ID: "b", Host: "b.local", UpstreamURL: "http://127.0.0.1:9002"},
	}

	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	httpRoutes := httpRoutesFromConfig(t, raw)
	if want := len(routes) + 1; len(httpRoutes) != want {
		t.Fatalf("got %d routes, want %d (user routes + catch-all)", len(httpRoutes), want)
	}

	catchAll := httpRoutes[len(httpRoutes)-1]
	if _, hasMatch := catchAll["match"]; hasMatch {
		t.Errorf("catch-all route must have no match block, got: %v", catchAll["match"])
	}

	handlers, ok := catchAll["handle"].([]any)
	if !ok || len(handlers) != 1 {
		t.Fatalf("catch-all handle malformed: %v", catchAll["handle"])
	}
	h := handlers[0].(map[string]any)
	if h["handler"] != "static_response" {
		t.Errorf("catch-all handler = %v, want static_response", h["handler"])
	}
	if status, _ := h["status_code"].(float64); int(status) != 404 {
		t.Errorf("catch-all status_code = %v, want 404", h["status_code"])
	}
	if body, _ := h["body"].(string); body != "Not Found - no route configured for this host" {
		t.Errorf("catch-all body = %q, want fixed sentence", body)
	}

	// User routes (a.local, b.local) must come BEFORE the catch-all so they
	// are still matched first.
	for i := 0; i < len(httpRoutes)-1; i++ {
		if _, ok := httpRoutes[i]["match"]; !ok {
			t.Errorf("route %d is missing a match block — would shadow catch-all", i)
		}
	}
}

func TestBuildConfigJSON_CatchAllOnHTTPSServer(t *testing.T) {
	routes := []storage.Route{
		{ID: "a", Host: "secure.local", UpstreamURL: "http://127.0.0.1:9001", TLSEnabled: true},
	}
	raw, err := buildConfigJSON(routes)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	servers := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	httpsServer, ok := servers["arenet_https"].(map[string]any)
	if !ok {
		t.Fatal("arenet_https server missing despite TLSEnabled route")
	}
	httpsRoutes := httpsServer["routes"].([]any)
	if len(httpsRoutes) != 2 {
		t.Fatalf("got %d routes on HTTPS server, want 2 (user + catch-all)", len(httpsRoutes))
	}
	last := httpsRoutes[len(httpsRoutes)-1].(map[string]any)
	if _, hasMatch := last["match"]; hasMatch {
		t.Errorf("HTTPS catch-all must have no match block")
	}
}

func TestUpstreamDial(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "http://127.0.0.1:9999", want: "127.0.0.1:9999"},
		{in: "http://example.com", want: "example.com:80"},
		{in: "https://example.com", want: "example.com:443"},
		{in: "https://example.com:8443", want: "example.com:8443"},
		{in: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			got, err := upstreamDial(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
