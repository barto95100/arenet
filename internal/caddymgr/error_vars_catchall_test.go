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

// #367 follow-up: the catch-all route serves a branded error-page body
// via an INLINE static_response that does NOT traverse the server
// errors.routes chain. v2.87.0 prefixed only errors.routes, so
// {arenet.request.*} rendered LITERALLY on any catch-all 404 (host
// matched a server but no specific route). These guards assert the
// prefix is present in the FULL emitted config (the gap no unit-level
// emission test caught) and that the catch-all body actually
// substitutes once the handler has run.

package caddymgr

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/errorvars"
	"github.com/barto95100/arenet/internal/storage"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// findCatchAllHandlers walks the full emitted config and returns the
// handler-name sequence of the matcherless (catch-all) route for the
// named server, or nil if the server or its catch-all is absent.
func findCatchAllHandlers(t *testing.T, cfg []byte, server string) []string {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	servers, _ := parsed["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
	srv, ok := servers[server].(map[string]any)
	if !ok {
		return nil
	}
	routes, _ := srv["routes"].([]any)
	for _, r := range routes {
		rm := r.(map[string]any)
		// The catch-all has NO match block (matches everything).
		if _, hasMatch := rm["match"]; hasMatch {
			continue
		}
		handle, _ := rm["handle"].([]any)
		// Must terminate in a static_response (the 404 body) — this is
		// the catch-all, not some other matcherless middleware route.
		var names []string
		var isCatchAll bool
		for _, h := range handle {
			hm := h.(map[string]any)
			name, _ := hm["handler"].(string)
			names = append(names, name)
			if name == "static_response" {
				isCatchAll = true
			}
		}
		if isCatchAll {
			return names
		}
	}
	return nil
}

// G_catchall_has_error_vars_prefix: in the FULL emitted config, the
// catch-all route of BOTH the HTTP and HTTPS servers runs
// arenet_error_vars immediately before static_response. This is the
// end-to-end structural guard the v2.87.0 unit tests lacked.
func TestErrorVarsCatchall_G_catchall_has_error_vars_prefix(t *testing.T) {
	routes := []storage.Route{
		{
			ID:         "https-route",
			Host:       "secure.example.com",
			TLSEnabled: true,
			Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:   storage.LBPolicyRoundRobin,
			WAFMode:    "off",
		},
		{
			ID:        "http-route",
			Host:      "plain.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
		},
	}
	cfg, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	for _, server := range []string{"arenet_http", "arenet_https"} {
		names := findCatchAllHandlers(t, cfg, server)
		if names == nil {
			t.Errorf("%s: no catch-all route found in emitted config", server)
			continue
		}
		// static_response must be present, and arenet_error_vars must be
		// the handler immediately before it.
		srIdx := -1
		for i, n := range names {
			if n == "static_response" {
				srIdx = i
			}
		}
		if srIdx <= 0 {
			t.Errorf("%s catch-all handlers = %v; static_response must not be first (needs arenet_error_vars before it)", server, names)
			continue
		}
		if names[srIdx-1] != errorvars.HandlerName {
			t.Errorf("%s catch-all handlers = %v; want %q immediately before static_response", server, names, errorvars.HandlerName)
		}
	}
}

// G_catchall_body_substitutes_arenet_request: a catch-all 404 whose
// template body uses {arenet.request.host} resolves to the HTML-escaped
// value once arenet_error_vars has populated the Replacer — i.e. the
// body prod serves no longer shows a literal token. Ties the emitted
// catch-all body to the runtime handler, close to the real 404 render.
func TestErrorVarsCatchall_G_catchall_body_substitutes_arenet_request(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {
			ID:               "t1",
			IsCatchallDefault: true,
			Pages:            map[int]string{404: `<p>host={arenet.request.host}</p>`},
		},
	}
	route := catchAllRoute(templates, false)
	body, _ := staticResponseHandler(route)["body"].(string)
	if !strings.Contains(body, "{arenet.request.host}") {
		t.Fatalf("precondition: catch-all body should carry the token before substitution; got %q", body)
	}

	// Populate the Replacer exactly as prod does: run the handler on a
	// request whose Host carries an XSS attempt.
	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	req.Host = `evil"><script>`
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	if err := (&errorvars.Handler{}).ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("errorvars ServeHTTP: %v", err)
	}

	rendered := repl.ReplaceKnown(body, "")
	if strings.Contains(rendered, "{arenet.request.host}") {
		t.Errorf("token not substituted in catch-all body: %q", rendered)
	}
	if want := "host=" + html.EscapeString(`evil"><script>`); !strings.Contains(rendered, want) {
		t.Errorf("rendered body missing escaped host %q; got %q", want, rendered)
	}
	if strings.Contains(rendered, "<script>") {
		t.Errorf("catch-all body leaked a raw <script> tag: %q", rendered)
	}
}
