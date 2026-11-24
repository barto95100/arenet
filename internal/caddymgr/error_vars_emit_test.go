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

// Emission guards for #367 (arenet_error_vars handler). These assert
// what the generated Caddy config carries, which decides what the
// browser ultimately receives through static_response.

package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/errorvars"
	"github.com/barto95100/arenet/internal/storage"
)

// staticResponseHandler returns the static_response handler map in a
// route's Handle chain, or nil if absent.
func staticResponseHandler(r httpRoute) map[string]any {
	for _, h := range r.Handle {
		if h["handler"] == "static_response" {
			return h
		}
	}
	return nil
}

// G_replacer_injection_order: every error route emits
// arenet_error_vars as Handle[0], BEFORE static_response at Handle[1].
// static_response's ReplaceKnown only sees {arenet.request.*} if the
// vars handler ran first — order is a correctness precondition, not
// cosmetics.
func TestErrorVars_G_replacer_injection_order(t *testing.T) {
	route := storage.Route{
		ID:        "r1",
		Host:      "example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("no error routes emitted")
	}
	for i, r := range got {
		if len(r.Handle) != 2 {
			t.Errorf("route[%d]: expected 2 handlers [arenet_error_vars, static_response]; got %d (%v)", i, len(r.Handle), r.Handle)
			continue
		}
		if r.Handle[0]["handler"] != errorvars.HandlerName {
			t.Errorf("route[%d]: Handle[0].handler = %v; want %q (must run BEFORE static_response)", i, r.Handle[0]["handler"], errorvars.HandlerName)
		}
		if r.Handle[1]["handler"] != "static_response" {
			t.Errorf("route[%d]: Handle[1].handler = %v; want static_response", i, r.Handle[1]["handler"])
		}
	}
}

// G_http_request_still_defanged: F42 is untouched. A stored body with
// a raw {http.request.host} reflector is still defanged to the
// &#123; entity in the emitted static_response body — the new vars
// handler adds {arenet.*} only and must not weaken the F42 pass.
func TestErrorVars_G_http_request_still_defanged(t *testing.T) {
	route := storage.Route{
		ID:                 "r1",
		Host:               "example.com",
		Upstreams:          []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{403: `<p>host={http.request.host}</p>`},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)

	var found bool
	for _, r := range got {
		if r.Match[0].Expression != "{http.error.status_code} == 403" {
			continue
		}
		found = true
		sr := staticResponseHandler(r)
		if sr == nil {
			t.Fatalf("403 route has no static_response handler: %v", r.Handle)
		}
		body, _ := sr["body"].(string)
		if strings.Contains(body, "{http.request.host}") {
			t.Errorf("F42 regression: raw {http.request.host} survived in emitted body: %q", body)
		}
		if !strings.Contains(body, "&#123;http.request.host}") {
			t.Errorf("expected defanged &#123;http.request.host} in emitted body; got %q", body)
		}
	}
	if !found {
		t.Fatal("no 403 error route emitted")
	}
}

// G_no_template_funcs_exposed: the error routes NEVER use the Caddy
// templates handler, and a Go-template-looking body is emitted
// VERBATIM (never executed). This is the structural proof that
// Option A did not introduce a template engine over operator
// content — the whole reason the Caddy templates handler was
// rejected (#367 security finding). A future refactor that swaps in
// "templates" would make this fail.
func TestErrorVars_G_no_template_funcs_exposed(t *testing.T) {
	const danger = `<p>{{env "ARENET_CROWDSEC_API_KEY"}}{{readFile "/etc/passwd"}}</p>`
	route := storage.Route{
		ID:                 "r1",
		Host:               "example.com",
		Upstreams:          []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{403: danger},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)

	for i, r := range got {
		for _, h := range r.Handle {
			if h["handler"] == "templates" {
				t.Fatalf("route[%d] uses the Caddy templates handler — forbidden (LFI/SSRF/secret-exfil surface)", i)
			}
		}
	}
	// The Go-template tokens must survive literally in the body (no
	// engine executes them). They render as inert text — the '{'
	// is not in any dangerous Caddy placeholder namespace, so F42
	// leaves it, and nothing executes {{...}}.
	var found bool
	for _, r := range got {
		if r.Match[0].Expression != "{http.error.status_code} == 403" {
			continue
		}
		found = true
		body, _ := staticResponseHandler(r)["body"].(string)
		for _, tok := range []string{`{{env`, `{{readFile`} {
			if !strings.Contains(body, tok) {
				t.Errorf("Go-template token %q was not emitted verbatim (executed or stripped?): %q", tok, body)
			}
		}
	}
	if !found {
		t.Fatal("no 403 error route emitted")
	}
}
