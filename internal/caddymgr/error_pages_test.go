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

// Step R — error-pages emit unit tests.
//
// Two layers : (a) pure resolution-order checks on resolveErrorPage,
// (b) caddymgr-side struct emission via buildErrorRoutesForRoute +
// buildErrorRoutesForServer + a full caddy.Validate integration
// check on a route that uses the feature end-to-end.

// --- Resolution order --------------------------------------------------------

func TestResolveErrorPage_OverrideWinsOverTemplate(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{
		ErrorPageTemplateID: "t1",
		ErrorPageOverrides:  map[int]string{403: "<h1>override-403</h1>"},
	}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>override-403</h1>" {
		t.Errorf("override layer should win ; got %q", got)
	}
}

func TestResolveErrorPage_TemplateWinsOverDefault(t *testing.T) {
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{ErrorPageTemplateID: "t1"}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>template-403</h1>" {
		t.Errorf("template layer should win over default ; got %q", got)
	}
}

func TestResolveErrorPage_DefaultUsedWhenNothingConfigured(t *testing.T) {
	route := storage.Route{}
	got := resolveErrorPage(route, 403, nil)
	if !strings.Contains(got, "Forbidden") {
		t.Errorf("expected built-in default for 403 ; got %q", got)
	}
}

func TestResolveErrorPage_DanglingTemplateRefFallsBackToDefault(t *testing.T) {
	route := storage.Route{ErrorPageTemplateID: "deleted-template"}
	// Empty templates map → ref dangles → should return default.
	got := resolveErrorPage(route, 404, map[string]storage.ErrorPageTemplate{})
	if !strings.Contains(got, "Not Found") {
		t.Errorf("dangling ref should fall back to default ; got %q", got)
	}
}

func TestResolveErrorPage_EmptyOverrideFallsThroughToTemplate(t *testing.T) {
	// Operator-visible UX : leaving an override empty in the UI
	// means "disable this code's override" — should resolve to
	// the template, NOT to "no body".
	templates := map[string]storage.ErrorPageTemplate{
		"t1": {ID: "t1", Pages: map[int]string{403: "<h1>template-403</h1>"}},
	}
	route := storage.Route{
		ErrorPageTemplateID: "t1",
		ErrorPageOverrides:  map[int]string{403: ""},
	}
	got := resolveErrorPage(route, 403, templates)
	if got != "<h1>template-403</h1>" {
		t.Errorf("empty override should fall through to template ; got %q", got)
	}
}

func TestResolveErrorPage_UnsupportedCodeReturnsEmpty(t *testing.T) {
	route := storage.Route{}
	got := resolveErrorPage(route, 418, nil)
	if got != "" {
		t.Errorf("unsupported code should return empty ; got %q", got)
	}
}

// --- Per-route route emission ------------------------------------------------

func TestBuildErrorRoutesForRoute_EmitsOnePerSupportedCode(t *testing.T) {
	route := storage.Route{
		ID:        "r1",
		Host:      "example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	// Built-in default covers all 8 codes → 8 routes emitted.
	if len(got) != len(storage.SupportedErrorStatusCodes) {
		t.Errorf("expected %d routes ; got %d", len(storage.SupportedErrorStatusCodes), len(got))
	}
	// Each route carries the expression matcher for its code.
	for i, r := range got {
		code := storage.SupportedErrorStatusCodes[i]
		if len(r.Match) != 1 {
			t.Errorf("route[%d] expected 1 matcher set ; got %d", i, len(r.Match))
			continue
		}
		wantExpr := "{http.error.status_code} == " + intToStr(code)
		if r.Match[0].Expression != wantExpr {
			t.Errorf("route[%d] expression = %q ; want %q", i, r.Match[0].Expression, wantExpr)
		}
		// Host is scoped to the route's host (defence-in-depth).
		if len(r.Match[0].Host) != 1 || r.Match[0].Host[0] != "example.com" {
			t.Errorf("route[%d] host scope = %v ; want [example.com]", i, r.Match[0].Host)
		}
		// Handler is static_response.
		if len(r.Handle) != 1 || r.Handle[0]["handler"] != "static_response" {
			t.Errorf("route[%d] handler = %v ; want static_response", i, r.Handle)
		}
	}
}

func TestBuildErrorRoutesForRoute_NoHostsReturnsNil(t *testing.T) {
	route := storage.Route{} // no Host, no Aliases
	got := buildErrorRoutesForRoute(route, nil, nil)
	if got != nil {
		t.Errorf("expected nil for hostless route ; got %d entries", len(got))
	}
}

func TestBuildErrorRoutesForRoute_HostMatcherIncludesAliases(t *testing.T) {
	route := storage.Route{
		Host:      "primary.example.com",
		Aliases:   []string{"alias1.example.com", "alias2.example.com"},
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("expected non-empty routes")
	}
	hosts := got[0].Match[0].Host
	if len(hosts) != 3 || hosts[0] != "primary.example.com" {
		t.Errorf("host matcher = %v ; want [primary, alias1, alias2]", hosts)
	}
}

// --- Sanitization -----------------------------------------------------------

func TestErrorPageSanitizer_StripsScriptTag(t *testing.T) {
	// XSS payload should never reach the emitted body, even from
	// an admin who typed it deliberately. UGCPolicy bans script.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			403: `<h1>403</h1><script>alert(1)</script>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	if len(got) == 0 {
		t.Fatal("expected at least one route")
	}
	// Find the 403 route.
	var body403 string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 403 {
			body403 = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if strings.Contains(body403, "<script>") {
		t.Errorf("sanitizer did not strip <script> ; got %q", body403)
	}
	if !strings.Contains(body403, "<h1>403</h1>") {
		t.Errorf("sanitizer stripped legitimate content ; got %q", body403)
	}
}

func TestErrorPageSanitizer_StripsEventHandlers(t *testing.T) {
	// Inline event handlers are a classic XSS vector. Bluemonday
	// UGCPolicy bans them all.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			404: `<a href="/" onclick="alert(1)">home</a>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 404 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if strings.Contains(body, "onclick") {
		t.Errorf("sanitizer did not strip onclick ; got %q", body)
	}
}

func TestErrorPageSanitizer_PrependsDoctype(t *testing.T) {
	// bluemonday strips the <!doctype> declaration by design
	// (sanitize.go:241). postSanitize re-prepends it so
	// browsers render in standards mode. Verified empirically
	// at Step R smoke : without the prepend the operator's
	// CSS rendered in quirks mode and looked wrong.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			502: `<!doctype html><html><head><title>x</title></head><body>x</body></html>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 502 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if !strings.HasPrefix(body, "<!doctype html>") {
		t.Errorf("doctype prefix missing ; got %q", body[:min(80, len(body))])
	}
}

func TestPostSanitize_FragmentNoDoctype(t *testing.T) {
	// Operator wrote just <h1>...</h1> — not a full document.
	// postSanitize must NOT prepend <!doctype html> because
	// the browser would interpret it as a separate document.
	got := postSanitize("<h1>just a fragment</h1>")
	if strings.HasPrefix(got, "<!doctype") {
		t.Errorf("fragment got unwanted doctype prefix: %q", got)
	}
}

func TestErrorPageSanitizer_PreservesCaddyPlaceholders(t *testing.T) {
	// Critical : the sanitizer must not destroy Caddy's
	// {placeholder} syntax — the curly braces are not HTML
	// special chars but a regex-style sanitizer could mangle
	// them. Bluemonday operates on the HTML tree, not on text.
	route := storage.Route{
		Host:      "x.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		ErrorPageOverrides: map[int]string{
			500: `<p>id: {http.request.uuid}</p>`,
		},
	}
	got := buildErrorRoutesForRoute(route, nil, nil)
	var body string
	for i, code := range storage.SupportedErrorStatusCodes {
		if code == 500 {
			body = got[i].Handle[0]["body"].(string)
			break
		}
	}
	if !strings.Contains(body, "{http.request.uuid}") {
		t.Errorf("sanitizer destroyed Caddy placeholder ; got %q", body)
	}
}

// --- Per-server emission split ----------------------------------------------

func TestBuildErrorRoutesForServer_SplitsByTLS(t *testing.T) {
	routes := []storage.Route{
		{Host: "http.example.com", Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}}, TLSEnabled: false},
		{Host: "https.example.com", Upstreams: []storage.Upstream{{URL: "http://x", Weight: 1}}, TLSEnabled: true},
	}
	httpRoutes := buildErrorRoutesForServer(routes, nil, false, nil)
	httpsRoutes := buildErrorRoutesForServer(routes, nil, true, nil)
	if len(httpRoutes) == 0 || len(httpsRoutes) == 0 {
		t.Fatalf("expected both servers populated ; got http=%d https=%d", len(httpRoutes), len(httpsRoutes))
	}
	// Each server should only carry its TLS-scope's hosts.
	for _, r := range httpRoutes {
		if r.Match[0].Host[0] != "http.example.com" {
			t.Errorf("HTTP server got non-HTTP host: %v", r.Match[0].Host)
		}
	}
	for _, r := range httpsRoutes {
		if r.Match[0].Host[0] != "https.example.com" {
			t.Errorf("HTTPS server got non-HTTPS host: %v", r.Match[0].Host)
		}
	}
}

// --- Shape pin (no caddy.Validate spawn — see precedent in
//     manager_https_upstream_test.go:210 explaining why a second
//     caddy.Validate test in this package poisons
//     TestSyncRegistry_NotCalledOnReloadFailure via leftover
//     admin-endpoint state. Step R folds its caddy.Validate
//     coverage into the existing TestBuildConfigJSON_LoadsCleanly
//     fixture via the extra `r-errpages` route declared there ;
//     this file pins the JSON SHAPE separately without spinning
//     up a real Caddy.) ------------------------------------------

// TestBuildConfigJSON_EmitsErrorsBlock_WhenAnyRouteOptsIn pins the
// presence + shape of the apps.http.servers.<*>.errors block in
// the emitted JSON when at least one route declares an override or
// template ref. Uses a raw map decode so a future struct refactor
// can't accidentally rename the field without flagging.
func TestBuildConfigJSON_EmitsErrorsBlock_WhenAnyRouteOptsIn(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r-override",
			Host:      "override.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			ErrorPageOverrides: map[int]string{
				404: "<h1>404 — override</h1>",
			},
		},
	}
	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	httpApp := apps["http"].(map[string]any)
	servers := httpApp["servers"].(map[string]any)
	srv := servers["arenet_http"].(map[string]any)
	errors, has := srv["errors"]
	if !has {
		t.Fatal("apps.http.servers.arenet_http.errors absent ; expected when a route declares overrides")
	}
	errorsMap := errors.(map[string]any)
	errorRoutes, has := errorsMap["routes"].([]any)
	if !has {
		t.Fatal("errors.routes absent or wrong type")
	}
	// 8 codes default + override merges → still 8 routes (the
	// override REPLACES the default for code 404, doesn't ADD).
	if got := len(errorRoutes); got != len(storage.SupportedErrorStatusCodes) {
		t.Errorf("errors.routes len = %d ; want %d", got, len(storage.SupportedErrorStatusCodes))
	}
	// Spot-check first route shape : match.expression +
	// handler=static_response.
	r0 := errorRoutes[0].(map[string]any)
	match := r0["match"].([]any)
	m0 := match[0].(map[string]any)
	expr, has := m0["expression"]
	if !has {
		t.Error("first error route lacks `expression` matcher")
	}
	if exprStr, ok := expr.(string); !ok || !strings.Contains(exprStr, "{http.error.status_code}") {
		t.Errorf("expression matcher = %v ; want {http.error.status_code} == <code>", expr)
	}
	handle := r0["handle"].([]any)
	h0 := handle[0].(map[string]any)
	if h0["handler"] != "static_response" {
		t.Errorf("handler = %v ; want static_response", h0["handler"])
	}
}

// TestBuildConfigJSON_NoErrorBlock_WhenNobodyOptsIn pins the "emit
// nothing extra for pre-R operators" invariant : if no route has
// any template ref / override, the apps.http.servers.<*>.errors
// field is omitted entirely. Pre-R operators get byte-identical
// JSON, no behaviour change, no Caddy reload diff.
func TestBuildConfigJSON_NoErrorBlock_WhenNobodyOptsIn(t *testing.T) {
	routes := []storage.Route{
		{
			ID:        "r1",
			Host:      "noerror.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
		},
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// Decode as map[string]any to inspect the apps.http.servers
	// shape without struct-tag rigidity. The "errors" key must
	// be absent everywhere.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	apps := generic["apps"].(map[string]any)
	http := apps["http"].(map[string]any)
	servers := http["servers"].(map[string]any)
	for name, srv := range servers {
		srvMap := srv.(map[string]any)
		if _, has := srvMap["errors"]; has {
			t.Errorf("server %q has 'errors' field but no route opted in (byte-identical-for-pre-R invariant broken)", name)
		}
	}
}

// intToStr is a tiny helper kept local to avoid pulling strconv
// into the test file's import for a single Sprintf-equivalent.
func intToStr(i int) string {
	switch i {
	case 401:
		return "401"
	case 403:
		return "403"
	case 404:
		return "404"
	case 429:
		return "429"
	case 500:
		return "500"
	case 502:
		return "502"
	case 503:
		return "503"
	case 504:
		return "504"
	}
	return "?"
}
