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

package errorvars

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// serveWithReplacer runs the handler against a request carrying a
// fresh Replacer in context, then returns that Replacer so a test
// can resolve what static_response WOULD substitute at serve time.
// Asserting on repl.ReplaceKnown is asserting on what the browser
// receives (static_response calls the same ReplaceKnown on the
// body) — §guard: assert the output, not internal state.
func serveWithReplacer(t *testing.T, host, path string) *caddy.Replacer {
	t.Helper()
	repl := caddy.NewReplacer()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Host = host
	req.URL.Path = path
	req = req.WithContext(context.WithValue(req.Context(), caddy.ReplacerCtxKey, repl))

	var called bool
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	})
	h := &Handler{}
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !called {
		t.Fatal("handler did not call next")
	}
	return repl
}

// G_arenet_request_host_escaped: a host carrying HTML metacharacters
// resolves to its HTML-escaped form, never the raw reflector.
func TestArenetErrorVars_G_arenet_request_host_escaped(t *testing.T) {
	const rawHost = `a"><script>alert(1)</script>`
	repl := serveWithReplacer(t, rawHost, "/")

	got := repl.ReplaceKnown("{"+PlaceholderHost+"}", "")
	if want := html.EscapeString(rawHost); got != want {
		t.Errorf("{%s} = %q, want %q", PlaceholderHost, got, want)
	}
	if strings.Contains(got, "<script>") {
		t.Errorf("{%s} leaked a raw <script> tag: %q", PlaceholderHost, got)
	}
}

// G_arenet_request_path_escaped: a path carrying < > " ' & resolves
// HTML-escaped.
func TestArenetErrorVars_G_arenet_request_path_escaped(t *testing.T) {
	const rawPath = `/x"><img src=x onerror=alert(1)>&'`
	repl := serveWithReplacer(t, "example.test", rawPath)

	got := repl.ReplaceKnown("{"+PlaceholderPath+"}", "")
	if want := html.EscapeString(rawPath); got != want {
		t.Errorf("{%s} = %q, want %q", PlaceholderPath, got, want)
	}
	// The tag opener must be neutralised ('<' → '&lt;'); the inert
	// text "onerror=" surviving is fine once "<img" can no longer
	// start a tag.
	if strings.Contains(got, "<img") {
		t.Errorf("{%s} leaked a raw <img tag: %q", PlaceholderPath, got)
	}
}

// G_arenet_request_path_unicode: a UTF-8 path with no HTML
// metacharacters is preserved byte-for-byte (IDN / non-ASCII paths
// must render correctly — html.EscapeString leaves UTF-8 intact).
func TestArenetErrorVars_G_arenet_request_path_unicode(t *testing.T) {
	const rawPath = "/café/€/日本/Ωμέγα"
	repl := serveWithReplacer(t, "xn--caf-dma.example", rawPath)

	got := repl.ReplaceKnown("{"+PlaceholderPath+"}", "")
	if got != rawPath {
		t.Errorf("{%s} = %q, want %q (UTF-8 must survive)", PlaceholderPath, got, rawPath)
	}
}

// G_arenet_vars_set_on_replacer: both keys are present on the
// Replacer after ServeHTTP (the couple handler→consumer, not just
// slice order — a refactor that stops setting the keys must fail
// here even if the emission order is untouched).
func TestArenetErrorVars_G_arenet_vars_set_on_replacer(t *testing.T) {
	repl := serveWithReplacer(t, "host.example", "/p")

	// ReplaceKnown leaves an UNKNOWN placeholder as its literal token
	// ("{arenet.request.host}"), so a key the handler set must NOT
	// come back as that literal token.
	for _, key := range []string{PlaceholderHost, PlaceholderPath} {
		literal := "{" + key + "}"
		if got := repl.ReplaceKnown(literal, ""); got == literal {
			t.Errorf("{%s} is not set on the Replacer after ServeHTTP (resolved to its literal token)", key)
		}
	}
	if got := repl.ReplaceKnown("{"+PlaceholderHost+"}", ""); got != "host.example" {
		t.Errorf("{%s} = %q, want host.example", PlaceholderHost, got)
	}
	if got := repl.ReplaceKnown("{"+PlaceholderPath+"}", ""); got != "/p" {
		t.Errorf("{%s} = %q, want /p", PlaceholderPath, got)
	}
}
