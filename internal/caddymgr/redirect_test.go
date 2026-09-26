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
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// v2.44 — the route-level redirect state.
//
// Like maintenance_test.go, this file deliberately does NOT call
// caddy.Validate: the package's single canonical Validate run lives in
// manager_test.go and carries a redirecting route ("r-redirect"), so
// the real-Provision guard is covered there without this file
// poisoning the process-global metrics registry.

func redirectRoute(rc *storage.RedirectConfig) storage.Route {
	return storage.Route{
		ID: "r1", Host: "old.example.com", TLSEnabled: true,
		Upstreams:      []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:       storage.LBPolicyRoundRobin,
		RedirectConfig: rc,
	}
}

func compactConfig(t *testing.T, routes []storage.Route) string {
	t.Helper()
	cfgJSON, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	// buildConfigJSON marshals with indentation; normalise whitespace
	// so the assertions do not depend on the marshaler's style.
	return strings.Join(strings.Fields(string(cfgJSON)), "")
}

func TestBuildConfigJSON_RedirectRoute(t *testing.T) {
	compact := compactConfig(t, []storage.Route{redirectRoute(&storage.RedirectConfig{
		Target:       "https://new.example.com",
		StatusCode:   301,
		PreservePath: true,
	})})

	if !strings.Contains(compact, `"status_code":301`) {
		t.Error("no 301 emitted")
	}
	// The path AND the query must travel: {http.request.uri} carries
	// both, {http.request.uri.path} would silently drop every query
	// parameter — a domain move that loses ?utm_source is a domain
	// move that loses its analytics without telling anyone.
	if !strings.Contains(compact, `"https://new.example.com{http.request.uri}"`) {
		t.Errorf("Location is not the target plus the request URI: %s", compact)
	}
	// A redirecting route does not proxy.
	if strings.Contains(compact, `"reverse_proxy"`) {
		t.Error("a redirecting route must not emit a reverse_proxy handler")
	}
	// It still counts: an operator who moved a domain needs to see
	// how much traffic still reaches the old name before retiring it.
	if !strings.Contains(compact, `"arenet_routemetrics"`) {
		t.Error("the metrics handler must stay in front of the redirect")
	}
}

func TestBuildConfigJSON_RedirectWithoutPreservePath(t *testing.T) {
	compact := compactConfig(t, []storage.Route{redirectRoute(&storage.RedirectConfig{
		Target:     "https://new.example.com/welcome",
		StatusCode: 302,
	})})

	if !strings.Contains(compact, `"status_code":302`) {
		t.Error("no 302 emitted")
	}
	if !strings.Contains(compact, `"https://new.example.com/welcome"`) {
		t.Errorf("Location must be the target verbatim: %s", compact)
	}
	// Scoped to this route's own Location: {http.request.uri} appears
	// elsewhere in any emitted config (error-page branding, the
	// HTTP->HTTPS redirect), so a bare substring search would fail
	// for reasons that have nothing to do with this feature.
	if strings.Contains(compact, `new.example.com/welcome{http.request.uri}`) {
		t.Errorf("preservePath is off: the request URI must not be appended: %s", compact)
	}
}

// A trailing slash on the target must not produce a doubled one once
// the request URI — which always starts with "/" — is appended.
func TestBuildConfigJSON_RedirectTrailingSlashIsNotDoubled(t *testing.T) {
	compact := compactConfig(t, []storage.Route{redirectRoute(&storage.RedirectConfig{
		Target: "https://new.example.com/", PreservePath: true,
	})})

	if strings.Contains(compact, `new.example.com/{http.request.uri}`) {
		t.Errorf("doubled slash in the Location: %s", compact)
	}
	if !strings.Contains(compact, `"https://new.example.com{http.request.uri}"`) {
		t.Errorf("Location: %s", compact)
	}
}

// The zero status code means 301 — a domain move is permanent far more
// often than not, and a silent 0 in the JSON would be invalid config.
func TestBuildConfigJSON_RedirectDefaultsToPermanent(t *testing.T) {
	compact := compactConfig(t, []storage.Route{redirectRoute(&storage.RedirectConfig{
		Target: "https://new.example.com", PreservePath: true,
	})})
	if !strings.Contains(compact, `"status_code":301`) {
		t.Errorf("zero must emit 301: %s", compact)
	}
}

// The standing non-regression rule: a route that uses none of this
// must emit exactly what it emitted before the feature existed.
func TestBuildConfigJSON_NoRedirectIsByteIdentical(t *testing.T) {
	plain := redirectRoute(nil)

	before := compactConfig(t, []storage.Route{plain})

	// Same route, with the field explicitly nil — the shape a
	// pre-v2.44 stored row decodes into.
	withNilField := plain
	withNilField.RedirectConfig = nil
	after := compactConfig(t, []storage.Route{withNilField})

	if before != after {
		t.Fatal("a route without a redirect must emit identical JSON")
	}
	// No Location pointing anywhere: static_response itself appears in
	// every config (error-page branding), so the meaningful assertion
	// is the absence of a redirect target, not of the handler.
	if strings.Contains(before, `"Location"`) {
		t.Error("no redirect configured: no Location header must be emitted")
	}
	if !strings.Contains(before, `"reverse_proxy"`) {
		t.Error("a route without a redirect must still proxy")
	}
}

// --- v2.44 — the path-rule redirect ------------------------------
//
// The second scope. The operator's live case: a mail server whose
// webadmin lives under /admin serves nothing at "/", so visiting the
// bare hostname gives a 404 that looks like Arenet's fault. A
// whole-host redirect cannot fix it — the target is the same host, so
// it would match its own target — which is why exact path matching
// exists at all.

func pathRedirectRoute(pr storage.PathRule) storage.Route {
	return storage.Route{
		ID: "r1", Host: "app.example.com",
		Upstreams: []storage.Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		PathRules: []storage.PathRule{pr},
	}
}

func TestBuildConfigJSON_ExactPathRedirect(t *testing.T) {
	compact := compactConfig(t, []storage.Route{pathRedirectRoute(storage.PathRule{
		PathPrefix: "/",
		MatchExact: true,
		Redirect:   &storage.PathRedirect{Target: "/admin/login"},
	})})

	// The matcher must be the bare path. The prefix form — ["/", "/*"]
	// — would also match /admin/login and loop the browser, which is
	// the whole reason MatchExact exists.
	if !strings.Contains(compact, `"path":["/"]`) {
		t.Errorf("exact match must emit the bare pattern: %s", compact)
	}
	if strings.Contains(compact, `"path":["/","/*"]`) {
		t.Error("exact match must not emit the prefix form")
	}
	if !strings.Contains(compact, `"Location":["/admin/login"]`) {
		t.Errorf("no Location for the path redirect: %s", compact)
	}
	// A path redirect replaces the proxy for THAT path only: the rest
	// of the route must still be proxied.
	if !strings.Contains(compact, `"reverse_proxy"`) {
		t.Error("the route must keep proxying everything else")
	}
	// Zero means 302 here, not 301: a landing path is a convenience an
	// application update can change, and a 301 cached by every
	// visitor's browser is remarkably hard to take back.
	if !strings.Contains(compact, `"status_code":302`) {
		t.Errorf("a path redirect must default to 302: %s", compact)
	}
}

// A prefix rule keeps emitting both patterns — the exact mode is
// opt-in and must not change what every existing rule emits.
func TestBuildConfigJSON_PrefixRuleStillEmitsBothPatterns(t *testing.T) {
	compact := compactConfig(t, []storage.Route{pathRedirectRoute(storage.PathRule{
		PathPrefix: "/docs",
		IPFilter:   &storage.IPFilter{Mode: "allow", CIDRs: []string{"10.0.0.0/8"}},
	})})
	if !strings.Contains(compact, `"path":["/docs","/docs/*"]`) {
		t.Errorf("a prefix rule must be unchanged: %s", compact)
	}
}
