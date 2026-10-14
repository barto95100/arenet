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
	"encoding/json"
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
	// Presence is not order — see TestBuildConfigJSON_RedirectMetricsRunBeforeStaticResponse.
}

// TestBuildConfigJSON_RedirectMetricsRunBeforeStaticResponse pins the
// ORDER the counters depend on.
//
// redirect.go's design comment says the metrics handler sits "in front
// of" the redirect so a moved domain still reports the traffic still
// arriving at the old name — the number that tells the operator when
// the old name can be retired. The assertion above only proved the
// handler was somewhere in the config, while its own message claimed
// it was in front; `static_response` terminates the chain, so a
// swapped pair would send every redirect counter silently to zero and
// leave that test green.
//
// This walks the emitted JSON instead of grepping it, so the invariant
// is actually checked rather than described.
func TestBuildConfigJSON_RedirectMetricsRunBeforeStaticResponse(t *testing.T) {
	cfgJSON, err := buildConfigJSON([]storage.Route{redirectRoute(&storage.RedirectConfig{
		Target:     "https://new.example.com",
		StatusCode: 301,
	})}, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	var cfg any
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// v2.72 — select the chain by WHAT IT CONTAINS, not by walk order.
	//
	// This used to call findHandlerChainWith(cfg, "static_response"),
	// which returns the FIRST chain the walk happens to reach — and
	// the walk recursed with `for _, v := range n` over a
	// map[string]any, whose iteration order Go randomises. The emitted
	// config holds several static_response chains: this route's
	// redirect, the HTTP→HTTPS redirect at manager.go:3090, the error
	// pages, the maintenance page. So the test picked one at random and
	// failed roughly one run in N with "no arenet_routemetrics in the
	// redirect chain: [static_response]" — the bare HTTP→HTTPS chain.
	//
	// It did that on main on 2026-10-14 and the blame landed on a PR
	// that had touched no Go file at all. A test that can fail for a
	// reason unrelated to what it asserts is worse than no test: it
	// spends someone's afternoon on an innocent change.
	chain := findRedirectChainTo(cfg, "https://new.example.com")
	if chain == nil {
		t.Fatal("no redirect chain to https://new.example.com in the emitted config")
	}

	metricsAt, staticAt := -1, -1
	for i, h := range chain {
		switch handlerName(h) {
		case "arenet_routemetrics":
			if metricsAt == -1 {
				metricsAt = i
			}
		case "static_response":
			if staticAt == -1 {
				staticAt = i
			}
		}
	}
	if metricsAt == -1 {
		t.Fatalf("no arenet_routemetrics in the redirect chain: %v", handlerNames(chain))
	}
	if staticAt == -1 {
		t.Fatalf("no static_response in the chain we selected: %v", handlerNames(chain))
	}
	if metricsAt > staticAt {
		t.Errorf("handler order is %v: static_response terminates the chain, so metrics placed after it never run and every redirect counter reads zero", handlerNames(chain))
	}
}

// findHandlerChainWith was removed in v2.72.
//
// It returned the FIRST "handle" array the walk reached, and the walk
// recursed with `for _, v := range n` over a map[string]any — whose
// iteration order Go randomises. With several static_response chains
// in the emitted config, callers got a different one per run. It
// failed on main on 2026-10-14 and the blame landed on a PR that had
// touched no Go file.
//
// Leaving it here with a warning comment would have been an invitation
// to reuse it; findRedirectChainTo below selects by content instead.
// If a future test needs "any chain containing handler X", build it on
// allHandlerChains, which returns all of them, and give it a predicate
// that can only match one.

// findRedirectChainTo returns the handler chain whose static_response
// sends the visitor to location.
//
// The determinism comes from the PREDICATE, not from the walk order:
// the Location header is what distinguishes this route's redirect from
// every other static_response in the config, so exactly one chain
// matches and the order it is reached in cannot change the answer.
//
// That is why there is no sorted traversal here. I wrote one, and the
// injection showed it was carrying nothing — reverting to plain map
// iteration left both guards green, because the predicate had already
// made the result unique. A future selector whose predicate CAN match
// two chains has to impose its own order; this one does not need to.
func findRedirectChainTo(node any, location string) []any {
	for _, chain := range allHandlerChains(node) {
		for _, h := range chain {
			if handlerName(h) != "static_response" {
				continue
			}
			m, ok := h.(map[string]any)
			if !ok {
				continue
			}
			headers, ok := m["headers"].(map[string]any)
			if !ok {
				continue
			}
			locs, ok := headers["Location"].([]any)
			if !ok || len(locs) == 0 {
				continue
			}
			if got, ok := locs[0].(string); ok && strings.HasPrefix(got, location) {
				return chain
			}
		}
	}
	return nil
}

// allHandlerChains collects EVERY "handle" array in the tree.
//
// Returning all of them is the fix: the helper it replaced returned
// the first one the walk reached, so the caller got whichever chain
// Go's randomised map iteration happened to visit first. Collecting
// them all hands the choice to a predicate instead of to chance.
func allHandlerChains(node any) [][]any {
	var out [][]any
	switch n := node.(type) {
	case map[string]any:
		if chain, ok := n["handle"].([]any); ok {
			out = append(out, chain)
		}
		for _, v := range n {
			out = append(out, allHandlerChains(v)...)
		}
	case []any:
		for _, v := range n {
			out = append(out, allHandlerChains(v)...)
		}
	}
	return out
}

func handlerName(h any) string {
	m, ok := h.(map[string]any)
	if !ok {
		return ""
	}
	name, _ := m["handler"].(string)
	return name
}

func handlerNames(chain []any) []string {
	out := make([]string, 0, len(chain))
	for _, h := range chain {
		out = append(out, handlerName(h))
	}
	return out
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

// TestFindRedirectChainTo_PicksTheRightChainAmongSeveral is the guard
// on the selector itself.
//
// The config this test builds is the shape that broke CI: a bare
// [static_response] for the HTTP→HTTPS redirect (manager.go:3090)
// alongside the route's own redirect chain. The old finder returned
// whichever the randomised map walk reached first, so this is the
// discrimination that has to hold — run many times, because one pass
// proves nothing against map ordering.
func TestFindRedirectChainTo_PicksTheRightChainAmongSeveral(t *testing.T) {
	// Built by hand rather than emitted, so the ambiguity is present
	// on every run instead of depending on what the emitter happens to
	// produce.
	cfg := map[string]any{
		// Several sibling keys: the walk's starting point is a map, so
		// the order it visits these is exactly what used to decide the
		// answer.
		"aaa_http_to_https": map[string]any{
			"handle": []any{
				map[string]any{
					"handler":     "static_response",
					"status_code": float64(301),
					"headers": map[string]any{
						"Location": []any{"https://{http.request.host}{http.request.uri}"},
					},
				},
			},
		},
		"mmm_route_redirect": map[string]any{
			"handle": []any{
				map[string]any{"handler": "arenet_routemetrics"},
				map[string]any{
					"handler":     "static_response",
					"status_code": float64(301),
					"headers": map[string]any{
						"Location": []any{"https://new.example.com"},
					},
				},
			},
		},
		"zzz_maintenance": map[string]any{
			"handle": []any{
				map[string]any{"handler": "static_response", "status_code": float64(503)},
			},
		},
	}

	for i := 0; i < 200; i++ {
		chain := findRedirectChainTo(cfg, "https://new.example.com")
		if chain == nil {
			t.Fatalf("iteration %d: no chain found", i)
		}
		names := handlerNames(chain)
		if len(names) != 2 || names[0] != "arenet_routemetrics" {
			t.Fatalf("iteration %d: picked the wrong chain: %v", i, names)
		}
	}
}

// And it answers nothing rather than something wrong when the target
// is not there — a nil is a failed test, a wrong chain is a false
// green.
func TestFindRedirectChainTo_NoMatch(t *testing.T) {
	cfg := map[string]any{
		"handle": []any{
			map[string]any{
				"handler": "static_response",
				"headers": map[string]any{"Location": []any{"https://elsewhere.example"}},
			},
		},
	}
	if chain := findRedirectChainTo(cfg, "https://new.example.com"); chain != nil {
		t.Errorf("found a chain for a target that is not in the config: %v", handlerNames(chain))
	}
}
