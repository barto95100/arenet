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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// A path rule must gate its whole subtree, not just the exact path.
//
// pathMatchers built the sub-tree pattern by concatenating the
// operator's prefix with "/*". For a prefix that already ended in "/"
// that produced "/admin//*", and Caddy disables slash-merging for any
// pattern containing "//" (matchers.go:475), then prefix-matches
// against the literal "/admin//" — which no ordinary request produces.
// So "/admin/" prompted for credentials and "/admin/users" was proxied
// to the backend with the rule's basic auth, forward auth, IP filter
// and rate limit never executed. The misconfiguration TESTED AS
// WORKING, which is what made it dangerous.
//
// These tests assert against Caddy's own MatchPath rather than against
// the strings pathMatchers returns. Asserting the strings would restate
// the implementation: it would have been just as green with the broken
// concatenation, because the bug is not in what we emit but in what
// Caddy does with it. The matcher is the thing under test, so the
// matcher is what runs.
//
// Note the two codebase facts that make this a defect rather than a
// design choice: storage's own matches() helper already trims the
// trailing slash (internal/storage/routes.go:410), and
// buildAuthPassthroughRoute already normalises its prefix the same way
// (manager.go:3985). Storage, the passthrough emitter and this emitter
// disagreed with each other.

// matchesUnderCaddy reports whether Caddy's path matcher, at the
// version this module pins, considers reqPath a match for patterns.
//
// MatchWithError type-asserts a *caddy.Replacer out of the request
// context without checking (matchers.go:447), so the context must
// carry one or the matcher panics.
func matchesUnderCaddy(t *testing.T, patterns []string, reqPath string) bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, reqPath, nil)
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	ok, err := caddyhttp.MatchPath(patterns).MatchWithError(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("MatchPath(%q).MatchWithError(%q): %v", patterns, reqPath, err)
	}
	return ok
}

func TestPathMatchers_GateCoversTheSubtree(t *testing.T) {
	cases := []struct {
		name    string
		prefix  string
		path    string
		want    bool
		because string
	}{
		{
			name:    "trailing slash, path under it",
			prefix:  "/admin/",
			path:    "/admin/users",
			want:    true,
			because: "the defect: this was proxied with the rule's gate skipped",
		},
		{
			name:    "trailing slash, the prefix itself",
			prefix:  "/admin/",
			path:    "/admin/",
			want:    true,
			because: "the one path that DID match before, which is why it tested as working",
		},
		{
			name:    "trailing slash, prefix without the slash",
			prefix:  "/admin/",
			path:    "/admin",
			want:    true,
			because: "the operator means the same resource either way",
		},
		{
			name:    "trailing slash, deep path",
			prefix:  "/admin/",
			path:    "/admin/users/42/edit",
			want:    true,
			because: "the whole subtree, not one level of it",
		},
		{
			name:    "no trailing slash, path under it",
			prefix:  "/docs",
			path:    "/docs/intro",
			want:    true,
			because: "the shape that already worked must keep working",
		},
		{
			name:    "no trailing slash, the prefix itself",
			prefix:  "/docs",
			path:    "/docs",
			want:    true,
			because: "unchanged behaviour",
		},
		{
			name:    "a sibling prefix is not covered",
			prefix:  "/admin/",
			path:    "/administration",
			want:    false,
			because: "normalising must not widen the gate to a longer name",
		},
		{
			name:    "an unrelated path is not covered",
			prefix:  "/admin/",
			path:    "/public/index.html",
			want:    false,
			because: "sanity",
		},
		{
			name:    "root prefix covers everything",
			prefix:  "/",
			path:    "/anything/at/all",
			want:    true,
			because: "a rule on / is a rule on the whole site",
		},
		{
			name:    "root prefix covers the root itself",
			prefix:  "/",
			path:    "/",
			want:    true,
			because: "the root must not fall through its own rule",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patterns := pathMatchers(storage.PathRule{PathPrefix: tc.prefix})
			got := matchesUnderCaddy(t, patterns, tc.path)
			if got != tc.want {
				t.Errorf("prefix %q emitted %q; Caddy match(%q) = %v, want %v\n  %s",
					tc.prefix, patterns, tc.path, got, tc.want, tc.because)
			}
		})
	}
}

// MatchExact is a separate contract and must stay exact: it exists so a
// per-path redirect does not also match its own target.
func TestPathMatchers_MatchExactStaysExact(t *testing.T) {
	patterns := pathMatchers(storage.PathRule{PathPrefix: "/go", MatchExact: true})

	if !matchesUnderCaddy(t, patterns, "/go") {
		t.Errorf("exact prefix %q emitted %q but does not match /go", "/go", patterns)
	}
	if matchesUnderCaddy(t, patterns, "/go/elsewhere") {
		t.Errorf("exact prefix %q emitted %q and wrongly matches /go/elsewhere", "/go", patterns)
	}
}

// No pattern may contain "//": that is the exact condition under which
// Caddy stops merging slashes (matchers.go:475) and the mechanism that
// produced the bypass. A guard on the emitted shape, so a future
// refactor cannot reintroduce it by another route.
func TestPathMatchers_NeverEmitDoubleSlash(t *testing.T) {
	prefixes := []string{"/", "/admin", "/admin/", "/a/b/", "/a/b"}
	for _, p := range prefixes {
		for _, exact := range []bool{false, true} {
			for _, pattern := range pathMatchers(storage.PathRule{PathPrefix: p, MatchExact: exact}) {
				if len(pattern) > 1 && containsDoubleSlash(pattern) {
					t.Errorf("prefix %q (exact=%v) emitted pattern %q, which disables Caddy's slash merging",
						p, exact, pattern)
				}
			}
		}
	}
}

func containsDoubleSlash(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '/' && s[i+1] == '/' {
			return true
		}
	}
	return false
}
