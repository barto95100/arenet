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

package storage

import (
	"strings"
	"testing"
)

// v2.44 — the route-level redirect state.
//
// What is pinned here is mostly what gets REFUSED. A redirect is one
// line of config that, wrong, produces a loop the operator discovers
// from their browser rather than from Arenet — so every refusal below
// is a message delivered while the form is still open.

func routeWithRedirect(rc *RedirectConfig) Route {
	return Route{
		ID: "r1", Host: "old.example.com",
		Upstreams:      []Upstream{{URL: "http://10.0.0.9:8080", Weight: 1}},
		LBPolicy:       LBPolicyRoundRobin,
		RedirectConfig: rc,
	}
}

func TestRedirectConfig_AcceptsAUsableTarget(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://new.example.com", PreservePath: true})
	if err := r.validate(); err != nil {
		t.Fatalf("a plain host target must be accepted: %v", err)
	}
}

func TestRedirectConfig_RefusesWhatCannotWork(t *testing.T) {
	cases := []struct {
		name string
		rc   *RedirectConfig
		want string
	}{
		{"empty target", &RedirectConfig{}, "target URL is required"},
		{"no scheme", &RedirectConfig{Target: "new.example.com"}, "http:// or https://"},
		{"wrong scheme", &RedirectConfig{Target: "ftp://new.example.com"}, "http:// or https://"},
		{"no host", &RedirectConfig{Target: "https://"}, "no host"},
		{"unsupported code", &RedirectConfig{Target: "https://new.example.com", StatusCode: 307}, "301 or 302"},
		// The silent-corruption case: appending the visitor's path to
		// a target that already has one produces /app/a/b, which
		// nobody asked for and nothing reports.
		{
			"path on target while preserving the path",
			&RedirectConfig{Target: "https://new.example.com/app", PreservePath: true},
			"already has a path",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := routeWithRedirect(c.rc)
			err := r.validate()
			if err == nil {
				t.Fatalf("%s must be refused", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("message must say why (%q): %v", c.want, err)
			}
		})
	}
}

// A target on the route's own host redirects to itself. The browser
// bounces until it gives up, and nothing in Arenet says so — which is
// exactly why this is refused at save.
func TestRedirectConfig_RefusesTheSelfLoop(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://old.example.com/admin/login"})
	err := r.validate()
	if err == nil {
		t.Fatal("a target on the route's own host must be refused")
	}
	if !strings.Contains(err.Error(), "old.example.com") {
		t.Errorf("the message must name the host: %v", err)
	}
	// And it must point at the way out rather than just refusing.
	if !strings.Contains(err.Error(), "path rule") {
		t.Errorf("the message must offer the alternative: %v", err)
	}
}

// Aliases answer for the same route, so a target on an alias loops too
// — less obviously, which makes it more worth catching.
func TestRedirectConfig_RefusesALoopThroughAnAlias(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://www.old.example.com"})
	r.Aliases = []string{"www.old.example.com"}
	if err := r.validate(); err == nil {
		t.Fatal("a target on an alias of this route must be refused")
	}
}

// Case and port must not let a loop through: Caddy matches hosts
// case-insensitively, and https://HOST:443 is the same place.
func TestRedirectConfig_LoopGuardIgnoresCaseAndPort(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://OLD.example.com:443"})
	if err := r.validate(); err == nil {
		t.Fatal("the loop guard must not be defeated by case or an explicit port")
	}
}

// The two states replace the proxy chain; both at once has no meaning.
func TestRedirectConfig_RefusesMaintenanceAtTheSameTime(t *testing.T) {
	r := routeWithRedirect(&RedirectConfig{Target: "https://new.example.com"})
	r.MaintenanceConfig = &MaintenanceConfig{RetryAfterSeconds: 300}
	err := r.validate()
	if err == nil {
		t.Fatal("maintenance and redirect together must be refused")
	}
	if !strings.Contains(err.Error(), "maintenance") {
		t.Errorf("message: %v", err)
	}
}

func TestRedirectConfig_CodeDefaultsToPermanent(t *testing.T) {
	if got := (&RedirectConfig{}).Code(); got != 301 {
		t.Errorf("zero must resolve to 301, got %d", got)
	}
	if got := (&RedirectConfig{StatusCode: 302}).Code(); got != 302 {
		t.Errorf("explicit 302 must survive, got %d", got)
	}
	var nilCfg *RedirectConfig
	if got := nilCfg.Code(); got != 301 {
		t.Errorf("nil must be usable, got %d", got)
	}
}

// A route that does not redirect must validate exactly as before.
func TestRedirectConfig_NilIsInert(t *testing.T) {
	r := routeWithRedirect(nil)
	if err := r.validate(); err != nil {
		t.Fatalf("no redirect configured must stay valid: %v", err)
	}
}
