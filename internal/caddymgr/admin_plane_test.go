// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

// Which route is the management plane, and which is not (v2.73).
//
// The CRS false-positive guard for Arenet's own admin API was
// prepended to EVERY route's WAF engine by internal/waf's buildWAF,
// and it keys on REQUEST_FILENAME — the path the client picks. So any
// unauthenticated request under /api/v1/ stripped CRS families 911*,
// 930*, 931* and the 949* anomaly-score evaluator from its own
// transaction, on any route in block mode.
//
// Only a route pointing at this instance's admin listener needs it.

func TestRouteTargetsAdminListener(t *testing.T) {
	cases := []struct {
		name        string
		adminListen string
		upstream    string
		want        bool
	}{
		{"loopback on the admin port", "127.0.0.1:8001", "http://127.0.0.1:8001", true},
		{"localhost by name", "127.0.0.1:8001", "http://localhost:8001", true},
		{"IPv6 loopback", "127.0.0.1:8001", "http://[::1]:8001", true},
		{"admin bound to every interface", ":8001", "http://127.0.0.1:8001", true},
		{"https to the admin listener", "127.0.0.1:8001", "https://127.0.0.1:8001", true},
		{"with a path", "127.0.0.1:8001", "http://127.0.0.1:8001/", true},

		// The two halves that must both hold.
		{"another host on the same port is someone else's machine",
			"127.0.0.1:8001", "http://10.0.0.5:8001", false},
		{"loopback on another port is another local service",
			"127.0.0.1:8001", "http://127.0.0.1:3000", false},

		{"no port cannot be the admin listener", "127.0.0.1:8001", "http://127.0.0.1", false},
		{"unparseable upstream", "127.0.0.1:8001", "not a url", false},

		// Fails CLOSED: an unknown admin address costs a false
		// positive on the admin route, where failing open would cost
		// the CRS blocking evaluator on every route.
		{"no admin address recorded", "", "http://127.0.0.1:8001", false},
		{"unparseable admin address", "8001", "http://127.0.0.1:8001", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := storage.Route{
				ID:        "r1",
				Host:      "admin.example.com",
				Upstreams: []storage.Upstream{{URL: tc.upstream, Weight: 1}},
			}
			if got := routeTargetsAdminListener(r, tc.adminListen); got != tc.want {
				t.Errorf("routeTargetsAdminListener(upstream=%q, admin=%q) = %v, want %v",
					tc.upstream, tc.adminListen, got, tc.want)
			}
		})
	}
}

// A route can carry several upstreams; one match is enough.
func TestRouteTargetsAdminListener_AnyUpstreamCounts(t *testing.T) {
	r := storage.Route{
		ID:   "r1",
		Host: "admin.example.com",
		Upstreams: []storage.Upstream{
			{URL: "http://10.0.0.5:9000", Weight: 1},
			{URL: "http://127.0.0.1:8001", Weight: 1},
		},
	}
	if !routeTargetsAdminListener(r, "127.0.0.1:8001") {
		t.Error("a pool containing the admin listener is the management plane")
	}
}

// The emission half: the exemption is in the directives for the admin
// plane and absent everywhere else.
func TestBuildWAFHandler_ExemptionOnlyForTheAdminPlane(t *testing.T) {
	marker := "id:100001"

	user := buildWAFHandler("r-user", "app.example.com", "block", false, false,
		nil, nil, nil, nil, "", false)
	userDirectives, _ := user["directives"].(string)
	if strings.Contains(userDirectives, marker) {
		t.Error("a user route must not carry the management-plane exemption: it keys on the " +
			"request path, so any client could strip the CRS blocking evaluator")
	}

	admin := buildWAFHandler("r-admin", "admin.example.com", "block", false, false,
		nil, nil, nil, nil, "", true)
	adminDirectives, _ := admin["directives"].(string)
	if !strings.Contains(adminDirectives, marker) {
		t.Error("the admin plane must keep the exemption, or the false positives it guards " +
			"against come back on the operator's own UI")
	}

	// Placement is load-bearing: the ctl actions remove rules from the
	// transaction's scope, and a rule already evaluated cannot be
	// removed. It has to come before the CRS includes.
	exemptionAt := strings.Index(adminDirectives, marker)
	crsAt := strings.Index(adminDirectives, "Include @owasp_crs")
	if exemptionAt < 0 || crsAt < 0 || exemptionAt > crsAt {
		t.Errorf("the exemption must precede the CRS includes (exemption at %d, CRS at %d)",
			exemptionAt, crsAt)
	}
}

// With the CRS disabled there are no CRS rules to exempt, so the
// directive would be dead weight in the emitted config.
func TestBuildWAFHandler_NoExemptionWithoutCRS(t *testing.T) {
	h := buildWAFHandler("r-admin", "admin.example.com", "block", false, true,
		nil, nil, nil, nil, "", true)
	d, _ := h["directives"].(string)
	if strings.Contains(d, "id:100001") {
		t.Error("no CRS loaded means nothing to exempt")
	}
}

// And the constant the two packages share is the one thing both sides
// agree on, so a rename cannot silently split them.
func TestAdminExemptionConstantIsTheSharedOne(t *testing.T) {
	if !strings.Contains(waf.AdminAPIExclusionDirective, "id:100001") {
		t.Error("the shared exemption constant no longer carries its rule id")
	}
	if !strings.Contains(waf.AdminAPIExclusionDirective, "REQUEST_FILENAME") {
		t.Error("the shared exemption constant no longer keys on REQUEST_FILENAME")
	}
}
