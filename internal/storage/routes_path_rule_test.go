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

import "testing"

func TestPathRule_Validate(t *testing.T) {
	ba := &BasicAuthRouteConfig{Username: "u", PasswordHash: "$argon2id$..."}
	ipf := &IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4"}}
	cases := []struct {
		name    string
		p       PathRule
		wantErr bool
	}{
		{"basic ok", PathRule{PathPrefix: "/docs", BasicAuth: ba}, false},
		{"ip ok", PathRule{PathPrefix: "/metrics", IPFilter: ipf}, false},
		{"both ok", PathRule{PathPrefix: "/x", BasicAuth: ba, IPFilter: ipf}, false},
		{"no leading slash", PathRule{PathPrefix: "docs", BasicAuth: ba}, true},
		{"empty prefix", PathRule{PathPrefix: "", BasicAuth: ba}, true},
		{"no protection", PathRule{PathPrefix: "/x"}, true},
		{"basic no user", PathRule{PathPrefix: "/x", BasicAuth: &BasicAuthRouteConfig{}}, true},
		{"basic no password hash", PathRule{PathPrefix: "/x", BasicAuth: &BasicAuthRouteConfig{Username: "u"}}, true},
		{"bad ip filter", PathRule{PathPrefix: "/x", IPFilter: &IPFilter{Mode: "allow"}}, true},
		{"whitespace prefix", PathRule{PathPrefix: "/a b", BasicAuth: ba}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if (c.p.Validate() != nil) != c.wantErr {
				t.Fatalf("Validate wantErr=%v", c.wantErr)
			}
		})
	}
}

func TestSortPathRulesByPrefixLenDesc(t *testing.T) {
	in := []PathRule{{PathPrefix: "/docs"}, {PathPrefix: "/docs/admin"}, {PathPrefix: "/a"}}
	got := SortPathRulesByPrefixLenDesc(in)
	if got[0].PathPrefix != "/docs/admin" || got[2].PathPrefix != "/a" {
		t.Fatalf("not longest-first: %v", got)
	}
	// input must be unmutated (returns a copy).
	if in[0].PathPrefix != "/docs" {
		t.Fatal("input slice was mutated")
	}
}

func TestRoute_Validate_RejectsDuplicatePathPrefix(t *testing.T) {
	r := Route{
		Host:      "app.example.com",
		Upstreams: []Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  LBPolicyRoundRobin,
		PathRules: []PathRule{
			{PathPrefix: "/docs", IPFilter: &IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}}},
			{PathPrefix: "/docs", BasicAuth: &BasicAuthRouteConfig{Username: "u"}},
		},
	}
	if err := r.validate(); err == nil {
		t.Fatal("expected duplicate path_prefix rejection")
	}
}
