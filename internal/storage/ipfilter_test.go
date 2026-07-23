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

func TestIPFilter_Validate(t *testing.T) {
	cases := []struct {
		name    string
		f       IPFilter
		wantErr bool
	}{
		{"off empty ok", IPFilter{Mode: ""}, false},
		{"off explicit ok", IPFilter{Mode: "off"}, false},
		{"allow with ip ok", IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.10"}}, false},
		{"allow with cidr ok", IPFilter{Mode: "allow", CIDRs: []string{"10.0.0.0/8"}}, false},
		{"deny with ipv6 ok", IPFilter{Mode: "deny", CIDRs: []string{"2001:db8::/32"}}, false},
		{"allow empty list rejected", IPFilter{Mode: "allow"}, true},
		{"deny empty list rejected", IPFilter{Mode: "deny"}, true},
		{"bad mode rejected", IPFilter{Mode: "maybe", CIDRs: []string{"1.2.3.4"}}, true},
		{"bad cidr rejected", IPFilter{Mode: "allow", CIDRs: []string{"not-an-ip"}}, true},
		{"dup entry rejected", IPFilter{Mode: "allow", CIDRs: []string{"1.2.3.4", "1.2.3.4"}}, true},
		{"status ok 444", IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}, StatusCode: 444}, false},
		{"status bad 200 rejected", IPFilter{Mode: "deny", CIDRs: []string{"1.2.3.4"}, StatusCode: 200}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.Validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("Validate()=%v wantErr=%v", err, c.wantErr)
			}
		})
	}
}

func TestIPFilter_IsActive(t *testing.T) {
	if (IPFilter{Mode: ""}).IsActive() || (IPFilter{Mode: "off"}).IsActive() {
		t.Fatal("off must be inactive")
	}
	if !(IPFilter{Mode: "allow"}).IsActive() || !(IPFilter{Mode: "deny"}).IsActive() {
		t.Fatal("allow/deny must be active")
	}
}
