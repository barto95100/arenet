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

func TestHostMatchesSAN(t *testing.T) {
	cases := []struct {
		host string
		sans []string
		want bool
	}{
		{"app.example.com", []string{"app.example.com"}, true},
		{"app.example.com", []string{"*.example.com"}, true},
		{"sub.app.example.com", []string{"*.example.com"}, false}, // wildcard = 1 label
		{"example.com", []string{"*.example.com"}, false},         // apex not covered by *.
		{"APP.example.com", []string{"app.example.com"}, true},    // case-insensitive
		{"other.com", []string{"app.example.com"}, false},
	}
	for _, c := range cases {
		if got := HostMatchesSAN(c.host, c.sans); got != c.want {
			t.Errorf("HostMatchesSAN(%q,%v)=%v want %v", c.host, c.sans, got, c.want)
		}
	}
}
