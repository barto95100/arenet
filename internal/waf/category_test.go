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

package waf

import "testing"

// TestCategoryForRule_RepresentativePerRange covers one rule
// ID per known CRS range. Sourced from the OWASP CRS v4.25.0
// rule filenames (REQUEST-942-APPLICATION-ATTACK-SQLI.conf,
// REQUEST-941-APPLICATION-ATTACK-XSS.conf, etc.). Adding a
// new range to category.go MUST add a row here.
func TestCategoryForRule_RepresentativePerRange(t *testing.T) {
	cases := []struct {
		name string
		id   string
		want OwaspCategory
	}{
		// 942xxx — SQLI rules.
		{"crs_942_sqli_first", "942100", CategorySQLi},
		{"crs_942_sqli_mid", "942500", CategorySQLi},
		{"crs_942_sqli_last", "942999", CategorySQLi},

		// 941xxx — XSS rules.
		{"crs_941_xss_first", "941000", CategoryXSS},
		{"crs_941_xss_mid", "941300", CategoryXSS},

		// 932xxx — RCE (command injection).
		{"crs_932_rce", "932100", CategoryRCE},
		// 933xxx — PHP injection (RCE-class).
		{"crs_933_php_rce", "933100", CategoryRCE},
		// 934xxx — generic / Node / SSRF (RCE-class).
		{"crs_934_generic_rce", "934100", CategoryRCE},
		// 944xxx — Java RCE (deserialisation, JNDI).
		{"crs_944_java_rce", "944100", CategoryRCE},

		// 930xxx — LFI.
		{"crs_930_lfi", "930100", CategoryLFI},
		// 931xxx — RFI (bucketed with LFI).
		{"crs_931_rfi", "931100", CategoryLFI},

		// Protocol: 911 method enforcement, 920 protocol
		// enforcement, 921 protocol attacks, 922 multipart.
		{"crs_911_method", "911100", CategoryProtocol},
		{"crs_920_proto", "920100", CategoryProtocol},
		{"crs_921_proto", "921100", CategoryProtocol},
		{"crs_922_multipart", "922100", CategoryProtocol},

		// 943xxx — session fixation, currently OTHER.
		{"crs_943_session", "943100", CategoryOther},
		// 949 blocking evaluation.
		{"crs_949_blocking", "949100", CategoryOther},
		// 913 scanner detection.
		{"crs_913_scanner", "913100", CategoryOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CategoryForRule(tc.id); got != tc.want {
				t.Errorf("CategoryForRule(%q) = %q, want %q", tc.id, got, tc.want)
			}
		})
	}
}

func TestCategoryForRule_UnknownAndMalformed_FallBackToOther(t *testing.T) {
	cases := []string{
		"",            // empty
		"abc",         // non-numeric
		"-1",          // negative
		"99999999999", // huge, falls through ranges
		"500",         // too small for any range
		"800000",      // between ranges
	}
	for _, id := range cases {
		t.Run("input="+id, func(t *testing.T) {
			if got := CategoryForRule(id); got != CategoryOther {
				t.Errorf("CategoryForRule(%q) = %q, want OTHER (fallback)", id, got)
			}
		})
	}
}

func TestCategoryForRule_BoundaryConditions(t *testing.T) {
	// The exclusive upper bounds matter: 942999 is SQLi,
	// 943000 should NOT be SQLi (it's session fixation →
	// OTHER in this build).
	if got := CategoryForRule("942999"); got != CategorySQLi {
		t.Errorf("942999 = %q, want SQLi (upper bound inclusive)", got)
	}
	if got := CategoryForRule("943000"); got != CategoryOther {
		t.Errorf("943000 = %q, want OTHER (session fixation, NOT SQLi)", got)
	}
	if got := CategoryForRule("941999"); got != CategoryXSS {
		t.Errorf("941999 = %q, want XSS", got)
	}
	if got := CategoryForRule("942000"); got != CategorySQLi {
		t.Errorf("942000 = %q, want SQLi (lower bound)", got)
	}
}
