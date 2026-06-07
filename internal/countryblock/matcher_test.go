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

package countryblock

import (
	"net"
	"testing"
)

// parseCIDRs is a test helper — panics on bad input because a
// bad fixture is a test bug, not a runtime concern.
func parseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("parseCIDRs: bad fixture %q: %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

// TestEvaluate_TableDriven is the matrix that pins every Evaluate
// branch. Each row exercises one decision path; the Reason field
// is asserted in addition to Accepted so a refactor that
// preserves Accepted but degrades the audit signal would still
// surface as a test failure.
func TestEvaluate_TableDriven(t *testing.T) {
	allowFR := Config{Mode: ModeAllow, CountryList: []string{"FR", "DE"}}
	denyRU := Config{Mode: ModeDeny, CountryList: []string{"RU", "KP"}}
	off := Config{Mode: ModeOff}
	emptyMode := Config{Mode: ""}

	trusted := parseCIDRs(t, "203.0.113.5/32", "2001:db8::/32")

	cases := []struct {
		name       string
		config     Config
		country    string
		srcIP      string
		trustedIPs []*net.IPNet
		want       Decision
	}{
		// --- Layer 1 — trusted-IP allowlist ---
		{
			name:       "trusted ipv4 bypasses deny mode for matching country",
			config:     denyRU,
			country:    "RU",
			srcIP:      "203.0.113.5",
			trustedIPs: trusted,
			want:       Decision{Accepted: true, Country: "", Reason: ReasonTrustedIP},
		},
		{
			name:       "trusted ipv6 bypasses allow mode when country missing",
			config:     allowFR,
			country:    "RU",
			srcIP:      "2001:db8::1",
			trustedIPs: trusted,
			want:       Decision{Accepted: true, Country: "", Reason: ReasonTrustedIP},
		},
		// --- Layer 2 — RFC1918 / loopback / link-local ---
		{
			name:    "rfc1918 class A bypasses allow mode",
			config:  allowFR,
			country: "",
			srcIP:   "10.0.0.5",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "rfc1918 class B bypasses deny mode",
			config:  denyRU,
			country: "RU",
			srcIP:   "172.16.0.99",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "rfc1918 class C bypasses allow mode",
			config:  allowFR,
			country: "",
			srcIP:   "192.168.1.42",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "ipv4 loopback bypasses allow mode",
			config:  allowFR,
			country: "",
			srcIP:   "127.0.0.1",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "ipv4 link-local bypasses deny mode",
			config:  denyRU,
			country: "",
			srcIP:   "169.254.1.1",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "ipv6 loopback bypasses allow mode",
			config:  allowFR,
			country: "",
			srcIP:   "::1",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "ipv6 link-local bypasses deny mode",
			config:  denyRU,
			country: "",
			srcIP:   "fe80::1",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "ipv6 unique-local bypasses allow mode",
			config:  allowFR,
			country: "",
			srcIP:   "fc00::1",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		// --- Layer 3 — off mode ---
		{
			name:    "off mode accepts everything",
			config:  off,
			country: "RU",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "RU", Reason: ReasonOff},
		},
		{
			name:    "empty-string mode acts like off (zero-value Config)",
			config:  emptyMode,
			country: "RU",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "RU", Reason: ReasonOff},
		},
		// --- Layer 4 — degraded lookup (fail-open per AC #18) ---
		{
			name:    "allow mode + degraded lookup fails open",
			config:  allowFR,
			country: "",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonLookupFailed},
		},
		{
			name:    "deny mode + degraded lookup fails open",
			config:  denyRU,
			country: "",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "", Reason: ReasonLookupFailed},
		},
		// --- Layer 5 — allow mode match / miss ---
		{
			name:    "allow mode accepts country in list",
			config:  allowFR,
			country: "FR",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "FR", Reason: ReasonAllowMatch},
		},
		{
			name:    "allow mode accepts second country in list",
			config:  allowFR,
			country: "DE",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "DE", Reason: ReasonAllowMatch},
		},
		{
			name:    "allow mode rejects country not in list",
			config:  allowFR,
			country: "RU",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: false, Country: "RU", Reason: ReasonAllowMiss},
		},
		{
			name:    "allow mode rejects unknown country (US)",
			config:  allowFR,
			country: "US",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: false, Country: "US", Reason: ReasonAllowMiss},
		},
		// --- Layer 6 — deny mode match / miss ---
		{
			name:    "deny mode rejects country in list",
			config:  denyRU,
			country: "RU",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: false, Country: "RU", Reason: ReasonDenyMatch},
		},
		{
			name:    "deny mode rejects second country in list",
			config:  denyRU,
			country: "KP",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: false, Country: "KP", Reason: ReasonDenyMatch},
		},
		{
			name:    "deny mode accepts country not in list",
			config:  denyRU,
			country: "FR",
			srcIP:   "1.2.3.4",
			want:    Decision{Accepted: true, Country: "FR", Reason: ReasonDenyMiss},
		},
		// --- Precedence checks ---
		{
			name:       "trusted-ip beats rfc1918 when both overlap",
			config:     allowFR,
			country:    "",
			srcIP:      "10.0.0.5",
			trustedIPs: parseCIDRs(t, "10.0.0.5/32"),
			want:       Decision{Accepted: true, Country: "", Reason: ReasonTrustedIP},
		},
		{
			name:       "empty trustedIPs slice — RFC1918 still applies",
			config:     allowFR,
			country:    "",
			srcIP:      "10.0.0.5",
			trustedIPs: nil,
			want:       Decision{Accepted: true, Country: "", Reason: ReasonRFC1918},
		},
		{
			name:    "unparseable srcIP + public country path — allow miss",
			config:  allowFR,
			country: "RU",
			srcIP:   "not-an-ip",
			want:    Decision{Accepted: false, Country: "RU", Reason: ReasonAllowMiss},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.config, tc.country, tc.srcIP, tc.trustedIPs)
			if got != tc.want {
				t.Errorf("Evaluate = %+v; want %+v", got, tc.want)
			}
		})
	}
}

// TestIsTrusted_HappyPaths covers the exported helper that the W.5
// activity-log surface will use. Combines operator-allowlist and
// RFC1918 paths.
func TestIsTrusted_HappyPaths(t *testing.T) {
	trusted := parseCIDRs(t, "203.0.113.5/32", "198.51.100.0/24")

	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"operator-allowlist /32", "203.0.113.5", true},
		{"operator-allowlist /24 member", "198.51.100.42", true},
		{"public IP outside allowlist", "8.8.8.8", false},
		{"rfc1918 class C", "192.168.1.1", true},
		{"loopback v4", "127.0.0.1", true},
		{"link-local v4", "169.254.1.1", true},
		{"loopback v6", "::1", true},
		{"unparseable", "definitely-not-an-ip", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsTrusted(tc.ip, trusted)
			if got != tc.want {
				t.Errorf("IsTrusted(%q) = %v; want %v", tc.ip, got, tc.want)
			}
		})
	}
}

// TestEvaluate_RaceFree exercises Evaluate from many goroutines
// concurrently. Surfaces races on the lanInit sync.Once (the only
// shared mutable state in matcher.go) and the global LRU absence
// (matcher.go should be pure; this is a regression guard).
func TestEvaluate_RaceFree(t *testing.T) {
	config := Config{Mode: ModeDeny, CountryList: []string{"RU", "KP", "CN"}}
	trusted := parseCIDRs(t, "203.0.113.5/32")
	srcIPs := []string{"1.2.3.4", "10.0.0.5", "203.0.113.5", "::1", "fe80::1"}
	countries := []string{"FR", "RU", "DE", "KP", "US", ""}

	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(seed int) {
			for j := 0; j < 1000; j++ {
				ip := srcIPs[(seed+j)%len(srcIPs)]
				c := countries[(seed+j)%len(countries)]
				_ = Evaluate(config, c, ip, trusted)
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
