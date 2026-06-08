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

package main

import (
	"net"
	"strings"
	"testing"
)

// Step W.3 — env-var parser tests for the country-block
// feature. Mirror of normal_traffic_config_test.go shape.

// --- parseCountryBlockStatus -------------------------------

func TestParseCountryBlockStatus_AcceptedValues(t *testing.T) {
	for _, sc := range []int{403, 451, 444} {
		got, err := parseCountryBlockStatus(toa(sc))
		if err != nil {
			t.Errorf("parseCountryBlockStatus(%d) returned err = %v; want nil", sc, err)
		}
		if got != sc {
			t.Errorf("parseCountryBlockStatus(%d) = %d; want %d", sc, got, sc)
		}
	}
}

func TestParseCountryBlockStatus_EmptyDefaultsTo403(t *testing.T) {
	got, err := parseCountryBlockStatus("")
	if err != nil {
		t.Fatalf("err = %v; want nil for empty input", err)
	}
	if got != defaultCountryBlockStatus {
		t.Errorf("got %d; want %d (default)", got, defaultCountryBlockStatus)
	}
}

func TestParseCountryBlockStatus_RejectedValues_FallBackTo403(t *testing.T) {
	// Per spec §D3: invalid values WARN + fall back to
	// default. The parser returns (default, err) so the
	// caller can log + proceed; this test pins both that
	// the err carries the bad value AND the fallback is the
	// canonical 403.
	cases := []string{"200", "301", "418", "500", "999", "garbage", "not-a-number", "-1"}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			got, err := parseCountryBlockStatus(raw)
			if err == nil {
				t.Errorf("expected err for %q; got nil", raw)
			}
			if got != defaultCountryBlockStatus {
				t.Errorf("got %d; want fallback %d", got, defaultCountryBlockStatus)
			}
		})
	}
}

// --- parseCountryBlockTrustedIPs ---------------------------

func TestParseCountryBlockTrustedIPs_EmptyReturnsNil(t *testing.T) {
	out, errs := parseCountryBlockTrustedIPs("")
	if out != nil {
		t.Errorf("expected nil slice for empty input; got %v", out)
	}
	if errs != nil {
		t.Errorf("expected nil errs for empty input; got %v", errs)
	}
}

func TestParseCountryBlockTrustedIPs_ValidCIDRs(t *testing.T) {
	out, errs := parseCountryBlockTrustedIPs("203.0.113.5/32,198.51.100.0/24,2001:db8::/32")
	if len(errs) > 0 {
		t.Errorf("unexpected errs: %v", errs)
	}
	if len(out) != 3 {
		t.Fatalf("got %d entries; want 3", len(out))
	}
	// Spot-check one IPv4 and one IPv6 entry contains its
	// expected address.
	if !out[0].Contains(net.ParseIP("203.0.113.5")) {
		t.Errorf("CIDR[0] does not contain 203.0.113.5: %v", out[0])
	}
	if !out[2].Contains(net.ParseIP("2001:db8::1")) {
		t.Errorf("CIDR[2] does not contain 2001:db8::1: %v", out[2])
	}
}

func TestParseCountryBlockTrustedIPs_BareIPsExpandToHostCIDR(t *testing.T) {
	// Operators commonly type "1.2.3.4" instead of
	// "1.2.3.4/32"; the parser expands to /32 (IPv4) or
	// /128 (IPv6) as appropriate.
	out, errs := parseCountryBlockTrustedIPs("1.2.3.4,::1")
	if len(errs) > 0 {
		t.Errorf("unexpected errs: %v", errs)
	}
	if len(out) != 2 {
		t.Fatalf("got %d entries; want 2", len(out))
	}
	// Both should match their host IP exactly and nothing
	// else (since they're host CIDRs).
	if !out[0].Contains(net.ParseIP("1.2.3.4")) {
		t.Errorf("bare-IP /32 does not match the input IP: %v", out[0])
	}
	if out[0].Contains(net.ParseIP("1.2.3.5")) {
		t.Errorf("bare-IP /32 erroneously matches a different IP: %v", out[0])
	}
}

func TestParseCountryBlockTrustedIPs_DropsInvalidEntries(t *testing.T) {
	// Per spec §D4: malformed entries are reported via the
	// returned error slice but DO NOT block the boot —
	// valid entries still apply.
	out, errs := parseCountryBlockTrustedIPs("203.0.113.5/32,not-a-cidr,198.51.100.42")
	if len(errs) != 1 {
		t.Fatalf("expected 1 err for the invalid entry; got %d (%v)", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "not-a-cidr") {
		t.Errorf("error should name the bad entry; got %v", errs[0])
	}
	if len(out) != 2 {
		t.Errorf("expected 2 valid entries to survive; got %d", len(out))
	}
}

func TestParseCountryBlockTrustedIPs_ForgivesWhitespaceAndEmptyEntries(t *testing.T) {
	// Operators sometimes paste env vars with spaces around
	// commas, trailing commas, or double commas from a
	// botched copy. Trim + skip-empty per the V.1.3 forgive-
	// shell-noise pattern.
	out, errs := parseCountryBlockTrustedIPs("  203.0.113.5/32 , , 198.51.100.0/24,")
	if len(errs) > 0 {
		t.Errorf("unexpected errs: %v", errs)
	}
	if len(out) != 2 {
		t.Errorf("got %d entries; want 2", len(out))
	}
}

func TestParseCountryBlockTrustedIPs_AllInvalidReturnsNilSlice(t *testing.T) {
	// When every entry is malformed, the returned slice is
	// nil (not empty) so the caller's
	// countryblock.SetGlobalTrustedIPs(nil) clears the atomic
	// pointer rather than installing an empty slice (defense
	// in depth — the package allows both, but nil is the
	// canonical "no allowlist" state).
	out, errs := parseCountryBlockTrustedIPs("not-a-cidr,also-bad")
	if len(errs) != 2 {
		t.Errorf("expected 2 errs; got %d", len(errs))
	}
	if out != nil {
		t.Errorf("expected nil slice when all entries invalid; got %v", out)
	}
}

// toa avoids the strconv import dance — same trick the
// other cmd-side tests use.
func toa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
