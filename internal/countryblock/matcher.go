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
	"sync"
)

// Decision is the pure result of Evaluate. The module's ServeHTTP
// converts Decision.Accepted into either next.ServeHTTP (accept) or
// w.WriteHeader(statusCode) + sink.Submit (block).
//
// Reason is a stable enum-string suitable for logs / tests /
// operator activity-log surfaces (W.5). Adding a new reason MUST
// be backwards-compatible: existing values cannot be renamed
// (downstream parsers — including the W.5 activity log — key off
// them).
type Decision struct {
	// Accepted is true when the request should be passed to the
	// next handler in the chain; false when the country-block
	// handler should short-circuit with the configured status code.
	Accepted bool

	// Country is the resolved country code (ISO 3166-1 alpha-2),
	// or "" when the source IP couldn't be resolved (degraded
	// mode) or didn't need resolution (trusted-IP / RFC1918
	// bypass — resolution is skipped on those paths).
	Country string

	// Reason is the path through Evaluate that produced this
	// Decision. Stable strings — see the const block below.
	Reason string
}

// Decision reason strings. Stable enum — parsers downstream key
// off them.
const (
	ReasonTrustedIP    = "trusted-ip"
	ReasonRFC1918      = "rfc1918"
	ReasonOff          = "off"
	ReasonLookupFailed = "lookup-failed"
	ReasonAllowMatch   = "allow-match"
	ReasonAllowMiss    = "allow-miss"
	ReasonDenyMatch    = "deny-match"
	ReasonDenyMiss     = "deny-miss"
)

// Evaluate is the pure-Go gate evaluation. No HTTP, no Caddy, no
// MMDB I/O — the caller (Handler.ServeHTTP, or a test) pre-resolves
// the country via the CountryLookup seam and passes it in.
//
// Bypass / decision precedence (must hold for the AC #6 / AC #7 /
// AC #18 tests to pass):
//
//  1. Trusted-IP allowlist (operator-supplied CIDR list).
//  2. RFC1918 / loopback / link-local source IP.
//  3. Mode == ModeOff (or empty) — gate disabled.
//  4. country == "" — fail-open per AC #18 (MMDB missing or IP
//     not in DB; rather than block legitimate traffic, pass it
//     through with reason="lookup-failed" so the operator can
//     spot the degraded state in the activity log).
//  5. Mode == ModeAllow — match in CountryList → accept; else block.
//  6. Mode == ModeDeny — match in CountryList → block; else accept.
//
// The trusted-IP layer is checked BEFORE RFC1918 because operators
// may add a public-looking IP to the trusted list (e.g. a static
// VPN exit) and that intent should win regardless of any
// hypothetical CIDR overlap. RFC1918 is the second layer because
// it is a hardcoded baseline; both are checked BEFORE the lookup
// because the lookup is the expensive part (1-5 µs warm; the
// allowlist + RFC1918 checks are O(len(trustedIPs)) of
// IPNet.Contains which is cheaper at typical homelab sizes).
//
// Evaluate is safe for concurrent use; no shared mutable state.
func Evaluate(
	config Config,
	country string,
	srcIP string,
	trustedIPs []*net.IPNet,
) Decision {
	// Parse srcIP once; reuse for both bypass layers.
	ip := net.ParseIP(srcIP)

	// Layer 1 — operator-supplied trusted-IP allowlist.
	if ip != nil {
		for _, cidr := range trustedIPs {
			if cidr != nil && cidr.Contains(ip) {
				return Decision{
					Accepted: true,
					Country:  "",
					Reason:   ReasonTrustedIP,
				}
			}
		}
	}

	// Layer 2 — RFC1918 / loopback / link-local.
	if ip != nil && isLAN(ip) {
		return Decision{
			Accepted: true,
			Country:  "",
			Reason:   ReasonRFC1918,
		}
	}

	// Layer 3 — mode gate.
	if config.Mode == "" || config.Mode == ModeOff {
		return Decision{
			Accepted: true,
			Country:  country,
			Reason:   ReasonOff,
		}
	}

	// Layer 4 — degraded GeoIP. Fail-open per AC #18. The
	// caller is expected to log a Warn once-per-Provision when
	// it observes this branch (rate-limited to avoid log
	// flooding under sustained MMDB outage).
	if country == "" {
		return Decision{
			Accepted: true,
			Country:  "",
			Reason:   ReasonLookupFailed,
		}
	}

	// Layer 5/6 — allow/deny match.
	match := containsCountry(config.CountryList, country)
	switch config.Mode {
	case ModeAllow:
		if match {
			return Decision{Accepted: true, Country: country, Reason: ReasonAllowMatch}
		}
		return Decision{Accepted: false, Country: country, Reason: ReasonAllowMiss}
	case ModeDeny:
		if match {
			return Decision{Accepted: false, Country: country, Reason: ReasonDenyMatch}
		}
		return Decision{Accepted: true, Country: country, Reason: ReasonDenyMiss}
	}

	// Unreachable — Validate rejects any Mode outside the enum,
	// and Provision calls Validate. Defensive fail-open so a
	// future Mode addition that bypasses Validate doesn't
	// surprise-block traffic.
	return Decision{Accepted: true, Country: country, Reason: ReasonOff}
}

// containsCountry is a linear scan — CountryList is typically
// <10 entries (operator-curated; not auto-imported). A map would
// add per-request allocation pressure (Handler reads the slice
// directly from JSON) for no measurable benefit at that size.
func containsCountry(list []string, country string) bool {
	for _, c := range list {
		if c == country {
			return true
		}
	}
	return false
}

// IsTrusted reports whether srcIP belongs to either an
// operator-supplied trusted CIDR OR an RFC1918 / loopback /
// link-local range. Exported for testing and for the W.5
// activity-log surface (which displays "trusted" vs "rfc1918"
// distinctly even though Evaluate folds both into "accept").
func IsTrusted(srcIP string, trustedIPs []*net.IPNet) bool {
	ip := net.ParseIP(srcIP)
	if ip == nil {
		return false
	}
	for _, cidr := range trustedIPs {
		if cidr != nil && cidr.Contains(ip) {
			return true
		}
	}
	return isLAN(ip)
}

// lanRanges is the hardcoded RFC1918 + loopback + link-local CIDR
// set. Identical to internal/geo's isLAN coverage; duplicated here
// rather than imported to keep internal/countryblock free of the
// geo package dependency (the geo package itself imports MMDB
// libraries; countryblock should remain pure).
var (
	lanRanges []*net.IPNet
	lanInit   sync.Once
)

func initLANRanges() {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918 class A
		"172.16.0.0/12",  // RFC1918 class B
		"192.168.0.0/16", // RFC1918 class C
		"127.0.0.0/8",    // IPv4 loopback
		"169.254.0.0/16", // IPv4 link-local (RFC3927)
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local (RFC4193)
	}
	lanRanges = make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			lanRanges = append(lanRanges, n)
		}
	}
}

func isLAN(ip net.IP) bool {
	if ip == nil {
		return false
	}
	lanInit.Do(initLANRanges)
	for _, n := range lanRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
