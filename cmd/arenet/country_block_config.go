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
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Step W.3 — operator-facing env-var parsers for the
// country-block feature (spec §5). Kept in a separate file
// so the parse rules + their tests are co-located and
// main.go stays readable. Mirrors the V.1.3
// normal_traffic_config.go shape.
//
// Validation philosophy: invalid STATUS values WARN at boot
// and fall back to 403 (spec §D3 — operator typo shouldn't
// keep arenet from booting). Invalid TRUSTED_IPS entries
// WARN per entry and are dropped (other valid entries still
// apply); fully empty / unset is the canonical "RFC1918-
// only bypass" default and produces no warning.

// defaultCountryBlockStatus is the spec §D3 default when
// ARENET_COUNTRY_BLOCK_STATUS is unset or invalid.
const defaultCountryBlockStatus = 403

// allowedCountryBlockStatuses is the §D3 enum of accepted
// HTTP status codes. Values outside this set fall back to
// defaultCountryBlockStatus with a WARN log line.
var allowedCountryBlockStatuses = map[int]struct{}{
	403: {}, // canonical "you can't access this"
	451: {}, // RFC 7725 — legal-reasons block
	444: {}, // nginx convention — close without response
}

// parseCountryBlockStatus parses
// ARENET_COUNTRY_BLOCK_STATUS. Empty input → default 403.
// Non-integer or out-of-enum → returns (403, error) so the
// caller can WARN + fall back. Per spec §D3 the failure
// mode is "boot with the default, log the bad value", NOT
// FATAL — operators copying a config from a tutorial
// should never get a boot-block over a single bad env var.
func parseCountryBlockStatus(raw string) (int, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return defaultCountryBlockStatus, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return defaultCountryBlockStatus, fmt.Errorf("%q is not an integer (falling back to %d)", raw, defaultCountryBlockStatus)
	}
	if _, ok := allowedCountryBlockStatuses[n]; !ok {
		return defaultCountryBlockStatus, fmt.Errorf("%d is not one of {403, 451, 444} (falling back to %d)", n, defaultCountryBlockStatus)
	}
	return n, nil
}

// parseCountryBlockTrustedIPs parses
// ARENET_COUNTRY_BLOCK_TRUSTED_IPS as a comma-separated CIDR
// list. Empty / unset input returns nil (only RFC1918 bypass
// active). Per spec §D4 the parser is forgiving on
// individual entries: malformed CIDRs are dropped + reported
// via the returned error slice (caller WARNs once per bad
// entry, then proceeds with the valid ones).
//
// Bare-IP entries (no /N suffix) are accepted as /32 (IPv4)
// or /128 (IPv6) — operators commonly type "1.2.3.4" instead
// of "1.2.3.4/32" and the convenience matters more than
// rigour at the env-var boundary.
//
// Each returned net.IPNet's IP is normalised (To4 → 4-byte
// form when applicable) so Contains() lookups against
// net.ParseIP() output land correctly without operator
// surprise on IPv4 entries.
func parseCountryBlockTrustedIPs(raw string) ([]*net.IPNet, []error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	out := make([]*net.IPNet, 0, len(parts))
	var errs []error
	for _, p := range parts {
		entry := strings.TrimSpace(p)
		if entry == "" {
			continue
		}
		// Bare-IP shortcut: append /32 or /128 as appropriate.
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				errs = append(errs, fmt.Errorf("%q is not a valid IP or CIDR", entry))
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				entry = ip4.String() + "/32"
			} else {
				entry = ip.String() + "/128"
			}
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", entry, err))
			continue
		}
		out = append(out, cidr)
	}
	if len(out) == 0 {
		return nil, errs
	}
	return out, errs
}
