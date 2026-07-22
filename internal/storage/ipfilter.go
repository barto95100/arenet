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
	"fmt"
	"net"
)

const (
	IPFilterModeOff   = "off"
	IPFilterModeAllow = "allow"
	IPFilterModeDeny  = "deny"
)

// allowedIPFilterStatus mirrors country-block: 0 = default 403.
var allowedIPFilterStatus = map[int]struct{}{403: {}, 444: {}, 451: {}}

// IPFilter is a reusable source-IP allow/deny gate. Mode "allow" passes
// ONLY the listed IP/CIDR (403 otherwise); "deny" blocks the listed
// (rest passes). Emitted via Caddy's client_ip matcher (honours
// ARENET_TRUSTED_PROXIES). Mirrors countryblock.Config.
type IPFilter struct {
	Mode       string   `json:"mode"`
	CIDRs      []string `json:"cidrs,omitempty"`
	StatusCode int      `json:"statusCode,omitempty"`
}

// IsActive reports whether the gate is enabled (Mode is allow or deny).
func (f IPFilter) IsActive() bool {
	return f.Mode == IPFilterModeAllow || f.Mode == IPFilterModeDeny
}

// Validate enforces the mode/CIDR/status-code invariants on an
// IPFilter. Returns the first violation found.
//
// Validation rules:
//   - Mode must be one of {"", off, allow, deny}. Empty is a synonym
//     for off.
//   - Each CIDRs[i] must parse as a CIDR (net.ParseCIDR) or a bare
//     IP (net.ParseIP).
//   - CIDRs contains no duplicates (exact string match).
//   - Mode == allow or Mode == deny requires len(CIDRs) >= 1.
//   - StatusCode is 0 (use default 403) or one of {403, 444, 451}.
func (f IPFilter) Validate() error {
	switch f.Mode {
	case "", IPFilterModeOff, IPFilterModeAllow, IPFilterModeDeny:
	default:
		return fmt.Errorf("ipfilter: mode %q is not one of off/allow/deny", f.Mode)
	}
	seen := make(map[string]struct{}, len(f.CIDRs))
	for _, e := range f.CIDRs {
		if _, _, err := net.ParseCIDR(e); err != nil {
			if net.ParseIP(e) == nil {
				return fmt.Errorf("ipfilter: %q is not a valid IP or CIDR", e)
			}
		}
		if _, dup := seen[e]; dup {
			return fmt.Errorf("ipfilter: %q appears more than once", e)
		}
		seen[e] = struct{}{}
	}
	if f.IsActive() && len(f.CIDRs) == 0 {
		return fmt.Errorf("ipfilter: mode %q requires at least one IP/CIDR", f.Mode)
	}
	if f.StatusCode != 0 {
		if _, ok := allowedIPFilterStatus[f.StatusCode]; !ok {
			return fmt.Errorf("ipfilter: statusCode %d must be 0 (default 403) or one of 403, 444, 451", f.StatusCode)
		}
	}
	return nil
}

// NormalizedCIDRs converts each bare IP in CIDRs to its single-host
// CIDR (/32 or /128) so emission can always feed the client_ip
// matcher CIDR ranges. Entries already in CIDR form pass through
// unchanged; unparsable entries are dropped defensively (callers are
// expected to have run Validate first).
func (f IPFilter) NormalizedCIDRs() []string {
	out := make([]string, 0, len(f.CIDRs))
	for _, e := range f.CIDRs {
		if _, _, err := net.ParseCIDR(e); err == nil {
			out = append(out, e)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			out = append(out, e+"/32")
		} else {
			out = append(out, e+"/128")
		}
	}
	return out
}
