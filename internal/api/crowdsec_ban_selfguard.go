// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

package api

import (
	"net"
	"strings"
)

// Refusing the two bans an operator almost never means (v2.72).
//
// validateManualBanValue checks syntax and nothing else: net.ParseCIDR
// accepts 0.0.0.0/0 and net.ParseIP accepts the caller's own address,
// so one mistyped field put every proxied service behind a 403 for up
// to 30 days. The modal had a non-blocking notice for wide masks and
// nothing at all for the caller's own IP.
//
// Two distinct refusals, each with its own reason string so the UI can
// say which one happened:
//
//   - the value covers the address this request came from;
//   - the value covers the whole internet.
//
// Both are bypassable with an explicit flag, because it is the
// operator's installation and there are legitimate reasons for either
// (a stolen laptop on the LAN; a deliberate lockdown). The bypass is
// recorded in the audit entry, which is the part that matters when
// someone asks later why everything went dark.
//
// This is NOT an authorization boundary, and must not be mistaken for
// one. The caller's address comes from auth.ClientIPFromContext, which
// honours X-Forwarded-For behind trusted proxies — so a client able to
// forge that header can make the guard miss, or make it fire for an
// address that is not theirs. Neither grants anything: the route is
// already admin-only, and the worst outcome is that an admin has to
// tick a box. The guard is a safety net against a typo, not a control.

// banGuardVerdict says which refusal applies, if any.
type banGuardVerdict struct {
	// CoversCaller is true when the ban would hit the address this
	// request arrived from.
	CoversCaller bool
	// CoversEverything is true for a default route — 0.0.0.0/0 or ::/0.
	CoversEverything bool
}

// Refused reports whether anything should stop the ban.
func (v banGuardVerdict) Refused() bool {
	return v.CoversCaller || v.CoversEverything
}

// classifyBanTarget decides whether scope/value needs a confirmation.
//
// scope and value are the already-normalised pair that
// validateManualBanValue returns, so this never re-parses operator
// text: "Ip" carries a bare address, "Range" a canonical CIDR.
//
// callerIP may be empty (no trusted client address on the request). The
// caller-coverage half is then skipped rather than guessed — refusing
// on an unknown address would block the ban feature outright behind a
// misconfigured proxy.
func classifyBanTarget(scope, value, callerIP string) banGuardVerdict {
	var v banGuardVerdict

	switch scope {
	case "Range":
		_, ipnet, err := net.ParseCIDR(value)
		if err != nil || ipnet == nil {
			return v
		}
		if isDefaultRoute(ipnet) {
			v.CoversEverything = true
		}
		if caller := parseCallerIP(callerIP); caller != nil && ipnet.Contains(caller) {
			v.CoversCaller = true
		}
	case "Ip":
		target := net.ParseIP(value)
		caller := parseCallerIP(callerIP)
		if target != nil && caller != nil && target.Equal(caller) {
			// What matters here is that both sides are PARSED before
			// being compared: a dual-stack listener reports the caller
			// as an IPv4-mapped IPv6 address (::ffff:203.0.113.9), so
			// comparing the raw strings against a plain 203.0.113.9
			// target would miss it — as would a caller in host:port
			// form. Both cases are table-tested.
			//
			// net.IP.Equal rather than comparing String(): for anything
			// net.ParseIP can return the two agree, because String()
			// normalises the mapped form to dotted quad. Equal is the
			// documented comparison and does not depend on that
			// formatting coincidence. An earlier version of this
			// comment claimed Equal was load-bearing on its own; the
			// injection that swapped it for String() passed, which is
			// how the overclaim surfaced.
			v.CoversCaller = true
		}
	}
	return v
}

// isDefaultRoute reports a prefix that covers its whole address family.
func isDefaultRoute(ipnet *net.IPNet) bool {
	ones, _ := ipnet.Mask.Size()
	return ones == 0
}

// parseCallerIP turns the context's client address into an IP.
//
// The value is usually a bare address, but a RemoteAddr-shaped
// "host:port" is tolerated so a future change of source cannot silently
// disable the guard.
func parseCallerIP(raw string) net.IP {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// banGuardCode is the machine code the UI translates.
//
// The caller case wins when both apply: a default route also covers the
// caller, and "this will cut you off" is the more actionable half.
func banGuardCode(v banGuardVerdict) string {
	if v.CoversCaller {
		return "crowdsec_ban_covers_caller"
	}
	if v.CoversEverything {
		return "crowdsec_ban_covers_everything"
	}
	return ""
}

// banGuardMessage is the English fallback, used in logs and by non-UI
// consumers. It says what will happen rather than naming a rule: the
// bouncer is not in front of the admin API, so an operator banning
// their own address keeps this UI and loses every proxied service.
func banGuardMessage(v banGuardVerdict) string {
	switch {
	case v.CoversCaller:
		return "this ban covers the address you are connecting from: every route proxied by Arenet " +
			"would answer 403 for you until it expires. The admin interface itself is not behind the " +
			"bouncer, so you would keep access to it. Send confirm=true to proceed."
	case v.CoversEverything:
		return "this ban covers the whole internet: every route proxied by Arenet would answer 403 " +
			"for everyone until it expires. Send confirm=true to proceed."
	default:
		return ""
	}
}
