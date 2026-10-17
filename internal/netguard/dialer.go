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

// Package netguard is the one place that decides where an
// operator-influenced, server-side outbound request may not go.
//
// Arenet makes such requests on the operator's behalf from more than one
// place: the upstream and health-check Test buttons (internal/api), and
// the alerting channels that POST to a webhook or Discord URL
// (internal/alerting). Each takes its target from operator config, which
// is correct — the operator is reaching an address they chose — and it
// makes those paths a way to reach anything the Arenet host can reach.
//
// A homelab reverse proxy MUST keep reaching private space: 10/8,
// 172.16/12, 192.168/16 and loopback are where the upstreams and the
// local notification services actually live. What it has no business
// fetching is the link-local range, because that is where cloud instance
// metadata lives (169.254.169.254 on every major provider, fd00:ec2::254
// on AWS over IPv6), handing instance credentials to whoever asks from
// the instance.
//
// The check runs AFTER name resolution, on the IP actually being dialled,
// once per candidate address — so a name with several A records has each
// inspected, and a name that resolves to a harmless address for a
// pre-flight look and to 169.254.169.254 for the connection (DNS
// rebinding) cannot slip past. net.Dialer.Control is that seam, and it
// also covers any redirect a request follows, since each hop dials again.
//
// Defined once, on purpose: a second copy would drift from this one.
package netguard

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
)

// ErrBlocked is returned when a target resolves to an address a
// server-side fetch may not reach. Wrapped rather than formatted so a
// caller can recognise it with errors.Is and explain itself instead of
// reporting a generic dial failure. Its message contains "not allowed",
// which callers that classify by string (e.g. an audit action) may rely
// on.
var ErrBlocked = errors.New("target is not allowed")

// metadataIPv6 is AWS's IMDS address over IPv6. The IPv4 one
// (169.254.169.254) needs no entry of its own: it already sits inside
// the link-local range Blocked refuses.
var metadataIPv6 = net.ParseIP("fd00:ec2::254")

// Blocked reports whether ip is one a server-side fetch must not connect
// to, and why. Private ranges and loopback are deliberately allowed:
// refusing them would break the feature for every homelab, where the
// upstream — or the local webhook — IS a private address.
func Blocked(ip net.IP) (bool, string) {
	if ip == nil {
		return true, "address could not be parsed"
	}
	// Covers 169.254.0.0/16 and fe80::/10, so the IPv4 metadata address
	// is already refused here.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true, "link-local address (cloud instance metadata lives there)"
	}
	if ip.Equal(metadataIPv6) {
		return true, "cloud instance metadata address"
	}
	return false, ""
}

// NewDialer returns a net.Dialer that refuses the addresses Blocked
// names. Control is called after resolution with the address about to be
// dialled, once per candidate, so a multi-address or rebound name cannot
// slip an uninspected address past us.
func NewDialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				// Control always receives host:port; a parse failure
				// here means something changed underneath us, so refuse
				// rather than connect to an address we did not inspect.
				return fmt.Errorf("%w: %q could not be read", ErrBlocked, address)
			}
			if blocked, why := Blocked(net.ParseIP(host)); blocked {
				return fmt.Errorf("%w: %s is a %s", ErrBlocked, host, why)
			}
			return nil
		},
	}
}
