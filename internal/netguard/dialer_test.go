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

package netguard

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestBlocked(t *testing.T) {
	blocked := []string{
		"169.254.169.254", // IMDS on every major provider (IPv4 link-local)
		"169.254.0.1",
		"169.254.255.254",
		"fe80::1",       // IPv6 link-local
		"fd00:ec2::254", // AWS IMDS over IPv6
	}
	for _, addr := range blocked {
		if ok, _ := Blocked(net.ParseIP(addr)); !ok {
			t.Errorf("Blocked(%s) = false; a server-side fetch must refuse it", addr)
		}
	}

	// Private + loopback stay reachable — a homelab upstream / webhook
	// is often one of these; refusing them would break the feature.
	allowed := []string{
		"10.0.4.12", "172.16.9.9", "192.168.1.50", "127.0.0.1", "::1",
		"203.0.113.9", // ordinary public
	}
	for _, addr := range allowed {
		if ok, why := Blocked(net.ParseIP(addr)); ok {
			t.Errorf("Blocked(%s) = true (%s); it must stay reachable", addr, why)
		}
	}

	if ok, _ := Blocked(nil); !ok {
		t.Error("Blocked(nil) = false; an unparseable address must be refused")
	}
}

func TestErrBlocked_MentionsNotAllowed(t *testing.T) {
	// Callers that classify a refusal by string (the probe audit action)
	// key on this substring; keep it stable.
	if !strings.Contains(ErrBlocked.Error(), "not allowed") {
		t.Errorf("ErrBlocked = %q; must contain \"not allowed\"", ErrBlocked.Error())
	}
}

func TestNewDialer_RefusesMetadataAtDial(t *testing.T) {
	cases := []string{
		net.JoinHostPort("169.254.169.254", "80"), // IPv4 IMDS
		net.JoinHostPort("fd00:ec2::254", "80"),   // IPv6 IMDS
		net.JoinHostPort("fe80::1", "80"),         // IPv6 link-local
	}
	d := NewDialer(2 * time.Second)
	for _, target := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := d.DialContext(ctx, "tcp", target)
		cancel()
		if err == nil {
			t.Errorf("dial to %s succeeded; it must be refused before connecting", target)
			continue
		}
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("dial to %s: err = %v; must wrap ErrBlocked so the caller can explain itself", target, err)
		}
	}
}
