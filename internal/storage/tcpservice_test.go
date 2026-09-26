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

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// v2.42 — TCP (layer 4) services: storage round trip + validation.
//
// The validation cases are the contract the API leans on, so they are
// pinned one by one rather than through a single "invalid" example.

func validTCPService() TCPService {
	return TCPService{
		Name:       "stalwart-imaps",
		ListenPort: 993,
		Upstreams: []TCPUpstream{
			{Host: "10.20.0.5", Port: 993},
		},
		ProxyProtocol: ProxyProtocolV2,
	}
}

func TestTCPService_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := validTCPService()
	in.ListenAddr = "192.168.1.10"
	in.LBPolicy = TCPLBLeastConn
	in.CrowdSecEnabled = true
	in.HealthCheck = &TCPHealthCheck{Enabled: true, Interval: "30s", Timeout: "5s"}
	in.IPFilter = &IPFilter{Mode: IPFilterModeAllow, CIDRs: []string{"192.168.1.0/24"}}

	created, err := s.CreateTCPService(ctx, in)
	if err != nil {
		t.Fatalf("CreateTCPService: %v", err)
	}
	if created.ID == "" {
		t.Fatal("CreateTCPService: expected an assigned id")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatal("CreateTCPService: expected timestamps")
	}

	got, err := s.GetTCPService(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetTCPService: %v", err)
	}
	if got.Name != in.Name || got.ListenPort != 993 || got.ListenAddr != "192.168.1.10" {
		t.Fatalf("GetTCPService: identity not preserved: %+v", got)
	}
	if got.ProxyProtocol != ProxyProtocolV2 || got.LBPolicy != TCPLBLeastConn || !got.CrowdSecEnabled {
		t.Fatalf("GetTCPService: gates not preserved: %+v", got)
	}
	if got.HealthCheck == nil || !got.HealthCheck.Enabled || got.HealthCheck.Interval != "30s" {
		t.Fatalf("GetTCPService: health check not preserved: %+v", got.HealthCheck)
	}
	if got.IPFilter == nil || got.IPFilter.Mode != IPFilterModeAllow ||
		len(got.IPFilter.CIDRs) != 1 || got.IPFilter.CIDRs[0] != "192.168.1.0/24" {
		t.Fatalf("GetTCPService: ip filter not preserved: %+v", got.IPFilter)
	}
	if got.Upstreams[0].Dial() != "10.20.0.5:993" {
		t.Fatalf("Dial: got %q", got.Upstreams[0].Dial())
	}
}

func TestTCPService_UpdatePreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	created, err := s.CreateTCPService(ctx, validTCPService())
	if err != nil {
		t.Fatalf("CreateTCPService: %v", err)
	}

	created.Name = "stalwart-imaps-renamed"
	updated, err := s.UpdateTCPService(ctx, created)
	if err != nil {
		t.Fatalf("UpdateTCPService: %v", err)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Fatalf("UpdateTCPService: CreatedAt changed: %v → %v", created.CreatedAt, updated.CreatedAt)
	}
	if updated.Name != "stalwart-imaps-renamed" {
		t.Fatalf("UpdateTCPService: name not applied: %q", updated.Name)
	}
}

func TestTCPService_NotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.GetTCPService(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetTCPService: want ErrNotFound, got %v", err)
	}
	if err := s.DeleteTCPService(ctx, "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteTCPService: want ErrNotFound, got %v", err)
	}
	svc := validTCPService()
	svc.ID = "does-not-exist"
	if _, err := s.UpdateTCPService(ctx, svc); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateTCPService: want ErrNotFound, got %v", err)
	}
}

// The emitted Caddy config must not depend on BoltDB's iteration
// order, so the list is sorted by name.
func TestTCPService_ListIsOrdered(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, name := range []string{"smtp", "imaps", "managesieve"} {
		svc := validTCPService()
		svc.Name = name
		if _, err := s.CreateTCPService(ctx, svc); err != nil {
			t.Fatalf("CreateTCPService(%s): %v", name, err)
		}
	}

	list, err := s.ListTCPServices(ctx)
	if err != nil {
		t.Fatalf("ListTCPServices: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListTCPServices: want 3, got %d", len(list))
	}
	if list[0].Name != "imaps" || list[1].Name != "managesieve" || list[2].Name != "smtp" {
		t.Fatalf("ListTCPServices: not ordered by name: %v", []string{list[0].Name, list[1].Name, list[2].Name})
	}
}

// A store with no service must expose an empty list, not nil — the
// emitter branches on the length, and the API marshals it as [].
func TestTCPService_ListEmpty(t *testing.T) {
	s := newTestStore(t)
	list, err := s.ListTCPServices(context.Background())
	if err != nil {
		t.Fatalf("ListTCPServices: %v", err)
	}
	if list == nil || len(list) != 0 {
		t.Fatalf("ListTCPServices: want empty non-nil slice, got %#v", list)
	}
}

func TestTCPService_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*TCPService)
		wantErr string
	}{
		{"valid", func(*TCPService) {}, ""},
		{"empty name", func(s *TCPService) { s.Name = "   " }, "name must not be empty"},
		{"long name", func(s *TCPService) { s.Name = strings.Repeat("a", 65) }, "64 characters"},
		{"bad listen addr", func(s *TCPService) { s.ListenAddr = "not-an-ip" }, "not an IP address"},
		{"listen port zero", func(s *TCPService) { s.ListenPort = 0 }, "out of range"},
		{"listen port too high", func(s *TCPService) { s.ListenPort = 70000 }, "out of range"},
		{"no backend", func(s *TCPService) { s.Upstreams = nil }, "at least one backend"},
		{"backend without host", func(s *TCPService) { s.Upstreams[0].Host = " " }, "host must not be empty"},
		{"backend bad port", func(s *TCPService) { s.Upstreams[0].Port = 0 }, "out of range"},
		{"negative max connections", func(s *TCPService) { s.Upstreams[0].MaxConnections = -1 }, "max_connections"},
		{
			"duplicate backend",
			func(s *TCPService) {
				s.Upstreams = append(s.Upstreams, TCPUpstream{Host: "10.20.0.5", Port: 993})
			},
			"listed twice",
		},
		{"unknown lb policy", func(s *TCPService) { s.LBPolicy = "weighted_round_robin" }, "not supported"},
		{"bad proxy protocol", func(s *TCPService) { s.ProxyProtocol = "v3" }, "proxy_protocol"},
		{"proxy protocol off is valid", func(s *TCPService) { s.ProxyProtocol = ProxyProtocolOff }, ""},
		{
			"bad health-check interval",
			func(s *TCPService) { s.HealthCheck = &TCPHealthCheck{Enabled: true, Interval: "soon"} },
			"is not a duration",
		},
		{
			"zero health-check timeout",
			func(s *TCPService) { s.HealthCheck = &TCPHealthCheck{Enabled: true, Timeout: "0s"} },
			"must be > 0",
		},
		{
			"disabled health check is not validated",
			func(s *TCPService) { s.HealthCheck = &TCPHealthCheck{Enabled: false, Interval: "soon"} },
			"",
		},
		{
			"bad ip filter",
			func(s *TCPService) {
				s.IPFilter = &IPFilter{Mode: IPFilterModeAllow, CIDRs: []string{"not-a-cidr"}}
			},
			"tcp service:",
		},
		{
			"allow filter with no cidr",
			func(s *TCPService) { s.IPFilter = &IPFilter{Mode: IPFilterModeDeny} },
			"tcp service:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := validTCPService()
			tc.mutate(&svc)
			err := svc.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("Validate: unexpected error %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("Validate: want error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("Validate: want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

// Validate trims in place: the stored row must not carry the
// operator's stray spaces into the emitted Caddy config.
func TestTCPService_ValidateTrims(t *testing.T) {
	svc := validTCPService()
	svc.Name = "  imaps  "
	svc.ListenAddr = " 10.0.0.1 "
	svc.Upstreams[0].Host = " 10.20.0.5 "

	if err := svc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if svc.Name != "imaps" || svc.ListenAddr != "10.0.0.1" || svc.Upstreams[0].Host != "10.20.0.5" {
		t.Fatalf("Validate: not trimmed: %+v", svc)
	}
}

func TestTCPService_ListenHostPort(t *testing.T) {
	svc := validTCPService()
	if got := svc.ListenHostPort(); got != "0.0.0.0:993" {
		t.Fatalf("ListenHostPort: empty addr should mean every interface, got %q", got)
	}
	svc.ListenAddr = "::1"
	if got := svc.ListenHostPort(); got != "[::1]:993" {
		t.Fatalf("ListenHostPort: IPv6 must be bracketed, got %q", got)
	}
}

// v2.42 — UDP. The guards are the interesting part: two pairings are
// refused because caddy-l4 cannot honour them, and saying so beats
// emitting a relay that silently does nothing useful.
func TestTCPService_UDP(t *testing.T) {
	svc := validTCPService()
	svc.Protocol = TCPServiceProtocolUDP
	svc.ListenPort = 51820
	svc.ProxyProtocol = ProxyProtocolV2
	if err := svc.Validate(); err != nil {
		t.Fatalf("a UDP relay with PROXY v2 is valid: %v", err)
	}
	if svc.Network() != TCPServiceProtocolUDP {
		t.Fatalf("Network: got %q", svc.Network())
	}
	if got := svc.ListenAddress(); got != "udp/0.0.0.0:51820" {
		t.Fatalf("ListenAddress: got %q", got)
	}
	if got := svc.DialAddress(svc.Upstreams[0]); got != "udp/10.20.0.5:993" {
		t.Fatalf("DialAddress: got %q", got)
	}

	// PROXY v1 has no UDP address family.
	v1 := svc
	v1.ProxyProtocol = ProxyProtocolV1
	if err := v1.Validate(); err == nil || !strings.Contains(err.Error(), "v1") {
		t.Fatalf("PROXY v1 over UDP must be refused, got %v", err)
	}

	// An active health check over UDP would never fail.
	hc := svc
	hc.HealthCheck = &TCPHealthCheck{Enabled: true, Interval: "30s"}
	if err := hc.Validate(); err == nil || !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("an active health check over UDP must be refused, got %v", err)
	}

	bad := validTCPService()
	bad.Protocol = "sctp"
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("an unknown protocol must be refused, got %v", err)
	}

	// Default: an empty protocol is TCP, and TCP keeps its prefix.
	def := validTCPService()
	if def.Network() != TCPServiceProtocolTCP || def.ListenAddress() != "tcp/0.0.0.0:993" {
		t.Fatalf("empty protocol must mean tcp: %q / %q", def.Network(), def.ListenAddress())
	}
}
