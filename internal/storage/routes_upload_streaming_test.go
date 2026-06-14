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
	"context"
	"testing"
)

// Phase 4.5 storage tests — Route.UploadStreamingMode field.
// Pins the roundtrip + the operator-safer default (false).

func TestRoute_UploadStreamingMode_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "registry.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:5000", Weight: 1},
		},
		LBPolicy:            LBPolicyRoundRobin,
		AuthMode:            "none",
		UploadStreamingMode: true,
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !got.UploadStreamingMode {
		t.Errorf("UploadStreamingMode = false after roundtrip; want true")
	}
}

func TestRoute_UploadStreamingMode_DefaultsFalse(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Operator does not set UploadStreamingMode — zero-value
	// false should persist. Default posture is "WAF body
	// inspection + Caddy buffering both active", same as
	// before this feature landed.
	r := Route{
		Host: "api.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.20:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if got.UploadStreamingMode {
		t.Errorf("UploadStreamingMode = true on default Route; want false")
	}
}

func TestRoute_UploadStreamingMode_CoExistsWithWAFAndInsecureSkip(t *testing.T) {
	// A registry-style route typically wants UploadStreaming
	// + WAF=detect + HTTPS upstream + InsecureSkipVerify (self-
	// signed registry cert). The combo must persist cleanly —
	// no field clobbers another.
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "registry.local",
		Upstreams: []Upstream{
			{URL: "https://192.168.1.50:5000", Weight: 1},
		},
		LBPolicy:            LBPolicyRoundRobin,
		AuthMode:            "none",
		WAFMode:             "detect",
		InsecureSkipVerify:  true,
		UploadStreamingMode: true,
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if !got.UploadStreamingMode {
		t.Error("UploadStreamingMode flipped to false during roundtrip")
	}
	if !got.InsecureSkipVerify {
		t.Error("InsecureSkipVerify flipped during roundtrip")
	}
	if got.WAFMode != "detect" {
		t.Errorf("WAFMode = %q after roundtrip, want detect", got.WAFMode)
	}
}
