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

// Step X.1 (2026-06-17) storage tests — Route.WAFDisableCRS field.
//
// Pins the BoltDB roundtrip + the pre-X.1-byte-equivalent default
// (zero-value false = "CRS loaded"). ADR D5 captures the no-
// migration rationale : the inverted-polarity field gives the
// right pre-X.1 runtime semantics for free at decode time.

func TestRoute_WAFDisableCRS_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "nas.lan",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:8080", Weight: 1},
		},
		LBPolicy:      LBPolicyRoundRobin,
		AuthMode:      "none",
		WAFMode:       "detect",
		WAFDisableCRS: true,
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, err := s.GetRoute(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetRoute: %v", err)
	}
	if !got.WAFDisableCRS {
		t.Errorf("WAFDisableCRS = false after roundtrip; want true")
	}
}

func TestRoute_WAFDisableCRS_DefaultsFalse(t *testing.T) {
	// Pre-X.1 byte-equivalence : zero-value WAFDisableCRS
	// persists as false ("CRS loaded"). Pre-X.1 stored rows
	// decode through the JSON zero-fill path to the same
	// runtime state — no boot migration needed (ADR D5).
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "api.default.local",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.20:8080", Weight: 1},
		},
		LBPolicy: LBPolicyRoundRobin,
		AuthMode: "none",
		WAFMode:  "detect",
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if got.WAFDisableCRS {
		t.Errorf("WAFDisableCRS = true on default Route; want false (pre-X.1 byte-equivalent)")
	}
}

func TestRoute_WAFDisableCRS_CoExistsWithUploadStreaming(t *testing.T) {
	// The two flags are independent — both can be true on a
	// trusted internal upload route ("internal artefact registry
	// that I want to stay observable but doesn't need the CRS
	// scrutiny"). Pin the orthogonality so a future change
	// doesn't accidentally couple them.
	s := newTestStore(t)
	ctx := context.Background()

	r := Route{
		Host: "registry.internal",
		Upstreams: []Upstream{
			{URL: "http://192.168.1.50:5000", Weight: 1},
		},
		LBPolicy:            LBPolicyRoundRobin,
		AuthMode:            "none",
		WAFMode:             "detect",
		UploadStreamingMode: true,
		WAFDisableCRS:       true,
	}
	created, err := s.CreateRoute(ctx, r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	got, _ := s.GetRoute(ctx, created.ID)
	if !got.UploadStreamingMode || !got.WAFDisableCRS {
		t.Errorf("orthogonal flags clobbered: streaming=%v disableCRS=%v",
			got.UploadStreamingMode, got.WAFDisableCRS)
	}
}
