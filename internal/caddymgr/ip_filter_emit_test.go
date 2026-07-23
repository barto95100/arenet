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

package caddymgr

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func TestBuildIPFilterRoute_Inactive(t *testing.T) {
	if buildIPFilterRoute(storage.IPFilter{Mode: "off"}) != nil {
		t.Fatal("off must emit nil")
	}
	if buildIPFilterRoute(storage.IPFilter{Mode: ""}) != nil {
		t.Fatal("empty must emit nil")
	}
}

func TestBuildIPFilterRoute_AllowFailsClosed(t *testing.T) {
	// allow mode: block everything NOT in the list → the matcher MUST be
	// a `not` wrapping client_ip, so a client outside the list is denied.
	r := buildIPFilterRoute(storage.IPFilter{Mode: "allow", CIDRs: []string{"192.168.1.5"}})
	m := r["match"].([]map[string]any)[0]
	if _, hasNot := m["not"]; !hasNot {
		t.Fatalf("allow mode MUST use a `not` matcher (fail-closed), got %v", m)
	}
	// the not wraps client_ip with the normalized CIDR (/32 for a bare IP)
	notSets := m["not"].([]map[string]any)
	clientIP := notSets[0]["client_ip"].(map[string]any)
	ranges := clientIP["ranges"].([]string)
	if len(ranges) != 1 || ranges[0] != "192.168.1.5/32" {
		t.Fatalf("expected client_ip ranges [192.168.1.5/32], got %v", ranges)
	}
	sr := r["handle"].([]map[string]any)[0]
	if sr["handler"] != "static_response" {
		t.Fatalf("expected static_response, got %v", sr)
	}
	if int(sr["status_code"].(int)) != 403 {
		t.Fatalf("default block status must be 403, got %v", sr["status_code"])
	}
}

func TestBuildIPFilterRoute_DenyBlocksListed(t *testing.T) {
	// deny mode: block clients IN the list → matcher is client_ip (no not).
	r := buildIPFilterRoute(storage.IPFilter{Mode: "deny", CIDRs: []string{"10.0.0.0/8"}, StatusCode: 444})
	m := r["match"].([]map[string]any)[0]
	if _, hasNot := m["not"]; hasNot {
		t.Fatalf("deny mode must NOT use `not`, got %v", m)
	}
	ranges := m["client_ip"].(map[string]any)["ranges"].([]string)
	if ranges[0] != "10.0.0.0/8" {
		t.Fatalf("expected 10.0.0.0/8, got %v", ranges)
	}
	if int(r["handle"].([]map[string]any)[0]["status_code"].(int)) != 444 {
		t.Fatal("status override 444 not applied")
	}
}
