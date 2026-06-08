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
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

// W.4 widened the BlockSink seam from a 4-arg Submit to
// Submit(BlockMatch). These tests pin that the Handler
// constructs the BlockMatch with the right Mode + Reason +
// Timestamp — the new fields the sink relies on for
// activity-log persistence (W.4) and the frontend tooltip
// (W.5).

// TestServeHTTP_BlockSinkMatch_CarriesModeAndReason — a
// deny-mode block fires the sink with Mode="deny" +
// Reason="deny-match". A future regression that drops
// Mode (e.g. an accidental `string("")` on the wrong
// field) breaks this assertion immediately.
func TestServeHTTP_BlockSinkMatch_CarriesModeAndReason(t *testing.T) {
	t.Cleanup(ResetGlobalsForTest)
	ResetGlobalsForTest()
	SetGlobalLookup(&mapLookup{m: map[string]string{"1.2.3.4": "RU"}})
	SetGlobalDefaultStatusCode(451)

	sink := &recordingSink{}
	SetGlobalBlockSink(sink)

	h := &Handler{
		Config:  Config{Mode: ModeDeny, CountryList: []string{"RU"}, StatusCode: 451},
		RouteID: "route-uuid",
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	before := time.Now().UTC().Add(-1 * time.Second)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, newRequest(t, "1.2.3.4"), &nextHandlerAdapter{inner: &nextCalled{}}); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	after := time.Now().UTC().Add(1 * time.Second)

	matches := sink.snapshotFull()
	if len(matches) != 1 {
		t.Fatalf("expected 1 BlockMatch; got %d", len(matches))
	}
	m := matches[0]
	if m.RouteID != "route-uuid" {
		t.Errorf("RouteID = %q; want route-uuid", m.RouteID)
	}
	if m.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP = %q; want 1.2.3.4", m.SourceIP)
	}
	if m.Country != "RU" {
		t.Errorf("Country = %q; want RU", m.Country)
	}
	if m.Mode != string(ModeDeny) {
		t.Errorf("Mode = %q; want %q", m.Mode, ModeDeny)
	}
	if m.StatusCode != 451 {
		t.Errorf("StatusCode = %d; want 451", m.StatusCode)
	}
	if m.Reason != ReasonDenyMatch {
		t.Errorf("Reason = %q; want %q", m.Reason, ReasonDenyMatch)
	}
	if m.Timestamp.Before(before) || m.Timestamp.After(after) {
		t.Errorf("Timestamp = %v; want within [%v, %v]", m.Timestamp, before, after)
	}
}

// TestServeHTTP_BlockSinkMatch_AllowMiss — an allow-mode
// route blocking a country NOT in its list should pass
// Mode="allow" + Reason="allow-miss".
func TestServeHTTP_BlockSinkMatch_AllowMiss(t *testing.T) {
	t.Cleanup(ResetGlobalsForTest)
	ResetGlobalsForTest()
	SetGlobalLookup(&mapLookup{m: map[string]string{"1.2.3.4": "RU"}})
	SetGlobalDefaultStatusCode(403)

	sink := &recordingSink{}
	SetGlobalBlockSink(sink)

	h := &Handler{
		Config:  Config{Mode: ModeAllow, CountryList: []string{"FR", "DE"}},
		RouteID: "route-uuid",
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, newRequest(t, "1.2.3.4"), &nextHandlerAdapter{inner: &nextCalled{}}); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	matches := sink.snapshotFull()
	if len(matches) != 1 {
		t.Fatalf("expected 1 BlockMatch; got %d", len(matches))
	}
	m := matches[0]
	if m.Mode != string(ModeAllow) {
		t.Errorf("Mode = %q; want %q", m.Mode, ModeAllow)
	}
	if m.Reason != ReasonAllowMiss {
		t.Errorf("Reason = %q; want %q", m.Reason, ReasonAllowMiss)
	}
}
