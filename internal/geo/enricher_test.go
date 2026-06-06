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

package geo

import (
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/waf"
)

// We test against a nil Lookup (degraded mode) and against a
// real-MMDB-free path that exercises only the LAN code path.
// The end-to-end MMDB-backed enrichment is covered by V.1's
// TestLookupIP_RealMMDB; the enricher unit tests focus on the
// translation layer's category mapping + sentinel handling.

func TestEnrichWAFEvent_NilLookup_Degraded(t *testing.T) {
	e := NewEnricher(nil)
	ts := time.Now().UTC()
	got := e.EnrichWAFEvent(waf.Event{
		Ts:      ts,
		SrcIP:   "8.8.8.8",
		RouteID: "r-1",
		RuleID:  "942100",
	})
	if got.Category != CategoryWAF {
		t.Errorf("Category = %q, want %q", got.Category, CategoryWAF)
	}
	if got.SourceIP != "8.8.8.8" {
		t.Errorf("SourceIP = %q, want 8.8.8.8", got.SourceIP)
	}
	if got.SourceCountry != countryUnknown {
		t.Errorf("SourceCountry = %q, want %q", got.SourceCountry, countryUnknown)
	}
	if got.SourceLat != 0 || got.SourceLon != 0 {
		t.Errorf("expected zero lat/lon in degraded mode, got %v/%v", got.SourceLat, got.SourceLon)
	}
	if got.IsLAN {
		t.Error("expected IsLAN=false for public IP, got true")
	}
	if got.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", got.StatusCode)
	}
	if got.Details != "942100" {
		t.Errorf("Details = %q, want rule id", got.Details)
	}
	if got.RouteID != "r-1" {
		t.Errorf("RouteID = %q, want r-1", got.RouteID)
	}
	if !got.Timestamp.Equal(ts) {
		t.Errorf("Timestamp = %v, want %v (pass-through)", got.Timestamp, ts)
	}
}

func TestEnrichWAFEvent_LANSource(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichWAFEvent(waf.Event{
		Ts:    time.Now().UTC(),
		SrcIP: "192.168.1.42",
	})
	if !got.IsLAN {
		t.Errorf("expected IsLAN=true for RFC1918, got false; full event: %+v", got)
	}
	if got.SourceCountry != countryUnknown {
		t.Errorf("LAN source should have SourceCountry=UNK, got %q", got.SourceCountry)
	}
	if got.SourceLat != 0 || got.SourceLon != 0 {
		t.Errorf("LAN source should have zero lat/lon, got %v/%v", got.SourceLat, got.SourceLon)
	}
}

func TestEnrichWAFEvent_InvalidIP(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichWAFEvent(waf.Event{
		Ts:    time.Now().UTC(),
		SrcIP: "not-an-ip",
	})
	if got.SourceCountry != countryUnknown {
		t.Errorf("invalid IP → SourceCountry should be UNK, got %q", got.SourceCountry)
	}
	if got.IsLAN {
		t.Error("invalid IP must not set IsLAN")
	}
}

func TestEnrichThrottleEvent_BasicMapping(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichThrottleEvent(observability.ThrottleEvent{
		Ts:                time.Now().UTC(),
		SrcIP:             "10.0.0.1",
		AttemptedUsername: "root",
		Tier:              2,
	})
	if got.Category != CategoryThrottle {
		t.Errorf("Category = %q, want %q", got.Category, CategoryThrottle)
	}
	if got.Details != "root" {
		t.Errorf("Details = %q, want username", got.Details)
	}
	if got.StatusCode != 429 {
		t.Errorf("StatusCode = %d, want 429", got.StatusCode)
	}
	if !got.IsLAN {
		t.Error("expected IsLAN=true for RFC1918")
	}
}

func TestEnrichCrowdsecDecision_IPScope(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichCrowdsecDecision(observability.DecisionEvent{
		Ts:       time.Now().UTC(),
		Scope:    "ip",
		Value:    "8.8.8.8",
		Type:     "ban",
		Scenario: "crowdsecurity/http-probing",
	})
	if got.Category != CategoryCrowdSec {
		t.Errorf("Category = %q, want %q", got.Category, CategoryCrowdSec)
	}
	if got.SourceIP != "8.8.8.8" {
		t.Errorf("SourceIP = %q, want 8.8.8.8 (ip scope)", got.SourceIP)
	}
	if got.Details != "crowdsecurity/http-probing" {
		t.Errorf("Details = %q, want scenario name", got.Details)
	}
	if got.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", got.StatusCode)
	}
}

func TestEnrichCrowdsecDecision_NonIPScope_Degraded(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichCrowdsecDecision(observability.DecisionEvent{
		Ts:       time.Now().UTC(),
		Scope:    "country",
		Value:    "RU",
		Scenario: "manual",
	})
	if got.SourceIP != "" {
		t.Errorf("non-ip scope should yield empty SourceIP, got %q", got.SourceIP)
	}
	if got.SourceCountry != countryUnknown {
		t.Errorf("non-ip scope → SourceCountry=UNK, got %q", got.SourceCountry)
	}
	if !strings.Contains(got.Details, "country:RU") {
		t.Errorf("Details should encode scope+value for non-ip scopes, got %q", got.Details)
	}
}

func TestEnrichAuthEvent_LoginFailure(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichAuthEvent(observability.AuthEvent{
		Ts:       time.Now().UTC(),
		Kind:     observability.AuthEventKindLoginFailure,
		SrcIP:    "1.2.3.4",
		Username: "admin",
	})
	if got.Category != CategoryAuth {
		t.Errorf("Category = %q, want %q", got.Category, CategoryAuth)
	}
	if got.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401 (login_failure → 401)", got.StatusCode)
	}
	if !strings.Contains(got.Details, "login_failure") {
		t.Errorf("Details = %q, want to contain kind", got.Details)
	}
	if !strings.Contains(got.Details, "admin") {
		t.Errorf("Details = %q, want to contain username", got.Details)
	}
}

func TestEnrichAuthEvent_Forbidden_403(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichAuthEvent(observability.AuthEvent{
		Ts:    time.Now().UTC(),
		Kind:  observability.AuthEventKindForbidden,
		SrcIP: "1.2.3.4",
	})
	if got.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403 (forbidden → 403)", got.StatusCode)
	}
}

func TestEnrichAuthEvent_SessionExpired_401(t *testing.T) {
	e := NewEnricher(nil)
	got := e.EnrichAuthEvent(observability.AuthEvent{
		Ts:    time.Now().UTC(),
		Kind:  observability.AuthEventKindSessionExpired,
		SrcIP: "1.2.3.4",
	})
	if got.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401 (session_expired → 401)", got.StatusCode)
	}
}

func TestEnricher_HasLookup(t *testing.T) {
	if (NewEnricher(nil)).HasLookup() {
		t.Error("nil lookup should report HasLookup=false")
	}
	var nilEnricher *Enricher
	if nilEnricher.HasLookup() {
		t.Error("nil enricher should report HasLookup=false")
	}
}

func TestTruncateDetails_UnderCap(t *testing.T) {
	s := "short"
	if got := truncateDetails(s); got != s {
		t.Errorf("under-cap input changed: %q", got)
	}
}

func TestTruncateDetails_OverCap(t *testing.T) {
	long := strings.Repeat("x", detailsMaxBytes+50)
	got := truncateDetails(long)
	if !strings.HasSuffix(got, "…") {
		t.Errorf("expected ellipsis suffix, got %q", got[len(got)-10:])
	}
	// Cap is on the byte prefix, ellipsis is extra.
	if len(got) > detailsMaxBytes+len("…") {
		t.Errorf("len(got) = %d, want <= %d", len(got), detailsMaxBytes+len("…"))
	}
}

func TestEnrichWAFEvent_TimestampPassesThrough(t *testing.T) {
	e := NewEnricher(nil)
	ts := time.Date(2026, 6, 6, 14, 0, 0, 0, time.UTC)
	got := e.EnrichWAFEvent(waf.Event{Ts: ts, SrcIP: "1.1.1.1"})
	if !got.Timestamp.Equal(ts) {
		t.Errorf("timestamp not preserved: got %v want %v", got.Timestamp, ts)
	}
}
