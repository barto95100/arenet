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

	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/waf"
)

// W.4 — EnrichCountryBlock tests + 6th-category no-leakage
// guard.

// TestEnrichCountryBlock_CategoryIsCountryBlock pins the
// per-method category contract: EnrichCountryBlock produces
// Category=="country_block", and the new constant matches
// the spec §5.6 enum value verbatim.
func TestEnrichCountryBlock_CategoryIsCountryBlock(t *testing.T) {
	e := NewEnricher(nil)
	ev := e.EnrichCountryBlock("203.0.113.5", "r-1", "RU", "deny", "deny-match", 403)
	if ev.Category != CategoryCountryBlock {
		t.Errorf("Category = %q; want %q", ev.Category, CategoryCountryBlock)
	}
	if CategoryCountryBlock != "country_block" {
		t.Errorf("CategoryCountryBlock = %q; want \"country_block\" (spec §5.6 enum value)", CategoryCountryBlock)
	}
}

// TestEnrichCountryBlock_FieldsRoundTrip pins the per-field
// contract: every BlockMatch field the W.1 matcher passes
// in lands on the GeoEvent.
func TestEnrichCountryBlock_FieldsRoundTrip(t *testing.T) {
	e := NewEnricher(nil)
	ev := e.EnrichCountryBlock("203.0.113.5", "route-abc", "RU", "deny", "deny-match", 451)

	if ev.SourceIP != "203.0.113.5" {
		t.Errorf("SourceIP = %q; want 203.0.113.5", ev.SourceIP)
	}
	if ev.RouteID != "route-abc" {
		t.Errorf("RouteID = %q; want route-abc", ev.RouteID)
	}
	if ev.SourceCountry != "RU" {
		t.Errorf("SourceCountry = %q; want RU (matcher-supplied wins over enrichBase)", ev.SourceCountry)
	}
	if ev.StatusCode != 451 {
		t.Errorf("StatusCode = %d; want 451", ev.StatusCode)
	}
	if !strings.Contains(ev.Details, "deny") || !strings.Contains(ev.Details, "deny-match") {
		t.Errorf("Details = %q; want both mode + reason", ev.Details)
	}
}

// TestEnrichCountryBlock_EmptyCountry_FallsThroughToEnrichBase
// — when the matcher passes "" (the §D5 fail-open path
// that doesn't currently emit but the contract reserves it
// for future ModeStrict), the enricher falls back to the
// enrichBase result. For a nil-Lookup test enricher,
// enrichBase yields SourceCountry="UNK" — confirm.
func TestEnrichCountryBlock_EmptyCountry_FallsThroughToEnrichBase(t *testing.T) {
	e := NewEnricher(nil)
	ev := e.EnrichCountryBlock("203.0.113.5", "r-1", "", "deny", "deny-match", 403)
	if ev.SourceCountry != countryUnknown {
		t.Errorf("empty country should fall through to enrichBase (UNK); got %q", ev.SourceCountry)
	}
}

// TestEnrichGeoEvent_NoLeakageAcrossCategories pins the
// per-method category isolation: each enricher method
// produces ITS OWN category, never another's. Catches a
// future refactor that accidentally reuses a constant
// across methods (mirror of the pre-W.4 5-category test
// pattern, extended to the 6th).
func TestEnrichGeoEvent_NoLeakageAcrossCategories(t *testing.T) {
	e := NewEnricher(nil)

	wafEv := e.EnrichWAFEvent(waf.Event{SrcIP: "1.2.3.4", RuleID: "942100"})
	if wafEv.Category != CategoryWAF {
		t.Errorf("EnrichWAFEvent leaked category %q; want %q", wafEv.Category, CategoryWAF)
	}

	throttleEv := e.EnrichThrottleEvent(observability.ThrottleEvent{SrcIP: "1.2.3.4"})
	if throttleEv.Category != CategoryThrottle {
		t.Errorf("EnrichThrottleEvent leaked category %q; want %q", throttleEv.Category, CategoryThrottle)
	}

	authEv := e.EnrichAuthEvent(observability.AuthEvent{SrcIP: "1.2.3.4"})
	if authEv.Category != CategoryAuth {
		t.Errorf("EnrichAuthEvent leaked category %q; want %q", authEv.Category, CategoryAuth)
	}

	cbEv := e.EnrichCountryBlock("1.2.3.4", "r", "RU", "deny", "deny-match", 403)
	if cbEv.Category != CategoryCountryBlock {
		t.Errorf("EnrichCountryBlock leaked category %q; want %q", cbEv.Category, CategoryCountryBlock)
	}

	normalEv := e.EnrichNormal("1.2.3.4", "r", 200)
	if normalEv.Category != CategoryNormal {
		t.Errorf("EnrichNormal leaked category %q; want %q", normalEv.Category, CategoryNormal)
	}

	crowdEv := e.EnrichCrowdsecDecision(observability.DecisionEvent{Scope: "ip", Value: "1.2.3.4"})
	if crowdEv.Category != CategoryCrowdSec {
		t.Errorf("EnrichCrowdsecDecision leaked category %q; want %q", crowdEv.Category, CategoryCrowdSec)
	}

	// And the 6-value enum is exhaustive — each constant
	// is distinct (no copy-paste duplicate).
	all := []string{CategoryNormal, CategoryThrottle, CategoryWAF, CategoryCrowdSec, CategoryAuth, CategoryCountryBlock}
	seen := make(map[string]bool, 6)
	for _, c := range all {
		if seen[c] {
			t.Errorf("category constant %q duplicated in the enum", c)
		}
		seen[c] = true
	}
	if len(seen) != 6 {
		t.Errorf("expected 6 distinct category constants; got %d", len(seen))
	}
}
