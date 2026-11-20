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

package automation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fakeGeoEnricher struct{ cn, asNumber, asName string }

func (f fakeGeoEnricher) EnrichSource(string) (string, string, string) {
	return f.cn, f.asNumber, f.asName
}

// TestBuildAlert_GeoEnrichment is G2: with an enricher, the alert source
// carries cn/as_number/as_name; with a nil enricher they stay empty
// (soft-fail / non-regression). Reinjecting "ignore the enricher" fails the
// populated case; a hard-fail on nil would fail the nil case.
func TestBuildAlert_GeoEnrichment(t *testing.T) {
	intent := Intent{SrcIP: "185.23.40.4", Source: SourceWafRCE, DurationSeconds: 3600, TriggeringEventCount: 4}
	now := time.Now()

	withGeo := buildAlert(intent, now, fakeGeoEnricher{cn: "NL", asNumber: "15169", asName: "GOOGLE"})
	if withGeo.Source.Cn != "NL" || withGeo.Source.AsNumber != "15169" || withGeo.Source.AsName != "GOOGLE" {
		t.Errorf("enriched source = %+v, want cn=NL as_number=15169 as_name=GOOGLE", withGeo.Source)
	}

	noGeo := buildAlert(intent, now, nil)
	if noGeo.Source.Cn != "" || noGeo.Source.AsNumber != "" || noGeo.Source.AsName != "" {
		t.Errorf("nil-enricher source = %+v, want empty geo fields (soft-fail)", noGeo.Source)
	}
}

// TestBuildAlert_GeoEnrichment_Wire is G3: assert on what LAPI actually
// receives — the marshaled JSON carries cn/as_number/as_name when enriched and
// omits them (omitempty) when not, so a pre-v2.84.0 push is byte-identical.
func TestBuildAlert_GeoEnrichment_Wire(t *testing.T) {
	intent := Intent{SrcIP: "185.23.40.4", Source: SourceWafRCE, DurationSeconds: 3600, TriggeringEventCount: 4}
	now := time.Now()

	enriched, err := json.Marshal(buildAlert(intent, now, fakeGeoEnricher{cn: "NL", asNumber: "15169", asName: "GOOGLE"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"cn":"NL"`, `"as_number":"15169"`, `"as_name":"GOOGLE"`} {
		if !strings.Contains(string(enriched), want) {
			t.Errorf("enriched JSON missing %s\n%s", want, enriched)
		}
	}

	plain, err := json.Marshal(buildAlert(intent, now, nil))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, absent := range []string{`"cn"`, `"as_number"`, `"as_name"`} {
		if strings.Contains(string(plain), absent) {
			t.Errorf("nil-enricher JSON should omit %s (omitempty)\n%s", absent, plain)
		}
	}
}
