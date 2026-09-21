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
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/countryblock"
)

// v2.27 — continents + exceptions reach the Caddy handler block, and a
// country-only config emits exactly what v2.26 emitted.

func TestBuildCountryBlockHandler_CountryOnlyUnchanged(t *testing.T) {
	h := buildCountryBlockHandler("r1", "", countryblock.Config{
		Mode: countryblock.ModeDeny, CountryList: []string{"RU"}, StatusCode: 451,
	})
	got, _ := json.Marshal(h)
	const want = `{"config":{"countryList":["RU"],"mode":"deny","statusCode":451},"handler":"arenet_country_block","routeID":"r1"}`
	if string(got) != want {
		t.Errorf("country-only handler changed:\n got %s\nwant %s", got, want)
	}
}

func TestBuildCountryBlockHandler_EmitsContinentsAndExceptions(t *testing.T) {
	h := buildCountryBlockHandler("r1", "", countryblock.Config{
		Mode: countryblock.ModeDeny, Continents: []string{"AS"},
		Exceptions: &countryblock.Exceptions{Countries: []string{"JP"}},
	})
	got, _ := json.Marshal(h)
	for _, want := range []string{`"continents":["AS"]`, `"exceptions":{"countries":["JP"]}`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
}

func TestCountryBlockFingerprint_StableAndExtended(t *testing.T) {
	base := countryblock.Config{Mode: countryblock.ModeDeny, CountryList: []string{"RU", "CN"}}
	if got := countryBlockFingerprint(base); got != "deny|CN,RU|0" {
		t.Errorf("pre-v2.27 fingerprint changed: %q", got)
	}
	ext := base
	ext.Continents = []string{"SA", "AS"}
	ext.Exceptions = &countryblock.Exceptions{Countries: []string{"JP"}}
	if got := countryBlockFingerprint(ext); got != "deny|CN,RU|0|continents=AS,SA|except=JP" {
		t.Errorf("extended fingerprint = %q", got)
	}
	if base.CountryList[0] != "RU" {
		t.Error("fingerprint mutated the input slice")
	}
}

func TestBuildCountryBlockHandler_EmitsASNs(t *testing.T) {
	h := buildCountryBlockHandler("r1", "", countryblock.Config{
		Mode: countryblock.ModeDeny, ASNs: []uint32{14061},
		Exceptions: &countryblock.Exceptions{ASNs: []uint32{16276}},
	})
	got, _ := json.Marshal(h)
	for _, want := range []string{`"asns":[14061]`, `"exceptions":{"asns":[16276]}`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	fp := countryBlockFingerprint(countryblock.Config{Mode: countryblock.ModeDeny, ASNs: []uint32{9, 3},
		Exceptions: &countryblock.Exceptions{ASNs: []uint32{5}}})
	if fp != "deny||0|asns=3,9|except-asns=5" {
		t.Errorf("fingerprint = %q", fp)
	}
}
