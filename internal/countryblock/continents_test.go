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

package countryblock

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// v2.27 — continents + deny-mode exceptions.

const publicIP = "203.0.113.7" // TEST-NET-3: not LAN, not trusted

func TestEvaluateGeo_ContinentsAndExceptions(t *testing.T) {
	asiaDeny := Config{Mode: ModeDeny, Continents: []string{"AS"},
		Exceptions: &Exceptions{Countries: []string{"JP"}}}
	cases := []struct {
		name       string
		cfg        Config
		geo        GeoInfo
		wantAccept bool
		wantReason string
	}{
		{"deny continent blocks", asiaDeny, GeoInfo{Country: "CN", Continent: "AS"}, false, ReasonDenyMatch},
		{"deny exception wins over continent", asiaDeny, GeoInfo{Country: "JP", Continent: "AS"}, true, ReasonException},
		{"deny other continent passes", asiaDeny, GeoInfo{Country: "FR", Continent: "EU"}, true, ReasonDenyMiss},
		{"deny continent + country list", Config{Mode: ModeDeny, CountryList: []string{"RU"}, Continents: []string{"SA"}},
			GeoInfo{Country: "RU", Continent: "EU"}, false, ReasonDenyMatch},
		{"allow continent accepts", Config{Mode: ModeAllow, Continents: []string{"EU"}},
			GeoInfo{Country: "DE", Continent: "EU"}, true, ReasonAllowMatch},
		{"allow continent rejects others", Config{Mode: ModeAllow, Continents: []string{"EU"}},
			GeoInfo{Country: "US", Continent: "NA"}, false, ReasonAllowMiss},
		{"allow country OR continent", Config{Mode: ModeAllow, CountryList: []string{"CA"}, Continents: []string{"EU"}},
			GeoInfo{Country: "CA", Continent: "NA"}, true, ReasonAllowMatch},
		{"continent only resolved still evaluates", Config{Mode: ModeDeny, Continents: []string{"AS"}},
			GeoInfo{Continent: "AS"}, false, ReasonDenyMatch},
		{"nothing resolved fails open", asiaDeny, GeoInfo{}, true, ReasonLookupFailed},
		{"country-only config ignores continent", Config{Mode: ModeDeny, CountryList: []string{"CN"}},
			GeoInfo{Country: "JP", Continent: "AS"}, true, ReasonDenyMiss},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := EvaluateGeo(tc.cfg, tc.geo, publicIP, nil)
			if d.Accepted != tc.wantAccept || d.Reason != tc.wantReason {
				t.Errorf("got accepted=%v reason=%q, want %v %q", d.Accepted, d.Reason, tc.wantAccept, tc.wantReason)
			}
		})
	}
}

func TestEvaluate_CountryOnlyUnchanged(t *testing.T) {
	// The legacy entry point keeps its exact behaviour.
	cfg := Config{Mode: ModeDeny, CountryList: []string{"RU"}}
	if d := Evaluate(cfg, "RU", publicIP, nil); d.Accepted || d.Reason != ReasonDenyMatch {
		t.Errorf("RU: %+v", d)
	}
	if d := Evaluate(cfg, "", publicIP, nil); !d.Accepted || d.Reason != ReasonLookupFailed {
		t.Errorf("unresolved: %+v", d)
	}
}

func TestValidate_ContinentsAndExceptions(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"allow with continents only is valid", Config{Mode: ModeAllow, Continents: []string{"EU"}}, ""},
		{"deny with exceptions is valid", Config{Mode: ModeDeny, Continents: []string{"AS"},
			Exceptions: &Exceptions{Countries: []string{"JP"}}}, ""},
		{"unknown continent", Config{Mode: ModeDeny, Continents: []string{"XX"}}, "not a valid code"},
		{"duplicate continent", Config{Mode: ModeDeny, Continents: []string{"EU", "EU"}}, "more than once"},
		{"allow with nothing", Config{Mode: ModeAllow}, "requires at least one"},
		{"exceptions outside deny", Config{Mode: ModeAllow, Continents: []string{"EU"},
			Exceptions: &Exceptions{Countries: []string{"FR"}}}, "only valid with mode=deny"},
		{"bad exception code", Config{Mode: ModeDeny, Continents: []string{"AS"},
			Exceptions: &Exceptions{Countries: []string{"jp"}}}, "not a valid code"},
		{"country both blocked and excepted", Config{Mode: ModeDeny, CountryList: []string{"JP"},
			Exceptions: &Exceptions{Countries: []string{"JP"}}}, "both blocked and an exception"},
		{"empty exceptions ignored in allow", Config{Mode: ModeAllow, CountryList: []string{"FR"},
			Exceptions: &Exceptions{}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// geoStub implements both CountryLookup and GeoLookup.
type geoStub struct{ geo GeoInfo }

func (g geoStub) Lookup(string) string     { return g.geo.Country }
func (g geoStub) LookupGeo(string) GeoInfo { return g.geo }

func TestServeHTTP_UsesContinentFromGeoLookup(t *testing.T) {
	t.Cleanup(ResetGlobalsForTest)
	ResetGlobalsForTest()
	SetGlobalLookup(geoStub{geo: GeoInfo{Country: "CN", Continent: "AS"}})
	sink := &recordingSink{}
	SetGlobalBlockSink(sink)

	h := &Handler{Config: Config{Mode: ModeDeny, Continents: []string{"AS"}}, RouteID: "r1"}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	next := &nextCalled{}
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, newRequest(t, publicIP), &nextHandlerAdapter{inner: next}); err != nil {
		t.Fatal(err)
	}
	if next.wasCalled() || rec.Code != http.StatusForbidden {
		t.Fatalf("continent block not applied: next=%v code=%d", next.wasCalled(), rec.Code)
	}
	if ev := sink.snapshotFull(); len(ev) != 1 || ev[0].Country != "CN" || ev[0].Reason != ReasonDenyMatch {
		t.Errorf("sink events = %+v", ev)
	}
}

// The handler config emitted by caddymgr must decode STRICTLY into
// Handler (Caddy decodes module config with unknown-field rejection).
func TestHandlerConfig_ContinentKeysDecodeStrictly(t *testing.T) {
	raw := []byte(`{"routeID":"r1","config":{"mode":"deny","countryList":["RU"],"statusCode":0,
		"continents":["AS"],"exceptions":{"countries":["JP"]}}}`)
	var h Handler
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if len(h.Config.Continents) != 1 || h.Config.Exceptions == nil || h.Config.Exceptions.Countries[0] != "JP" {
		t.Errorf("decoded config = %+v", h.Config)
	}
}

// v2.28 — ASN rules and ASN exceptions.
func TestEvaluateGeo_ASN(t *testing.T) {
	const ovh, do = 16276, 14061
	denyDO := Config{Mode: ModeDeny, ASNs: []uint32{do}, Exceptions: &Exceptions{ASNs: []uint32{ovh}}}
	cases := []struct {
		name       string
		cfg        Config
		geo        GeoInfo
		wantAccept bool
		wantReason string
	}{
		{"deny ASN blocks", denyDO, GeoInfo{Country: "US", Continent: "NA", ASN: do}, false, ReasonDenyMatch},
		{"deny other ASN passes", denyDO, GeoInfo{Country: "FR", Continent: "EU", ASN: 3215}, true, ReasonDenyMiss},
		{"ASN exception beats continent", Config{Mode: ModeDeny, Continents: []string{"EU"},
			Exceptions: &Exceptions{ASNs: []uint32{ovh}}}, GeoInfo{Country: "FR", Continent: "EU", ASN: ovh}, true, ReasonException},
		{"allow ASN accepts", Config{Mode: ModeAllow, ASNs: []uint32{ovh}},
			GeoInfo{Country: "FR", Continent: "EU", ASN: ovh}, true, ReasonAllowMatch},
		{"allow ASN rejects other ASN", Config{Mode: ModeAllow, ASNs: []uint32{ovh}},
			GeoInfo{Country: "FR", Continent: "EU", ASN: 3215}, false, ReasonAllowMiss},
		{"allow ASN fails open when ASN unknown", Config{Mode: ModeAllow, ASNs: []uint32{ovh}},
			GeoInfo{Country: "FR", Continent: "EU"}, true, ReasonLookupFailed},
		{"allow country still blocks when ASN unknown and no ASN rule", Config{Mode: ModeAllow, CountryList: []string{"DE"}},
			GeoInfo{Country: "FR", Continent: "EU"}, false, ReasonAllowMiss},
		{"deny ASN only, ASN unknown → pass", Config{Mode: ModeDeny, ASNs: []uint32{do}},
			GeoInfo{Country: "US", Continent: "NA"}, true, ReasonDenyMiss},
		{"only ASN resolved still evaluates", denyDO, GeoInfo{ASN: do}, false, ReasonDenyMatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := EvaluateGeo(tc.cfg, tc.geo, publicIP, nil)
			if d.Accepted != tc.wantAccept || d.Reason != tc.wantReason {
				t.Errorf("got accepted=%v reason=%q, want %v %q", d.Accepted, d.Reason, tc.wantAccept, tc.wantReason)
			}
		})
	}
}

func TestValidate_ASN(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"allow with ASNs only is valid", Config{Mode: ModeAllow, ASNs: []uint32{16276}}, ""},
		{"AS0 rejected", Config{Mode: ModeDeny, ASNs: []uint32{0}}, "not a valid AS number"},
		{"duplicate ASN", Config{Mode: ModeDeny, ASNs: []uint32{1, 1}}, "more than once"},
		{"ASN exception outside deny", Config{Mode: ModeAllow, ASNs: []uint32{1},
			Exceptions: &Exceptions{ASNs: []uint32{2}}}, "only valid with mode=deny"},
		{"ASN both blocked and excepted", Config{Mode: ModeDeny, ASNs: []uint32{7},
			Exceptions: &Exceptions{ASNs: []uint32{7}}}, "both blocked and an exception"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestHandlerConfig_ASNKeysDecodeStrictly(t *testing.T) {
	raw := []byte(`{"routeID":"r1","config":{"mode":"deny","countryList":[],"statusCode":0,
		"asns":[14061],"exceptions":{"countries":["JP"],"asns":[16276]}}}`)
	var h Handler
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("strict decode: %v", err)
	}
	if len(h.Config.ASNs) != 1 || h.Config.Exceptions.ASNs[0] != 16276 {
		t.Errorf("decoded = %+v", h.Config)
	}
}
