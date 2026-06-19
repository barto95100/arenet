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

package api

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/geo"
)

// fakeGeoLookup is the test double for the Z.5.3
// GeoIPLookup interface. Returns a static map keyed by IP
// string ; an IP not in the map is treated as "no MMDB
// record" (matches geo.LookupIP's empty-Country return for
// unrecognized public IPs).
type fakeGeoLookup struct {
	m map[string]string
}

func (f *fakeGeoLookup) LookupIP(ip net.IP) geo.Location {
	c, ok := f.m[ip.String()]
	if !ok {
		return geo.Location{Found: false}
	}
	if c == "LAN" {
		return geo.Location{Country: "LAN", Found: false}
	}
	return geo.Location{Country: c, Found: true}
}

func TestGeoLookupBatch_HappyPath_PublicAndLAN(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoLookup(&fakeGeoLookup{
		m: map[string]string{
			"82.65.1.2":   "FR",
			"203.0.113.7": "US",
			"192.168.1.5": "LAN",
		},
	})
	body, _ := json.Marshal(map[string]any{
		"ips": []string{"82.65.1.2", "192.168.1.5", "203.0.113.7"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200; body=%s", rec.Code, rec.Body)
	}
	var resp geoLookupBatchResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Degraded {
		t.Errorf("Degraded = true; want false (lookup wired)")
	}
	if got := resp.Results["82.65.1.2"]; got != "FR" {
		t.Errorf("82.65.1.2 = %q; want FR", got)
	}
	if got := resp.Results["203.0.113.7"]; got != "US" {
		t.Errorf("203.0.113.7 = %q; want US", got)
	}
	if got := resp.Results["192.168.1.5"]; got != "LAN" {
		t.Errorf("192.168.1.5 = %q; want LAN (RFC1918 sentinel)", got)
	}
}

func TestGeoLookupBatch_NilLookup_DegradedResponse(t *testing.T) {
	m := newMetricsTestEnv(t)
	// Lookup intentionally not set → nil → degraded path.
	body, _ := json.Marshal(map[string]any{
		"ips": []string{"82.65.1.2", "192.168.1.5"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (degraded is OK, not 5xx)", rec.Code)
	}
	var resp geoLookupBatchResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if !resp.Degraded {
		t.Errorf("Degraded = false; want true (lookup is nil)")
	}
	// Every IP gets an empty string so the frontend renders
	// raw IPs cleanly instead of crashing on a missing key.
	if resp.Results["82.65.1.2"] != "" {
		t.Errorf("82.65.1.2 = %q; want empty (degraded)", resp.Results["82.65.1.2"])
	}
	if _, ok := resp.Results["192.168.1.5"]; !ok {
		t.Errorf("192.168.1.5 missing from degraded results map")
	}
}

func TestGeoLookupBatch_MalformedIP_SingleEmptyNotBatchFailure(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoLookup(&fakeGeoLookup{
		m: map[string]string{"82.65.1.2": "FR"},
	})
	body, _ := json.Marshal(map[string]any{
		"ips": []string{"82.65.1.2", "not-an-ip", "192.168.1.5"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (malformed IP does not fail the batch)", rec.Code)
	}
	var resp geoLookupBatchResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	// Valid IPs answered, malformed → empty string.
	if resp.Results["82.65.1.2"] != "FR" {
		t.Errorf("82.65.1.2 = %q; want FR (valid IP, batch survived)", resp.Results["82.65.1.2"])
	}
	if resp.Results["not-an-ip"] != "" {
		t.Errorf("malformed IP got %q; want empty", resp.Results["not-an-ip"])
	}
}

func TestGeoLookupBatch_OverCap_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoLookup(&fakeGeoLookup{m: map[string]string{}})

	ips := make([]string, maxLookupBatchSize+1)
	for i := range ips {
		ips[i] = "1.2.3.4"
	}
	body, _ := json.Marshal(map[string]any{"ips": ips})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400 (cap %d)", rec.Code, maxLookupBatchSize)
	}
}

func TestGeoLookupBatch_BadJSON_400(t *testing.T) {
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoLookup(&fakeGeoLookup{m: map[string]string{}})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch",
		strings.NewReader(`{not json`))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d; want 400", rec.Code)
	}
}

func TestGeoLookupBatch_UnknownIP_EmptyString(t *testing.T) {
	// Public IP not in the fake's map → geo.LookupIP returns
	// Location{Found:false}, which surfaces as empty Country.
	// Operator-honest : "we don't know the country" → empty
	// suffix on the frontend.
	m := newMetricsTestEnv(t)
	m.env.handler.SetGeoLookup(&fakeGeoLookup{m: map[string]string{}})

	body, _ := json.Marshal(map[string]any{"ips": []string{"203.0.113.99"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/geo/lookup-batch", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	m.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	var resp geoLookupBatchResponse
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Results["203.0.113.99"] != "" {
		t.Errorf("unknown IP = %q; want empty (MMDB no record)", resp.Results["203.0.113.99"])
	}
}
