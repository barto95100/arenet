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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/countryblock"
)

// W.2 API tests for the per-route country-block surface. Pin the
// wire-shape preserve-on-PUT semantics, the §D2 footgun
// rejection at the 400 boundary, the country-code canonicalization
// (lowercase → uppercase), and the toResponse normalisation of
// zero-value rows.

// jsonBodyCountryBlock builds a minimal POST/PUT body with the
// supplied CountryBlock JSON literal already serialized — mirrors
// the existing test pattern in this package
// (TestCreateRoute_AcceptsWAFModeDetect builds bodies via string
// concatenation rather than struct marshalling).
//
// cbJSON empty → no countryBlock key in the body (tests the
// "absent → zero-value" path).
func jsonBodyCountryBlock(host, cbJSON string) string {
	tail := ""
	if cbJSON != "" {
		tail = `,"countryBlock":` + cbJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"off"%s}`,
		host, tail,
	)
}

func TestCreateRoute_CountryBlock_AcceptsAllowMode(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyCountryBlock("cb-allow.local",
		`{"mode":"allow","countryList":["FR","DE"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	r := got[0]
	if r.CountryBlock.Mode != countryblock.ModeAllow {
		t.Errorf("Mode = %q; want %q", r.CountryBlock.Mode, countryblock.ModeAllow)
	}
	wantList := []string{"FR", "DE"}
	if len(r.CountryBlock.CountryList) != len(wantList) {
		t.Fatalf("CountryList len = %d; want %d", len(r.CountryBlock.CountryList), len(wantList))
	}
	for i := range wantList {
		if r.CountryBlock.CountryList[i] != wantList[i] {
			t.Errorf("CountryList[%d] = %q; want %q", i, r.CountryBlock.CountryList[i], wantList[i])
		}
	}
	// Response wire shape: countryBlock present with normalised
	// state so the frontend renders a single consistent value.
	if !strings.Contains(rec.Body.String(), `"countryBlock":`) {
		t.Errorf("response missing countryBlock key: %s", rec.Body)
	}
}

func TestCreateRoute_CountryBlock_RejectsAllowEmpty(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyCountryBlock("cb-footgun.local",
		`{"mode":"allow","countryList":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400 (§D2 footgun)", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "all non-RFC1918 traffic") {
		t.Errorf("400 body does not explain the footgun: %s", rec.Body)
	}
}

func TestCreateRoute_CountryBlock_AcceptsDenyEmpty(t *testing.T) {
	// Per spec §D2 deny+empty is a legal no-op (the API logs a
	// Warn but persists). Pin against a future tightening that
	// might reject without a spec change.
	env := newTestEnv(t, false)
	body := jsonBodyCountryBlock("cb-deny-empty.local",
		`{"mode":"deny","countryList":[]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s; want 201 (legal no-op)", rec.Code, rec.Body)
	}
}

func TestCreateRoute_CountryBlock_RejectsInvalidCountryCode(t *testing.T) {
	cases := []struct {
		name string
		list string // raw JSON array literal
	}{
		{"three-letter ISO 3166-1 alpha-3", `["FRA"]`},
		{"numeric code", `["12"]`},
		{"duplicate", `["FR","FR"]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			body := jsonBodyCountryBlock("cb-bad.local",
				`{"mode":"deny","countryList":`+tc.list+`}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s; want 400", rec.Code, rec.Body)
			}
		})
	}
}

func TestCreateRoute_CountryBlock_CanonicalisesLowercase(t *testing.T) {
	// Operators commonly type "fr" / "de" out of habit; the API
	// uppercases before validation rather than rejecting (UX
	// nicety — country codes are case-insensitive in operator
	// intent, only the MMDB returns canonical uppercase).
	env := newTestEnv(t, false)
	body := jsonBodyCountryBlock("cb-canon.local",
		`{"mode":"allow","countryList":["fr","de"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	want := []string{"FR", "DE"}
	if len(got[0].CountryBlock.CountryList) != len(want) {
		t.Fatalf("CountryList len mismatch")
	}
	for i := range want {
		if got[0].CountryBlock.CountryList[i] != want[i] {
			t.Errorf("CountryList[%d] = %q; want %q (uppercased)",
				i, got[0].CountryBlock.CountryList[i], want[i])
		}
	}
}

func TestCreateRoute_CountryBlock_AcceptsCustomStatusCode(t *testing.T) {
	for _, sc := range []int{403, 451, 444} {
		t.Run(fmt.Sprintf("statusCode-%d", sc), func(t *testing.T) {
			env := newTestEnv(t, false)
			body := jsonBodyCountryBlock(fmt.Sprintf("cb-sc-%d.local", sc),
				`{"mode":"deny","countryList":["RU"],"statusCode":`+itoa(sc)+`}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("status=%d body=%s; want 201 for statusCode=%d", rec.Code, rec.Body, sc)
			}
			got, _ := env.store.ListRoutes(context.Background())
			if got[0].CountryBlock.StatusCode != sc {
				t.Errorf("stored statusCode = %d; want %d", got[0].CountryBlock.StatusCode, sc)
			}
		})
	}
}

func TestCreateRoute_CountryBlock_RejectsInvalidStatusCode(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyCountryBlock("cb-sc-bad.local",
		`{"mode":"deny","countryList":["RU"],"statusCode":418}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s; want 400 (statusCode enum violation)", rec.Code, rec.Body)
	}
}

func TestCreateRoute_CountryBlock_AbsentBlock_DefaultsToOff(t *testing.T) {
	// Pin the zero-value default: a POST WITHOUT a countryBlock
	// key creates a route with Mode="off" (no gate emitted in
	// W.3 caddymgr). Backward-compat path for clients that don't
	// yet know about the field.
	env := newTestEnv(t, false)
	body := `{"host":"cb-absent.local","upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	if got[0].CountryBlock.Mode != "" {
		t.Errorf("absent countryBlock should leave Mode at zero-value \"\"; got %q",
			got[0].CountryBlock.Mode)
	}
	// And the toResponse normalisation surfaces "off" on the wire.
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.CountryBlock.Mode != string(countryblock.ModeOff) {
		t.Errorf("response countryBlock.mode = %q; want %q (toResponse normalisation)",
			resp.CountryBlock.Mode, countryblock.ModeOff)
	}
	if resp.CountryBlock.CountryList == nil {
		t.Error("response countryBlock.countryList is nil; want [] (toResponse normalisation)")
	}
}

func TestUpdateRoute_CountryBlock_NilPreservesPrevious(t *testing.T) {
	// PUT without a countryBlock block MUST preserve the
	// previously stored Config — same UX as wafMode / healthCheck
	// preserve-on-omission. Operators editing unrelated fields
	// don't need to restate the country list every time.
	env := newTestEnv(t, false)

	// 1. Create with a deny list.
	createBody := jsonBodyCountryBlock("cb-preserve.local",
		`{"mode":"deny","countryList":["RU","KP"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// 2. PUT WITHOUT a countryBlock key — preserve-previous path.
	putBody := `{"host":"cb-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"off"}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	// 3. Assert the deny list survived the unrelated edit.
	got, _ := env.store.ListRoutes(context.Background())
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if got[0].CountryBlock.Mode != countryblock.ModeDeny {
		t.Errorf("Mode = %q; want %q (preserved across PUT)",
			got[0].CountryBlock.Mode, countryblock.ModeDeny)
	}
	if len(got[0].CountryBlock.CountryList) != 2 {
		t.Errorf("CountryList len = %d; want 2 (preserved across PUT)",
			len(got[0].CountryBlock.CountryList))
	}
}

func TestUpdateRoute_CountryBlock_NonNilReplaces(t *testing.T) {
	// PUT WITH an explicit countryBlock key replaces the stored
	// config in full — same semantics as healthCheck.
	env := newTestEnv(t, false)

	createBody := jsonBodyCountryBlock("cb-replace.local",
		`{"mode":"deny","countryList":["RU"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	putBody := jsonBodyCountryBlock("cb-replace.local",
		`{"mode":"allow","countryList":["FR","DE","ES"]}`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if got[0].CountryBlock.Mode != countryblock.ModeAllow {
		t.Errorf("Mode = %q; want %q (replaced)",
			got[0].CountryBlock.Mode, countryblock.ModeAllow)
	}
	if len(got[0].CountryBlock.CountryList) != 3 {
		t.Errorf("CountryList len = %d; want 3 (replaced)",
			len(got[0].CountryBlock.CountryList))
	}
}

func TestUpdateRoute_CountryBlock_NonNilFootgunRejected(t *testing.T) {
	// PUT with an explicit allow+empty MUST be rejected (the
	// §D2 footgun, defense-in-depth even after a successful
	// initial create).
	env := newTestEnv(t, false)

	createBody := jsonBodyCountryBlock("cb-edit-footgun.local",
		`{"mode":"deny","countryList":["RU"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	putBody := jsonBodyCountryBlock("cb-edit-footgun.local",
		`{"mode":"allow","countryList":[]}`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusBadRequest {
		t.Fatalf("put status=%d body=%s; want 400 (§D2 footgun on edit)",
			putRec.Code, putRec.Body)
	}
}

// itoa avoids the strconv import in this one-call site (the test
// file already imports a handful of stdlib packages; one more
// trivial helper keeps the import list tight).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
