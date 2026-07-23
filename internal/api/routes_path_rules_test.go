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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// pathRulesRouteBody builds a route POST/PUT body with the supplied
// extra top-level JSON fields spliced in (e.g. ipFilter/pathRules, or
// an unrelated field to prove an omitted ipFilter is preserved on
// PUT). extraJSON is a raw `,"key":value` fragment or "".
func pathRulesRouteBody(host, extraJSON string) string {
	return `{` +
		`"host":"` + host + `",` +
		`"upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},` +
		`"wafMode":"off"` + extraJSON + `}`
}

// TestCreateRoute_WithPathRulesAndIPFilter pins the v1 path-based-rules
// wire contract (Task 3): POST accepts camelCase ipFilter/pathRules
// (DisallowUnknownFields would otherwise 400 on the wire-field gap —
// see memory route_wire_field_gap_regression), and the response never
// echoes a path-rule's basic-auth password hash. It also round-trips
// the decoded response to confirm the values (not just their raw
// presence in the body) match what was submitted.
func TestCreateRoute_WithPathRulesAndIPFilter(t *testing.T) {
	env := newTestEnv(t, false)
	// API wire is camelCase (mirrors countryBlock). Nested keys too.
	body := `{
	  "host":"api.example.com",
	  "upstreams":[{"url":"http://127.0.0.1:9000","weight":1}],
	  "ipFilter":{"mode":"deny","cidrs":["10.0.0.0/8"]},
	  "pathRules":[
	    {"pathPrefix":"/metrics","ipFilter":{"mode":"allow","cidrs":["192.168.1.5"]}},
	    {"pathPrefix":"/docs","basicAuth":{"username":"doc","passwordHash":"$argon2id$v=19$m=65536,t=3,p=4$U0FMVFNBTFRTQUxUU0FMVA$S0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0VZS0U"}}
	  ]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status=%d body=%s (wire-field-gap? DisallowUnknownFields)", rec.Code, rec.Body)
	}
	// GET redacts the path-rule basic-auth password hash.
	if strings.Contains(rec.Body.String(), "S0VZS0VZ") {
		t.Errorf("path-rule password_hash leaked in response: %s", rec.Body)
	}

	// Round-trip the decoded response: values, not just raw presence.
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.IPFilter == nil || created.IPFilter.Mode != "deny" {
		t.Fatalf("response ipFilter.mode = %+v; want mode=deny", created.IPFilter)
	}
	if len(created.PathRules) != 2 {
		t.Fatalf("response pathRules len = %d; want 2", len(created.PathRules))
	}
	wantPrefixes := map[string]bool{"/metrics": false, "/docs": false}
	for _, pr := range created.PathRules {
		if _, ok := wantPrefixes[pr.PathPrefix]; !ok {
			t.Errorf("unexpected pathPrefix %q in response", pr.PathPrefix)
			continue
		}
		wantPrefixes[pr.PathPrefix] = true
	}
	for prefix, seen := range wantPrefixes {
		if !seen {
			t.Errorf("pathPrefix %q missing from response", prefix)
		}
	}
	for _, pr := range created.PathRules {
		if pr.PathPrefix == "/docs" {
			if pr.BasicAuth == nil {
				t.Fatalf("/docs pathRule missing basicAuth in response")
			}
			if pr.BasicAuth.Username != "doc" {
				t.Errorf("/docs basicAuth.username = %q; want %q", pr.BasicAuth.Username, "doc")
			}
			if pr.BasicAuth.PasswordHash != "" {
				t.Errorf("/docs basicAuth.passwordHash = %q; want redacted empty string", pr.BasicAuth.PasswordHash)
			}
		}
	}
}

// TestUpdateRoute_OmittedIPFilter_Preserved pins the Task 3 review
// Important-finding fix: PUT /api/v1/routes/{id} omitting ipFilter
// MUST preserve the previously stored whole-domain IP filter rather
// than silently clearing a configured security control — same
// preserve-on-omission contract as CountryBlock / HealthCheck (see
// TestUpdateRoute_CountryBlock_NilPreservesPrevious in
// routes_country_block_test.go, the pattern this test mirrors).
func TestUpdateRoute_OmittedIPFilter_Preserved(t *testing.T) {
	env := newTestEnv(t, false)

	// 1. Create with an ipFilter (deny 10.0.0.0/8).
	createBody := pathRulesRouteBody("ipf-preserve.local",
		`,"ipFilter":{"mode":"deny","cidrs":["10.0.0.0/8"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// 2. PUT WITHOUT an ipFilter key, but changing an unrelated field
	// (request headers) — proves an operator editing something else
	// doesn't wipe the IP filter.
	putBody := `{"host":"ipf-preserve.local","upstreams":[{"url":"http://127.0.0.1:9001","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,` +
		`"aliases":[],"authMode":"none","requestHeaders":{"X-Test":"1"},"responseHeaders":{},"wafMode":"off"}`
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body)
	}

	// 3. Assert the IP filter survived the unrelated edit — read
	// directly from the store (bypasses response serialization).
	got, err := env.store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 route, got %d", len(got))
	}
	if got[0].IPFilter == nil {
		t.Fatalf("IPFilter = nil after PUT omitting ipFilter; want preserved deny 10.0.0.0/8")
	}
	if got[0].IPFilter.Mode != "deny" {
		t.Errorf("IPFilter.Mode = %q; want %q (preserved across PUT)", got[0].IPFilter.Mode, "deny")
	}
	if len(got[0].IPFilter.CIDRs) != 1 || got[0].IPFilter.CIDRs[0] != "10.0.0.0/8" {
		t.Errorf("IPFilter.CIDRs = %v; want [10.0.0.0/8] (preserved across PUT)", got[0].IPFilter.CIDRs)
	}
}
