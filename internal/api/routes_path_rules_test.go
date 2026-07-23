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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateRoute_WithPathRulesAndIPFilter pins the v1 path-based-rules
// wire contract (Task 3): POST accepts camelCase ipFilter/pathRules
// (DisallowUnknownFields would otherwise 400 on the wire-field gap —
// see memory route_wire_field_gap_regression), and the response never
// echoes a path-rule's basic-auth password hash.
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
}
