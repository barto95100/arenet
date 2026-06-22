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
	"reflect"
	"strings"
	"testing"
)

// Step X Option (e) (2026-06-22) — API wire roundtrip tests for
// Route.WAFExcludeTags. Mirror of routes_waf_exclude_rules_test.go.
//
//   1. POST→GET roundtrip with explicit list echoes + persists
//      canonicalised (lowercase, dedup, ascending sort).
//   2. POST without the field defaults to empty (non-nil [] in
//      the response, nil/empty in storage).
//   3. PUT WITHOUT the key preserves the stored list.
//   4. PUT WITH an empty list clears the stored list.
//   5. Validation : reject characters that would smuggle ctl:
//      actions into the SecAction directive line.

func jsonBodyWithExcludeTags(host, excludeJSON string) string {
	tail := ""
	if excludeJSON != "" {
		tail = `,"wafExcludeTags":` + excludeJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"detect"%s}`,
		host, tail,
	)
}

func TestCreateRoute_WAFExcludeTags_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	// Submit messy input ; expect canonicalised echo.
	body := jsonBodyWithExcludeTags("tags.local",
		`["Attack-SQLI","attack-protocol","attack-sqli","paranoia-level/3"]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}

	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	want := []string{"attack-protocol", "attack-sqli", "paranoia-level/3"}
	if !reflect.DeepEqual(resp.WAFExcludeTags, want) {
		t.Errorf("response WAFExcludeTags=%v want=%v (canonicalised)",
			resp.WAFExcludeTags, want)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !reflect.DeepEqual(got[0].WAFExcludeTags, want) {
		t.Errorf("storage WAFExcludeTags=%v want=%v", got[0].WAFExcludeTags, want)
	}
}

func TestCreateRoute_WAFExcludeTags_Defaults_Empty(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithExcludeTags("api.tags-default.local", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}

	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.WAFExcludeTags == nil {
		t.Errorf("response WAFExcludeTags = nil ; want []string{} (non-nil empty)")
	}
	if len(resp.WAFExcludeTags) != 0 {
		t.Errorf("response WAFExcludeTags = %v ; want empty", resp.WAFExcludeTags)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeTags) != 0 {
		t.Errorf("storage WAFExcludeTags = %v ; want empty (pre-X(e) byte-equivalent)",
			got[0].WAFExcludeTags)
	}
}

func TestUpdateRoute_WAFExcludeTags_NilPreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)

	createBody := jsonBodyWithExcludeTags("tags.preserve.local", `["attack-sqli"]`)
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

	// PUT WITHOUT the wafExcludeTags key — preserve path.
	putBody := jsonBodyWithExcludeTags("tags.preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s ; want 200 (preserve path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeTags) != 1 || got[0].WAFExcludeTags[0] != "attack-sqli" {
		t.Errorf("WAFExcludeTags lost after PUT-without-key ; got=%v want=[attack-sqli]",
			got[0].WAFExcludeTags)
	}
}

func TestUpdateRoute_WAFExcludeTags_EmptyListClears(t *testing.T) {
	env := newTestEnv(t, false)

	createBody := jsonBodyWithExcludeTags("tags.clear.local", `["attack-sqli","attack-protocol"]`)
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

	// PUT WITH an explicit empty array — clear path.
	putBody := jsonBodyWithExcludeTags("tags.clear.local", `[]`)
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s ; want 200 (clear path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeTags) != 0 {
		t.Errorf("WAFExcludeTags survived an explicit-empty PUT ; got=%v",
			got[0].WAFExcludeTags)
	}
}

func TestCreateRoute_WAFExcludeTags_RejectsSecActionSmuggling(t *testing.T) {
	env := newTestEnv(t, false)
	// Comma inside a single tag would smuggle a second ctl: action
	// into the SecAction directive line. The normaliser rejects.
	body := jsonBodyWithExcludeTags("tags.smuggle.local", `["attack-sqli,attack-rce"]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("create status=%d ; want 400 (SecAction smuggling rejected)", rec.Code)
	}
}
