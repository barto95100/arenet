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

// Step X Option (c) (2026-06-18) — API wire for
// Route.WAFExcludeRules.
//
// Mirror of the WAFDisableCRS wire tests (X.1) :
//   1. POST→GET roundtrip with explicit list echoes and persists.
//   2. POST without the field defaults to empty (no exclusions).
//   3. PUT WITHOUT the field preserves the stored list.
//   4. PUT WITH an empty list clears the stored list.
//   5. Validation : reject IDs out of [100000, 999999] range.
//   6. Validation : reject IDs in the Arenet-reserved range
//      [100000, 199999].
//   7. Dedup + sort happens server-side at write time.

func jsonBodyWithExcludeRules(host, excludeJSON string) string {
	tail := ""
	if excludeJSON != "" {
		tail = `,"wafExcludeRules":` + excludeJSON
	}
	return fmt.Sprintf(
		`{"host":%q,"upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],`+
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,`+
			`"aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},`+
			`"wafMode":"detect"%s}`,
		host, tail,
	)
}

func TestCreateRoute_WAFExcludeRules_Wire_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithExcludeRules("fp.local", `[942100,941390,920280]`)
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
	// Response is canonicalised : ascending sort + dedup.
	want := []int{920280, 941390, 942100}
	if !reflect.DeepEqual(resp.WAFExcludeRules, want) {
		t.Errorf("response WAFExcludeRules=%v want=%v (canonicalised order)",
			resp.WAFExcludeRules, want)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if !reflect.DeepEqual(got[0].WAFExcludeRules, want) {
		t.Errorf("storage WAFExcludeRules=%v want=%v", got[0].WAFExcludeRules, want)
	}
}

func TestCreateRoute_WAFExcludeRules_Defaults_Empty(t *testing.T) {
	env := newTestEnv(t, false)
	body := jsonBodyWithExcludeRules("api.default.local", "")
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
	// Non-nil-empty in the JSON response (the toResponse helper
	// normalises nil → []) so the frontend can render the
	// editor without a null-check.
	if resp.WAFExcludeRules == nil {
		t.Errorf("response WAFExcludeRules = nil ; want []int{} (non-nil empty)")
	}
	if len(resp.WAFExcludeRules) != 0 {
		t.Errorf("response WAFExcludeRules = %v ; want empty", resp.WAFExcludeRules)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeRules) != 0 {
		t.Errorf("storage WAFExcludeRules = %v ; want empty (pre-Y byte-equivalent)",
			got[0].WAFExcludeRules)
	}
}

func TestUpdateRoute_WAFExcludeRules_NilPreservesPrevious(t *testing.T) {
	env := newTestEnv(t, false)

	createBody := jsonBodyWithExcludeRules("fp.preserve.local", `[942100]`)
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

	// PUT WITHOUT the wafExcludeRules key — preserve path.
	putBody := jsonBodyWithExcludeRules("fp.preserve.local", "")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s ; want 200 (preserve path)",
			putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeRules) != 1 || got[0].WAFExcludeRules[0] != 942100 {
		t.Errorf("WAFExcludeRules lost after PUT-without-key ; got=%v want=[942100]",
			got[0].WAFExcludeRules)
	}
}

func TestUpdateRoute_WAFExcludeRules_EmptyListClears(t *testing.T) {
	// Explicit `"wafExcludeRules": []` MUST clear the stored
	// list (the only way an operator can drop every exclusion
	// from the API after configuring some).
	env := newTestEnv(t, false)

	createBody := jsonBodyWithExcludeRules("fp.clear.local", `[942100,941390]`)
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

	putBody := jsonBodyWithExcludeRules("fp.clear.local", "[]")
	putReq := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+created.ID, strings.NewReader(putBody))
	putRec := httptest.NewRecorder()
	env.router.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s ; want 200", putRec.Code, putRec.Body)
	}

	got, _ := env.store.ListRoutes(context.Background())
	if len(got[0].WAFExcludeRules) != 0 {
		t.Errorf("WAFExcludeRules survived an explicit-empty PUT ; got=%v",
			got[0].WAFExcludeRules)
	}
}

func TestCreateRoute_WAFExcludeRules_RejectsOutOfRange(t *testing.T) {
	env := newTestEnv(t, false)
	cases := []struct {
		name string
		ids  string
	}{
		{"below_min", `[99999]`},
		{"above_max", `[1000000]`},
		{"negative", `[-1]`},
		{"zero", `[0]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := jsonBodyWithExcludeRules("bad.local", tc.ids)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status=%d body=%s ; want 400 for %s",
					rec.Code, rec.Body, tc.name)
			}
		})
	}
}

func TestCreateRoute_WAFExcludeRules_RejectsArenetReservedRange(t *testing.T) {
	// IDs 100000..199999 are reserved for Arenet's internally-
	// generated SecRules (admin-API exclusion uses id:100001).
	// Operator-supplied exclusions of those IDs would either be
	// no-ops (the rules they target are Arenet's own pre-emitted
	// directives, not CRS rules) or actively dangerous (they
	// would remove an Arenet defense the runtime depends on).
	env := newTestEnv(t, false)
	cases := []string{`[100001]`, `[150000]`, `[199999]`}
	for _, ids := range cases {
		body := jsonBodyWithExcludeRules("reserved.local", ids)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status=%d body=%s ; want 400 for ids=%s",
				rec.Code, rec.Body, ids)
		}
	}
}

func TestCreateRoute_WAFExcludeRules_DedupsAndSorts(t *testing.T) {
	// Operator-supplied [942100, 941390, 942100, 920280] must
	// land in storage as [920280, 941390, 942100] (ascending
	// sort, duplicates removed).
	env := newTestEnv(t, false)
	body := jsonBodyWithExcludeRules("dedup.local", `[942100,941390,942100,920280]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	got, _ := env.store.ListRoutes(context.Background())
	want := []int{920280, 941390, 942100}
	if !reflect.DeepEqual(got[0].WAFExcludeRules, want) {
		t.Errorf("storage WAFExcludeRules=%v want=%v (deduped + sorted)",
			got[0].WAFExcludeRules, want)
	}
}
