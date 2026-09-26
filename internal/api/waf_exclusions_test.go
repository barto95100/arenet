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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

func TestNormalizeTargetedExclusions_Canonical(t *testing.T) {
	got, err := normalizeTargetedExclusions([]wafTargetedExclusionWire{
		{RuleID: 942100, Target: " args:content ", Path: "/api/save"},
		{RuleID: 941100, Target: "REQUEST_HEADERS:Referer"},
		{RuleID: 942100, Target: "ARGS:content", Path: "/api/save"}, // duplicate after normalisation
		{RuleID: 942100, Target: "ARGS:content", PathPrefix: true},  // prefix without path is dropped
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := []storage.WAFTargetedExclusion{
		{RuleID: 941100, Target: "REQUEST_HEADERS:Referer"},
		{RuleID: 942100, Target: "ARGS:content"},
		{RuleID: 942100, Target: "ARGS:content", Path: "/api/save"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestNormalizeTargetedExclusions_Rejects(t *testing.T) {
	cases := map[string]wafTargetedExclusionWire{
		"arenet rule":           {RuleID: 100001, Target: "ARGS:a"},
		"out of range":          {RuleID: 42, Target: "ARGS:a"},
		"blocking evaluation":   {RuleID: 949110, Target: "ARGS:a"},
		"initialization":        {RuleID: 901100, Target: "ARGS:a"},
		"correlation":           {RuleID: 980170, Target: "ARGS:a"},
		"no key":                {RuleID: 942100, Target: "ARGS"},
		"empty key":             {RuleID: 942100, Target: "ARGS:"},
		"unsupported variable":  {RuleID: 942100, Target: "TX:score"},
		"comma smuggling":       {RuleID: 942100, Target: "ARGS:a,ctl:ruleEngine=Off"},
		"semicolon":             {RuleID: 942100, Target: "ARGS:a;b"},
		"quote":                 {RuleID: 942100, Target: `ARGS:a"`},
		"regex key":             {RuleID: 942100, Target: "ARGS:/^x/"},
		"relative path":         {RuleID: 942100, Target: "ARGS:a", Path: "api"},
		"path with quote":       {RuleID: 942100, Target: "ARGS:a", Path: `/a" "id:1`},
		"path with space":       {RuleID: 942100, Target: "ARGS:a", Path: "/a b"},
		"path control char":     {RuleID: 942100, Target: "ARGS:a", Path: "/a\nb"},
		"path too long":         {RuleID: 942100, Target: "ARGS:a", Path: "/" + strings.Repeat("a", wafExclusionPathMaxLen)},
		"target name too long":  {RuleID: 942100, Target: "ARGS:" + strings.Repeat("a", wafTargetKeyMaxLen+1)},
		"target with backslash": {RuleID: 942100, Target: `ARGS:a\`},
	}
	for name, in := range cases {
		if _, err := normalizeTargetedExclusions([]wafTargetedExclusionWire{in}); err == nil {
			t.Errorf("%s: %+v accepted, want an error", name, in)
		}
	}
	tooMany := make([]wafTargetedExclusionWire, wafTargetedMaxCount+1)
	if _, err := normalizeTargetedExclusions(tooMany); err == nil {
		t.Error("more than the per-route cap accepted")
	}
}

// seedWAFRoute stores a route to attach exclusions to.
func seedWAFRoute(t *testing.T, env *testEnv, r storage.Route) storage.Route {
	t.Helper()
	if r.Host == "" {
		r.Host = "waf.local"
	}
	r.Upstreams = []storage.Upstream{{URL: "http://10.0.0.50:5000", Weight: 1}}
	r.LBPolicy = storage.LBPolicyRoundRobin
	r.WAFMode = "block"
	created, err := env.store.CreateRoute(context.Background(), r)
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	return created
}

func postWAFExclusion(env *testEnv, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/routes/"+id+"/waf-exclusions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestAddWAFExclusion_Targeted(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{})

	rec := postWAFExclusion(env, route.ID, `{"ruleId":942100,"target":"ARGS:content","path":"/api/save"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	wantWire := []wafTargetedExclusionWire{{RuleID: 942100, Target: "ARGS:content", Path: "/api/save"}}
	if !reflect.DeepEqual(resp.WAFTargetedExclusions, wantWire) {
		t.Errorf("response exclusions = %+v, want %+v", resp.WAFTargetedExclusions, wantWire)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFTargetedExclusions) != 1 || len(stored.WAFExcludeRules) != 0 {
		t.Errorf("stored = targeted %+v rules %v", stored.WAFTargetedExclusions, stored.WAFExcludeRules)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("reloads = %d, want 1", env.caddy.CallCount())
	}
	events, _, _ := env.audit.List(context.Background(), audit.Filter{})
	if len(events) != 1 || events[0].Action != audit.ActionRouteUpdated {
		t.Errorf("audit = %+v, want one route_updated", events)
	}

	// Same exclusion again → 409, nothing reloaded.
	if rec := postWAFExclusion(env, route.ID, `{"ruleId":942100,"target":"args:content","path":"/api/save"}`); rec.Code != http.StatusConflict {
		t.Errorf("duplicate status=%d body=%s, want 409", rec.Code, rec.Body)
	}
	if env.caddy.CallCount() != 1 {
		t.Errorf("duplicate triggered a reload")
	}
}

func TestAddWAFExclusion_NoTarget_WholeRoute(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{WAFExcludeRules: []int{942100}})

	if rec := postWAFExclusion(env, route.ID, `{"ruleId":920350}`); rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if !reflect.DeepEqual(stored.WAFExcludeRules, []int{920350, 942100}) {
		t.Errorf("WAFExcludeRules = %v, want [920350 942100]", stored.WAFExcludeRules)
	}
	if len(stored.WAFTargetedExclusions) != 0 {
		t.Errorf("no-target exclusion landed in the targeted list")
	}
	if rec := postWAFExclusion(env, route.ID, `{"ruleId":942100}`); rec.Code != http.StatusConflict {
		t.Errorf("already-excluded rule status=%d, want 409", rec.Code)
	}
}

func TestAddWAFExclusion_Rejects(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{})

	for _, body := range []string{
		`{"ruleId":949110}`,
		`{"ruleId":949110,"target":"ARGS:a"}`,
		`{"ruleId":942100,"target":"ARGS:a,ctl:ruleEngine=Off"}`,
		`{"ruleId":942100,"target":"ARGS:a","unknown":1}`,
		`not json`,
	} {
		if rec := postWAFExclusion(env, route.ID, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status=%d, want 400", body, rec.Code)
		}
	}
	if rec := postWAFExclusion(env, "missing", `{"ruleId":942100}`); rec.Code != http.StatusNotFound {
		t.Errorf("unknown route status=%d, want 404", rec.Code)
	}
	if env.caddy.CallCount() != 0 {
		t.Errorf("a rejected exclusion reloaded Caddy")
	}
}

func TestAddWAFExclusion_ReloadFailureRollsBack(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{})
	env.caddy.SetNextErr(errors.New("boom"))

	if rec := postWAFExclusion(env, route.ID, `{"ruleId":942100,"target":"ARGS:a"}`); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rec.Code)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFTargetedExclusions) != 0 {
		t.Errorf("exclusion kept after a refused reload: %+v", stored.WAFTargetedExclusions)
	}
}

func TestUpdateRoute_WAFTargetedExclusions_PreserveAndReplace(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{
		WAFTargetedExclusions: []storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:a"}},
	})
	put := func(extra string) *httptest.ResponseRecorder {
		body := `{"host":"waf.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
			`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
			`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"block"` + extra + `}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+route.ID, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		return rec
	}

	if rec := put(""); rec.Code != http.StatusOK {
		t.Fatalf("PUT without the field: status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFTargetedExclusions) != 1 {
		t.Fatalf("absent field must preserve; got %+v", stored.WAFTargetedExclusions)
	}

	if rec := put(`,"wafTargetedExclusions":[{"ruleId":941100,"target":"ARGS:b","path":"/x","pathPrefix":true}]`); rec.Code != http.StatusOK {
		t.Fatalf("PUT replace: status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ = env.store.GetRoute(context.Background(), route.ID)
	want := []storage.WAFTargetedExclusion{{RuleID: 941100, Target: "ARGS:b", Path: "/x", PathPrefix: true}}
	if !reflect.DeepEqual(stored.WAFTargetedExclusions, want) {
		t.Fatalf("replace = %+v, want %+v", stored.WAFTargetedExclusions, want)
	}

	if rec := put(`,"wafTargetedExclusions":[]`); rec.Code != http.StatusOK {
		t.Fatalf("PUT clear: status=%d", rec.Code)
	}
	stored, _ = env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFTargetedExclusions) != 0 {
		t.Fatalf("empty list must clear; got %+v", stored.WAFTargetedExclusions)
	}

	if rec := put(`,"wafTargetedExclusions":[{"ruleId":949110,"target":"ARGS:b"}]`); rec.Code != http.StatusBadRequest {
		t.Fatalf("protected rule via PUT: status=%d, want 400", rec.Code)
	}
}
