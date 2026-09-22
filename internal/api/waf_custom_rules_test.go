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
	"reflect"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

func pathRuleWire(name, op string, values ...string) wafCustomRuleWire {
	return wafCustomRuleWire{Name: name, Conditions: []wafRuleConditionWire{{Field: "path", Operator: op, Values: values}}}
}

func TestNormalizeCustomRules_IDs(t *testing.T) {
	// New route: IDs allocated from 120000.
	got, err := normalizeCustomRules([]wafCustomRuleWire{pathRuleWire("a", "is", "/a"), pathRuleWire("b", "is", "/b")}, nil)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got[0].ID != 120000 || got[1].ID != 120001 {
		t.Fatalf("ids = %d, %d; want 120000, 120001", got[0].ID, got[1].ID)
	}

	// Edit: existing IDs kept, a new rule gets max+1, order preserved.
	previous := []storage.WAFCustomRule{{ID: 120000, Name: "a"}, {ID: 120004, Name: "b"}}
	edit := []wafCustomRuleWire{pathRuleWire("new", "is", "/n"), pathRuleWire("b", "is", "/b"), pathRuleWire("a", "is", "/a")}
	edit[1].ID, edit[2].ID = 120004, 120000
	got, err = normalizeCustomRules(edit, previous)
	if err != nil {
		t.Fatalf("normalize edit: %v", err)
	}
	if ids := []int{got[0].ID, got[1].ID, got[2].ID}; !reflect.DeepEqual(ids, []int{120005, 120004, 120000}) {
		t.Fatalf("ids = %v, want [120005 120004 120000]", ids)
	}

	unknown := pathRuleWire("x", "is", "/x")
	unknown.ID = 120009
	if _, err := normalizeCustomRules([]wafCustomRuleWire{unknown}, previous); err == nil {
		t.Error("an unknown id must be refused")
	}
	dup := []wafCustomRuleWire{pathRuleWire("a", "is", "/a"), pathRuleWire("a2", "is", "/a")}
	dup[0].ID, dup[1].ID = 120000, 120000
	if _, err := normalizeCustomRules(dup, previous); err == nil {
		t.Error("a duplicate id must be refused")
	}
	full := []storage.WAFCustomRule{{ID: 129999, Name: "last"}}
	if _, err := normalizeCustomRules([]wafCustomRuleWire{pathRuleWire("x", "is", "/x")}, full); err == nil {
		t.Error("allocating past 129999 must be refused")
	}
}

func TestNormalizeCustomRules_Canonical(t *testing.T) {
	got, err := normalizeCustomRules([]wafCustomRuleWire{{
		Name: "  login bots ",
		Conditions: []wafRuleConditionWire{
			{Field: "method", Operator: "is_not", Values: []string{" get", "Post "}},
			{Field: "header", Header: " X-Api-Key ", Operator: "absent", Values: []string{"ignored"}},
			{Field: "user_agent", Operator: "missing"},
		},
	}}, nil)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	want := storage.WAFCustomRule{ID: 120000, Name: "login bots", Conditions: []storage.WAFRuleCondition{
		{Field: "method", Operator: "is_not", Values: []string{"GET", "POST"}},
		{Field: "header", Header: "X-Api-Key", Operator: "absent"},
		{Field: "user_agent", Operator: "missing"},
	}}
	if !reflect.DeepEqual(got[0], want) {
		t.Fatalf("got %+v\nwant %+v", got[0], want)
	}
}

func TestNormalizeCustomRules_Rejects(t *testing.T) {
	c := func(field, op string, values ...string) wafRuleConditionWire {
		return wafRuleConditionWire{Field: field, Operator: op, Values: values}
	}
	rule := func(conds ...wafRuleConditionWire) wafCustomRuleWire {
		return wafCustomRuleWire{Name: "r", Conditions: conds}
	}
	cases := map[string]wafCustomRuleWire{
		"no name":             {Name: " ", Conditions: []wafRuleConditionWire{c("path", "is", "/a")}},
		"quote in name":       {Name: "a'b", Conditions: []wafRuleConditionWire{c("path", "is", "/a")}},
		"no condition":        rule(),
		"too many conditions": rule(c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a"), c("path", "is", "/a")),
		"unknown field":       rule(c("ip", "is", "1.2.3.4")),
		"bad operator":        rule(c("method", "contains", "PO")),
		"missing on path":     rule(c("path", "missing")),
		"no values":           rule(c("path", "is")),
		"empty value":         rule(c("path", "contains", " ")),
		"path without slash":  rule(c("path", "is", "admin")),
		"double quote":        rule(c("user_agent", "contains", `a" "id:1`)),
		"backslash":           rule(c("user_agent", "contains", `a\`)),
		"control char":        rule(c("user_agent", "contains", "a\nb")),
		"method with digits":  rule(c("method", "is", "GET1")),
		"bad header name":     rule(wafRuleConditionWire{Field: "header", Header: "X Api", Operator: "present"}),
		"no header name":      rule(wafRuleConditionWire{Field: "header", Operator: "present"}),
		"value too long":      rule(c("path", "contains", strings.Repeat("a", wafCustomValueMaxLen+1))),
	}
	for name, in := range cases {
		if _, err := normalizeCustomRules([]wafCustomRuleWire{in}, nil); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
	tooMany := make([]wafCustomRuleWire, wafCustomRulesMaxCount+1)
	if _, err := normalizeCustomRules(tooMany, nil); err == nil {
		t.Error("more than the per-route cap accepted")
	}
}

func putCustomRules(t *testing.T, env *testEnv, id, rulesJSON string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"host":"waf.local","upstreams":[{"url":"http://10.0.0.50:5000","weight":1}],` +
		`"lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,"aliases":[],` +
		`"authMode":"none","requestHeaders":{},"responseHeaders":{},"wafMode":"block"`
	if rulesJSON != "" {
		body += `,"wafCustomRules":` + rulesJSON
	}
	body += `}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/routes/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func TestUpdateRoute_WAFCustomRules_Roundtrip(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{})

	rec := putCustomRules(t, env, route.ID, `[{"id":0,"name":"sensitive","conditions":[{"field":"path","operator":"contains","values":["/.env"]}]}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}
	var resp routeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.WAFCustomRules) != 1 || resp.WAFCustomRules[0].ID != 120000 {
		t.Fatalf("response rules = %+v, want one rule with id 120000", resp.WAFCustomRules)
	}

	// Absent field preserves.
	if rec := putCustomRules(t, env, route.ID, ""); rec.Code != http.StatusOK {
		t.Fatalf("PUT without field: %d", rec.Code)
	}
	stored, _ := env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFCustomRules) != 1 {
		t.Fatalf("absent field must preserve; got %+v", stored.WAFCustomRules)
	}

	// Disable it, keep the ID, add one.
	rec = putCustomRules(t, env, route.ID, `[{"id":120000,"name":"sensitive","disabled":true,"conditions":[{"field":"path","operator":"contains","values":["/.env"]}]},`+
		`{"id":0,"name":"scanners","conditions":[{"field":"user_agent","operator":"contains","values":["sqlmap"]}]}]`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT edit: status=%d body=%s", rec.Code, rec.Body)
	}
	stored, _ = env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFCustomRules) != 2 || !stored.WAFCustomRules[0].Disabled || stored.WAFCustomRules[1].ID != 120001 {
		t.Fatalf("stored = %+v", stored.WAFCustomRules)
	}

	// Invalid → 400, nothing changed.
	if rec := putCustomRules(t, env, route.ID, `[{"id":0,"name":"x","conditions":[{"field":"ip","operator":"is","values":["1.2.3.4"]}]}]`); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid rule: status=%d, want 400", rec.Code)
	}

	// Empty list clears.
	if rec := putCustomRules(t, env, route.ID, `[]`); rec.Code != http.StatusOK {
		t.Fatalf("PUT clear: %d", rec.Code)
	}
	stored, _ = env.store.GetRoute(context.Background(), route.ID)
	if len(stored.WAFCustomRules) != 0 {
		t.Fatalf("empty list must clear; got %+v", stored.WAFCustomRules)
	}
}

func TestCustomRuleNames_Lookup(t *testing.T) {
	env := newTestEnv(t, false)
	route := seedWAFRoute(t, env, storage.Route{WAFCustomRules: []storage.WAFCustomRule{
		{ID: 120003, Name: "block scanners", Conditions: []storage.WAFRuleCondition{{Field: "user_agent", Operator: "contains", Values: []string{"sqlmap"}}}},
	}})
	names := env.handler.newCustomRuleNames()
	ctx := context.Background()
	if got := names.lookup(ctx, route.ID, "120003"); got != "block scanners" {
		t.Errorf("lookup = %q, want block scanners", got)
	}
	for _, tc := range []struct{ route, rule string }{
		{route.ID, "942100"}, {route.ID, "120004"}, {"gone", "120003"}, {route.ID, "x"},
	} {
		if got := names.lookup(ctx, tc.route, tc.rule); got != "" {
			t.Errorf("lookup(%s, %s) = %q, want empty", tc.route, tc.rule, got)
		}
	}
}
