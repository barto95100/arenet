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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

func cond(field, op string, values ...string) storage.WAFRuleCondition {
	return storage.WAFRuleCondition{Field: field, Operator: op, Values: values}
}

func TestCustomRuleDirectives_Shapes(t *testing.T) {
	got := customRuleDirectives([]storage.WAFCustomRule{
		{ID: 120001, Name: "b", Conditions: []storage.WAFRuleCondition{
			cond(storage.WAFFieldMethod, storage.WAFOpIs, "POST"),
			cond(storage.WAFFieldPath, storage.WAFOpBeginsWith, "/login"),
			{Field: storage.WAFFieldUserAgent, Operator: storage.WAFOpMissing},
		}},
		{ID: 120000, Name: "a", Conditions: []storage.WAFRuleCondition{
			cond(storage.WAFFieldPath, storage.WAFOpContains, "/.env", "/.git"),
		}},
		{ID: 120002, Name: "off", Disabled: true, Conditions: []storage.WAFRuleCondition{
			cond(storage.WAFFieldPath, storage.WAFOpIs, "/x"),
		}},
	})
	want := []string{
		`SecRule REQUEST_FILENAME "@rx (?:/\.env|/\.git)" "id:120000,phase:1,deny,status:403,log,severity:CRITICAL,tag:arenet-custom,msg:'Arenet custom rule 120000',t:none"`,
		`SecRule REQUEST_METHOD "@rx ^(?:POST)$" "id:120001,phase:1,deny,status:403,log,severity:CRITICAL,tag:arenet-custom,msg:'Arenet custom rule 120001',t:none,chain"` + "\n" +
			`SecRule REQUEST_FILENAME "@rx ^(?:/login)" "t:none,chain"` + "\n" +
			`SecRule &REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:User-Agent "@rx ^0?$" "t:none"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("directives =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(customRuleDirectives(nil)) != 0 {
		t.Error("no rule must render no directive")
	}
}

func TestBuildWAFHandler_CustomRules_AfterExclusionsBeforeCRS(t *testing.T) {
	got := buildWAFHandler("r-1", "h", "block", false, false, []int{920170}, nil,
		[]storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:a"}},
		[]storage.WAFCustomRule{{ID: 120000, Conditions: []storage.WAFRuleCondition{cond(storage.WAFFieldPath, storage.WAFOpIs, "/x")}}}, "")
	dirs := got["directives"].(string)
	i1, i2, i3, i4 := strings.Index(dirs, "id:999001"), strings.Index(dirs, "id:110000"), strings.Index(dirs, "id:120000"), strings.Index(dirs, "Include @coraza")
	if !(i1 >= 0 && i1 < i2 && i2 < i3 && i3 < i4) {
		t.Fatalf("order must be 999001 < 110000 < 120000 < Include; got %q", dirs)
	}
	// CRS disabled: the rule is still emitted (no Include).
	off := buildWAFHandler("r-1", "h", "block", false, true, nil, nil, nil,
		[]storage.WAFCustomRule{{ID: 120000, Conditions: []storage.WAFRuleCondition{cond(storage.WAFFieldPath, storage.WAFOpIs, "/x")}}}, "")
	if d := off["directives"].(string); !strings.Contains(d, "id:120000") || strings.Contains(d, "Include") {
		t.Fatalf("CRS disabled: want the custom rule and no Include, got %q", d)
	}
}

// --- End-to-end against Coraza ---------------------------------------

type customReq struct {
	method  string
	path    string
	headers map[string]string
	noUA    bool
}

// runCustom provisions the handler as caddymgr emits it (CRS loaded)
// and returns the response status and whether ruleID fired.
func runCustom(t *testing.T, mode string, rules []storage.WAFCustomRule, r customReq, ruleID string) (int, bool) {
	t.Helper()
	cfg := buildWAFHandler("r-custom", "example.com", mode, false, false, nil, nil, nil, rules, "")
	h := &waf.ArenetWafHandler{RouteID: "r-custom", Mode: mode, Directives: cfg["directives"].(string), LoadOWASPCRS: true}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision (directives must parse with the CRS): %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	sink := &targetedCaptureSink{}
	waf.SetGlobalSink(sink)
	t.Cleanup(func() { waf.SetGlobalSink(nil) })

	method := r.method
	if method == "" {
		method = http.MethodGet
	}
	req := httptest.NewRequest(method, "http://example.com"+r.path, nil)
	// A browser-like baseline so the CRS itself stays quiet.
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0")
	req.Header.Set("Accept", "text/html")
	if r.noUA {
		req.Header.Del("User-Agent")
	}
	for k, v := range r.headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	err := h.ServeHTTP(rec, req, next)
	status := rec.Code
	if he, ok := err.(caddyhttp.HandlerError); ok {
		status = he.StatusCode
	}
	_, fired := sink.fired(ruleID)
	return status, fired
}

func rule(conds ...storage.WAFRuleCondition) []storage.WAFCustomRule {
	return []storage.WAFCustomRule{{ID: 120000, Name: "t", Conditions: conds}}
}

func TestCustomRules_E2E(t *testing.T) {
	loginNoUA := rule(
		cond(storage.WAFFieldMethod, storage.WAFOpIs, "POST"),
		cond(storage.WAFFieldPath, storage.WAFOpBeginsWith, "/login"),
		storage.WAFRuleCondition{Field: storage.WAFFieldUserAgent, Operator: storage.WAFOpMissing},
	)
	cases := []struct {
		name  string
		rules []storage.WAFCustomRule
		req   customReq
		block bool
	}{
		{"path is — match", rule(cond("path", "is", "/wp-login.php")), customReq{path: "/wp-login.php"}, true},
		{"path is — longer path", rule(cond("path", "is", "/wp-login.php")), customReq{path: "/wp-login.php2"}, false},
		{"path is — dot is literal", rule(cond("path", "is", "/a.b")), customReq{path: "/axb"}, false},
		{"path begins_with", rule(cond("path", "begins_with", "/admin")), customReq{path: "/admin/users"}, true},
		{"path begins_with — elsewhere", rule(cond("path", "begins_with", "/admin")), customReq{path: "/x/admin"}, false},
		{"path contains — any value", rule(cond("path", "contains", "/.env", "/.git")), customReq{path: "/app/.git/config"}, true},
		{"path is case-sensitive", rule(cond("path", "is", "/Admin")), customReq{path: "/admin"}, false},
		{"method is", rule(cond("method", "is", "DELETE", "PUT")), customReq{method: "DELETE", path: "/"}, true},
		{"method is — other", rule(cond("method", "is", "DELETE", "PUT")), customReq{method: "GET", path: "/"}, false},
		{"method is_not", rule(cond("method", "is_not", "GET", "POST")), customReq{method: "PATCH", path: "/"}, true},
		{"method is_not — allowed", rule(cond("method", "is_not", "GET", "POST")), customReq{method: "GET", path: "/"}, false},
		{"UA contains (case-insensitive)", rule(cond("user_agent", "contains", "sqlmap")), customReq{path: "/", headers: map[string]string{"User-Agent": "SQLMap/1.8"}}, true},
		{"UA contains — browser", rule(cond("user_agent", "contains", "sqlmap")), customReq{path: "/"}, false},
		{"UA is", rule(cond("user_agent", "is", "curl/8.0")), customReq{path: "/", headers: map[string]string{"User-Agent": "curl/8.0"}}, true},
		{"UA missing — absent", rule(storage.WAFRuleCondition{Field: "user_agent", Operator: "missing"}), customReq{path: "/", noUA: true}, true},
		{"UA missing — empty", rule(storage.WAFRuleCondition{Field: "user_agent", Operator: "missing"}), customReq{path: "/", headers: map[string]string{"User-Agent": ""}}, true},
		{"UA missing — present", rule(storage.WAFRuleCondition{Field: "user_agent", Operator: "missing"}), customReq{path: "/"}, false},
		{"header absent", rule(storage.WAFRuleCondition{Field: "header", Header: "X-Api-Key", Operator: "absent"}), customReq{path: "/"}, true},
		{"header absent — present", rule(storage.WAFRuleCondition{Field: "header", Header: "X-Api-Key", Operator: "absent"}), customReq{path: "/", headers: map[string]string{"X-Api-Key": "k"}}, false},
		{"header present", rule(storage.WAFRuleCondition{Field: "header", Header: "X-Debug", Operator: "present"}), customReq{path: "/", headers: map[string]string{"X-Debug": "1"}}, true},
		{"header contains", rule(storage.WAFRuleCondition{Field: "header", Header: "Referer", Operator: "contains", Values: []string{"Spam.example"}}), customReq{path: "/", headers: map[string]string{"Referer": "https://spam.example/x"}}, true},
		{"header is — different", rule(storage.WAFRuleCondition{Field: "header", Header: "X-Env", Operator: "is", Values: []string{"prod"}}), customReq{path: "/", headers: map[string]string{"X-Env": "production"}}, false},
		{"AND — all match", loginNoUA, customReq{method: "POST", path: "/login", noUA: true}, true},
		{"AND — UA present", loginNoUA, customReq{method: "POST", path: "/login"}, false},
		{"AND — wrong method", loginNoUA, customReq{method: "GET", path: "/login", noUA: true}, false},
		{"disabled rule", []storage.WAFCustomRule{{ID: 120000, Disabled: true, Conditions: []storage.WAFRuleCondition{cond("path", "is", "/x")}}}, customReq{path: "/x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, fired := runCustom(t, "block", tc.rules, tc.req, "120000")
			if fired != tc.block {
				t.Fatalf("rule fired = %v, want %v (status %d)", fired, tc.block, status)
			}
			if tc.block && status != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", status)
			}
			if !tc.block && status != http.StatusOK {
				t.Fatalf("status = %d, want 200 (the CRS must not block the baseline request)", status)
			}
		})
	}
}

func TestCustomRules_E2E_DetectModeLogsOnly(t *testing.T) {
	status, fired := runCustom(t, "detect", rule(cond("path", "is", "/wp-login.php")), customReq{path: "/wp-login.php"}, "120000")
	if !fired {
		t.Fatal("detect mode: the match must be recorded")
	}
	if status != http.StatusOK {
		t.Fatalf("detect mode: status = %d, want 200 (logged only)", status)
	}
}

func TestGuidedRuleSecLang_ValidAndEquivalent(t *testing.T) {
	r := storage.WAFCustomRule{ID: 120004, Name: "Login bots", Disabled: true, Conditions: []storage.WAFRuleCondition{
		cond(storage.WAFFieldMethod, storage.WAFOpIs, "POST"),
		cond(storage.WAFFieldPath, storage.WAFOpBeginsWith, "/login"),
		{Field: storage.WAFFieldUserAgent, Operator: storage.WAFOpMissing},
	}}
	sl := GuidedRuleSecLang(r, 130007)
	if !strings.HasPrefix(sl, "# Login bots") || !strings.Contains(sl, "id:130007") || !strings.Contains(sl, "msg:'Login bots'") {
		t.Fatalf("SecLang = %q", sl)
	}
	if _, errs := waf.CheckSecLang(sl); len(errs) != 0 {
		t.Fatalf("converted SecLang refused by the allowlist: %+v", errs)
	}
	// Same behaviour as the guided rule: blocks POST /login without UA.
	route := storage.Route{ID: "r", Host: "h", WAFSecLang: sl}
	dirs, loadCRS := WAFDirectivesForRoute(route, nil)
	res, err := waf.DryRun(dirs, loadCRS, waf.DryRunRequest{Method: "POST", Path: "/login", Host: "h"})
	if err != nil || !res.Blocked || res.BlockedBy != 130007 {
		t.Fatalf("converted rule: res=%+v err=%v, want blocked by 130007", res, err)
	}
	res, _ = waf.DryRun(dirs, loadCRS, waf.DryRunRequest{Method: "POST", Path: "/login", Host: "h",
		Headers: [][2]string{{"User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0"}, {"Accept", "text/html"}}})
	if res.Blocked {
		t.Fatalf("with a browser UA the request must pass: %+v", res)
	}
}

func TestWAFDirectivesForRoute_DraftOverridesStored(t *testing.T) {
	route := storage.Route{ID: "r", Host: "h", WAFMode: "off", WAFSecLang: `SecAction "id:130000,phase:1,pass,nolog"`}
	stored, loadCRS := WAFDirectivesForRoute(route, nil)
	if !strings.Contains(stored, "id:130000") || !loadCRS {
		t.Fatalf("stored SecLang missing or CRS off: %q", stored)
	}
	draft := `SecAction "id:130001,phase:1,pass,nolog"`
	withDraft, _ := WAFDirectivesForRoute(route, &draft)
	if strings.Contains(withDraft, "id:130000") || !strings.Contains(withDraft, "id:130001") {
		t.Fatalf("draft must replace the stored SecLang: %q", withDraft)
	}
}

func TestBuildWAFHandler_SecLang_LastBeforeCRS(t *testing.T) {
	got := buildWAFHandler("r", "h", "block", false, false, nil, nil, nil,
		[]storage.WAFCustomRule{{ID: 120000, Conditions: []storage.WAFRuleCondition{cond("path", "is", "/x")}}},
		"  SecAction \"id:130000,phase:1,pass,nolog\"\n")
	dirs := got["directives"].(string)
	i1, i2, i3 := strings.Index(dirs, "id:120000"), strings.Index(dirs, "id:130000"), strings.Index(dirs, "Include @coraza")
	if !(i1 >= 0 && i1 < i2 && i2 < i3) {
		t.Fatalf("order must be guided < SecLang < Include; got %q", dirs)
	}
	blank := buildWAFHandler("r", "h", "block", false, false, nil, nil, nil, nil, " \n ")
	plain := buildWAFHandler("r", "h", "block", false, false, nil, nil, nil, nil, "")
	if blank["directives"] != plain["directives"] {
		t.Fatal("blank SecLang must not change the directives")
	}
}
