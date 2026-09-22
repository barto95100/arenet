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
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/waf"
)

func TestTargetedExclusionDirectives_Shapes(t *testing.T) {
	got := targetedExclusionDirectives([]storage.WAFTargetedExclusion{
		{RuleID: 942100, Target: "ARGS:content", Path: "/api/", PathPrefix: true},
		{RuleID: 941100, Target: "ARGS:body"},
		{RuleID: 942100, Target: "ARGS:content", Path: "/api/save"},
		{RuleID: 942100, Target: "ARGS:q", Path: "/search", PathPrefix: true},
	})
	want := []string{
		`SecAction "id:110000,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body"`,
		`SecRule REQUEST_FILENAME "@beginsWith /api/" "id:110001,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:content"`,
		`SecRule REQUEST_FILENAME "@streq /api/save" "id:110002,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:content"`,
		// "below /search" = /search itself + /search/…, never /searchx.
		`SecRule REQUEST_FILENAME "@streq /search" "id:110003,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:q"`,
		`SecRule REQUEST_FILENAME "@beginsWith /search/" "id:110004,phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:q"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("directives =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if targetedExclusionDirectives(nil) != nil {
		t.Error("no exclusion must render no directive")
	}
}

func TestBuildWAFHandler_TargetedExclusions_BeforeCRSAfterSecAction(t *testing.T) {
	got := buildWAFHandler("r-1", "example.com", "block", false, false, []int{920170}, nil,
		[]storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:content"}}, nil, "")
	dirs, _ := got["directives"].(string)
	iSecAction := strings.Index(dirs, "id:999001")
	iTargeted := strings.Index(dirs, "id:110000")
	iInclude := strings.Index(dirs, "Include @coraza.conf-recommended")
	if iSecAction < 0 || iTargeted < 0 || iInclude < 0 || !(iSecAction < iTargeted && iTargeted < iInclude) {
		t.Fatalf("order must be 999001 < 110000 < Include; directives = %q", dirs)
	}
}

func TestBuildWAFHandler_NoTargeted_Unchanged(t *testing.T) {
	a := buildWAFHandler("r-1", "example.com", "block", false, false, []int{942100}, nil, nil, nil, "")
	b := buildWAFHandler("r-1", "example.com", "block", false, false, []int{942100}, nil, []storage.WAFTargetedExclusion{}, nil, "")
	if a["directives"] != b["directives"] {
		t.Fatalf("empty targeted list changed the directives: %q vs %q", a["directives"], b["directives"])
	}
	if strings.Contains(a["directives"].(string), "110000") {
		t.Fatalf("no targeted exclusion must emit no 110000 directive: %q", a["directives"])
	}
}

func TestBuildWAFHandler_TargetedOrderIndependent(t *testing.T) {
	x := storage.WAFTargetedExclusion{RuleID: 942100, Target: "ARGS:a"}
	y := storage.WAFTargetedExclusion{RuleID: 941100, Target: "ARGS:b", Path: "/p"}
	a := buildWAFHandler("r-1", "h", "block", false, false, nil, nil, []storage.WAFTargetedExclusion{x, y}, nil, "")
	b := buildWAFHandler("r-1", "h", "block", false, false, nil, nil, []storage.WAFTargetedExclusion{y, x}, nil, "")
	if a["directives"] != b["directives"] {
		t.Fatalf("input order changed the directives (pool key churn)")
	}
}

// --- End-to-end against Coraza + the real CRS -----------------------

type targetedCaptureSink struct {
	mu     sync.Mutex
	events []waf.Event
}

func (c *targetedCaptureSink) Emit(e waf.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *targetedCaptureSink) fired(ruleID string) (waf.Event, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.RuleID == ruleID {
			return e, true
		}
	}
	return waf.Event{}, false
}

// sqliPayload trips CRS 942100 (libinjection) deterministically.
const sqliPayload = "1%27%20OR%20%271%27=%271"

// runTargeted provisions the arenet_waf handler exactly as caddymgr
// emits it for the given exclusions, sends one GET and reports the
// captured events.
func runTargeted(t *testing.T, targeted []storage.WAFTargetedExclusion, url string) *targetedCaptureSink {
	t.Helper()
	cfg := buildWAFHandler("r-e2e", "example.com", "block", false, false, nil, nil, targeted, nil, "")
	h := &waf.ArenetWafHandler{
		RouteID:      "r-e2e",
		Mode:         "block",
		Directives:   cfg["directives"].(string),
		LoadOWASPCRS: true,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision (the emitted directives must parse with the CRS): %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })

	sink := &targetedCaptureSink{}
	waf.SetGlobalSink(sink)
	t.Cleanup(func() { waf.SetGlobalSink(nil) })

	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	_ = h.ServeHTTP(rec, req, next)
	return sink
}

func TestTargetedExclusion_E2E(t *testing.T) {
	onSave := []storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:content", Path: "/api/save"}}
	underAPI := []storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:content", Path: "/api", PathPrefix: true}}
	everywhere := []storage.WAFTargetedExclusion{{RuleID: 942100, Target: "ARGS:content"}}

	cases := []struct {
		name      string
		targeted  []storage.WAFTargetedExclusion
		url       string
		wantFired bool
	}{
		{"baseline fires", nil, "http://example.com/api/save?content=" + sqliPayload, true},
		{"excluded field on its path", onSave, "http://example.com/api/save?content=" + sqliPayload, false},
		{"other field still inspected", onSave, "http://example.com/api/save?other=" + sqliPayload, true},
		{"other path still inspected", onSave, "http://example.com/login?content=" + sqliPayload, true},
		{"prefix covers sub-path", underAPI, "http://example.com/api/save?content=" + sqliPayload, false},
		{"prefix covers the path itself", underAPI, "http://example.com/api?content=" + sqliPayload, false},
		{"prefix does not cover sibling", underAPI, "http://example.com/login?content=" + sqliPayload, true},
		{"prefix does not cover a longer name", underAPI, "http://example.com/apix?content=" + sqliPayload, true},
		{"no path covers every path", everywhere, "http://example.com/login?content=" + sqliPayload, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := runTargeted(t, tc.targeted, tc.url)
			ev, fired := sink.fired("942100")
			if fired != tc.wantFired {
				t.Fatalf("942100 fired = %v, want %v", fired, tc.wantFired)
			}
			if fired && strings.Contains(tc.url, "content=") && ev.MatchedVar != "ARGS:content" {
				t.Errorf("MatchedVar = %q, want ARGS:content (the exact target an exclusion needs)", ev.MatchedVar)
			}
		})
	}
}
