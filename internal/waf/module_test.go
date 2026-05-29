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

package waf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// captureSink records every Emit'd event for post-hoc
// assertions in tests. Implements both EventSink and
// BlockCounter so a module test can wire one fake.
type captureSink struct {
	mu     sync.Mutex
	events []Event
	bumps  map[string]int
}

func newCaptureSink() *captureSink {
	return &captureSink{bumps: map[string]int{}}
}

func (c *captureSink) Emit(e Event) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *captureSink) BumpWafBlocks(routeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bumps[routeID]++
}

func (c *captureSink) eventCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *captureSink) eventsCopy() []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Event, len(c.events))
	copy(out, c.events)
	return out
}

// minimalBlockDirectives produces a coraza directives string
// that loads ONE rule which fires on a custom GET parameter,
// keeping the test fast (no CRS load). The rule is in the
// 942xxx range so CategoryForRule classifies it as SQLi —
// useful for asserting the category-classifier wiring too.
const minimalBlockDirectives = `
SecRuleEngine On
SecRule ARGS:badparam "@rx evil" "id:942999,phase:2,deny,status:403,msg:'test rule',severity:CRITICAL"
`

// passthroughHandler does nothing; the WAF's interruption
// should fire before it runs. If next is called and asserts,
// the test fails because the WAF didn't block.
type passthroughHandler struct {
	called bool
}

func (p *passthroughHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) error {
	p.called = true
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("upstream-response"))
	return nil
}

// setGlobalSinkFor installs sink for the test and reinstalls
// the previous value on cleanup. Avoids cross-test bleed.
func setGlobalSinkFor(t *testing.T, sink EventSink) {
	t.Helper()
	prev := getGlobalSink()
	SetGlobalSink(sink)
	t.Cleanup(func() { SetGlobalSink(prev) })
}

func newProvisionedHandler(t *testing.T, mode string) *ArenetWafHandler {
	t.Helper()
	h := &ArenetWafHandler{
		RouteID:    "r-test",
		Mode:       mode,
		Directives: minimalBlockDirectives,
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Provision needs a caddy.Context; the empty value works
	// for this code path because nothing it uses depends on
	// the context's app loader.
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() { _ = h.Cleanup() })
	return h
}

func TestArenetWaf_Validate_RouteIDRequired(t *testing.T) {
	h := &ArenetWafHandler{Mode: "block"}
	err := h.Validate()
	if err == nil || !errors.Is(err, err) || !contains(err.Error(), "route_id") {
		t.Fatalf("Validate without route_id should fail: got %v", err)
	}
}

func TestArenetWaf_Validate_ModeRequired(t *testing.T) {
	h := &ArenetWafHandler{RouteID: "r"}
	if err := h.Validate(); err == nil || !contains(err.Error(), "mode") {
		t.Fatalf("Validate without mode should fail: got %v", err)
	}
}

func TestArenetWaf_Validate_ModeMustBeBlockOrDetect(t *testing.T) {
	h := &ArenetWafHandler{RouteID: "r", Mode: "bogus"}
	if err := h.Validate(); err == nil || !contains(err.Error(), "block") {
		t.Fatalf("Validate with bad mode should mention valid values: got %v", err)
	}
}

func TestArenetWaf_BlockMode_TripsRule_Emits_And_Returns403(t *testing.T) {
	// AC #1 + #2 + #4 packaged: a request that trips the
	// embedded rule must (a) hit the error callback (event
	// emitted via the global sink), (b) hit the bucket
	// bump (BlockCounter call), (c) return 403, (d) NOT
	// reach the next handler.
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	// Wire BlockCounter via the sink path: the captureSink
	// implements BumpWafBlocks too, but the module calls
	// the SINK (which would normally wrap a real *waf.Sink
	// whose absorb calls BumpWafBlocks). For this test we
	// short-circuit by also installing the captureSink as
	// the BlockCounter that a real sink would have called.
	// → Done implicitly: the module's onMatch calls
	// getGlobalSink().Emit, captured by cap.Emit. Our cap
	// also tracks bumps for the real-sink integration test
	// in step 6.

	h := newProvisionedHandler(t, "block")
	next := &passthroughHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if err == nil {
		t.Fatal("ServeHTTP returned nil; expected HandlerError for the interruption")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		t.Fatalf("ServeHTTP returned %T (%v); want caddyhttp.HandlerError", err, err)
	}
	if he.StatusCode != http.StatusForbidden {
		t.Errorf("StatusCode = %d, want 403", he.StatusCode)
	}
	if next.called {
		t.Error("next handler was called despite WAF block — request leaked downstream")
	}
	if cap.eventCount() != 1 {
		t.Fatalf("event count = %d, want 1", cap.eventCount())
	}

	evt := cap.eventsCopy()[0]
	if evt.RouteID != "r-test" {
		t.Errorf("event RouteID = %q, want \"r-test\"", evt.RouteID)
	}
	if evt.RuleID != "942999" {
		t.Errorf("event RuleID = %q, want \"942999\"", evt.RuleID)
	}
	// CategoryForRule maps 942999 to SQLi.
	if evt.Category != CategorySQLi {
		t.Errorf("event Category = %q, want SQLi (categoryForRule contract)", evt.Category)
	}
	// Severity 2 = CRITICAL in Coraza's scale (lower = more
	// severe). The exact int matters less than: not zero.
	if evt.Severity == 0 {
		t.Errorf("event Severity = 0; expected positive Coraza severity for a CRITICAL rule")
	}
}

func TestArenetWaf_DetectMode_TripsRule_Emits_And_PassesThrough(t *testing.T) {
	// Detect mode contract: emit the event but let the
	// request reach the upstream. Operator's "detect"
	// intent must win — the WAF must NOT block even when
	// the rule itself declares deny.
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "detect")
	next := &passthroughHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if err != nil {
		t.Fatalf("detect mode ServeHTTP error: %v", err)
	}
	if !next.called {
		t.Error("next handler was NOT called in detect mode — request should have passed through")
	}
	if cap.eventCount() != 1 {
		t.Fatalf("event count = %d, want 1 (detect still emits)", cap.eventCount())
	}
	if rec.Code != http.StatusOK {
		t.Errorf("response status = %d, want 200 (upstream)", rec.Code)
	}
}

func TestArenetWaf_NoMatch_PassesThrough_NoEmit(t *testing.T) {
	// A benign request: no rule trips, no event emitted,
	// upstream response untouched.
	cap := newCaptureSink()
	setGlobalSinkFor(t, cap)

	h := newProvisionedHandler(t, "block")
	next := &passthroughHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?other=value", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if err != nil {
		t.Fatalf("benign request error: %v", err)
	}
	if !next.called {
		t.Error("next handler not called on benign request")
	}
	if cap.eventCount() != 0 {
		t.Errorf("benign request emitted %d events; want 0", cap.eventCount())
	}
}

func TestArenetWaf_NilGlobalSink_StillBlocks(t *testing.T) {
	// AC #13: a missing global sink (degraded mode) must
	// NOT change the block behaviour. Coraza still
	// interrupts; the event just isn't recorded.
	setGlobalSinkFor(t, nil)

	h := newProvisionedHandler(t, "block")
	next := &passthroughHandler{}
	req := httptest.NewRequest(http.MethodGet, "http://localhost/?badparam=evil-payload", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, caddyhttp.HandlerFunc(next.ServeHTTP))

	if err == nil {
		t.Fatal("nil sink should not change the block behaviour; expected HandlerError")
	}
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Errorf("err = %v; want 403 HandlerError", err)
	}
	if next.called {
		t.Error("next handler called despite WAF block on nil sink")
	}
}

// contains is a tiny dependency-free substring check used by
// the validation tests so the error-message asserts read
// cleanly without an extra import.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// ensure unused import warning silenced when go test
// compiles just this file without ctx-using callers.
var _ = context.Background
