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

package metrics

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// newTestHandler returns a RouteMetricsHandler with the registry
// field set directly (bypassing Provision). For ServeHTTP-focused
// tests that don't need to exercise the singleton resolution path.
func newTestHandler(t *testing.T, registry *Registry, routeID string) *RouteMetricsHandler {
	t.Helper()
	return &RouteMetricsHandler{
		RouteID:  routeID,
		registry: registry,
	}
}

// fakeRWNoHijack is a minimal http.ResponseWriter that does NOT
// implement Hijacker / Flusher / Pusher. Used to validate the
// graceful-degradation paths of statusRecorder.
type fakeRWNoHijack struct {
	header http.Header
	body   []byte
	status int
}

func (f *fakeRWNoHijack) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *fakeRWNoHijack) Write(b []byte) (int, error) {
	f.body = append(f.body, b...)
	return len(b), nil
}
func (f *fakeRWNoHijack) WriteHeader(code int) { f.status = code }

// --- Module registration ---------------------------------------------------

func TestRouteMetrics_Module_Registers(t *testing.T) {
	// caddy.GetModule resolves the registered module by its dotted
	// ID. The factory returns a *RouteMetricsHandler pointer (per
	// CaddyModule()), so we assert that the type assertion succeeds.
	info, err := caddy.GetModule(ModuleID)
	if err != nil {
		t.Fatalf("caddy.GetModule(%q): %v", ModuleID, err)
	}
	mod := info.New()
	if _, ok := mod.(*RouteMetricsHandler); !ok {
		t.Errorf("registered module type is %T, want *RouteMetricsHandler", mod)
	}
}

func TestRouteMetrics_HandlerName_MatchesLastSegment(t *testing.T) {
	// Spec §3.5 invariant: HandlerName MUST be the last dotted
	// segment of ModuleID. Mixing forms silently breaks Caddy config
	// load. Test guards future refactors.
	const want = "arenet_routemetrics"
	if HandlerName != want {
		t.Errorf("HandlerName=%q want %q", HandlerName, want)
	}
	// Module ID must end with HandlerName preceded by a dot.
	expectedSuffix := "." + HandlerName
	if got := ModuleID[len(ModuleID)-len(expectedSuffix):]; got != expectedSuffix {
		t.Errorf("ModuleID=%q does not end with %q", ModuleID, expectedSuffix)
	}
}

// --- Provision -------------------------------------------------------------

func TestRouteMetrics_Provision_InstallsRegistry(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	reg := NewRegistry()
	SetRegistry(reg)

	h := &RouteMetricsHandler{RouteID: "r1"}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision returned %v", err)
	}
	if h.registry != reg {
		t.Errorf("h.registry=%p want %p", h.registry, reg)
	}
}

func TestRouteMetrics_Provision_NoRegistry(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()
	// No SetRegistry call: GlobalRegistry() returns nil.

	h := &RouteMetricsHandler{RouteID: "r1"}
	err := h.Provision(caddy.Context{})
	if !errors.Is(err, ErrRegistryNotInstalled) {
		t.Errorf("Provision err=%v want ErrRegistryNotInstalled", err)
	}
}

// --- Validate --------------------------------------------------------------

func TestRouteMetrics_Validate_EmptyRouteID(t *testing.T) {
	h := &RouteMetricsHandler{RouteID: ""}
	if err := h.Validate(); err == nil {
		t.Error("Validate accepted empty RouteID; want error")
	}
}

func TestRouteMetrics_Validate_NonEmptyRouteID(t *testing.T) {
	h := &RouteMetricsHandler{RouteID: "r1"}
	if err := h.Validate(); err != nil {
		t.Errorf("Validate returned %v on valid RouteID", err)
	}
}

// --- ServeHTTP increment paths --------------------------------------------

func TestRouteMetrics_IncrementsOnSuccess(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	snap := reg.Snapshot()
	if snap["r1"].Reqs != 1 || snap["r1"].Errs != 0 {
		t.Errorf("delta=%+v want Reqs=1 Errs=0", snap["r1"])
	}
}

func TestRouteMetrics_IncrementsOnError(t *testing.T) {
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusServiceUnavailable) // 503
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}

	snap := reg.Snapshot()
	if snap["r1"].Reqs != 1 || snap["r1"].Errs != 1 {
		t.Errorf("delta=%+v want Reqs=1 Errs=1", snap["r1"])
	}
}

func TestRouteMetrics_Increments_4xxNotCounted(t *testing.T) {
	// Spec §1.3: 4xx must increment reqs but NOT errs.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound) // 404
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, next)

	snap := reg.Snapshot()
	if snap["r1"].Reqs != 1 || snap["r1"].Errs != 0 {
		t.Errorf("delta=%+v want Reqs=1 Errs=0 (4xx must not count as err)", snap["r1"])
	}
}

func TestRouteMetrics_Increments_ImplicitWriteOK(t *testing.T) {
	// When the inner handler writes the body without calling
	// WriteHeader, http.ResponseWriter implicitly emits 200.
	// statusRecorder must record 200, not 0.
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		_, _ = w.Write([]byte("hello"))
		return nil
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	_ = h.ServeHTTP(rec, req, next)

	snap := reg.Snapshot()
	// 200 implicit → reqs +1, errs +0
	if snap["r1"].Reqs != 1 || snap["r1"].Errs != 0 {
		t.Errorf("delta=%+v want Reqs=1 Errs=0 (implicit 200)", snap["r1"])
	}
}

func TestRouteMetrics_Increments_OnNextError(t *testing.T) {
	// next.ServeHTTP returns an error WITHOUT writing the header.
	// statusRecorder still has its default 200; the defer closure
	// observes that and increments reqs. This matches §11.6: a
	// handler that errors before writing is recorded as 200 (which
	// matches Caddy's implicit-OK behavior on the wire).
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")

	upstreamErr := errors.New("upstream failed")
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return upstreamErr
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	err := h.ServeHTTP(rec, req, next)
	if !errors.Is(err, upstreamErr) {
		t.Errorf("ServeHTTP did not propagate next's error: %v", err)
	}

	snap := reg.Snapshot()
	if snap["r1"].Reqs != 1 {
		t.Errorf("delta=%+v want Reqs=1 even on next-error", snap["r1"])
	}
	if snap["r1"].Errs != 0 {
		t.Errorf("delta=%+v want Errs=0 (status defaulted to 200 per §11.6)", snap["r1"])
	}
}

// --- statusRecorder behavior ----------------------------------------------

// hijackableRW implements http.ResponseWriter + http.Hijacker. Used
// to test the forwarding path of statusRecorder.Hijack.
type hijackableRW struct {
	*httptest.ResponseRecorder
	hijackCalled bool
}

func (h *hijackableRW) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.hijackCalled = true
	// Return a sentinel error so we don't need a real net.Conn for
	// the test — the assertion is on "did the call reach us".
	return nil, nil, errors.New("hijack reached underlying writer")
}

func TestRouteMetrics_StatusRecorder_ForwardsHijacker(t *testing.T) {
	underlying := &hijackableRW{ResponseRecorder: httptest.NewRecorder()}
	rec := newStatusRecorder(underlying)

	_, _, err := rec.Hijack()
	if !underlying.hijackCalled {
		t.Error("Hijack did not reach the underlying writer")
	}
	if err == nil || err.Error() != "hijack reached underlying writer" {
		t.Errorf("Hijack err=%v want 'hijack reached underlying writer'", err)
	}
}

func TestRouteMetrics_StatusRecorder_DegradesNoHijacker(t *testing.T) {
	// fakeRWNoHijack does NOT implement Hijacker. statusRecorder
	// must return ErrNotSupported, not panic.
	rec := newStatusRecorder(&fakeRWNoHijack{})
	_, _, err := rec.Hijack()
	if !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack err=%v want http.ErrNotSupported", err)
	}
}

func TestRouteMetrics_StatusRecorder_Flush_NoOpOnPlainWriter(t *testing.T) {
	// fakeRWNoHijack does not implement Flusher. Calling Flush on
	// our recorder must be a no-op, not a panic.
	rec := newStatusRecorder(&fakeRWNoHijack{})
	rec.Flush()
	// Reached here without panic → pass.
}

func TestRouteMetrics_StatusRecorder_DoubleWriteHeader_KeepsFirst(t *testing.T) {
	// First WriteHeader wins for the recorded status. Subsequent
	// calls forward to the underlying writer (which may log
	// "superfluous WriteHeader") but do not overwrite our recorded
	// status.
	underlying := httptest.NewRecorder()
	rec := newStatusRecorder(underlying)

	rec.WriteHeader(http.StatusServiceUnavailable)  // 503
	rec.WriteHeader(http.StatusInternalServerError) // 500 — must NOT overwrite

	if rec.Status() != http.StatusServiceUnavailable {
		t.Errorf("Status()=%d want 503 (first write wins)", rec.Status())
	}
}

func TestRouteMetrics_StatusRecorder_DefaultIsOK(t *testing.T) {
	// A freshly-created recorder reports 200 before any write.
	rec := newStatusRecorder(httptest.NewRecorder())
	if rec.Status() != http.StatusOK {
		t.Errorf("default Status()=%d want %d", rec.Status(), http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Step V.1.2 — eligibleForNormal gate tests.
//
// Pure-function tests that don't need a Caddy module
// lifecycle. Constructs a bare RouteMetricsHandler with
// just the ExcludePaths field set as needed.

// recordingNormalSink is the test stub that captures Submit
// calls. Mirrors the V.1.1 sink tests' countingLANCounter
// shape. Concurrent-safe via the sync.Mutex on calls.
type recordingNormalSink struct {
	mu    sync.Mutex
	calls []recordingNormalSinkCall
}

type recordingNormalSinkCall struct {
	status int
	srcIP  string
	route  string
}

func (s *recordingNormalSink) Submit(status int, srcIP, routeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, recordingNormalSinkCall{status: status, srcIP: srcIP, route: routeID})
}

func (s *recordingNormalSink) snapshot() []recordingNormalSinkCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]recordingNormalSinkCall, len(s.calls))
	copy(out, s.calls)
	return out
}

func newReqForGate(method, path string) *http.Request {
	r := httptest.NewRequest(method, "http://test.local"+path, nil)
	r.RemoteAddr = "203.0.113.7:54321"
	return r
}

func TestEligibleForNormal_StatusCodes(t *testing.T) {
	h := &RouteMetricsHandler{RouteID: "r1"}
	cases := []struct {
		name   string
		status int
		want   bool
	}{
		{"100 continue rejected (1xx)", 100, false},
		{"101 switching protocols rejected (1xx)", 101, false},
		{"200 OK accepted", 200, true},
		{"204 No Content accepted", 204, true},
		{"301 Moved accepted (3xx)", 301, true},
		{"302 Found accepted (3xx)", 302, true},
		{"304 Not Modified REJECTED (D1 carve-out)", 304, false},
		{"307 Temporary Redirect accepted (3xx)", 307, true},
		{"308 Permanent Redirect accepted (3xx)", 308, true},
		{"400 Bad Request rejected (4xx)", 400, false},
		{"401 Unauthorized rejected (4xx)", 401, false},
		{"403 Forbidden rejected (4xx)", 403, false},
		{"404 Not Found rejected (4xx)", 404, false},
		{"429 Too Many Requests rejected (4xx)", 429, false},
		{"500 ISE rejected (5xx)", 500, false},
		{"502 Bad Gateway rejected (5xx)", 502, false},
		{"503 Unavailable rejected (5xx)", 503, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := newReqForGate(http.MethodGet, "/")
			if got := h.eligibleForNormal(req, c.status); got != c.want {
				t.Errorf("status=%d → got %v want %v", c.status, got, c.want)
			}
		})
	}
}

func TestEligibleForNormal_Methods(t *testing.T) {
	h := &RouteMetricsHandler{RouteID: "r1"}
	cases := []struct {
		method string
		want   bool
	}{
		{http.MethodGet, true},
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodDelete, true},
		{http.MethodPatch, true},
		{http.MethodHead, false},    // D1: probe-class, rejected
		{http.MethodOptions, false}, // D1: preflight, rejected
		// Trace + Connect are exotic; not explicitly listed in
		// the spec but accepted by default (anything not in
		// the reject list passes). Pin both to the current
		// behavior so a future spec tightening surfaces here.
		{http.MethodTrace, true},
		{http.MethodConnect, true},
	}
	for _, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			req := newReqForGate(c.method, "/api/v1/some-endpoint")
			if got := h.eligibleForNormal(req, 200); got != c.want {
				t.Errorf("method=%s → got %v want %v", c.method, got, c.want)
			}
		})
	}
}

func TestEligibleForNormal_HardcodedExclude(t *testing.T) {
	h := &RouteMetricsHandler{RouteID: "r1"}
	// Each hardcoded prefix MUST reject. Subpaths under the
	// prefix MUST also reject (HasPrefix semantics — pins
	// the D3 contract that a future regex-based matcher
	// can't silently change the semantics).
	for _, prefix := range hardcodedExcludePaths {
		t.Run("exact "+prefix, func(t *testing.T) {
			req := newReqForGate(http.MethodGet, prefix)
			if h.eligibleForNormal(req, 200) {
				t.Errorf("path=%s should be rejected (hardcoded exclude)", prefix)
			}
		})
		t.Run("subpath under "+prefix, func(t *testing.T) {
			req := newReqForGate(http.MethodGet, prefix+"/sub/resource")
			if h.eligibleForNormal(req, 200) {
				t.Errorf("path=%s/sub/resource should be rejected (HasPrefix)", prefix)
			}
		})
	}
}

func TestEligibleForNormal_HardcodedExclude_IncludesGeoEventsWSPreempt(t *testing.T) {
	// Pin the spec-freeze §7 finding: /api/v1/ws/geo-events
	// MUST be in the hardcoded list to pre-empt the
	// meta-recursion (opening /map → WS upgrade → emit
	// normal event for the upgrade → publish back over
	// the same WS → operator sees own connection arc).
	// A future regression that drops this entry from the
	// hardcoded list fails this test immediately.
	found := false
	for _, p := range hardcodedExcludePaths {
		if p == "/api/v1/ws/geo-events" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("/api/v1/ws/geo-events MUST be in hardcodedExcludePaths (spec-freeze §7 meta-recursion pre-empt)")
	}
}

func TestEligibleForNormal_ConfiguredExclude(t *testing.T) {
	h := &RouteMetricsHandler{
		RouteID:      "r1",
		ExcludePaths: []string{"/internal/probes", "/v2/heartbeat"},
	}
	cases := []struct {
		path string
		want bool
	}{
		// Configured exclude — direct hit + subpath.
		{"/internal/probes", false},
		{"/internal/probes/foo", false},
		{"/v2/heartbeat", false},
		{"/v2/heartbeat/check", false},
		// Adjacent paths NOT excluded (prefix semantics).
		{"/internal/something-else", true},
		{"/v2/health", true},
		// Standard public path — passes.
		{"/api/v1/widgets", true},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			req := newReqForGate(http.MethodGet, c.path)
			if got := h.eligibleForNormal(req, 200); got != c.want {
				t.Errorf("path=%s → got %v want %v", c.path, got, c.want)
			}
		})
	}
}

func TestEligibleForNormal_ConfiguredExcludeExtends_NotReplaces(t *testing.T) {
	// Hardcoded list still applies even when ExcludePaths
	// is non-empty — operator extension never replaces
	// the floor.
	h := &RouteMetricsHandler{
		RouteID:      "r1",
		ExcludePaths: []string{"/custom"},
	}
	req := newReqForGate(http.MethodGet, "/healthz")
	if h.eligibleForNormal(req, 200) {
		t.Error("/healthz must remain rejected even with ExcludePaths set (extension semantics)")
	}
}

// ---------------------------------------------------------------------------
// Step V.1.2 — ServeHTTP Submit integration tests.

func TestServeHTTP_NilSink_NoCrash(t *testing.T) {
	// V.1 disabled path (normalSink=nil). ServeHTTP must
	// process requests without panicking. The V.1 defer
	// branch is a single nil-check.
	t.Cleanup(ResetForTest)
	ResetForTest()

	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")
	// normalSink intentionally not set.

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := newReqForGate(http.MethodGet, "/")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP returned %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
}

func TestServeHTTP_CallsSubmit_WhenEligible(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	sink := &recordingNormalSink{}
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")
	h.normalSink = sink
	h.clientIP = func(r *http.Request) string { return "203.0.113.42" }

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	req := newReqForGate(http.MethodGet, "/api/v1/widgets")
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP returned %v", err)
	}
	calls := sink.snapshot()
	if len(calls) != 1 {
		t.Fatalf("Submit calls=%d, want 1", len(calls))
	}
	got := calls[0]
	if got.status != 200 || got.srcIP != "203.0.113.42" || got.route != "r1" {
		t.Errorf("Submit args = %+v want {status:200 srcIP:203.0.113.42 route:r1}", got)
	}
}

func TestServeHTTP_DoesNotCallSubmit_WhenExcluded(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	sink := &recordingNormalSink{}
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")
	h.normalSink = sink
	h.clientIP = RemoteAddrClientIPFn

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	// /healthz is hardcoded-excluded.
	req := newReqForGate(http.MethodGet, "/healthz")
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP returned %v", err)
	}
	if got := len(sink.snapshot()); got != 0 {
		t.Errorf("Submit calls on /healthz = %d, want 0", got)
	}
}

func TestServeHTTP_DoesNotCallSubmit_WhenStatusRejected(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	sink := &recordingNormalSink{}
	reg := NewRegistry()
	reg.Sync([]string{"r1"})
	h := newTestHandler(t, reg, "r1")
	h.normalSink = sink
	h.clientIP = RemoteAddrClientIPFn

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusInternalServerError) // 500 — rejected
		return nil
	})
	req := newReqForGate(http.MethodGet, "/api/v1/widgets")
	if err := h.ServeHTTP(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("ServeHTTP returned %v", err)
	}
	if got := len(sink.snapshot()); got != 0 {
		t.Errorf("Submit calls on 5xx response = %d, want 0", got)
	}
}

func TestServeHTTP_Provision_ResolvesNormalSinkAndClientIP(t *testing.T) {
	// AC #11 path — Provision installs the optional V.1
	// dependencies from the globals. Pinned so a future
	// regression (e.g. Provision dropping the V.1 lines)
	// surfaces without needing a full ServeHTTP round.
	t.Cleanup(ResetForTest)
	ResetForTest()

	reg := NewRegistry()
	SetRegistry(reg)
	sink := &recordingNormalSink{}
	SetNormalSubmitter(sink)
	customIPFn := func(r *http.Request) string { return "custom" }
	SetClientIPFn(customIPFn)

	h := &RouteMetricsHandler{RouteID: "r1"}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if h.normalSink == nil {
		t.Error("Provision must resolve normalSink from GlobalNormalSubmitter()")
	}
	if h.clientIP == nil {
		t.Error("Provision must resolve clientIP from GlobalClientIPFn()")
	}
}

func TestServeHTTP_Provision_NoNormalSink_StillProvisionsCleanly(t *testing.T) {
	// V.1 disabled path is the default (SAMPLE_PCT=0 in
	// production → SetNormalSubmitter never called).
	// Provision MUST succeed regardless.
	t.Cleanup(ResetForTest)
	ResetForTest()

	reg := NewRegistry()
	SetRegistry(reg)
	// SetNormalSubmitter intentionally NOT called.

	h := &RouteMetricsHandler{RouteID: "r1"}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v (V.1 disabled should not gate Provision)", err)
	}
	if h.normalSink != nil {
		t.Errorf("normalSink=%T want nil (no SetNormalSubmitter call)", h.normalSink)
	}
}

// ---------------------------------------------------------------------------
// Step V.1.2 — ClientIPFunc fallback + SetClientIPFn.

func TestRemoteAddrClientIPFn_StripsPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://test.local/", nil)
	r.RemoteAddr = "10.0.0.5:54321"
	if got := RemoteAddrClientIPFn(r); got != "10.0.0.5" {
		t.Errorf("RemoteAddrClientIPFn=%q want %q", got, "10.0.0.5")
	}
}

func TestRemoteAddrClientIPFn_IPv6WithPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://test.local/", nil)
	r.RemoteAddr = "[::1]:54321"
	// net.SplitHostPort strips the brackets — caller sees "::1".
	if got := RemoteAddrClientIPFn(r); got != "::1" {
		t.Errorf("RemoteAddrClientIPFn=%q want %q", got, "::1")
	}
}

func TestRemoteAddrClientIPFn_Malformed_ReturnsRawString(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://test.local/", nil)
	r.RemoteAddr = "garbage-no-port"
	// Fallback: SplitHostPort errors → return raw string.
	if got := RemoteAddrClientIPFn(r); got != "garbage-no-port" {
		t.Errorf("RemoteAddrClientIPFn=%q want %q", got, "garbage-no-port")
	}
}

func TestRemoteAddrClientIPFn_NilRequest(t *testing.T) {
	if got := RemoteAddrClientIPFn(nil); got != "" {
		t.Errorf("RemoteAddrClientIPFn(nil)=%q want \"\"", got)
	}
}

func TestGlobalClientIPFn_FallbackWhenUnset(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()
	fn := GlobalClientIPFn()
	if fn == nil {
		t.Fatal("GlobalClientIPFn() returned nil; must fall back to RemoteAddrClientIPFn")
	}
	r := httptest.NewRequest(http.MethodGet, "http://test.local/", nil)
	r.RemoteAddr = "9.9.9.9:1234"
	if got := fn(r); got != "9.9.9.9" {
		t.Errorf("fallback fn returned %q want 9.9.9.9", got)
	}
}

func TestSetGlobalNormalSubmitter_RoundTrip(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()
	sink := &recordingNormalSink{}
	SetNormalSubmitter(sink)
	got := GlobalNormalSubmitter()
	if got != sink {
		t.Errorf("GlobalNormalSubmitter()=%p want %p", got, sink)
	}
}

func TestSetGlobalNormalSubmitter_AcceptsReassignment(t *testing.T) {
	// Unlike SetRegistry's once-only guard, SetNormalSubmitter
	// allows re-installation (future runtime reload of the
	// V.1 sink config). Pin the current behavior.
	t.Cleanup(ResetForTest)
	ResetForTest()
	s1 := &recordingNormalSink{}
	s2 := &recordingNormalSink{}
	SetNormalSubmitter(s1)
	SetNormalSubmitter(s2)
	if GlobalNormalSubmitter() != s2 {
		t.Errorf("re-installation did not take effect; got %p want %p", GlobalNormalSubmitter(), s2)
	}
}
