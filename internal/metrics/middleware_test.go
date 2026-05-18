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
func (f *fakeRWNoHijack) Write(b []byte) (int, error) { f.body = append(f.body, b...); return len(b), nil }
func (f *fakeRWNoHijack) WriteHeader(code int)        { f.status = code }

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

	rec.WriteHeader(http.StatusServiceUnavailable) // 503
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
