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

package caddymgr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// #R-CADDY-ADMIN-DEADLOCK regression suite — ReloadFromStore's
// 25 s timeout wrapper.
//
// Approach: override the manager's applyFn seam with a stub
// that does what each test needs (block forever, return a
// chosen error, or finish promptly). No embedded Caddy boot
// required — the wrapper's goroutine + select + pprof dump
// path is exercised independently of the real applyLocked.

func newReloadTestManager(t *testing.T) *CaddyManager {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("caddymgr.New: %v", err)
	}
	return mgr
}

// withShortTimeout swaps reloadFromStoreTimeout for the duration
// of a test so we don't have to actually sleep 25s. The package-
// level constant is the production ceiling; tests want a tighter
// budget so the suite stays fast. Returns a restore func.
func withShortTimeout(t *testing.T, d time.Duration) func() {
	t.Helper()
	prev := reloadFromStoreTimeoutForTest
	reloadFromStoreTimeoutForTest = d
	return func() { reloadFromStoreTimeoutForTest = prev }
}

func TestReloadFromStore_Timeout_FiresOnBlockedApplyFn(t *testing.T) {
	mgr := newReloadTestManager(t)
	restore := withShortTimeout(t, 100*time.Millisecond)
	defer restore()

	// applyFn blocks forever — the timeout wrapper must
	// preempt it and return DeadlineExceeded promptly. Use
	// an atomic to verify the goroutine WAS started (the
	// select's <-done case did not race the timeout).
	var started atomic.Bool
	mgr.applyFn = func(ctx context.Context) error {
		started.Store(true)
		<-ctx.Done()
		return ctx.Err()
	}

	start := time.Now()
	err := mgr.ReloadFromStore(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ReloadFromStore returned nil; want timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v; want wraps context.DeadlineExceeded", err)
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("err message = %q; want it to contain \"timed out\"", err.Error())
	}
	if elapsed > 5*time.Second {
		t.Errorf("ReloadFromStore took %s on a 100ms-budget test; timeout did not fire", elapsed)
	}
	if !started.Load() {
		t.Errorf("applyFn never ran; the select fired before the goroutine started")
	}
}

func TestReloadFromStore_Timeout_PropagatesApplyError(t *testing.T) {
	mgr := newReloadTestManager(t)
	restore := withShortTimeout(t, 5*time.Second)
	defer restore()

	// applyFn returns a chosen error promptly. The wrapper
	// must forward it verbatim without wrapping it in the
	// timeout message. Operator-readable error parity is
	// what the 11 callsite handlers rely on for their
	// rollback + writeError("caddy reload failed: "+err)
	// pattern.
	want := errors.New("synthetic load failure")
	mgr.applyFn = func(_ context.Context) error { return want }

	err := mgr.ReloadFromStore(context.Background())
	if err == nil {
		t.Fatal("ReloadFromStore returned nil; want the synthetic error")
	}
	if !errors.Is(err, want) {
		// errors.Is requires Unwrap to chain; we return the
		// raw error so Is on the leaf works.
		if err.Error() != want.Error() {
			t.Errorf("err = %v; want %v", err, want)
		}
	}
	if strings.Contains(err.Error(), "timed out") {
		t.Errorf("non-timeout error leaked the timeout message: %q", err.Error())
	}
}

func TestReloadFromStore_Timeout_HappyPathReturnsNil(t *testing.T) {
	mgr := newReloadTestManager(t)
	restore := withShortTimeout(t, 5*time.Second)
	defer restore()

	// applyFn returns nil promptly — the wrapper must
	// return nil and the goroutine must have been
	// scheduled (not skipped).
	var ran atomic.Bool
	mgr.applyFn = func(_ context.Context) error {
		ran.Store(true)
		return nil
	}

	if err := mgr.ReloadFromStore(context.Background()); err != nil {
		t.Fatalf("ReloadFromStore returned %v on success path; want nil", err)
	}
	if !ran.Load() {
		t.Errorf("applyFn never ran")
	}
}

// v2.26 — ReloadHealth replaces the systemhealth probe of the (now
// disabled) Caddy admin API: a hung reload must be visible as an
// in-flight duration, a timeout as timedOut, and a later completed
// reload must clear both.
func TestReloadHealth_TracksStuckAndRecoveredReloads(t *testing.T) {
	mgr := newReloadTestManager(t)
	restore := withShortTimeout(t, 50*time.Millisecond)
	defer restore()

	if started, inFlight, timedOut := mgr.ReloadHealth(); started || inFlight != 0 || timedOut {
		t.Fatalf("fresh manager: started=%v inFlight=%s timedOut=%v", started, inFlight, timedOut)
	}

	release := make(chan struct{})
	mgr.applyFn = func(context.Context) error {
		<-release // ignore ctx: simulate caddy.Load stuck on its mutex
		return nil
	}
	if err := mgr.ReloadFromStore(context.Background()); err == nil {
		t.Fatal("want timeout")
	}
	time.Sleep(20 * time.Millisecond)
	if _, inFlight, timedOut := mgr.ReloadHealth(); inFlight < 50*time.Millisecond || !timedOut {
		t.Errorf("stuck reload: inFlight=%s timedOut=%v; want >=50ms and true", inFlight, timedOut)
	}

	close(release) // the stuck caddy.Load eventually returns
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, inFlight, timedOut := mgr.ReloadHealth(); inFlight == 0 && !timedOut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("reload state did not recover after the stuck apply returned")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// v2.72 — a reload Caddy REJECTED has to leave a trace.
//
// The apply goroutine clears reloadTimedOut whatever applyFn returned,
// and ReloadHealth reports only (started, inFlight, timedOut), so a
// rejection was indistinguishable from a clean run. Several handlers
// log a reload error and answer 200 on purpose — the store write is
// committed and undoing it would be worse — so the operator got a
// success toast, a UI reading back the new value, an edge still on the
// old config, and systemhealth saying "config reloads healthy".
func TestLastReloadFailure_RecordsAndClears(t *testing.T) {
	mgr := newReloadTestManager(t)

	if msg, at := mgr.LastReloadFailure(); msg != "" || !at.IsZero() {
		t.Fatalf("fresh manager: msg=%q at=%v; want empty", msg, at)
	}

	mgr.applyFn = func(context.Context) error {
		return errors.New("loading new config: http app module: provision: tls: no DNS provider")
	}
	if err := mgr.ReloadFromStore(context.Background()); err == nil {
		t.Fatal("want the rejection to reach the caller too")
	}
	msg, at := mgr.LastReloadFailure()
	if !strings.Contains(msg, "no DNS provider") {
		t.Errorf("msg = %q; want Caddy's reason", msg)
	}
	if at.IsZero() {
		t.Error("at is zero; the operator needs to know when it failed")
	}

	// The next accepted reload clears it — a stale failure reported
	// forever would be its own lie.
	mgr.applyFn = func(context.Context) error { return nil }
	if err := mgr.ReloadFromStore(context.Background()); err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if msg, _ := mgr.LastReloadFailure(); msg != "" {
		t.Errorf("msg = %q after a successful reload; want it cleared", msg)
	}
}

// And the apply that completes AFTER its caller gave up still records
// what Caddy answered: that goroutine outlives the timeout, so it is
// the only thing that knows the outcome.
func TestLastReloadFailure_RecordedByALateApply(t *testing.T) {
	mgr := newReloadTestManager(t)
	restore := withShortTimeout(t, 50*time.Millisecond)
	defer restore()

	release := make(chan struct{})
	mgr.applyFn = func(context.Context) error {
		<-release // ignore ctx: simulate caddy.Load stuck on its mutex
		return errors.New("rejected after the caller gave up")
	}
	if err := mgr.ReloadFromStore(context.Background()); err == nil {
		t.Fatal("want timeout")
	}
	// The timeout is what the caller saw; nothing is known yet.
	if msg, _ := mgr.LastReloadFailure(); msg != "" {
		t.Errorf("msg = %q before the apply returned; want empty", msg)
	}

	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if msg, _ := mgr.LastReloadFailure(); strings.Contains(msg, "gave up") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the late apply's rejection was never recorded")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
