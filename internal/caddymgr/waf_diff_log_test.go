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
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// W.bugfix Fix #3 — applyLocked emits a "waf config diff
// applied" summary log when this Apply pass adds / removes
// / changes the WAF mode of any route relative to the
// previous successful apply. Silent when nothing WAF-shaped
// changed (operator routes that edit non-WAF fields don't
// fill the log).

// TestApplyLocked_LogsWAFDiff_OnModeChange — edit a route's
// WAFMode through the store and apply twice. The second
// apply should log changed_count=1 with the from→to detail.
func TestApplyLocked_LogsWAFDiff_OnModeChange(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	r, err := store.CreateRoute(ctx, storage.Route{
		Host:      "ha.example.test",
		WAFMode:   "detect",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First apply — primes the WAFMode baseline. The route
	// is brand new (no previous state), so it shows up as
	// added_count=1. caddy.Load fails (no embedded server)
	// but the diff log fires BEFORE caddy.Load.
	_ = mgr.ReloadFromStore(ctx)
	if !strings.Contains(buf.String(), `msg="waf config diff applied"`) {
		t.Fatalf("first apply expected to log diff (added); got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "added_count=1") {
		t.Errorf("first apply expected added_count=1; got:\n%s", buf.String())
	}
	buf.Reset()

	// Flip wafMode detect → block in the store, apply again.
	r.WAFMode = "block"
	if _, err := store.UpdateRoute(ctx, r); err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	_ = mgr.ReloadFromStore(ctx)

	out := buf.String()
	if !strings.Contains(out, `msg="waf config diff applied"`) {
		t.Fatalf("second apply expected to log diff; got:\n%s", out)
	}
	if !strings.Contains(out, "changed_count=1") {
		t.Errorf("expected changed_count=1; got:\n%s", out)
	}
	if !strings.Contains(out, "detect→block") {
		t.Errorf("expected from→to detail 'detect→block'; got:\n%s", out)
	}
}

// TestApplyLocked_NoDiffLog_WhenNoWAFChange — apply twice
// with no WAF-shaped change between them. Only the FIRST
// apply (which transitions from empty baseline) logs;
// the second apply is silent.
func TestApplyLocked_NoDiffLog_WhenNoWAFChange(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "stable.example.test",
		WAFMode:   "block",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// First apply: logs added_count=1.
	_ = mgr.ReloadFromStore(ctx)
	buf.Reset()

	// Second apply with no change: must NOT log.
	_ = mgr.ReloadFromStore(ctx)
	if strings.Contains(buf.String(), `msg="waf config diff applied"`) {
		t.Errorf("second apply with no WAF change should not log; got:\n%s", buf.String())
	}
}

// TestApplyLocked_LogsRemovedCount_OnRouteDelete — deleting
// a WAF-on route surfaces as removed_count=1 in the next
// apply.
func TestApplyLocked_LogsRemovedCount_OnRouteDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	r, err := store.CreateRoute(ctx, storage.Route{
		Host:      "deleteme.example.test",
		WAFMode:   "block",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = mgr.ReloadFromStore(ctx)
	buf.Reset()

	if err := store.DeleteRoute(ctx, r.ID); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}
	_ = mgr.ReloadFromStore(ctx)

	out := buf.String()
	if !strings.Contains(out, "removed_count=1") {
		t.Errorf("expected removed_count=1 after delete; got:\n%s", out)
	}
}

// TestApplyLocked_NoLogOnOffRouteAdded — adding a route with
// WAFMode=off does NOT log (off routes don't contribute to
// the WAF coverage signal). Only routes with WAF on are
// tracked for added/removed; mode flips between empty/off
// and a real mode DO surface as changes.
func TestApplyLocked_NoDiffLogOnOffRouteAdded(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Empty baseline + first apply: no routes, no log.
	_ = mgr.ReloadFromStore(ctx)
	if strings.Contains(buf.String(), `msg="waf config diff applied"`) {
		t.Errorf("empty-baseline apply should not log diff; got:\n%s", buf.String())
	}
	buf.Reset()

	// Add an off-route. Should NOT log a diff (off routes
	// aren't tracked in the WAF coverage view).
	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "off.example.test",
		WAFMode:   "off",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	_ = mgr.ReloadFromStore(ctx)
	if strings.Contains(buf.String(), `msg="waf config diff applied"`) {
		t.Errorf("adding an off-mode route should not log diff; got:\n%s", buf.String())
	}
}
