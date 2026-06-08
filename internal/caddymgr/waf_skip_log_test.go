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

// W.bugfix Fix #2 — applyLocked emits a "waf handler skipped"
// log line for every route whose WAFMode is empty / "off".
// Symmetric to the per-handler "waf handler provisioned" log
// in internal/waf module.Provision (which only fires when the
// handler is actually emitted in the chain).
//
// The skip log runs BEFORE caddy.Load, so this test exercises
// it via ReloadFromStore even though Caddy isn't running:
// caddy.Load returns an error AFTER the skip-log loop has
// already executed.

// TestApplyLocked_LogsWAFSkippedForOffRoute pins that a route
// with WAFMode="off" produces the skip log with the correct
// fields. Two off-routes + one on-route → exactly two skip
// log lines.
func TestApplyLocked_LogsWAFSkippedForOffRoute(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Seed three routes: two off + one detect.
	for _, r := range []storage.Route{
		{Host: "off1.local", WAFMode: "off",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin},
		{Host: "off2.local", WAFMode: "off",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin},
		{Host: "detect.local", WAFMode: "detect",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9002", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin},
	} {
		if _, err := store.CreateRoute(context.Background(), r); err != nil {
			t.Fatalf("CreateRoute %s: %v", r.Host, err)
		}
	}

	// Capture the manager's logger so we can scan its output.
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// ReloadFromStore runs applyLocked. caddy.Load will error
	// (no Caddy started in the test) — that's fine, the skip-
	// log loop runs BEFORE caddy.Load.
	_ = mgr.ReloadFromStore(context.Background())

	out := buf.String()
	// Two skip log lines expected — one for each off route.
	count := strings.Count(out, `msg="waf handler skipped"`)
	if count != 2 {
		t.Fatalf("expected 2 'waf handler skipped' lines (one per off-mode route); got %d\nfull log:\n%s",
			count, out)
	}
	// Every skip log line carries the reason field.
	if !strings.Contains(out, `reason=mode_off`) {
		t.Errorf("skip log missing reason=mode_off; got:\n%s", out)
	}
	// Each off-mode host appears in at least one skip line.
	for _, host := range []string{"off1.local", "off2.local"} {
		if !strings.Contains(out, "host="+host) {
			t.Errorf("skip log missing host=%s; got:\n%s", host, out)
		}
	}
	// detect.local should NOT appear in a skip line (the
	// caddymgr-side log only fires for off routes; the
	// detect-mode route's provisioned-side log fires inside
	// internal/waf module.Provision instead, which doesn't
	// run in this test because Caddy isn't started).
	if strings.Contains(out, "host=detect.local") {
		// The "waf handler skipped" message specifically must NOT
		// reference detect.local — but other unrelated log lines
		// may. Scope the assertion to the skip-log subset.
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "waf handler skipped") && strings.Contains(line, "detect.local") {
				t.Errorf("detect.local appeared in a skip log line; it should only fire for off routes")
			}
		}
	}
}

// TestApplyLocked_NoSkipLog_WhenAllRoutesWAFOn pins the
// no-noise invariant: a deployment with WAF on every route
// produces zero skip log lines.
func TestApplyLocked_NoSkipLog_WhenAllRoutesWAFOn(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, r := range []storage.Route{
		{Host: "on1.local", WAFMode: "block",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin},
		{Host: "on2.local", WAFMode: "detect",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin},
	} {
		if _, err := store.CreateRoute(context.Background(), r); err != nil {
			t.Fatalf("CreateRoute %s: %v", r.Host, err)
		}
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = mgr.ReloadFromStore(context.Background())

	out := buf.String()
	if count := strings.Count(out, `msg="waf handler skipped"`); count != 0 {
		t.Errorf("expected 0 skip log lines (all routes have WAF on); got %d\nfull log:\n%s",
			count, out)
	}
}
