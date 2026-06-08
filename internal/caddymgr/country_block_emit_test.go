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

	"github.com/barto95100/arenet/internal/countryblock"
	"github.com/barto95100/arenet/internal/storage"
)

// Step W.3 — pin the per-route country-block emit logic +
// the chain position #2 invariant + the boot/diff log
// shape. Mirror of waf_skip_log_test.go and
// waf_diff_log_test.go.

// --- buildCountryBlockHandler -------------------------------

func TestBuildCountryBlockHandler_EmitsJSON_WhenModeNotOff(t *testing.T) {
	got := buildCountryBlockHandler("r-abc", "ha.example.test", countryblock.Config{
		Mode:        countryblock.ModeAllow,
		CountryList: []string{"FR", "DE"},
		StatusCode:  451,
	})
	if got == nil {
		t.Fatal("expected non-nil handler JSON")
	}
	if got["handler"] != countryblock.HandlerName {
		t.Errorf("handler name = %v; want %s", got["handler"], countryblock.HandlerName)
	}
	if got["routeID"] != "r-abc" {
		t.Errorf("routeID = %v; want r-abc", got["routeID"])
	}
	// The W.1 Handler struct intentionally has no Host
	// field; the host is captured only in caddymgr's boot/
	// diff log lines (see TestApplyLocked_LogsCountryBlock-
	// BootSignal). Pin the absence here so a future drift
	// that re-adds host to the JSON surfaces at this guard.
	if _, present := got["host"]; present {
		t.Errorf("handler JSON should NOT carry host; got %v", got["host"])
	}
	cfg, ok := got["config"].(map[string]any)
	if !ok {
		t.Fatalf("config block is not a map: %T", got["config"])
	}
	if cfg["mode"] != "allow" {
		t.Errorf("config.mode = %v; want allow", cfg["mode"])
	}
	list, ok := cfg["countryList"].([]string)
	if !ok || len(list) != 2 {
		t.Errorf("config.countryList = %v; want 2-element []string", cfg["countryList"])
	}
	if cfg["statusCode"] != 451 {
		t.Errorf("config.statusCode = %v; want 451", cfg["statusCode"])
	}
}

func TestBuildCountryBlockHandler_SkipsWhenModeOff(t *testing.T) {
	cases := []countryblock.Config{
		{}, // zero value, Mode == ""
		{Mode: countryblock.ModeOff},
		{Mode: countryblock.ModeOff, CountryList: []string{"FR"}},
	}
	for _, c := range cases {
		got := buildCountryBlockHandler("r-abc", "h.example.test", c)
		if got != nil {
			t.Errorf("expected nil (skip) for Mode=%q, list=%v; got %+v", c.Mode, c.CountryList, got)
		}
	}
}

// --- countryBlockFingerprint --------------------------------

func TestCountryBlockFingerprint_StableAcrossListReorder(t *testing.T) {
	// Operator reordering [FR, DE] to [DE, FR] in the UI
	// MUST NOT trigger a spurious diff log entry. The
	// fingerprint sorts the list before hashing.
	a := countryBlockFingerprint(countryblock.Config{
		Mode:        countryblock.ModeAllow,
		CountryList: []string{"FR", "DE"},
	})
	b := countryBlockFingerprint(countryblock.Config{
		Mode:        countryblock.ModeAllow,
		CountryList: []string{"DE", "FR"},
	})
	if a != b {
		t.Errorf("fingerprint should be order-invariant\n  a = %q\n  b = %q", a, b)
	}
}

func TestCountryBlockFingerprint_DifferentiatesModes(t *testing.T) {
	allow := countryBlockFingerprint(countryblock.Config{Mode: countryblock.ModeAllow, CountryList: []string{"FR"}})
	deny := countryBlockFingerprint(countryblock.Config{Mode: countryblock.ModeDeny, CountryList: []string{"FR"}})
	if allow == deny {
		t.Errorf("allow and deny fingerprints must differ; both = %q", allow)
	}
}

func TestCountryBlockFingerprint_DifferentiatesStatusCodes(t *testing.T) {
	a := countryBlockFingerprint(countryblock.Config{Mode: countryblock.ModeDeny, CountryList: []string{"RU"}, StatusCode: 403})
	b := countryBlockFingerprint(countryblock.Config{Mode: countryblock.ModeDeny, CountryList: []string{"RU"}, StatusCode: 451})
	if a == b {
		t.Errorf("statusCode change should produce different fingerprint; both = %q", a)
	}
}

// --- applyLocked observability ------------------------------

// TestApplyLocked_LogsCountryBlockBootSignal — a fresh apply
// with one country-block-on route + one country-block-off
// route emits exactly one "provisioned" log + one "skipped"
// log + a diff log with added_count=1.
func TestApplyLocked_LogsCountryBlockBootSignal(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "blocked.example.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeDeny,
			CountryList: []string{"RU", "KP"},
			StatusCode:  451,
		},
	}); err != nil {
		t.Fatalf("CreateRoute (cb-on): %v", err)
	}
	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "open.example.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9001", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		// CountryBlock zero-value = off.
	}); err != nil {
		t.Fatalf("CreateRoute (cb-off): %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mgr, err := New(store, logger, nil, true, "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_ = mgr.ReloadFromStore(ctx)

	out := buf.String()
	if c := strings.Count(out, `msg="country block handler provisioned"`); c != 1 {
		t.Errorf("expected 1 provisioned log; got %d\n---\n%s", c, out)
	}
	if c := strings.Count(out, `msg="country block handler skipped"`); c != 1 {
		t.Errorf("expected 1 skipped log; got %d\n---\n%s", c, out)
	}
	if c := strings.Count(out, `msg="country block config diff applied"`); c != 1 {
		t.Errorf("expected 1 diff log on first apply (added route); got %d\n---\n%s", c, out)
	}
	// Provisioned log carries the gate-on details.
	if !strings.Contains(out, "host=blocked.example.test") {
		t.Errorf("provisioned log missing host; got:\n%s", out)
	}
	if !strings.Contains(out, "mode=deny") {
		t.Errorf("provisioned log missing mode=deny; got:\n%s", out)
	}
	if !strings.Contains(out, "country_list_count=2") {
		t.Errorf("provisioned log missing country_list_count=2; got:\n%s", out)
	}
	if !strings.Contains(out, "status_code=451") {
		t.Errorf("provisioned log missing status_code=451; got:\n%s", out)
	}
	// Skipped log carries reason=mode_off.
	if !strings.Contains(out, "reason=mode_off") {
		t.Errorf("skipped log missing reason=mode_off; got:\n%s", out)
	}
}

// TestApplyLocked_LogsCountryBlockDiff_OnModeChange — flipping
// a route's CountryBlock between applies fires the diff log
// with changed_count=1.
func TestApplyLocked_LogsCountryBlockDiff_OnModeChange(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	r, err := store.CreateRoute(ctx, storage.Route{
		Host:      "flip.example.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeAllow,
			CountryList: []string{"FR"},
		},
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

	// First apply — added.
	_ = mgr.ReloadFromStore(ctx)
	if !strings.Contains(buf.String(), "added_count=1") {
		t.Fatalf("first apply expected added_count=1; got:\n%s", buf.String())
	}
	buf.Reset()

	// Flip allow → deny on a different list; expect
	// changed_count=1 with the from→to detail.
	r.CountryBlock = countryblock.Config{
		Mode:        countryblock.ModeDeny,
		CountryList: []string{"RU", "KP"},
	}
	if _, err := store.UpdateRoute(ctx, r); err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}
	_ = mgr.ReloadFromStore(ctx)

	out := buf.String()
	if !strings.Contains(out, `msg="country block config diff applied"`) {
		t.Fatalf("expected diff log on mode flip; got:\n%s", out)
	}
	if !strings.Contains(out, "changed_count=1") {
		t.Errorf("expected changed_count=1; got:\n%s", out)
	}
	if !strings.Contains(out, "allow|FR|0→deny|KP,RU|0") {
		t.Errorf("expected from→to fingerprint with sorted country list; got:\n%s", out)
	}
}

// TestApplyLocked_NoCountryBlockDiff_WhenStable — apply twice
// without changing any CountryBlock field; the second apply
// must NOT emit a diff log (silent on no-op edits).
func TestApplyLocked_NoCountryBlockDiff_WhenStable(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "stable.example.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeDeny,
			CountryList: []string{"RU"},
		},
	}); err != nil {
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
	_ = mgr.ReloadFromStore(ctx)
	if strings.Contains(buf.String(), `msg="country block config diff applied"`) {
		t.Errorf("expected no diff log on stable apply; got:\n%s", buf.String())
	}
}

// TestBuildConfigJSON_CountryBlockJSONShape — anti-regression
// guard for the handler JSON shape. The full Caddy empirical-
// verification (caddy.Validate against a country-block route)
// lives in TestBuildConfigJSON_LoadsCleanly_CountryBlock in
// manager_test.go (placed there because the existing
// TestSyncRegistry_NotCalledOnReloadFailure test is sensitive
// to caddy.Validate residual state and the file ordering matters).
// Here we just assert the JSON keys + types from buildConfigJSON's
// output WITHOUT invoking the Caddy module Provision pipeline.
func TestBuildConfigJSON_CountryBlockJSONShape(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.CreateRoute(context.Background(), storage.Route{
		Host:      "blocked.example.com",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		WAFMode:   "off",
		CountryBlock: countryblock.Config{
			Mode:        countryblock.ModeDeny,
			CountryList: []string{"RU", "KP"},
			StatusCode:  451,
		},
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	routes, err := store.ListRoutes(context.Background())
	if err != nil {
		t.Fatalf("ListRoutes: %v", err)
	}

	raw, err := buildConfigJSON(routes, buildOpts{DevMode: true})
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}

	// The emitted JSON must reference the W.1 handler ID
	// + the country-list strings + the per-route StatusCode.
	// Substring-match against the marshalled output — keeps
	// the assertion robust to caddymgr's structural changes
	// while still catching a drift in the W.1 handler ID
	// (Finding #2-class regression).
	// buildConfigJSON emits indented JSON (json.MarshalIndent),
	// so post-colon spaces matter for substring assertions.
	out := string(raw)
	for _, want := range []string{
		`"arenet_country_block"`,
		`"mode": "deny"`,
		`"RU"`,
		`"KP"`,
		`"statusCode": 451`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("emitted config missing %q", want)
		}
	}
}

// TestApplyLocked_NoCountryBlockDiff_OnOffRouteAdded —
// symmetric to the WAF Fix #3 carve-out: adding a fresh
// off-mode route does NOT fire the diff log (off routes
// aren't part of the country-block coverage signal).
func TestApplyLocked_NoCountryBlockDiff_OnOffRouteAdded(t *testing.T) {
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

	_ = mgr.ReloadFromStore(ctx)
	buf.Reset()

	if _, err := store.CreateRoute(ctx, storage.Route{
		Host:      "off.example.test",
		Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		// Zero-value CountryBlock = off.
	}); err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	_ = mgr.ReloadFromStore(ctx)
	if strings.Contains(buf.String(), `msg="country block config diff applied"`) {
		t.Errorf("adding off-mode route should not fire diff log; got:\n%s", buf.String())
	}
}
