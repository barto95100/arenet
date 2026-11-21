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

package main

import (
	"context"
	"log/slog"
	"testing"
)

// v2.84.2 regression guard for the v2.84.1 dogfood symptom: an operator
// set ARENET_LOG_LEVEL=debug and the two Debug lines added in PR #354
// never appeared. Root cause: newLogger gated Debug on Dev alone and
// ignored the configured level, so a production (dev=false) boot stayed
// at Info regardless of the env var. These guards assert on what the
// operator actually receives — whether a Debug record is emitted — not
// merely on the resolved level value.

// TestNewLogger_DebugEnabledFromConfig is the headline guard: a
// production boot (dev=false) with log level "debug" MUST enable Debug
// records. Reinjecting the old body (level from dev only, logLevel
// ignored) fails exactly this.
func TestNewLogger_DebugEnabledFromConfig(t *testing.T) {
	ctx := context.Background()

	if l := newLogger(false, "debug"); !l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=false, \"debug\") does not emit Debug — " +
			"ARENET_LOG_LEVEL=debug is a no-op (the v2.84.1 bug)")
	}
	// The default production boot must stay quiet at Debug.
	if l := newLogger(false, ""); l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=false, \"\") emits Debug — production default must be Info")
	}
	// Dev with no explicit level keeps its historical Debug verbosity.
	if l := newLogger(true, ""); !l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=true, \"\") does not emit Debug — dev must stay verbose")
	}
	// An explicit level wins over dev: dev + "warn" must drop Info.
	if l := newLogger(true, "warn"); l.Enabled(ctx, slog.LevelInfo) {
		t.Error("newLogger(dev=true, \"warn\") emits Info — an explicit level must override dev")
	}
}

// TestResolveLogLevel pins the name→level mapping and the recognised
// flag that drives the boot warning.
func TestResolveLogLevel(t *testing.T) {
	cases := []struct {
		name       string
		dev        bool
		in         string
		wantLevel  slog.Level
		wantRecogn bool
	}{
		{"debug lowercases and trims", false, " DEBUG ", slog.LevelDebug, true},
		{"info explicit", false, "info", slog.LevelInfo, true},
		{"warn", false, "warn", slog.LevelWarn, true},
		{"warning alias", false, "warning", slog.LevelWarn, true},
		{"error", false, "error", slog.LevelError, true},
		{"empty in prod is info", false, "", slog.LevelInfo, true},
		{"empty in dev is debug", true, "", slog.LevelDebug, true},
		{"explicit wins over dev", true, "info", slog.LevelInfo, true},
		{"garbage in prod falls back to info, unrecognised", false, "verbose", slog.LevelInfo, false},
		{"garbage in dev falls back to debug, unrecognised", true, "loud", slog.LevelDebug, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			lvl, ok := resolveLogLevel(c.dev, c.in)
			if lvl != c.wantLevel || ok != c.wantRecogn {
				t.Errorf("resolveLogLevel(%v, %q) = (%v, %v), want (%v, %v)",
					c.dev, c.in, lvl, ok, c.wantLevel, c.wantRecogn)
			}
		})
	}
}

// TestLogLevelName pins the lowercase label used in the boot
// "effective config" line, so an operator can read off the level in
// force (the other half of the v2.84.1 gap: there was no such line).
func TestLogLevelName(t *testing.T) {
	cases := []struct {
		dev  bool
		in   string
		want string
	}{
		{false, "debug", "debug"},
		{false, "", "info"},
		{true, "", "debug"},
		{false, "nonsense", "info"},
	}
	for _, c := range cases {
		if got := logLevelName(c.dev, c.in); got != c.want {
			t.Errorf("logLevelName(%v, %q) = %q, want %q", c.dev, c.in, got, c.want)
		}
	}
}
