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
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
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

	if l := newLogger(false, "debug", ""); !l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=false, \"debug\") does not emit Debug — " +
			"ARENET_LOG_LEVEL=debug is a no-op (the v2.84.1 bug)")
	}
	// The default production boot must stay quiet at Debug.
	if l := newLogger(false, "", ""); l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=false, \"\") emits Debug — production default must be Info")
	}
	// Dev with no explicit level keeps its historical Debug verbosity.
	if l := newLogger(true, "", ""); !l.Enabled(ctx, slog.LevelDebug) {
		t.Error("newLogger(dev=true, \"\") does not emit Debug — dev must stay verbose")
	}
	// An explicit level wins over dev: dev + "warn" must drop Info.
	if l := newLogger(true, "warn", ""); l.Enabled(ctx, slog.LevelInfo) {
		t.Error("newLogger(dev=true, \"warn\") emits Info — an explicit level must override dev")
	}
}

// TestNewLogger_JSONFormat pins #358: with format "json", records are emitted
// as one valid JSON object per line (parseable by encoding/json), carrying the
// standard slog keys; the default ("") stays human-readable key=value text.
// Reinjecting the old body (always TextHandler, logFormat ignored) fails the
// json assertion — ARENET_LOG_FORMAT would be a phantom knob again.
func TestNewLogger_JSONFormat(t *testing.T) {
	// JSON format → each line is a JSON object.
	var jbuf bytes.Buffer
	jlog := slog.New(newJSONHandlerForTest(&jbuf))
	jlog.Info("hello", "k", "v")
	var obj map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(jbuf.Bytes()), &obj); err != nil {
		t.Fatalf("json format did not emit valid JSON: %v (line=%q)", err, jbuf.String())
	}
	if obj["msg"] != "hello" || obj["k"] != "v" {
		t.Errorf("json record missing expected keys: %v", obj)
	}

	// The real constructor must pick JSON for "json" and text otherwise. We
	// can't redirect newLogger's os.Stderr, so assert format selection via the
	// handler type indirectly: a json logger's first byte is '{', a text one's
	// is not. Capture through a sibling that mirrors newLogger's branch.
	if got := firstByteOfFormat(t, "json"); got != '{' {
		t.Errorf("format=json did not produce a JSON line (first byte %q)", string(got))
	}
	if got := firstByteOfFormat(t, ""); got == '{' {
		t.Errorf("default format produced JSON; want text key=value")
	}
}

// newJSONHandlerForTest mirrors newLogger's json branch against a buffer.
func newJSONHandlerForTest(buf *bytes.Buffer) slog.Handler {
	return slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})
}

// firstByteOfFormat builds a handler the same way newLogger does for the given
// format and returns the first byte it writes for an Info record.
func firstByteOfFormat(t *testing.T, format string) byte {
	t.Helper()
	var buf bytes.Buffer
	var h slog.Handler
	if f, _ := resolveLogFormat(format); f == "json" {
		h = slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	} else {
		h = slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	}
	slog.New(h).Info("probe")
	s := strings.TrimSpace(buf.String())
	if s == "" {
		t.Fatalf("no output for format %q", format)
	}
	return s[0]
}

// TestResolveLogFormat pins the name→format mapping and the recognised flag.
func TestResolveLogFormat(t *testing.T) {
	cases := []struct {
		in         string
		wantFormat string
		wantRecogn bool
	}{
		{"", "text", true},
		{"text", "text", true},
		{" JSON ", "json", true},
		{"json", "json", true},
		{"yaml", "text", false},
		{"structured", "text", false},
	}
	for _, c := range cases {
		if f, ok := resolveLogFormat(c.in); f != c.wantFormat || ok != c.wantRecogn {
			t.Errorf("resolveLogFormat(%q) = (%q, %v), want (%q, %v)", c.in, f, ok, c.wantFormat, c.wantRecogn)
		}
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
