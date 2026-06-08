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
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// W.bugfix Fix #2 — pin the per-route boot log line emitted
// from Provision. Pre-Fix-#2 boot logs only carried one
// sink-level "waf event sink wired" entry; operators had no
// per-route signal showing which routes had WAF on and at
// what mode + which pool key they shared. The provisioned-
// side log now fires on every Provision call (i.e. once per
// route-with-WAF-on per Caddy reload).

// installCaptureLogger swaps slog.Default with a buffer-
// capturing handler for the duration of the test and
// restores the previous default at cleanup.
func installCaptureLogger(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func TestProvision_EmitsBootLogWithModeAndHost(t *testing.T) {
	buf := installCaptureLogger(t)

	h := newProvisionedHandler(t, "block")
	// newProvisionedHandler doesn't set Host; set it directly
	// then re-Provision so the boot log carries the host
	// field. (Provision is idempotent against the pool — the
	// second call hits the pool cache, which still fires the
	// log line.)
	h.Host = "ha.example.test"
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("re-Provision: %v", err)
	}

	out := buf.String()
	// The log message itself.
	if !strings.Contains(out, "waf handler provisioned") {
		t.Fatalf("boot log missing message; got: %s", out)
	}
	// Every expected field must be present.
	for _, want := range []string{
		`route_id=`,
		`host=ha.example.test`,
		`mode=block`,
		`pool_key=arenet-waf-`,
		`pooled=true`, // second Provision hit the pool
		`load_owasp_crs=`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("boot log missing field %q\nfull log:\n%s", want, out)
		}
	}
}

func TestProvision_EmitsBootLog_DetectMode(t *testing.T) {
	buf := installCaptureLogger(t)
	h := newProvisionedHandler(t, "detect")
	_ = h // Provision already happened inside the helper

	out := buf.String()
	if !strings.Contains(out, "waf handler provisioned") {
		t.Fatalf("boot log missing; got: %s", out)
	}
	if !strings.Contains(out, `mode=detect`) {
		t.Errorf("boot log should carry mode=detect; got: %s", out)
	}
}
