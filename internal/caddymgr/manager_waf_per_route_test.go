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
	"strings"
	"testing"
)

// Step X.1 (2026-06-17) — buildWAFHandler per-route WAFDisableCRS
// emit shape.
//
// Empirical-verification pattern from CLAUDE.md §Empirical
// verification — these tests assert the EXACT shape of the
// emitted Caddy JSON map for the WAF handler, because the
// arenet_waf Caddy module reads `load_owasp_crs` to decide
// whether to mount the embedded CRS filesystem, and reads
// `directives` to feed Coraza. The two MUST move together :
// load_owasp_crs:false WITHOUT stripping the @owasp_crs / @crs-
// setup includes makes Coraza fail to construct the WAF at
// Provision time (the Include alias has nothing to resolve).

func TestBuildWAFHandler_DisableCRS_False_KeepsLegacyShape(t *testing.T) {
	// Pre-X.1 behaviour : disableCRS=false ⇒ full CRS chain.
	// Pins the byte-equality of the pre-X.1 emit for any route
	// that doesn't opt out.
	got := buildWAFHandler("r-1", "example.com", "block", false, false)
	if got == nil {
		t.Fatalf("buildWAFHandler returned nil for block mode")
	}
	if v, ok := got["load_owasp_crs"].(bool); !ok || !v {
		t.Errorf("load_owasp_crs = %v, want true", got["load_owasp_crs"])
	}
	dirs, _ := got["directives"].(string)
	for _, want := range []string{
		"@coraza.conf-recommended",
		"@crs-setup.conf.example",
		"@owasp_crs/*.conf",
	} {
		if !strings.Contains(dirs, want) {
			t.Errorf("directives missing %q\n  got = %q", want, dirs)
		}
	}
}

func TestBuildWAFHandler_DisableCRS_True_DropsEveryAtInclude(t *testing.T) {
	// Step X.1 opt-out shape. load_owasp_crs:false AND
	// directives drop EVERY @-Include — including
	// @coraza.conf-recommended which lives in the same
	// coreruleset embedded FS as the CRS rule files (verified
	// empirically at smoke time : the FS hosts the three of
	// them side-by-side at coreruleset/rules/). Mounting the
	// FS conditionally on LoadOWASPCRS means NONE of the three
	// @-aliases resolve when the bit is false — Coraza errors
	// at Provision with "open @coraza.conf-recommended: no such
	// file or directory".
	//
	// The operator-facing posture stays sound : Coraza's engine
	// constructs cleanly with zero @-Includes, the
	// SecRuleEngine directive still appends (in waf/module.go
	// buildWAF), and the adminAPIExclusionDirective prepend
	// still parses (it's a SecRule, not an @-Include). So the
	// handler is wired, the WAF instance exists, events still
	// fire if a hypothetical rule did trip, and the
	// per-request cost is the bare Coraza dispatch overhead.
	got := buildWAFHandler("r-1", "example.com", "block", false, true)
	if got == nil {
		t.Fatalf("buildWAFHandler returned nil for block mode")
	}
	if v, ok := got["load_owasp_crs"].(bool); !ok || v {
		t.Errorf("load_owasp_crs = %v, want false", got["load_owasp_crs"])
	}
	dirs, _ := got["directives"].(string)
	// EVERY @-Include MUST be gone.
	for _, forbidden := range []string{
		"@coraza.conf-recommended",
		"@crs-setup.conf.example",
		"@owasp_crs/*.conf",
	} {
		if strings.Contains(dirs, forbidden) {
			t.Errorf("directives still contains %q after disableCRS=true\n  got = %q", forbidden, dirs)
		}
	}
}

func TestBuildWAFHandler_OffMode_ShortCircuits_Regardless(t *testing.T) {
	// Mode "off" returns nil regardless of disableCRS — no handler
	// emitted, the route's chain skips the arenet_waf slot
	// entirely. WAFDisableCRS is silent when WAFMode is off.
	for _, disable := range []bool{false, true} {
		got := buildWAFHandler("r-1", "example.com", "off", false, disable)
		if got != nil {
			t.Errorf("disableCRS=%v: off mode emitted a handler %+v; want nil", disable, got)
		}
	}
}

func TestBuildWAFHandler_DisableCRS_PreservesSkipBodyInteraction(t *testing.T) {
	// WAFDisableCRS and UploadStreamingMode are independent ; the
	// combo (disable CRS + streaming upload) is operator-valid
	// (e.g. a binary upload route on a trusted internal host) and
	// must emit BOTH the load_owasp_crs:false AND the
	// skip_body_inspection:true flags.
	got := buildWAFHandler("r-1", "example.com", "detect", true, true)
	if got == nil {
		t.Fatalf("buildWAFHandler returned nil for detect mode")
	}
	if v, ok := got["load_owasp_crs"].(bool); !ok || v {
		t.Errorf("load_owasp_crs = %v, want false", got["load_owasp_crs"])
	}
	if v, ok := got["skip_body_inspection"].(bool); !ok || !v {
		t.Errorf("skip_body_inspection = %v, want true", got["skip_body_inspection"])
	}
}

func TestBuildWAFHandler_DisableCRS_DetectMode_LegacyDirectivesPreserved(t *testing.T) {
	// Detect mode + disable CRS : same shape as block mode + disable
	// CRS. Pins the mode-independence of the disableCRS branch.
	got := buildWAFHandler("r-1", "example.com", "detect", false, true)
	if got == nil {
		t.Fatalf("buildWAFHandler returned nil for detect mode")
	}
	if v, ok := got["mode"].(string); !ok || v != "detect" {
		t.Errorf("mode = %v, want detect", got["mode"])
	}
	dirs, _ := got["directives"].(string)
	if strings.Contains(dirs, "@owasp_crs/*.conf") {
		t.Errorf("disableCRS=true on detect mode still loads CRS rules: %q", dirs)
	}
}
