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

import "testing"

// Step X.1 (2026-06-17) — computePoolKey LoadOWASPCRS sensitivity.
//
// The arenet_waf pool reuses Coraza instances across routes whose
// (mode, directives, LoadOWASPCRS) tuple matches. Step I.4
// already added the LoadOWASPCRS bit to the hash input (see
// computePoolKey in module.go) anticipating Step X.1 ; these
// tests pin the contract.
//
// Pool dedup invariants :
//   - Two routes with the SAME (mode, directives, LoadOWASPCRS)
//     share a pool key.
//   - Two routes that differ ONLY on LoadOWASPCRS get DIFFERENT
//     pool keys.
//   - Two routes that differ ONLY on directives get DIFFERENT
//     pool keys.

func TestComputePoolKey_LoadCRS_True_VsFalse_DistinctKeys(t *testing.T) {
	// The Step X.1 caddymgr emit changes BOTH load_owasp_crs AND
	// directives when WAFDisableCRS is true (see
	// internal/caddymgr/manager.go:buildWAFHandler). To pin that
	// the LoadOWASPCRS bit ALONE distinguishes pool keys (the
	// belt of the belt-and-suspenders pool-dedup story), test
	// with identical directives.
	a := &ArenetWafHandler{Mode: "block", Directives: "Include @coraza.conf-recommended", LoadOWASPCRS: true}
	b := &ArenetWafHandler{Mode: "block", Directives: "Include @coraza.conf-recommended", LoadOWASPCRS: false}
	ka, kb := a.computePoolKey(), b.computePoolKey()
	if ka == kb {
		t.Errorf("expected distinct pool keys for LoadOWASPCRS true vs false; got both = %q", ka)
	}
}

func TestComputePoolKey_SameConfig_SameKey(t *testing.T) {
	// Sanity : two routes with byte-identical config get the same
	// pool key. Without this the WAF pool would never dedup and
	// the homelab would carry 1 Coraza instance per route — the
	// regression the Step I.4 pool was built to prevent.
	a := &ArenetWafHandler{Mode: "block", Directives: "Include @owasp_crs/*.conf", LoadOWASPCRS: true}
	b := &ArenetWafHandler{Mode: "block", Directives: "Include @owasp_crs/*.conf", LoadOWASPCRS: true}
	if a.computePoolKey() != b.computePoolKey() {
		t.Errorf("expected same pool key for identical config; got %q vs %q",
			a.computePoolKey(), b.computePoolKey())
	}
}

func TestComputePoolKey_DifferentDirectives_DistinctKeys(t *testing.T) {
	// In Step X.1 production flow, disableCRS=true ALSO mutates
	// the directives string (drops the CRS Includes). This test
	// pins that the directives-only diff is enough to distinguish
	// pool keys — so the belt-and-suspenders design (LoadOWASPCRS
	// bit + directives string both differ) gives TWO independent
	// dedup signals.
	a := &ArenetWafHandler{
		Mode:         "block",
		Directives:   "Include @coraza.conf-recommended\nInclude @crs-setup.conf.example\nInclude @owasp_crs/*.conf",
		LoadOWASPCRS: true,
	}
	b := &ArenetWafHandler{
		Mode:         "block",
		Directives:   "Include @coraza.conf-recommended",
		LoadOWASPCRS: true,
	}
	if a.computePoolKey() == b.computePoolKey() {
		t.Errorf("expected distinct pool keys for distinct directives; got both = %q", a.computePoolKey())
	}
}

func TestComputePoolKey_ModeDistinguishes(t *testing.T) {
	// Detect vs block share directives + load flag but the mode
	// itself drives different Coraza SecRuleEngine, so the WAF
	// instances must not share. Pins the existing Step I.4
	// invariant inadvertently might be at risk if the hash input
	// order ever changes.
	a := &ArenetWafHandler{Mode: "detect", Directives: "Include @owasp_crs/*.conf", LoadOWASPCRS: true}
	b := &ArenetWafHandler{Mode: "block", Directives: "Include @owasp_crs/*.conf", LoadOWASPCRS: true}
	if a.computePoolKey() == b.computePoolKey() {
		t.Errorf("expected distinct pool keys for detect vs block; got both = %q", a.computePoolKey())
	}
}
