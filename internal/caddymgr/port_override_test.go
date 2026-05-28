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
	"os"
	"testing"
)

// lookupEnvForTest returns (currentValue, wasSet) for name.
// Mirrors os.LookupEnv but exposed under a test-only name so
// the call sites read clearly.
func lookupEnvForTest(name string) (string, bool) {
	return os.LookupEnv(name)
}

// unsetForTest unsets the variable. Use when a test needs to
// PROVE the "unset" behaviour; t.Setenv("", "") is NOT
// equivalent (it sets to empty string, which most code paths
// treat differently from unset — and TrimSpace makes us identical,
// but the contract is about LookupEnv-returns-false on unset
// rather than returns-empty-string on set-to-empty).
func unsetForTest(name string) {
	_ = os.Unsetenv(name)
}

// restoreEnvForTest restores a (value, wasSet) pair captured by
// lookupEnvForTest. If wasSet is false the variable is unset;
// otherwise it's set back to its previous value.
func restoreEnvForTest(name, value string, wasSet bool) {
	if wasSet {
		_ = os.Setenv(name, value)
		return
	}
	_ = os.Unsetenv(name)
}

// TestPortOverride_ProdNeverImpactedWhenVarUnset is the
// load-bearing invariant: when ARENET_HTTP_PORT and
// ARENET_HTTPS_PORT are unset, prod deployments MUST get
// exactly :80 / :443. Any regression here silently breaks
// ACME HTTP-01 challenges on existing production installs.
//
// t.Setenv with an empty string is NOT equivalent to "unset" —
// Go's testing pkg explicitly documents that t.Setenv calls
// t.Cleanup to RESTORE the prior value. To prove the
// "unset" path we must explicitly Unsetenv (and restore via
// cleanup ourselves since testing doesn't have an Unsetenv
// helper).
func TestPortOverride_ProdNeverImpactedWhenVarUnset(t *testing.T) {
	// Save + clear + restore on cleanup.
	prevHTTP, prevHTTPSet := lookupEnvForTest(envHTTPPort)
	prevHTTPS, prevHTTPSSet := lookupEnvForTest(envHTTPSPort)
	unsetForTest(envHTTPPort)
	unsetForTest(envHTTPSPort)
	t.Cleanup(func() {
		restoreEnvForTest(envHTTPPort, prevHTTP, prevHTTPSet)
		restoreEnvForTest(envHTTPSPort, prevHTTPS, prevHTTPSSet)
	})

	if got := httpPortFor(false); got != httpPortProd {
		t.Errorf("prod httpPortFor = %d, want %d — ARENET_HTTP_PORT unset MUST yield :80", got, httpPortProd)
	}
	if got := httpsPortFor(false); got != httpsPortProd {
		t.Errorf("prod httpsPortFor = %d, want %d — ARENET_HTTPS_PORT unset MUST yield :443", got, httpsPortProd)
	}
	wantHTTP, wantHTTPS := ":80", ":443"
	gotHTTP, gotHTTPS := listenPortsFor(false)
	if gotHTTP != wantHTTP || gotHTTPS != wantHTTPS {
		t.Errorf("prod listenPortsFor = (%s, %s), want (%s, %s)", gotHTTP, gotHTTPS, wantHTTP, wantHTTPS)
	}
}

func TestPortOverride_DevDefaultsWhenVarUnset(t *testing.T) {
	prevHTTP, prevHTTPSet := lookupEnvForTest(envHTTPPort)
	prevHTTPS, prevHTTPSSet := lookupEnvForTest(envHTTPSPort)
	unsetForTest(envHTTPPort)
	unsetForTest(envHTTPSPort)
	t.Cleanup(func() {
		restoreEnvForTest(envHTTPPort, prevHTTP, prevHTTPSet)
		restoreEnvForTest(envHTTPSPort, prevHTTPS, prevHTTPSSet)
	})

	if got := httpPortFor(true); got != httpPortDev {
		t.Errorf("dev httpPortFor = %d, want %d", got, httpPortDev)
	}
	if got := httpsPortFor(true); got != httpsPortDev {
		t.Errorf("dev httpsPortFor = %d, want %d", got, httpsPortDev)
	}
}

func TestPortOverride_ValidValueWins(t *testing.T) {
	t.Setenv(envHTTPPort, "19090")
	t.Setenv(envHTTPSPort, "19443")

	if got := httpPortFor(true); got != 19090 {
		t.Errorf("dev httpPortFor with override = %d, want 19090", got)
	}
	if got := httpsPortFor(true); got != 19443 {
		t.Errorf("dev httpsPortFor with override = %d, want 19443", got)
	}
	// Listen strings derived from the int ports must stay in
	// lockstep — boot log line and actual listener must match.
	gotHTTP, gotHTTPS := listenPortsFor(true)
	if gotHTTP != ":19090" || gotHTTPS != ":19443" {
		t.Errorf("listenPortsFor = (%s, %s), want (:19090, :19443)", gotHTTP, gotHTTPS)
	}
}

func TestPortOverride_ValidOnProdMode(t *testing.T) {
	// A prod deployment that explicitly opts into a high port
	// (e.g. running behind an external load balancer that
	// terminates :80/:443) still gets the override honoured.
	t.Setenv(envHTTPPort, "8080")
	t.Setenv(envHTTPSPort, "8443")

	if got := httpPortFor(false); got != 8080 {
		t.Errorf("prod httpPortFor with override = %d, want 8080", got)
	}
	if got := httpsPortFor(false); got != 8443 {
		t.Errorf("prod httpsPortFor with override = %d, want 8443", got)
	}
}

func TestPortOverride_InvalidFallsBackToDefault(t *testing.T) {
	// Documented contract: unparseable / out-of-range values
	// fall back to the devMode-based default. An operator
	// typo'd ARENET_HTTP_PORT=foo should NOT crash boot or
	// produce a 0/-1 listener; it must silently fall back so
	// the proxy stays up, with the boot log line showing the
	// effective (fallback) port.
	cases := []struct {
		name string
		val  string
	}{
		{"empty_string_only_spaces", "   "},
		{"non_numeric", "foo"},
		{"negative", "-1"},
		{"zero", "0"},
		{"too_high", "70000"},
		{"float", "8080.5"},
		{"hex", "0x1f90"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(envHTTPPort, c.val)
			if got := httpPortFor(true); got != httpPortDev {
				t.Errorf("dev httpPortFor with invalid %q = %d, want %d (fallback)", c.val, got, httpPortDev)
			}
			if got := httpPortFor(false); got != httpPortProd {
				t.Errorf("prod httpPortFor with invalid %q = %d, want %d (fallback)", c.val, got, httpPortProd)
			}
		})
	}
}

func TestPortOverride_WhitespaceTrimmed(t *testing.T) {
	// Operators often paste values with stray whitespace
	// (especially from copy-paste in shell or systemd
	// EnvironmentFile= lines). " 9090 " must parse as 9090,
	// not fall back to the default.
	t.Setenv(envHTTPPort, "  9090  ")
	if got := httpPortFor(true); got != 9090 {
		t.Errorf("httpPortFor with whitespace-padded value = %d, want 9090", got)
	}
}

func TestPortOverride_HTTPSetWithoutHTTPSStillWorks(t *testing.T) {
	// Partial override is allowed: setting only HTTP overrides
	// HTTP but leaves HTTPS at the default. Useful when an
	// operator wants to move HTTP off port 80 while running
	// without TLS at all.
	prevHTTPS, prevHTTPSSet := lookupEnvForTest(envHTTPSPort)
	unsetForTest(envHTTPSPort)
	t.Cleanup(func() {
		restoreEnvForTest(envHTTPSPort, prevHTTPS, prevHTTPSSet)
	})
	t.Setenv(envHTTPPort, "9090")

	if got := httpPortFor(false); got != 9090 {
		t.Errorf("httpPortFor with partial override = %d, want 9090", got)
	}
	if got := httpsPortFor(false); got != httpsPortProd {
		t.Errorf("httpsPortFor without override = %d, want %d (default)", got, httpsPortProd)
	}
}
