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

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"

	"github.com/barto95100/arenet/internal/storage"
)

// TestStoreDNS01Inconsistency pins the predicate that drives the
// boot WARN + the frontend bandeaux (the (β) safety net the
// edit-time guard cannot cover). A regression here would silence
// the WARN: an operator deleting the OVH provider config after
// dns-01 routes have been saved would get no signal until the
// next cert renewal fails in production. The four cases below
// exhaust the truth table.
func TestStoreDNS01Inconsistency(t *testing.T) {
	mkStore := func(t *testing.T) *storage.Store {
		t.Helper()
		dir := t.TempDir()
		s, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
		if err != nil {
			t.Fatalf("NewStore: %v", err)
		}
		t.Cleanup(func() { _ = s.Close() })
		return s
	}

	ctx := context.Background()

	t.Run("no routes, no provider", func(t *testing.T) {
		s := mkStore(t)
		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if anyDNS01 {
			t.Errorf("anyDNS01 = true on empty store")
		}
		// No dns-01 routes → providerOK is the trivially-true
		// "no problem to detect" sentinel. The boot WARN gate
		// requires anyDNS01 AND !providerOK, so this is correct
		// (no warn fires).
		if !providerOK {
			t.Errorf("providerOK = false on empty store; want true (no dns-01 routes ⇒ no inconsistency)")
		}
	})

	t.Run("dns-01 route, no provider", func(t *testing.T) {
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:          "wild.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !anyDNS01 {
			t.Errorf("anyDNS01 = false; want true")
		}
		if providerOK {
			t.Errorf("providerOK = true with no provider configured")
		}
	})

	t.Run("dns-01 route, complete provider", func(t *testing.T) {
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:          "wild.example.com",
			Upstreams:     []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:      storage.LBPolicyRoundRobin,
			ACMEChallenge: storage.ACMEChallengeDNS01,
			WAFMode:       "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}
		if _, err := s.CreateDNSProvider(ctx, storage.DNSProviderConfig{
			Label:             "OVH",
			Type:              storage.DNSProviderTypeOVH,
			Endpoint:          "ovh-eu",
			ApplicationKey:    "k",
			ApplicationSecret: "s",
			ConsumerKey:       "c",
		}); err != nil {
			t.Fatalf("CreateDNSProvider: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !anyDNS01 {
			t.Errorf("anyDNS01 = false; want true")
		}
		if !providerOK {
			t.Errorf("providerOK = false with complete provider")
		}
	})

	t.Run("http-01 routes only, complete provider", func(t *testing.T) {
		// The provider exists but no route uses it — a benign
		// pre-staging state. anyDNS01 must be false so the WARN
		// stays silent.
		s := mkStore(t)
		_, err := s.CreateRoute(ctx, storage.Route{
			Host:      "plain.example.com",
			Upstreams: []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
			LBPolicy:  storage.LBPolicyRoundRobin,
			WAFMode:   "off",
		})
		if err != nil {
			t.Fatalf("CreateRoute: %v", err)
		}
		if _, err := s.CreateDNSProvider(ctx, storage.DNSProviderConfig{
			Label:             "OVH",
			Type:              storage.DNSProviderTypeOVH,
			Endpoint:          "ovh-eu",
			ApplicationKey:    "k",
			ApplicationSecret: "s",
			ConsumerKey:       "c",
		}); err != nil {
			t.Fatalf("CreateDNSProvider: %v", err)
		}

		anyDNS01, providerOK, err := storeDNS01Inconsistency(ctx, s)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if anyDNS01 {
			t.Errorf("anyDNS01 = true with only http-01 routes")
		}
		if !providerOK {
			t.Errorf("providerOK = false despite complete config (irrelevant here but tracks the truth)")
		}
	})
}

// TestResolveCertStorageHome pins the Docker cert-storage fix. certmagic's
// default storage path is caddy.AppDataDir(), which on Linux derives from
// $HOME ($HOME/.local/share/caddy). systemd sets $HOME=/var/lib/arenet via
// the arenet user's passwd entry, so the binary install lands certs at the
// documented /var/lib/arenet/.local/share/caddy. A distroless Docker
// container sets NO $HOME, so AppDataDir() falls back to the RELATIVE
// "./caddy" (cwd-dependent) — a different, fragile path that breaks the
// "works on binary, not Docker" reverse-proxy TLS. This helper makes the
// process deterministic: when neither $HOME nor $XDG_DATA_HOME is set, it
// pins $HOME to the data dir so AppDataDir() resolves to the same absolute
// path the systemd install uses. It is a no-op when either is already set,
// preserving every existing install's cert path (no silent migration).
func TestResolveCertStorageHome(t *testing.T) {
	t.Run("HOME unset, XDG unset → defaults HOME to dataDir", func(t *testing.T) {
		env := map[string]string{} // both empty
		set := map[string]string{}
		home, defaulted, err := resolveCertStorageHome(
			func(k string) string { return env[k] },
			func(k, v string) error { set[k] = v; return nil },
			"/var/lib/arenet",
		)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !defaulted {
			t.Errorf("defaulted = false; want true (HOME was unset)")
		}
		if home != "/var/lib/arenet" {
			t.Errorf("home = %q; want /var/lib/arenet", home)
		}
		if set["HOME"] != "/var/lib/arenet" {
			t.Errorf("HOME setenv = %q; want /var/lib/arenet", set["HOME"])
		}
	})

	t.Run("HOME already set → no-op, preserves existing install", func(t *testing.T) {
		env := map[string]string{"HOME": "/home/someone"}
		set := map[string]string{}
		home, defaulted, err := resolveCertStorageHome(
			func(k string) string { return env[k] },
			func(k, v string) error { set[k] = v; return nil },
			"/var/lib/arenet",
		)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if defaulted {
			t.Errorf("defaulted = true; want false (HOME was already set)")
		}
		if home != "/home/someone" {
			t.Errorf("home = %q; want /home/someone (untouched)", home)
		}
		if _, ok := set["HOME"]; ok {
			t.Errorf("HOME was overwritten (%q); must be a no-op when set", set["HOME"])
		}
	})

	t.Run("XDG_DATA_HOME set, HOME unset → no-op (XDG governs AppDataDir)", func(t *testing.T) {
		// AppDataDir() prefers $XDG_DATA_HOME over $HOME, so if XDG is
		// set we must NOT touch HOME — the storage path is already
		// deterministic and operator-controlled.
		env := map[string]string{"XDG_DATA_HOME": "/data/xdg"}
		set := map[string]string{}
		_, defaulted, err := resolveCertStorageHome(
			func(k string) string { return env[k] },
			func(k, v string) error { set[k] = v; return nil },
			"/var/lib/arenet",
		)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if defaulted {
			t.Errorf("defaulted = true; want false (XDG_DATA_HOME governs)")
		}
		if _, ok := set["HOME"]; ok {
			t.Errorf("HOME was set despite XDG_DATA_HOME present")
		}
	})
}

// TestDefaultStorageFrozenAtInit pins the load-bearing invariant behind
// the two-layer cert-storage fix: caddy.DefaultStorage is a package-level
// var materialized at PROGRAM INIT (caddy v2.11.3 storage.go:160,
// `var DefaultStorage = &FileStorage{Path: AppDataDir()}`), and config
// load assigns that frozen pointer without re-deriving the path
// (caddy.go:553-554). Consequently, setting $HOME inside run() (after
// init) CANNOT move Caddy's cert store — only $HOME set before process
// start (the Dockerfile ENV) does. This test guards against a future
// reader "fixing" the code to rely on the Go-side HOME pin to redirect
// Caddy's storage, which would silently not work. It also confirms the
// contrast: caddy.AppDataDir() (which certinfo calls live) DOES follow a
// late $HOME change, which is exactly what resolveCertStorageHome aligns.
func TestDefaultStorageFrozenAtInit(t *testing.T) {
	frozen := caddy.DefaultStorage.Path

	t.Setenv("HOME", "/tmp/arenet-late-home-"+t.Name())

	if got := caddy.DefaultStorage.Path; got != frozen {
		t.Fatalf("DefaultStorage.Path changed after late Setenv HOME: %q → %q; "+
			"the init-freeze invariant broke — the Go HOME pin must NOT be relied on "+
			"to redirect Caddy storage; only the Dockerfile ENV HOME (pre-init) does", frozen, got)
	}

	// Contrast: AppDataDir() is derived live, so certinfo's path DOES track
	// the late $HOME — this is the piece resolveCertStorageHome legitimately
	// aligns. If this ever stops tracking, certinfo would diverge silently.
	live := caddy.AppDataDir()
	if got := os.Getenv("HOME"); got != "" && live == frozen {
		t.Errorf("caddy.AppDataDir() did not track the late HOME change "+
			"(live=%q, frozen=%q); certinfo path alignment would be a no-op", live, frozen)
	}
}
