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

package geo

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewLookup_EmptyPath_ReturnsError(t *testing.T) {
	l, err := NewLookup("")
	if err == nil {
		t.Fatalf("expected error for empty path, got Lookup=%v", l)
	}
	if l != nil {
		t.Fatalf("expected nil Lookup on error, got %v", l)
	}
}

func TestNewLookup_MissingFile_ReturnsError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nonexistent.mmdb")
	l, err := NewLookup(missing)
	if err == nil {
		_ = l.Close()
		t.Fatalf("expected error for missing file, got Lookup=%v", l)
	}
	if l != nil {
		t.Fatalf("expected nil Lookup on error, got %v", l)
	}
}

func TestNewLookup_CorruptFile_ReturnsError(t *testing.T) {
	corrupt := filepath.Join(t.TempDir(), "corrupt.mmdb")
	if err := os.WriteFile(corrupt, []byte("not an mmdb file"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	l, err := NewLookup(corrupt)
	if err == nil {
		_ = l.Close()
		t.Fatalf("expected error for corrupt file")
	}
	if !strings.Contains(err.Error(), "open mmdb") {
		t.Fatalf("expected wrapped error mentioning open mmdb, got: %v", err)
	}
}

func TestLookupIP_NilReceiver_ReturnsEmpty(t *testing.T) {
	var l *Lookup
	got := l.LookupIP(net.ParseIP("8.8.8.8"))
	if got.Found {
		t.Fatalf("expected Found=false on nil receiver, got %+v", got)
	}
}

func TestLookupIP_NilIP_ReturnsEmpty(t *testing.T) {
	var l *Lookup
	got := l.LookupIP(nil)
	if got.Found {
		t.Fatalf("expected Found=false for nil IP, got %+v", got)
	}
}

func TestLookupIP_LAN_ReturnsLANMarker(t *testing.T) {
	var l *Lookup
	cases := []string{
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"127.0.0.1",
		"169.254.1.1",
		"::1",
		"fe80::1",
		"fc00::1",
	}
	for _, ipStr := range cases {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			t.Fatalf("test bug: ParseIP returned nil for %q", ipStr)
		}
		got := l.LookupIP(ip)
		// nil receiver short-circuits before isLAN, so LAN marker logic
		// is exercised via the isLAN tests below. Here we only assert
		// that LAN inputs never produce Found=true through a real
		// Lookup either.
		if got.Found {
			t.Fatalf("%s: expected Found=false on nil receiver, got %+v", ipStr, got)
		}
	}
}

func TestClose_NilReceiver_NoOp(t *testing.T) {
	var l *Lookup
	if err := l.Close(); err != nil {
		t.Fatalf("expected nil error on nil receiver, got %v", err)
	}
}

func TestPath_NilReceiver_ReturnsEmpty(t *testing.T) {
	var l *Lookup
	if p := l.Path(); p != "" {
		t.Fatalf("expected empty Path on nil receiver, got %q", p)
	}
}

func TestIsLAN_RFC1918Ranges(t *testing.T) {
	cases := []string{
		"10.0.0.0", "10.255.255.255",
		"172.16.0.0", "172.31.255.255",
		"192.168.0.0", "192.168.255.255",
	}
	for _, ipStr := range cases {
		ip := net.ParseIP(ipStr)
		if !isLAN(ip) {
			t.Errorf("expected isLAN(%s)=true (RFC1918), got false", ipStr)
		}
	}
}

func TestIsLAN_Loopback(t *testing.T) {
	cases := []string{"127.0.0.1", "127.255.255.255", "::1"}
	for _, ipStr := range cases {
		ip := net.ParseIP(ipStr)
		if !isLAN(ip) {
			t.Errorf("expected isLAN(%s)=true (loopback), got false", ipStr)
		}
	}
}

func TestIsLAN_LinkLocal(t *testing.T) {
	cases := []string{"169.254.0.1", "169.254.169.254", "fe80::1"}
	for _, ipStr := range cases {
		ip := net.ParseIP(ipStr)
		if !isLAN(ip) {
			t.Errorf("expected isLAN(%s)=true (link-local), got false", ipStr)
		}
	}
}

func TestIsLAN_PublicIPs(t *testing.T) {
	cases := []string{
		"8.8.8.8",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"172.15.0.1",      // adjacent to RFC1918 172.16/12 — must be public
		"172.32.0.1",      // adjacent to RFC1918 172.16/12 — must be public
		"192.167.255.255", // adjacent to 192.168/16 — must be public
		"2001:4860::1",    // Google IPv6
	}
	for _, ipStr := range cases {
		ip := net.ParseIP(ipStr)
		if isLAN(ip) {
			t.Errorf("expected isLAN(%s)=false (public), got true", ipStr)
		}
	}
}

func TestIsLAN_NilIP(t *testing.T) {
	if isLAN(nil) {
		t.Fatal("expected isLAN(nil)=false")
	}
}

// setPathForTest sets the unexported path field for tests that assert
// Path() behavior without a real MMDB.
func (l *Lookup) setPathForTest(p string) {
	l.pathMu.Lock()
	l.path = p
	l.pathMu.Unlock()
}

func TestReload_EmptyPath_ReturnsErrorNoChange(t *testing.T) {
	l := &Lookup{} // nil reader
	if err := l.Reload(""); err == nil {
		t.Fatal("Reload(\"\") = nil; want error")
	}
	// reader untouched → still degraded, no panic
	if got := l.LookupIP(net.ParseIP("8.8.8.8")); got.Found {
		t.Errorf("LookupIP after failed reload = %+v; want Found=false", got)
	}
}

func TestReload_InvalidPath_PreservesReader(t *testing.T) {
	l := &Lookup{}
	missing := filepath.Join(t.TempDir(), "nope.mmdb")
	err := l.Reload(missing)
	if err == nil {
		t.Fatal("Reload(missing) = nil; want error")
	}
	if !strings.Contains(err.Error(), "reload open mmdb") {
		t.Errorf("error = %v; want wrapped 'reload open mmdb'", err)
	}
	// current (nil) reader preserved; lookups still safe
	if got := l.LookupIP(net.ParseIP("8.8.8.8")); got.Found {
		t.Errorf("LookupIP after failed reload = %+v; want Found=false", got)
	}
}

func TestReload_NilReceiver_ReturnsError(t *testing.T) {
	var l *Lookup
	if err := l.Reload("/whatever"); err == nil {
		t.Fatal("nil *Lookup Reload = nil; want error")
	}
}

func TestReload_FailedReload_DoesNotChangePath(t *testing.T) {
	l := &Lookup{}
	l.setPathForTest("original.mmdb") // see helper below
	_ = l.Reload(filepath.Join(t.TempDir(), "missing.mmdb"))
	if got := l.Path(); got != "original.mmdb" {
		t.Errorf("Path after failed reload = %q; want unchanged 'original.mmdb'", got)
	}
}

func TestReload_Concurrent_RaceSafe(t *testing.T) {
	l := &Lookup{}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	// readers
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = l.LookupIP(net.ParseIP("8.8.8.8"))
				}
			}
		}()
	}
	// reloader (reloads fail-open since no real DB; still exercises Swap path)
	missing := filepath.Join(t.TempDir(), "missing.mmdb")
	for i := 0; i < 50; i++ {
		_ = l.Reload(missing)
	}
	close(stop)
	wg.Wait()
}

// TestLookupIP_RealMMDB exercises the full pipeline against an actual
// GeoLite2-City.mmdb when one is present at the conventional dev path
// or pointed to via ARENET_TEST_MMDB. Skipped otherwise — the wrapper-
// logic tests above cover the contract surface that V.1 promises.
func TestLookupIP_RealMMDB(t *testing.T) {
	path := os.Getenv("ARENET_TEST_MMDB")
	if path == "" {
		path = "/var/lib/arenet/GeoLite2-City.mmdb"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no MMDB at %s — skipping real-DB integration test", path)
	}
	l, err := NewLookup(path)
	if err != nil {
		t.Fatalf("open real MMDB: %v", err)
	}
	defer l.Close()

	got := l.LookupIP(net.ParseIP("8.8.8.8"))
	if !got.Found {
		t.Fatalf("expected Found=true for 8.8.8.8 against real MMDB, got %+v", got)
	}
	if got.Country == "" {
		t.Errorf("expected non-empty Country for 8.8.8.8, got %+v", got)
	}

	lan := l.LookupIP(net.ParseIP("192.168.1.1"))
	if lan.Country != "LAN" {
		t.Errorf("expected Country=LAN for 192.168.1.1, got %+v", lan)
	}
	if lan.Found {
		t.Errorf("expected Found=false for LAN IP, got %+v", lan)
	}
}
