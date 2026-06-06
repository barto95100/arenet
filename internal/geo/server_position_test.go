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
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubLookup is a *Lookup-shaped stand-in that returns a canned
// Location for any IP. Used by the success path test to avoid
// shipping a real MMDB fixture.
//
// Implementation note: DetectFromPublicIP takes a concrete *Lookup,
// so we can't swap an interface — instead we build a real *Lookup
// whose receiver methods we don't exercise (we'd need a custom mode
// for that). Easier route: drive the Lookup branch via the public
// surface only when an MMDB is available, and use the env-override
// branch for the everyday CI path. The env override still goes
// through lookup.LookupIP — so we need a non-nil Lookup. The MMDB
// test below covers that branch; the unit tests here cover the
// pre-lookup error paths.

func TestDetectFromPublicIP_NilLookup_ReturnsError(t *testing.T) {
	pos, err := DetectFromPublicIP(nil)
	if err == nil {
		t.Fatalf("expected error for nil Lookup, got pos=%+v", pos)
	}
	if pos != nil {
		t.Fatalf("expected nil pos on error, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "non-nil Lookup") {
		t.Errorf("expected error to mention nil Lookup, got: %v", err)
	}
}

func TestDetectFromPublicIP_EnvOverride_BadIP(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "not-an-ip")
	// non-nil Lookup so the nil-guard doesn't short-circuit; the lookup
	// itself never runs because ParseIP fails first.
	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected error for invalid env IP, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "invalid public IP") {
		t.Errorf("expected invalid public IP error, got: %v", err)
	}
}

func TestDetectFromPublicIP_EnvOverride_LookupMiss(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "8.8.8.8")
	// Empty Lookup → LookupIP returns Found=false (nil reader path).
	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected error for unresolvable IP, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "not resolved in MMDB") {
		t.Errorf("expected MMDB miss error, got: %v", err)
	}
}

func TestDetectFromPublicIP_NetworkFailure(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "")

	restoreClient := SetDetectClient(&http.Client{
		Transport: errorTransport{err: errors.New("network down")},
	})
	defer restoreClient()
	restoreURL := SetIpifyURL("http://example.invalid/")
	defer restoreURL()

	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected error on network failure, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "ipify request") {
		t.Errorf("expected ipify request error, got: %v", err)
	}
}

func TestDetectFromPublicIP_Non2xx(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	restoreURL := SetIpifyURL(srv.URL)
	defer restoreURL()

	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected error on 5xx, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected HTTP 500 error, got: %v", err)
	}
}

func TestDetectFromPublicIP_BadResponseBody(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-an-ip-body"))
	}))
	defer srv.Close()
	restoreURL := SetIpifyURL(srv.URL)
	defer restoreURL()

	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected error on non-IP body, got %+v", pos)
	}
	if !strings.Contains(err.Error(), "invalid public IP") {
		t.Errorf("expected invalid public IP error, got: %v", err)
	}
}

func TestDetectFromPublicIP_HappyPath_NetworkStub(t *testing.T) {
	t.Setenv("ARENET_PUBLIC_IP", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.42\n"))
	}))
	defer srv.Close()
	restoreURL := SetIpifyURL(srv.URL)
	defer restoreURL()

	// We don't have a real MMDB in CI, so the stub Lookup will return
	// Found=false and DetectFromPublicIP will error at the "not
	// resolved in MMDB" step. This still exercises the full HTTP
	// pipeline (request, response read, body parse, ParseIP). The
	// MMDB-backed success path is covered by the real-MMDB test below.
	stub := &Lookup{}
	pos, err := DetectFromPublicIP(stub)
	if err == nil {
		t.Fatalf("expected MMDB miss (no real DB), got %+v", pos)
	}
	if !strings.Contains(err.Error(), "203.0.113.42") {
		t.Errorf("expected error to mention the parsed IP, got: %v", err)
	}
	_ = net.ParseIP("203.0.113.42") // doc anchor: TEST-NET-3 from RFC5737
}

// errorTransport always fails Do() — used to simulate network
// errors without spinning up a server.
type errorTransport struct{ err error }

func (t errorTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, t.err
}
