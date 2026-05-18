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

package auth

import (
	"bytes"
	"context"
	"crypto/sha1" // HIBP wire protocol only — see hibp.go package doc.
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hibpSuffixOf returns the uppercase 35-char SHA-1 suffix that HIBP
// would expect for the given password. Used by the mock server to
// craft responses containing the suffix when the test wants a
// "compromised" outcome.
func hibpSuffixOf(password string) string {
	h := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(h[:]))[5:]
}

// hibpPrefixOf returns the uppercase 5-char SHA-1 prefix HIBP receives.
func hibpPrefixOf(password string) string {
	h := sha1.Sum([]byte(password))
	return strings.ToUpper(hex.EncodeToString(h[:]))[:5]
}

// newMockHIBPServer returns a httptest.Server that responds with
// the provided body when the request path matches /range/<expectedPrefix>.
// Any other path returns 404. Returns server and the captured request
// path for verification.
func newMockHIBPServer(t *testing.T, response string, status int) (*httptest.Server, *[]string) {
	t.Helper()
	var seenPaths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPaths = append(seenPaths, r.URL.Path)
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(srv.Close)
	return srv, &seenPaths
}

// newTestClient constructs an HIBPClient pointing at the given mock
// server, with the production User-Agent.
func newTestClient(serverURL string) *HIBPClient {
	return &HIBPClient{
		httpClient: &http.Client{Timeout: 2 * time.Second},
		baseURL:    serverURL,
		userAgent:  hibpUserAgent,
		disabled:   false,
	}
}

func TestHIBP_CheckPassword_Clean(t *testing.T) {
	// Response contains arbitrary other suffixes, NOT the one for "password".
	body := "0000000000000000000000000000000000A:1\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:5\n"
	srv, _ := newMockHIBPServer(t, body, http.StatusOK)
	c := newTestClient(srv.URL)

	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusClean {
		t.Errorf("got %q, want %q", status, HIBPStatusClean)
	}
}

func TestHIBP_CheckPassword_Compromised(t *testing.T) {
	// The response includes the SHA-1 suffix of "password".
	suffix := hibpSuffixOf("password")
	body := "0000000000000000000000000000000000A:1\n" + suffix + ":1234567\n"
	srv, _ := newMockHIBPServer(t, body, http.StatusOK)
	c := newTestClient(srv.URL)

	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusCompromised {
		t.Errorf("got %q, want %q", status, HIBPStatusCompromised)
	}
}

func TestHIBP_CheckPassword_5xxIsPending(t *testing.T) {
	srv, _ := newMockHIBPServer(t, "", http.StatusInternalServerError)
	c := newTestClient(srv.URL)

	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusPending {
		t.Errorf("got %q, want %q", status, HIBPStatusPending)
	}
}

func TestHIBP_CheckPassword_NetworkErrorIsPending(t *testing.T) {
	// Construct a client pointing at an address that refuses
	// connections to simulate a network error without using the
	// real HIBP endpoint.
	c := &HIBPClient{
		httpClient: &http.Client{Timeout: 200 * time.Millisecond},
		baseURL:    "http://127.0.0.1:1", // port 1 typically refused
		userAgent:  hibpUserAgent,
	}
	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusPending {
		t.Errorf("got %q, want %q", status, HIBPStatusPending)
	}
}

func TestHIBP_CheckPassword_Disabled(t *testing.T) {
	c := &HIBPClient{
		httpClient: &http.Client{Timeout: time.Second},
		baseURL:    "http://example.invalid", // would fail if actually called
		userAgent:  hibpUserAgent,
		disabled:   true,
	}
	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusSkipped {
		t.Errorf("got %q, want %q", status, HIBPStatusSkipped)
	}
}

// TestHIBP_KAnonymity_Only5CharPrefixSent verifies that HIBP receives
// only the 5-character SHA-1 prefix, never the full hash and never
// the plaintext. This is the spec §7.2 k-anonymity guarantee.
func TestHIBP_KAnonymity_Only5CharPrefixSent(t *testing.T) {
	srv, seenPaths := newMockHIBPServer(t, "0000000000000000000000000000000000A:1\n", http.StatusOK)
	c := newTestClient(srv.URL)

	password := "very-secret-password-which-must-not-appear-anywhere"
	if _, err := c.CheckPassword(context.Background(), password); err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}

	if len(*seenPaths) != 1 {
		t.Fatalf("expected 1 HTTP call, got %d", len(*seenPaths))
	}
	path := (*seenPaths)[0]

	// The path must be exactly /range/<5 uppercase hex chars>.
	wantPrefix := hibpPrefixOf(password)
	wantPath := "/range/" + wantPrefix
	if path != wantPath {
		t.Errorf("HIBP path = %q, want %q", path, wantPath)
	}
	if len(wantPrefix) != 5 {
		t.Errorf("prefix length = %d, want 5", len(wantPrefix))
	}

	// And the plaintext password must not appear in the URL path.
	if strings.Contains(path, password) {
		t.Errorf("plaintext password leaked into URL: %q", path)
	}
}

// TestHIBP_PlaintextNeverLogged is sub-test security #2 (plan §4.2):
// the HIBP client must never log the plaintext password, even at
// Debug level. We swap the default slog logger for one that writes
// into a buffer and inspect the captured logs.
//
// In addition to the plaintext, we also assert that the FULL SHA-1
// hash never appears in the logs. The 5-char prefix alone is safe
// (~1 million buckets, k-anonymity) and the 35-char suffix alone is
// safe (no link to a specific account without the prefix), but
// concatenated they form the full hash which is directly crackable
// offline against rainbow tables. Detecting either the full hashHex
// or any string of the form prefix+suffix would be a leak.
//
// This test intentionally does NOT use t.Parallel(): it manipulates
// global slog state (slog.SetDefault) and parallel execution would
// race with other tests that may also touch the default logger.
func TestHIBP_PlaintextNeverLogged(t *testing.T) {
	// Capture global slog state and restore on cleanup.
	originalDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(originalDefault) })

	var buf bytes.Buffer
	captureLogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(captureLogger)

	// Canary password chosen so its plaintext, full hash, and full
	// hex digest are all easy to grep in the log buffer.
	secret := "very-secret-and-unique-canary-password-xyz"
	fullHash := sha1.Sum([]byte(secret))
	fullHashHex := strings.ToUpper(hex.EncodeToString(fullHash[:]))

	// Mock server returns the compromised suffix to also exercise the
	// match path (Compromised) which is the most "interesting" path
	// where a careless logger might decide to record the hit.
	body := fullHashHex[5:] + ":42\n"
	srv, _ := newMockHIBPServer(t, body, http.StatusOK)

	c := newTestClient(srv.URL)
	if _, err := c.CheckPassword(context.Background(), secret); err != nil {
		t.Fatalf("CheckPassword (compromised path): %v", err)
	}
	// Also exercise the network error path.
	c2 := &HIBPClient{
		httpClient: &http.Client{Timeout: 100 * time.Millisecond},
		baseURL:    "http://127.0.0.1:1",
		userAgent:  hibpUserAgent,
	}
	if _, err := c2.CheckPassword(context.Background(), secret); err != nil {
		t.Fatalf("CheckPassword (network error path): %v", err)
	}

	logs := buf.String()
	if strings.Contains(logs, secret) {
		t.Errorf("plaintext password leaked into logs: %q", logs)
	}
	// Full hash leak check: concatenated prefix+suffix = directly
	// crackable offline against rainbow tables.
	if strings.Contains(logs, fullHashHex) {
		t.Errorf("full SHA-1 hash leaked into logs: %q", logs)
	}
}

func TestHIBP_CheckPassword_ContextCancellation(t *testing.T) {
	// Server that never responds, simulating a hang.
	hangSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(hangSrv.Close)
	c := newTestClient(hangSrv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	status, err := c.CheckPassword(ctx, "password")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusPending {
		t.Errorf("got %q, want %q", status, HIBPStatusPending)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("did not honor ctx deadline; elapsed=%v", elapsed)
	}
	// Sanity: confirm we are not depending on net.Error being a specific type.
	_ = errors.Is
	_ = (*net.OpError)(nil)
}

// TestHIBP_CheckPassword_EmptyString is a defensive regression test:
// length validation is upstream (in userstore.go and the future
// ValidatePasswordSync wrapper), so CheckPassword is never called
// with "" in production. But if a future refactor accidentally
// removes the upstream check, this test ensures CheckPassword does
// not panic and returns a benign result.
//
// SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709, prefix DA39A.
// The mock server returns a response with no matching suffix, so
// the expected outcome is HIBPStatusClean.
func TestHIBP_CheckPassword_EmptyString(t *testing.T) {
	srv, _ := newMockHIBPServer(t, "FAKE_SUFFIX_NOT_MATCHING:1\n", http.StatusOK)
	c := newTestClient(srv.URL)

	status, err := c.CheckPassword(context.Background(), "")
	if err != nil {
		t.Fatalf("CheckPassword(\"\") returned error: %v", err)
	}
	// Result is deterministic: empty string's SHA-1 suffix won't appear
	// in our mock response. The point of the test is mainly "no panic".
	if status != HIBPStatusClean {
		t.Errorf("CheckPassword(\"\") = %q, want %q (defensive test, exact value not critical)", status, HIBPStatusClean)
	}
}

// TestHIBP_CheckPassword_MalformedResponseLines verifies the parser
// tolerates lines without a colon and lines with empty values.
// Malformed lines are skipped, NOT treated as compromised.
func TestHIBP_CheckPassword_MalformedResponseLines(t *testing.T) {
	body := "" +
		"this-has-no-colon\n" +
		":42\n" +
		"\n" +
		"FAKE:1\n"
	srv, _ := newMockHIBPServer(t, body, http.StatusOK)
	c := newTestClient(srv.URL)

	status, err := c.CheckPassword(context.Background(), "password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != HIBPStatusClean {
		t.Errorf("got %q, want %q (malformed lines should be skipped)", status, HIBPStatusClean)
	}
}

// TestNewHIBPClient_DefaultsAndEnvVar verifies the production
// constructor reads ARENET_HIBP_DISABLED correctly.
func TestNewHIBPClient_DefaultsAndEnvVar(t *testing.T) {
	t.Run("default enabled", func(t *testing.T) {
		t.Setenv(envHIBPDisabled, "")
		c := NewHIBPClient()
		if c.disabled {
			t.Error("default should be enabled")
		}
		if c.baseURL != hibpDefaultBaseURL {
			t.Errorf("baseURL = %q, want %q", c.baseURL, hibpDefaultBaseURL)
		}
		if c.httpClient.Timeout != HIBPTimeoutSync {
			t.Errorf("Timeout = %v, want %v", c.httpClient.Timeout, HIBPTimeoutSync)
		}
	})

	t.Run("disabled via env=true", func(t *testing.T) {
		t.Setenv(envHIBPDisabled, "true")
		c := NewHIBPClient()
		if !c.disabled {
			t.Error("env=true should disable")
		}
	})

	t.Run("AC-CONFIG-04: env=True does NOT disable", func(t *testing.T) {
		t.Setenv(envHIBPDisabled, "True")
		c := NewHIBPClient()
		if c.disabled {
			t.Error("env=True (capitalized) must NOT disable; only exact \"true\"")
		}
	})

	t.Run("AC-CONFIG-04: env=1 does NOT disable", func(t *testing.T) {
		t.Setenv(envHIBPDisabled, "1")
		c := NewHIBPClient()
		if c.disabled {
			t.Error("env=1 must NOT disable; only exact \"true\"")
		}
	})

	t.Run("AC-CONFIG-04: env=yes does NOT disable", func(t *testing.T) {
		t.Setenv(envHIBPDisabled, "yes")
		c := NewHIBPClient()
		if c.disabled {
			t.Error("env=yes must NOT disable; only exact \"true\"")
		}
	})
}
