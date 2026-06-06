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

package certinfo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// newTestEvent builds a caddy.Event for the test. The package's
// NewEvent constructor needs a Context — zero-value works because
// our Handle only reads Name() and Data, never Origin().
func newTestEvent(t *testing.T, name string, data map[string]any) caddy.Event {
	t.Helper()
	ev, err := caddy.NewEvent(caddy.Context{}, name, data)
	if err != nil {
		t.Fatalf("NewEvent: %v", err)
	}
	return ev
}

// withSingletonTracker installs `tr` as the package singleton and
// restores the previous value on test cleanup. Required because
// the handler reads through getTracker() — there's no per-handler
// tracker injection (intentional: the Caddy module receives empty
// JSON during Provision, so a singleton is the only seam).
func withSingletonTracker(t *testing.T, tr *Tracker) {
	t.Helper()
	prev := getTracker()
	SetTracker(tr)
	t.Cleanup(func() { SetTracker(prev) })
}

// writeFreshLeafForTest mints a self-signed leaf cert at the
// certinfo storage path the listener will dereference. Returns
// the absolute path so the test can stash it into the event
// payload's certificate_path field.
func writeFreshLeafForTest(t *testing.T, storageRoot, issuerSafe, domainSafe string, sans []string, notAfter time.Time) string {
	t.Helper()
	dir := filepath.Join(storageRoot, "certificates", issuerSafe, domainSafe)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: sans[0]},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	path := filepath.Join(dir, domainSafe+".crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestCaddyEventHandler_CertObtaining(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_obtaining", map[string]any{
		"identifier": "api.example.com",
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	// cert_obtaining is informational — the tracker doesn't record
	// persistent state, but the Subscribe seam should have fired.
	if _, ok := tr.Get("api.example.com"); ok {
		t.Fatalf("cert_obtaining must not create a persistent entry")
	}
}

func TestCaddyEventHandler_CertObtained(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	storage := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second).UTC()
	certPath := writeFreshLeafForTest(t, storage,
		"acme-v02.api.letsencrypt.org-directory",
		"api.example.com",
		[]string{"api.example.com"},
		notAfter,
	)

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_obtained", map[string]any{
		"identifier":       "api.example.com",
		"issuer":           "acme-v02.api.letsencrypt.org-directory",
		"certificate_path": certPath,
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	got, ok := tr.Get("api.example.com")
	if !ok {
		t.Fatalf("Get miss after cert_obtained")
	}
	if !got.NotAfter.Equal(notAfter) {
		t.Fatalf("NotAfter=%v want=%v", got.NotAfter, notAfter)
	}
	if got.Issuer != "Let's Encrypt" {
		t.Fatalf("Issuer=%q want=Let's Encrypt", got.Issuer)
	}
	if got.Status != StatusValid {
		t.Fatalf("Status=%q want=VALID", got.Status)
	}
}

// TestCaddyEventHandler_CertObtained_FallbackOnReadFailure pins
// the degraded path: cert_obtained fires but the cert file is
// missing (race, wrong path, weird storage backend). The handler
// must still create a minimal tracker entry rather than silently
// dropping the event.
func TestCaddyEventHandler_CertObtained_FallbackOnReadFailure(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_obtained", map[string]any{
		"identifier":       "ghost.example.com",
		"issuer":           "acme-v02.api.letsencrypt.org-directory",
		"certificate_path": "/this/path/does/not/exist.crt",
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	got, ok := tr.Get("ghost.example.com")
	if !ok {
		t.Fatalf("Get miss after fallback path")
	}
	if got.Status != StatusUnknown {
		t.Fatalf("Status=%q want=UNKNOWN (no NotAfter parsed from disk)", got.Status)
	}
	if got.Issuer != "Let's Encrypt" {
		t.Fatalf("Issuer=%q want=Let's Encrypt (decoded from key)", got.Issuer)
	}
}

func TestCaddyEventHandler_CertFailed(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_failed", map[string]any{
		"identifier": "broken.example.com",
		"error":      "dns lookup failed",
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	got, ok := tr.Get("broken.example.com")
	if !ok {
		t.Fatalf("Get miss after cert_failed")
	}
	if got.Status != StatusObtainFailed {
		t.Fatalf("Status=%q want=OBTAIN_FAILED", got.Status)
	}
	if got.LastError == nil || *got.LastError != "dns lookup failed" {
		t.Fatalf("LastError=%v want=%q", got.LastError, "dns lookup failed")
	}
}

// TestCaddyEventHandler_NilSingleton_Silent: when the singleton
// hasn't been installed, the handler must drop events silently
// (the singleton-install ordering is a main.go concern; the
// handler must not panic if the order ever flips).
func TestCaddyEventHandler_NilSingleton_Silent(t *testing.T) {
	withSingletonTracker(t, nil)
	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_obtained", map[string]any{
		"identifier": "x.example.com",
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle should not error on nil singleton: %v", err)
	}
}

// TestCaddyEventHandler_UnknownEvent: defensive — the subscription
// filter pins the three event names we care about, but if Caddy
// were to ever dispatch a sibling event through us, we drop it
// rather than panic.
func TestCaddyEventHandler_UnknownEvent(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cached_managed_cert", map[string]any{
		"sans": []any{"x.example.com"},
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if len(tr.List()) != 0 {
		t.Fatalf("unknown event must not mutate tracker; got %d entries", len(tr.List()))
	}
}

// TestCaddyEventHandler_CertOCSPRevoked pins the U.2 dispatch:
// a cert_ocsp_revoked Caddy event lands on tracker.RecordRevoked
// which fans out EventCertOCSPRevoked WITHOUT mutating tracker
// state (the cert remains operationally VALID until certmagic
// replaces it per spec §3.6).
func TestCaddyEventHandler_CertOCSPRevoked(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)
	// Pre-seed a VALID cert so we can confirm the revocation
	// does NOT change its tracker status.
	tr.RecordCert(&CertRuntimeInfo{
		Domain:   "x.example.com",
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
		Issuer:   "Let's Encrypt",
	})

	var captured Event
	tr.Subscribe(captureHandler{cb: func(e Event) {
		if e.Kind == EventCertOCSPRevoked {
			captured = e
		}
	}})

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_ocsp_revoked", map[string]any{
		"identifier": "x.example.com",
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if captured.Kind != EventCertOCSPRevoked {
		t.Fatalf("EventCertOCSPRevoked not fanned out; got Kind=%q", captured.Kind)
	}
	if captured.Domain != "x.example.com" {
		t.Errorf("event.Domain = %q, want x.example.com", captured.Domain)
	}
	// State unchanged.
	info, ok := tr.Get("x.example.com")
	if !ok {
		t.Fatalf("tracker entry purged by revocation — must NOT happen per spec §3.6")
	}
	if info.Status != StatusValid {
		t.Errorf("post-revocation status = %q, want VALID (revocation does not change tracker status)", info.Status)
	}
}

// TestCaddyEventHandler_CertObtained_RenewalBit pins the U.2
// renewal disambiguation: the listener extracts renewal=true
// from the cert_obtained payload and threads it through
// RecordCertWithRenewal so the fan-out Event carries the bit.
// The adapter relies on this for the cert_event row.
func TestCaddyEventHandler_CertObtained_RenewalBit(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	var captured Event
	tr.Subscribe(captureHandler{cb: func(e Event) {
		if e.Kind == EventCertObtained {
			captured = e
		}
	}})

	h := &CaddyEventHandler{logger: zap.NewNop()}
	// No certificate_path → falls into the fallback branch (the
	// listener still calls RecordCertWithRenewal with the
	// renewal bool). This is the simpler test path; the
	// happy-path branch is already covered by the existing
	// TestCaddyEventHandler_CertObtained test.
	ev := newTestEvent(t, "cert_obtained", map[string]any{
		"identifier": "renewed.example.com",
		"issuer":     "acme-v02.api.letsencrypt.org-directory",
		"renewal":    true,
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if captured.Kind != EventCertObtained {
		t.Fatalf("EventCertObtained not received; got Kind=%q", captured.Kind)
	}
	if !captured.IsRenewal {
		t.Errorf("IsRenewal = false, want true (renewal payload field was true)")
	}
}

// TestCaddyEventHandler_CertObtained_NoRenewalField pins the
// defensive default: a cert_obtained payload that omits the
// renewal field falls back to IsRenewal=false (legitimate
// first-issuance path).
func TestCaddyEventHandler_CertObtained_NoRenewalField(t *testing.T) {
	tr := NewTracker()
	withSingletonTracker(t, tr)

	var captured Event
	tr.Subscribe(captureHandler{cb: func(e Event) {
		if e.Kind == EventCertObtained {
			captured = e
		}
	}})

	h := &CaddyEventHandler{logger: zap.NewNop()}
	ev := newTestEvent(t, "cert_obtained", map[string]any{
		"identifier": "first.example.com",
		"issuer":     "acme-v02.api.letsencrypt.org-directory",
		// renewal field intentionally omitted
	})
	if err := h.Handle(context.Background(), ev); err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if captured.IsRenewal {
		t.Errorf("IsRenewal = true, want false (renewal field omitted = first issuance)")
	}
}

// TestExtractError covers the polymorphic-payload defensive path:
// certmagic stores the error as the Go `error` value, but
// formatters / mocks may pass it through as string.
func TestExtractError(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"string", map[string]any{"error": "boom"}, "boom"},
		{"error type", map[string]any{"error": &stringErr{s: "wrap"}}, "wrap"},
		{"missing", map[string]any{}, ""},
		{"nil", nil, ""},
		{"explicit nil", map[string]any{"error": nil}, ""},
		{"weird type", map[string]any{"error": 42}, "42"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractError(tc.in); got != tc.want {
				t.Fatalf("got=%q want=%q", got, tc.want)
			}
		})
	}
}

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }
