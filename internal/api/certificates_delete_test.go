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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// seedCertOnDisk creates a fake cert dir under the env's cert storage
// root so the delete handler has something to remove. Returns the leaf
// dir path.
func seedCertOnDisk(t *testing.T, storageDir, issuer, safeDomain string) string {
	t.Helper()
	dir := filepath.Join(storageDir, "certificates", issuer, safeDomain)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, safeDomain+".crt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir
}

func TestDeleteCertificate_Orphan_200(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	leaf := seedCertOnDisk(t, storageDir, "local", "orphan.example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/orphan.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	if _, err := os.Stat(leaf); !os.IsNotExist(err) {
		t.Error("cert dir still on disk after delete")
	}
}

func TestDeleteCertificate_BlockedByRouteHost_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	// A TLS-enabled route serves the domain -> it emits the cert
	// subject, so deleting the cert would churn it. Blocked.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "used.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: true,
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/used.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409", rec.Code, rec.Body)
	}
	var resp struct {
		BlockingRoutes []string `json:"blockingRoutes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	found := false
	for _, h := range resp.BlockingRoutes {
		if h == "used.example.com" {
			found = true
		}
	}
	if !found {
		t.Errorf("blockingRoutes=%v; want it to contain used.example.com", resp.BlockingRoutes)
	}
}

func TestDeleteCertificate_BlockedByDisabledRoute_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	// A DISABLED but TLS-enabled route still references the domain:
	// re-enabling it would re-issue the cert, so deleting now would
	// churn. Blocked. (A disabled route WITHOUT TLS is covered by
	// TestDeleteCertificate_NonTLSRoute_NotBlocked_200.)
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "dis.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		Disabled:   true,
		TLSEnabled: true,
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/dis.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (disabled route still references domain)", rec.Code, rec.Body)
	}
}

// v2.18.2 — a route WITHOUT TLS never emits a cert subject (the
// emission is gated on r.TLSEnabled, manager.go), so it does not "use"
// the cert and must NOT block deletion. Previously the block matched on
// host equality alone, ignoring TLSEnabled — a non-TLS route wrongly
// blocked deletion of a cert it can't possibly serve.
func TestDeleteCertificate_NonTLSRoute_NotBlocked_200(t *testing.T) {
	env := newTestEnv(t, false)
	dir := t.TempDir()
	env.handler.SetCertStorageDir(dir)
	// Put a real cert dir on disk so this is a genuine delete, not a
	// ghost-row idempotent 200.
	seedCertOnDisk(t, dir, "local", "notls.example.com")

	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:       "notls.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		TLSEnabled: false, // the whole point
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/notls.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (non-TLS route must not block cert deletion)", rec.Code, rec.Body)
	}
}

// v2.18.2 — a TLS route whose host is COVERED by a managed-domain
// wildcard (and which did NOT opt into a dedicated cert) is served by
// the wildcard cert, not its own per-host cert. Its leftover per-host
// HTTP-01 cert is orphaned and must be deletable — the route no longer
// emits that subject (manager.go: !UseDedicatedCert && covered → skip).
func TestDeleteCertificate_WildcardCoveredRoute_NotBlocked_200(t *testing.T) {
	env := newTestEnv(t, false)
	dir := t.TempDir()
	env.handler.SetCertStorageDir(dir)
	seedCertOnDisk(t, dir, "local", "app.example.com")

	// Managed wildcard *.example.com covers app.example.com.
	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex: "example.com",
	}); err != nil {
		t.Fatalf("seed managed domain: %v", err)
	}
	// TLS route, covered by the wildcard, NOT opting into a dedicated
	// cert → served by the wildcard, its per-host cert is orphaned.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:             "app.example.com",
		Upstreams:        []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:         storage.LBPolicyRoundRobin,
		TLSEnabled:       true,
		UseDedicatedCert: false,
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/app.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (wildcard-covered route must not block deletion of its orphaned per-host cert)", rec.Code, rec.Body)
	}
}

// Guard the inverse of the wildcard case: a TLS route covered by a
// wildcard but which OPTED INTO a dedicated cert (UseDedicatedCert) DOES
// emit its own subject, so it must still block.
func TestDeleteCertificate_WildcardCovered_ButDedicated_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex: "example.com",
	}); err != nil {
		t.Fatalf("seed managed domain: %v", err)
	}
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:             "ded.example.com",
		Upstreams:        []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:         storage.LBPolicyRoundRobin,
		TLSEnabled:       true,
		UseDedicatedCert: true, // opts out of wildcard → emits own subject
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/ded.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (dedicated-cert route still emits its own subject)", rec.Code, rec.Body)
	}
}

// v2.18.2 review finding — the forward-auth fail-closed deny path
// (manager.go) emits a per-host cert subject UNCONDITIONALLY (no
// managed-domain coverage skip) when a forward_auth route references an
// UNKNOWN provider. routeEmitsCertSubject must mirror that: such a route
// blocks deletion even when wildcard-covered, so an in-use deny-path cert
// is never freed. (Reachable only via corrupted route state — the API
// enforces provider existence — but the mirror must stay exact.)
func TestDeleteCertificate_ForwardAuthMissingProvider_WildcardCovered_409(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir())
	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex: "example.com",
	}); err != nil {
		t.Fatalf("seed managed domain: %v", err)
	}
	// forward_auth route referencing a provider that does NOT exist,
	// covered by the wildcard, NOT opting into a dedicated cert. On the
	// emission side this hits the deny path → emits its own subject.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:             "fa.example.com",
		Upstreams:        []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:         storage.LBPolicyRoundRobin,
		TLSEnabled:       true,
		UseDedicatedCert: false,
		AuthMode:         storage.RouteAuthForwardAuth,
		ForwardAuth:      storage.ForwardAuthRouteConfig{ProviderName: "ghost-provider"},
	}); err != nil {
		t.Fatalf("seed route: %v", err)
	}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/fa.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (forward-auth deny path emits its subject unconditionally)", rec.Code, rec.Body)
	}
}

func TestDeleteCertificate_GhostRow_Idempotent_200(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir()) // empty — no files
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/ghost.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (idempotent ghost row)", rec.Code, rec.Body)
	}
}

func TestDeleteCertificate_Wildcard_Routes(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	seedCertOnDisk(t, storageDir, "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")
	// URL-encode the wildcard subject the way the frontend will.
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/"+url.PathEscape("*.darro.ovh"), nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 for wildcard", rec.Code, rec.Body)
	}
	if _, err := os.Stat(filepath.Join(storageDir, "certificates", "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")); !os.IsNotExist(err) {
		t.Error("wildcard cert dir still present")
	}
}

// TestDeleteCertificate_BlockedByManagedDomainWildcard_409 pins the
// final-review bug fix: a live managed domain (Apex="darro.ovh")
// emits the cert subject "*.darro.ovh" unconditionally (via
// buildAutomateList), so deleting that exact wildcard cert while the
// managed domain still exists must be blocked with 409 — otherwise
// Caddy just re-issues it on the next reload (cert churn).
// IsHostCoveredByManagedDomain alone does NOT catch this: it bails on
// any "*."-prefixed host, so this test exercises the new
// managed-domain-subject check added in deleteCertificate.
func TestDeleteCertificate_BlockedByManagedDomainWildcard_409(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)

	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex:        "darro.ovh",
		IncludeApex: true,
	}); err != nil {
		t.Fatalf("seed managed domain: %v", err)
	}
	leaf := seedCertOnDisk(t, storageDir, "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/"+url.PathEscape("*.darro.ovh"), nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (live managed domain still emits this wildcard)", rec.Code, rec.Body)
	}
	var resp struct {
		BlockingRoutes []string `json:"blockingRoutes"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.BlockingRoutes) == 0 {
		t.Error("blockingRoutes empty; want it to name the managed domain")
	}
	if _, err := os.Stat(leaf); os.IsNotExist(err) {
		t.Error("wildcard cert dir was deleted; want it left on disk since delete was blocked")
	}
}

// TestDeleteCertificate_BlockedByManagedDomainApex_409 covers the
// bare-apex half of the same fix: a managed domain with
// IncludeApex=true also emits a cert covering the bare apex itself
// (e.g. "darro.ovh", not just "*.darro.ovh"). Deleting that apex cert
// while the managed domain is live must also be blocked with 409.
func TestDeleteCertificate_BlockedByManagedDomainApex_409(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)

	if err := env.store.PutManagedDomain(context.Background(), storage.ManagedDomain{
		Apex:        "darro.ovh",
		IncludeApex: true,
	}); err != nil {
		t.Fatalf("seed managed domain: %v", err)
	}
	seedCertOnDisk(t, storageDir, "acme-v02.api.letsencrypt.org-directory", "darro.ovh")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/darro.ovh", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s; want 409 (live managed domain with IncludeApex still emits this apex cert)", rec.Code, rec.Body)
	}
}

// --- Gap 1: tracker purge assertions ---------------------------------------

// TestDeleteCertificate_Orphan_PurgesTracker pins that the DELETE
// handler calls h.certInfo.Remove(domain) for an orphan cert that
// has on-disk material. Without wiring a certInfo reader (via
// SetCertInfoReader) this branch of deleteCertificate was never
// exercised by any test — this closes that gap using the same
// stubCertInfoPurger pattern as managed_domain_test.go.
func TestDeleteCertificate_Orphan_PurgesTracker(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	seedCertOnDisk(t, storageDir, "local", "orphan.example.com")

	purger := &stubCertInfoPurger{}
	env.handler.SetCertInfoReader(purger)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/orphan.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}
	if len(purger.removed) != 1 || purger.removed[0] != "orphan.example.com" {
		t.Fatalf("tracker not purged: removed=%v want=[orphan.example.com]", purger.removed)
	}
}

// TestDeleteCertificate_GhostRow_PurgesTracker strengthens the
// existing ghost-row idempotency test: a "ghost" tracker entry (no
// files on disk) is exactly the case that distinguishes a no-op
// from real behavior — the handler must still call Remove so a
// stale /certs row doesn't linger forever. Previously only the
// HTTP 200 was asserted; this pins the purge call too.
func TestDeleteCertificate_GhostRow_PurgesTracker(t *testing.T) {
	env := newTestEnv(t, false)
	env.handler.SetCertStorageDir(t.TempDir()) // empty — no files

	purger := &stubCertInfoPurger{}
	env.handler.SetCertInfoReader(purger)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/ghost.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 (idempotent ghost row)", rec.Code, rec.Body)
	}
	if len(purger.removed) != 1 || purger.removed[0] != "ghost.example.com" {
		t.Fatalf("ghost tracker row not purged: removed=%v want=[ghost.example.com]", purger.removed)
	}
}

// --- Gap 2: DeleteCertFiles error -> 500 -----------------------------------

// TestDeleteCertificate_DeleteFilesError_500 forces
// certinfo.DeleteCertFiles to return a non-ErrNotExist error by
// making the "certificates" child of the storage dir a regular file
// instead of a directory: os.ReadDir(certsDir) then fails with
// ENOTDIR, which is NOT errors.Is(err, fs.ErrNotExist), so
// DeleteCertFiles returns a real error (see
// internal/certinfo/delete.go lines 50-56). This proves the
// handler's `if derr != nil { writeError(...500...) }` branch is
// reachable and doesn't silently swallow the error into a 200.
func TestDeleteCertificate_DeleteFilesError_500(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	// Create a FILE named "certificates" where DeleteCertFiles
	// expects a directory — os.ReadDir on it fails with ENOTDIR.
	if err := os.WriteFile(filepath.Join(storageDir, "certificates"), []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("seed bogus certificates file: %v", err)
	}
	env.handler.SetCertStorageDir(storageDir)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/broken.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s; want 500 when DeleteCertFiles errors", rec.Code, rec.Body)
	}
}

// --- Gap 3: reload failure is non-fatal -------------------------------------

// TestDeleteCertificate_ReloadFails_StillReturns200 pins that a
// Caddy reload error after a successful delete is logged, not
// fatal: the files and tracker entry are already gone, so the
// handler must still respond 200. Uses the fakeReloader.SetNextErr
// harness from handler_test.go (also exercised in
// managed_domain_test.go's reload-failure tests).
func TestDeleteCertificate_ReloadFails_StillReturns200(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	leaf := seedCertOnDisk(t, storageDir, "local", "reload-fail.example.com")

	env.caddy.SetNextErr(errors.New("simulated reload failure"))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/reload-fail.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200 even though reload failed", rec.Code, rec.Body)
	}
	if _, err := os.Stat(leaf); !os.IsNotExist(err) {
		t.Error("cert dir still on disk after delete despite reload failure")
	}
}

// --- Gap 4: audit event assertion ------------------------------------------

// TestDeleteCertificate_EmitsAuditEvent pins that a successful
// delete appends an audit.ActionCertDeleted event with the deleted
// domain as TargetID (audit.Event.TargetID, see
// internal/audit/types.go), using the env.audit.Events() accessor
// already exercised by sibling tests (e.g.
// TestAudit_BasicAuthHashNeverInAuditLog in handler_test.go).
func TestDeleteCertificate_EmitsAuditEvent(t *testing.T) {
	env := newTestEnv(t, false)
	storageDir := t.TempDir()
	env.handler.SetCertStorageDir(storageDir)
	seedCertOnDisk(t, storageDir, "local", "audited.example.com")

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/certificates/audited.example.com", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s; want 200", rec.Code, rec.Body)
	}

	var got *audit.Event
	for _, e := range env.audit.Events() {
		if e.Action == audit.ActionCertDeleted {
			evt := e
			got = &evt
			break
		}
	}
	if got == nil {
		t.Fatal("no cert_deleted audit event found")
	}
	if got.TargetID != "audited.example.com" {
		t.Errorf("TargetID=%q; want %q", got.TargetID, "audited.example.com")
	}
	if got.TargetType != "certificate" {
		t.Errorf("TargetType=%q; want %q", got.TargetType, "certificate")
	}
}
