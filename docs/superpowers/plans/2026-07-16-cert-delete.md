# Certificate Deletion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator permanently delete an orphan certificate (any type) from the `/certs` page via `DELETE /api/v1/certificates/{domain}`, removing on-disk material across all issuers and clearing the list entry.

**Architecture:** A new storage-layer helper deletes the certmagic cert directories for a domain across every issuer. A new admin-gated API handler enforces an orphans-only rule (409 with blocking routes otherwise, reusing the existing managed-domain coverage matcher), deletes the files, purges the in-memory tracker, and triggers Arenet's normal reload (which auto-evicts the cert from Caddy's memory cache). The `/certs` frontend gains a delete action with a confirm dialog and a blocked dialog rendered from the 409.

**Tech Stack:** Go 1.25 (stdlib `os`/`filepath`, chi router, `certmagic.StorageKeys`), SvelteKit 5, vitest, i18n JSON bundles.

## Global Constraints

- **AGPL header** on every new Go and TS file (see CLAUDE.md; `//` comment block).
- **Target version v2.16.0** (feature = minor bump).
- **Orphans only:** a cert is deletable ONLY if no route (host or alias), no disabled route, and no managed-domain (exact or wildcard-apex coverage) references its domain. Otherwise **409** with `blockingRoutes`.
- **All issuers:** delete `certificates/*/<domainSafe>/` across every issuer dir.
- **Local only:** no ACME revocation.
- **Idempotent:** files already absent → still purge tracker, return 200.
- **Backend is the authoritative orphan check.** The frontend does not duplicate it.
- **Reuse, don't hand-roll:** `certmagic.StorageKeys.Safe` for the domain-dir name; `caddymgr.IsHostCoveredByManagedDomain` for wildcard coverage; `certinfo` scan structure for the disk walk; the existing `CertInfoReader.Remove` for the tracker purge.
- **Empirically verified** (2026-07-16): cert storage root = `caddy.AppDataDir()` (main.go:453); matcher = `IsHostCoveredByManagedDomain(host string, mds []storage.ManagedDomain) (storage.ManagedDomain, bool)` (caddymgr/managed_domain.go:63); Caddy in-place reload auto-evicts no-longer-managed certs (caddytls/tls.go:478-553); DELETE route site = the RequireAdmin subgroup (routes.go:333-339).

---

### Task 1: Storage helper `DeleteCertFiles`

**Files:**
- Create: `internal/certinfo/delete.go`
- Test: `internal/certinfo/delete_test.go`

**Interfaces:**
- Consumes: `certmagic.StorageKeys.Safe(domain string) string` (github.com/caddyserver/certmagic, exported at storage.go:354/269).
- Produces: `func DeleteCertFiles(storageDir, domain string) (deleted int, err error)` — removes `<storageDir>/certificates/<issuer>/<safeDomain>/` for every issuer dir; returns count of issuer-dirs removed; idempotent (0, nil) when nothing matches.

- [ ] **Step 1: Write the failing test**

```go
// internal/certinfo/delete_test.go
package certinfo

import (
	"os"
	"path/filepath"
	"testing"
)

// buildCertTree fabricates a certmagic-shaped storage dir with the
// given (issuer, safeDomain) leaf dirs each holding a .crt/.key/.json.
func buildCertTree(t *testing.T, leaves map[string][]string) string {
	t.Helper()
	root := t.TempDir()
	for issuer, domains := range leaves {
		for _, d := range domains {
			dir := filepath.Join(root, "certificates", issuer, d)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir %s: %v", dir, err)
			}
			for _, ext := range []string{".crt", ".key", ".json"} {
				if err := os.WriteFile(filepath.Join(dir, d+ext), []byte("x"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
		}
	}
	return root
}

func TestDeleteCertFiles_RemovesAcrossIssuers(t *testing.T) {
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"darro.ovh"},
		"local":                                  {"darro.ovh"},
	})
	n, err := DeleteCertFiles(root, "darro.ovh")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d; want 2 (both issuers)", n)
	}
	for _, issuer := range []string{"acme-v02.api.letsencrypt.org-directory", "local"} {
		if _, err := os.Stat(filepath.Join(root, "certificates", issuer, "darro.ovh")); !os.IsNotExist(err) {
			t.Errorf("issuer %s domain dir still present", issuer)
		}
	}
}

func TestDeleteCertFiles_Wildcard(t *testing.T) {
	// *.darro.ovh is stored under the certmagic-safe name
	// "wildcard_.darro.ovh".
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"wildcard_.darro.ovh"},
	})
	n, err := DeleteCertFiles(root, "*.darro.ovh")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 1 {
		t.Errorf("deleted = %d; want 1 (wildcard)", n)
	}
	if _, err := os.Stat(filepath.Join(root, "certificates", "acme-v02.api.letsencrypt.org-directory", "wildcard_.darro.ovh")); !os.IsNotExist(err) {
		t.Error("wildcard dir still present")
	}
}

func TestDeleteCertFiles_Idempotent_Absent(t *testing.T) {
	root := buildCertTree(t, map[string][]string{
		"acme-v02.api.letsencrypt.org-directory": {"other.example.com"},
	})
	n, err := DeleteCertFiles(root, "notpresent.example.com")
	if err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	if n != 0 {
		t.Errorf("deleted = %d; want 0 (absent domain)", n)
	}
	// The unrelated domain is untouched.
	if _, err := os.Stat(filepath.Join(root, "certificates", "acme-v02.api.letsencrypt.org-directory", "other.example.com")); err != nil {
		t.Errorf("unrelated domain dir removed: %v", err)
	}
}

func TestDeleteCertFiles_NeverTouchesPKIorLocks(t *testing.T) {
	root := buildCertTree(t, map[string][]string{"local": {"darro.ovh"}})
	// Fabricate sibling pki/ and locks/ dirs that must survive.
	for _, sib := range []string{"pki", "locks"} {
		if err := os.MkdirAll(filepath.Join(root, sib), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", sib, err)
		}
	}
	if _, err := DeleteCertFiles(root, "darro.ovh"); err != nil {
		t.Fatalf("DeleteCertFiles: %v", err)
	}
	for _, sib := range []string{"pki", "locks"} {
		if _, err := os.Stat(filepath.Join(root, sib)); err != nil {
			t.Errorf("sibling %s removed: %v", sib, err)
		}
	}
}

func TestDeleteCertFiles_EmptyArgs(t *testing.T) {
	if _, err := DeleteCertFiles("", "darro.ovh"); err == nil {
		t.Error("want error for empty storageDir")
	}
	if _, err := DeleteCertFiles(t.TempDir(), ""); err == nil {
		t.Error("want error for empty domain")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/certinfo/ -run TestDeleteCertFiles -v`
Expected: FAIL — `undefined: DeleteCertFiles`.

- [ ] **Step 3: Write minimal implementation**

```go
// internal/certinfo/delete.go
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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/caddyserver/certmagic"
)

// DeleteCertFiles removes all on-disk certificate material for domain
// across every issuer directory under <storageDir>/certificates/.
// Returns the number of issuer directories from which the domain's
// cert directory was removed. Idempotent: a domain with no material
// on disk returns (0, nil).
//
// The per-domain directory name is derived with
// certmagic.StorageKeys.Safe so wildcard subjects map identically to
// how certmagic wrote them (e.g. "*.darro.ovh" -> "wildcard_.darro.ovh").
// Only the domain's own leaf directory is removed; sibling issuers,
// pki/, and locks/ are never touched.
func DeleteCertFiles(storageDir, domain string) (int, error) {
	if storageDir == "" {
		return 0, errors.New("certinfo.DeleteCertFiles: storageDir is empty")
	}
	if domain == "" {
		return 0, errors.New("certinfo.DeleteCertFiles: domain is empty")
	}
	safeDomain := certmagic.StorageKeys.Safe(domain)

	certsDir := filepath.Join(storageDir, "certificates")
	issuers, err := os.ReadDir(certsDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil // no certs at all — nothing to delete
		}
		return 0, fmt.Errorf("certinfo.DeleteCertFiles: read %s: %w", certsDir, err)
	}

	deleted := 0
	for _, issuerEntry := range issuers {
		if !issuerEntry.IsDir() {
			continue
		}
		domainDir := filepath.Join(certsDir, issuerEntry.Name(), safeDomain)
		if _, statErr := os.Stat(domainDir); statErr != nil {
			continue // this issuer has no dir for the domain
		}
		if rmErr := os.RemoveAll(domainDir); rmErr != nil {
			return deleted, fmt.Errorf("certinfo.DeleteCertFiles: remove %s: %w", domainDir, rmErr)
		}
		deleted++
	}
	return deleted, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/certinfo/ -run TestDeleteCertFiles -v`
Expected: PASS (all 5 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/certinfo/delete.go internal/certinfo/delete_test.go
git commit -m "feat(certinfo): DeleteCertFiles removes a domain's cert dirs across issuers"
```

---

### Task 2: Audit action `cert_deleted`

**Files:**
- Modify: `internal/audit/actions.go` (const block ~55, `allActions` ~244)
- Modify: `internal/audit/actions_test.go:28` (`wantCount` 58 → 59)

**Interfaces:**
- Produces: `audit.ActionCertDeleted = "cert_deleted"`.

- [ ] **Step 1: Update the count test to fail first**

In `internal/audit/actions_test.go`, change `const wantCount = 58` to `const wantCount = 59` and append `+ cert-delete=1)` to the drift message string.

- [ ] **Step 2: Run test to verify it fails**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -run TestAllActions -v`
Expected: FAIL — `AllActions count drift: got 58, want 59` (and the ExactSet test fails on the missing action).

- [ ] **Step 3: Add the action constant + register it**

In `internal/audit/actions.go`, after `ActionRouteEnabled = "route_enabled"` (line ~56):
```go
	ActionCertDeleted = "cert_deleted"
```
And in `allActions` (after `ActionRouteEnabled,` ~line 257):
```go
	ActionCertDeleted,
```
If `TestAllActions_ExactSet` enumerates the expected set, add `ActionCertDeleted` there too.

- [ ] **Step 4: Run test to verify it passes**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/audit/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/actions.go internal/audit/actions_test.go
git commit -m "feat(audit): add cert_deleted action (58->59)"
```

---

### Task 3: Extend the CertInfoReader seam to expose the storage dir

**Files:**
- Modify: `internal/api/handler.go` (CertInfoReader interface ~526; `SetCertInfoReader` ~805; new `certStorageDir` field on Handler ~371)
- Modify: `cmd/arenet/main.go:1426` (pass the storage dir when wiring)
- Test: covered by Task 4's handler tests (this task is a wiring change with no standalone behavior).

**Interfaces:**
- Produces: `Handler.certStorageDir string` (set at wiring), and a setter `Handler.SetCertStorageDir(dir string)`. The delete handler (Task 4) reads `h.certStorageDir` to call `certinfo.DeleteCertFiles`.
- Consumes: `caddy.AppDataDir()` (already computed as `certStorageDir` in main.go:453).

- [ ] **Step 1: Add the field + setter (no test — pure wiring, exercised by Task 4)**

In `internal/api/handler.go`, add to the `Handler` struct (near the `certInfo CertInfoReader` field ~371):
```go
	// certStorageDir is the certmagic storage root
	// (caddy.AppDataDir()); the cert-delete handler needs it to
	// remove on-disk cert material. Empty until SetCertStorageDir.
	certStorageDir string
```
Add the setter near `SetCertInfoReader` (~805):
```go
// SetCertStorageDir attaches the certmagic storage root so the
// cert-delete handler can remove on-disk material. Wired once at
// boot from main.go's certStorageDir (caddy.AppDataDir()).
func (h *Handler) SetCertStorageDir(dir string) {
	h.certStorageDir = dir
}
```

- [ ] **Step 2: Wire it in main.go**

In `cmd/arenet/main.go`, right after `apiHandler.SetCertInfoReader(certTracker)` (line 1426):
```go
	apiHandler.SetCertStorageDir(certStorageDir)
```
(`certStorageDir` is already in scope from line 453.)

- [ ] **Step 3: Build to verify it compiles**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go build ./...`
Expected: builds clean.

- [ ] **Step 4: Commit**

```bash
git add internal/api/handler.go cmd/arenet/main.go
git commit -m "feat(api): wire certStorageDir into the API handler for cert deletion"
```

---

### Task 4: `deleteCertificate` API handler + route

**Files:**
- Create: `internal/api/certificates_delete.go`
- Modify: `internal/api/routes.go:339` (register `r.Delete("/certificates/{domain}", h.deleteCertificate)` in the RequireAdmin subgroup)
- Test: `internal/api/certificates_delete_test.go`

**Interfaces:**
- Consumes: `certinfo.DeleteCertFiles(storageDir, domain string) (int, error)` (Task 1); `audit.ActionCertDeleted` (Task 2); `h.certStorageDir` (Task 3); `h.certInfo.Remove(domain)` (existing); `caddymgr.IsHostCoveredByManagedDomain(host string, mds []storage.ManagedDomain) (storage.ManagedDomain, bool)` (caddymgr/managed_domain.go:63); `h.store.ListRoutes(ctx)`, `h.store.ListManagedDomains(ctx)`; `h.reloadFromStore`/`ReloadFromStore` (the existing reload seam used by disableRoute — check `toggleRouteDisabled` for the exact call).
- Produces: `func (h *Handler) deleteCertificate(w http.ResponseWriter, r *http.Request)`.

**Note on the orphan check:** a domain is "referenced" (→ 409) if ANY of:
- a route's `Host` equals the domain (case-insensitive), OR
- a route's `Aliases` contains the domain, OR
- `IsHostCoveredByManagedDomain(domain, managedDomains)` returns covered==true.
Disabled routes are INCLUDED in the scan (a disabled route still references the domain — orphan means no config references it at all). The response lists the blocking route hosts.

- [ ] **Step 1: Write the failing tests**

```go
// internal/api/certificates_delete_test.go
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	// A route serves the domain -> not an orphan.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "used.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
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
	// A DISABLED route still references the domain -> blocked.
	if _, err := env.store.CreateRoute(context.Background(), storage.Route{
		Host:      "dis.example.com",
		Upstreams: []storage.Upstream{{URL: "http://u:1", Weight: 1}},
		LBPolicy:  storage.LBPolicyRoundRobin,
		Disabled:  true,
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestDeleteCertificate -v`
Expected: FAIL — route not registered (404) / `h.deleteCertificate` undefined. NOTE: if `env.handler` is not the field name on the test env, adapt to the actual field (check `newTestEnv` in `handler_test.go`); the reviewer flagged in route-disable that the env exposes `env.handler`/`env.store`/`env.router` — confirm names before writing.

- [ ] **Step 3: Write the handler**

```go
// internal/api/certificates_delete.go
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
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/caddymgr"
	"github.com/barto95100/arenet/internal/certinfo"
)

// deleteCertificate removes an orphan certificate's on-disk material
// (across all issuers) and clears its /certs tracker entry. Orphans
// only: if any route (incl. disabled) or managed-domain still
// references the domain, it responds 409 with the blocking hosts.
// Idempotent: a domain with no files on disk still returns 200 after
// purging the tracker. No ACME revocation.
func (h *Handler) deleteCertificate(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSpace(chi.URLParam(r, "domain"))
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}

	// Orphan check (authoritative). Reference == route host/alias
	// equality (case-insensitive) OR managed-domain coverage.
	ctx := r.Context()
	routes, err := h.store.ListRoutes(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list routes: "+err.Error())
		return
	}
	mds, err := h.store.ListManagedDomains(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list managed domains: "+err.Error())
		return
	}

	var blocking []string
	target := strings.ToLower(domain)
	for _, rt := range routes {
		if strings.EqualFold(rt.Host, target) {
			blocking = append(blocking, rt.Host)
			continue
		}
		for _, a := range rt.Aliases {
			if strings.EqualFold(a, target) {
				blocking = append(blocking, rt.Host)
				break
			}
		}
	}
	if _, covered := caddymgr.IsHostCoveredByManagedDomain(domain, mds); covered {
		blocking = append(blocking, "*."+strings.TrimPrefix(target, "*."))
	}
	if len(blocking) > 0 {
		writeJSONWithHint(w, map[string]any{
			"error":          "certificate in use; delete or disable the referencing route(s) first",
			"blockingRoutes": blocking,
		}, true) // helper that sets 409 — see note in Step 3b
		return
	}

	// Delete on-disk material across all issuers (idempotent).
	deleted := 0
	if h.certStorageDir != "" {
		n, derr := certinfo.DeleteCertFiles(h.certStorageDir, domain)
		if derr != nil {
			writeError(w, http.StatusInternalServerError, "delete cert files: "+derr.Error())
			return
		}
		deleted = n
	}

	// Purge the /certs list entry (ghost or real).
	if h.certInfo != nil {
		h.certInfo.Remove(domain)
	}

	// Trigger the normal reload so Caddy's in-place reload evicts the
	// cert from its memory cache (auto for a now-unreferenced domain).
	// Best-effort: a reload error is logged, not fatal to the delete
	// (files are already gone). Mirror the reload call used by
	// toggleRouteDisabled.
	if rerr := h.reloadFromStore(ctx); rerr != nil {
		h.logger.Warn("cert delete: reload after delete failed", "domain", domain, "err", rerr)
	}

	h.appendAudit(ctx, r, audit.ActionCertDeleted, domain, nil)

	writeJSON(w, http.StatusOK, map[string]any{
		"domain":  domain,
		"deleted": deleted,
	})
}
```

**Step 3b (adapt to real helpers — MANDATORY before finalizing):** the exact names of `writeError`, `writeJSON`, `writeJSONWithHint`, `h.appendAudit`, `h.reloadFromStore`, and `h.logger` must match this package. Confirm each against `toggleRouteDisabled` (routes.go:1980) and `internal/api/errors.go`: use the SAME 409-writing helper and the SAME reload + audit calls `toggleRouteDisabled` uses. If there is no `writeJSONWithHint` that sets 409, write the 409 with the package's standard JSON-error writer at `http.StatusConflict` including the `blockingRoutes` array. Do NOT invent a helper.

- [ ] **Step 4: Register the route**

In `internal/api/routes.go`, in the RequireAdmin subgroup after line 339 (`r.Post("/routes/{id}/enable", h.enableRoute)`):
```go
				r.Delete("/certificates/{domain}", h.deleteCertificate)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET && go test ./internal/api/ -run TestDeleteCertificate -v`
Expected: PASS (4 tests).

- [ ] **Step 6: Verify wildcard URL encoding empirically (open item #1)**

Add one test that a wildcard domain routes correctly through chi. `*` is a valid path segment char, but confirm:
```go
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
```
Run it. If chi does NOT decode `%2A` back to `*` in the URLParam (so the orphan/delete keys on the wrong string), the handler must `url.PathUnescape(chi.URLParam(...))` first — add that and re-run. Record the empirical result in the progress ledger. (Add `"net/url"` to the test imports.)

- [ ] **Step 7: Commit**

```bash
git add internal/api/certificates_delete.go internal/api/certificates_delete_test.go internal/api/routes.go
git commit -m "feat(api): DELETE /certificates/{domain} — orphan-only cert deletion"
```

---

### Task 5: Frontend API client method

**Files:**
- Modify: `web/frontend/src/lib/api/certificates.ts` (add `deleteCertificate`)
- Modify: `web/frontend/src/lib/api/types.ts` if a response/error type is needed
- Test: `web/frontend/src/lib/api/certificates.test.ts` (create if absent, else extend)

**Interfaces:**
- Produces: `deleteCertificate(domain: string): Promise<{ domain: string; deleted: number }>` → `DELETE /certificates/${encodeURIComponent(domain)}`. On 409, throws an error carrying the parsed `{ error, blockingRoutes }` so the page can render the blocked dialog.

- [ ] **Step 1: Write the failing test**

```ts
// web/frontend/src/lib/api/certificates.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { certificatesApi } from './certificates';

describe('certificatesApi.deleteCertificate', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('DELETEs the URL-encoded domain and returns the result', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ domain: 'darro.ovh', deleted: 2 }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const res = await certificatesApi.deleteCertificate('*.darro.ovh');
    expect(res).toEqual({ domain: 'darro.ovh', deleted: 2 });
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain('/certificates/' + encodeURIComponent('*.darro.ovh'));
    expect(fetchMock.mock.calls[0][1].method).toBe('DELETE');
  });

  it('throws with blockingRoutes on 409', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ error: 'in use', blockingRoutes: ['a.example.com'] }),
    }));
    await expect(certificatesApi.deleteCertificate('a.example.com')).rejects.toMatchObject({
      status: 409,
      blockingRoutes: ['a.example.com'],
    });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/lib/api/certificates.test.ts`
Expected: FAIL — `deleteCertificate is not a function`.

- [ ] **Step 3: Implement the client method**

Open `web/frontend/src/lib/api/certificates.ts`. Follow the file's existing request pattern (it already has `list()` hitting `GET /certificates`). Add, using the SAME base-fetch/client helper the file already uses (do not introduce a new fetch style — mirror `list()`):
```ts
	async deleteCertificate(domain: string): Promise<{ domain: string; deleted: number }> {
		const res = await fetch(`${API_BASE}/certificates/${encodeURIComponent(domain)}`, {
			method: 'DELETE',
			credentials: 'include',
		});
		if (!res.ok) {
			const body = await res.json().catch(() => ({}));
			throw Object.assign(new Error(body.error ?? 'delete failed'), {
				status: res.status,
				blockingRoutes: body.blockingRoutes ?? [],
			});
		}
		return res.json();
	},
```
**Adapt `API_BASE`/fetch wrapper to whatever `list()` in this file uses** — if `list()` calls a shared `apiFetch`/`client` helper, use that instead of raw `fetch` so credentials/headers/error-translation stay consistent.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/lib/api/certificates.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/api/certificates.ts web/frontend/src/lib/api/types.ts web/frontend/src/lib/api/certificates.test.ts
git commit -m "feat(web): certificatesApi.deleteCertificate client method"
```

---

### Task 6: i18n keys (EN + FR)

**Files:**
- Modify: `web/frontend/src/lib/i18n/en.json`
- Modify: `web/frontend/src/lib/i18n/fr.json`
- Test: the existing i18n parity guard (`web/frontend/src/lib/i18n/index.test.ts` ~line 112) enforces EN/FR key-set equality; no new test file.

**Interfaces:**
- Produces keys (under the existing `certs` namespace — confirm the exact nesting used by the /certs page):
  `certs.delete.action`, `certs.delete.confirm.title`, `certs.delete.confirm.text`, `certs.delete.confirm.action`, `certs.delete.blocked.title`, `certs.delete.blocked.text`, `certs.delete.success`.

- [ ] **Step 1: Add EN keys**

In `web/frontend/src/lib/i18n/en.json`, under `certs` (match the existing structure — find the current `certs` object):
```json
"delete": {
  "action": "Delete certificate",
  "confirm": {
    "title": "Delete certificate",
    "text": "Permanently delete the certificate for {domain}? The .crt/.key/.json files will be removed from disk. This is irreversible.",
    "action": "Delete certificate"
  },
  "blocked": {
    "title": "Cannot delete",
    "text": "The certificate for {domain} is in use by: {routes}. Delete or disable those route(s) first."
  },
  "success": "Certificate for {domain} deleted"
}
```

- [ ] **Step 2: Add FR keys (mirror structure exactly)**

In `web/frontend/src/lib/i18n/fr.json`:
```json
"delete": {
  "action": "Supprimer le certificat",
  "confirm": {
    "title": "Supprimer le certificat",
    "text": "Supprimer définitivement le certificat de {domain} ? Les fichiers .crt/.key/.json seront supprimés du disque. Cette action est irréversible.",
    "action": "Supprimer le certificat"
  },
  "blocked": {
    "title": "Suppression impossible",
    "text": "Le certificat de {domain} est utilisé par : {routes}. Supprime ou désactive d'abord ces route(s)."
  },
  "success": "Certificat de {domain} supprimé"
}
```

- [ ] **Step 3: Run the parity guard**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/lib/i18n/index.test.ts`
Expected: PASS (EN and FR key sets equal). If it fails on a missing/extra key, reconcile the two files.

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/lib/i18n/en.json web/frontend/src/lib/i18n/fr.json
git commit -m "feat(web): i18n keys for certificate deletion (EN+FR)"
```

---

### Task 7: /certs page delete action + dialogs

**Files:**
- Modify: `web/frontend/src/routes/certs/+page.svelte`
- Test: `web/frontend/src/routes/certs/page.test.ts` (create if absent; else extend)

**Interfaces:**
- Consumes: `certificatesApi.deleteCertificate` (Task 5), the i18n keys (Task 6), the existing Modal/ConfirmDialog component the page already uses for `confirmDeleteManagedDomain`.
- Produces: a per-row Delete button that opens a confirm dialog; on confirm calls `deleteCertificate`; on 200 refreshes the list + success toast; on 409 opens the blocked dialog listing `blockingRoutes`.

- [ ] **Step 1: Write the failing component test**

```ts
// web/frontend/src/routes/certs/page.test.ts
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte';
import Page from './+page.svelte';
import { certificatesApi } from '$lib/api/certificates';

describe('/certs delete action', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('deletes an orphan cert then refreshes', async () => {
    vi.spyOn(certificatesApi, 'list').mockResolvedValue([
      { domain: 'orphan.example.com', /* minimal shape the page needs */ } as any,
    ]);
    const del = vi.spyOn(certificatesApi, 'deleteCertificate').mockResolvedValue({ domain: 'orphan.example.com', deleted: 1 });

    render(Page);
    // open the row's delete action, confirm in the dialog
    await fireEvent.click(await screen.findByTestId('cert-delete-orphan.example.com'));
    await fireEvent.click(await screen.findByTestId('cert-delete-confirm'));

    expect(del).toHaveBeenCalledWith('orphan.example.com');
  });

  it('shows the blocked dialog on 409', async () => {
    vi.spyOn(certificatesApi, 'list').mockResolvedValue([
      { domain: 'used.example.com' } as any,
    ]);
    vi.spyOn(certificatesApi, 'deleteCertificate').mockRejectedValue(
      Object.assign(new Error('in use'), { status: 409, blockingRoutes: ['used.example.com'] }),
    );

    render(Page);
    await fireEvent.click(await screen.findByTestId('cert-delete-used.example.com'));
    await fireEvent.click(await screen.findByTestId('cert-delete-confirm'));

    expect(await screen.findByText(/used\.example\.com/)).toBeInTheDocument();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/routes/certs/page.test.ts`
Expected: FAIL — no delete button / testids.

- [ ] **Step 3: Implement the UI**

In `web/frontend/src/routes/certs/+page.svelte` (Svelte 5 runes; mirror the existing `confirmDeleteManagedDomain` dialog pattern already in this file):
- Add per-row a Delete button with `data-testid={`cert-delete-${cert.domain}`}` and `aria-label={t('certs.delete.action')}`.
- Add reactive state: `let deleteTarget = $state<string | null>(null); let blockedDialog = $state<{ domain: string; routes: string[] } | null>(null);`.
- Clicking the button sets `deleteTarget = cert.domain` (opens the confirm dialog). The confirm dialog reuses the same Modal component as the managed-domain delete, with a confirm button `data-testid="cert-delete-confirm"`.
- On confirm:
```ts
async function doDeleteCert(domain: string) {
  try {
    await certificatesApi.deleteCertificate(domain);
    toast.success(t('certs.delete.success', { domain }));
    deleteTarget = null;
    await reloadCerts(); // the page's existing list-refresh fn
  } catch (e: any) {
    deleteTarget = null;
    if (e?.status === 409) {
      blockedDialog = { domain, routes: e.blockingRoutes ?? [] };
    } else {
      toast.error(e?.message ?? 'delete failed');
    }
  }
}
```
- Render the blocked dialog (variant B) from `blockedDialog`, showing `t('certs.delete.blocked.text', { domain, routes: blockedDialog.routes.join(', ') })` with a single "Got it" button that clears it.
- Confirm the exact toast + Modal + reload-fn names against what the file already imports/uses; do NOT introduce new components.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npx vitest run src/routes/certs/page.test.ts`
Expected: PASS.

- [ ] **Step 5: Build the frontend**

Run: `cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend && npm run build`
Expected: builds clean (TS strict).

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/routes/certs/+page.svelte web/frontend/src/routes/certs/page.test.ts
git commit -m "feat(web): delete action + confirm/blocked dialogs on the /certs page"
```

---

### Task 8: Smoke (verification-only, no commit)

**Files:** none (gates only).

- [ ] **Step 1: Backend gates**

Run:
```
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH && cd /Users/l.ramos/Documents/Projets/AreNET
go vet ./...
go build ./...
go test -race ./internal/certinfo/ ./internal/api/ ./internal/audit/
```
Expected: all clean/green. (If internal/api -race is slow, it may be left to CI's longer budget — note it in the ledger.)

- [ ] **Step 2: Frontend gates**

Run:
```
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npx vitest run src/lib/api/certificates.test.ts src/lib/i18n/index.test.ts src/routes/certs/page.test.ts
npm run build
```
Expected: all pass, build clean.

- [ ] **Step 3: Functional gate — the empirical open items**

Confirm in the ledger the resolved answers to the 4 open items:
1. Wildcard URL encoding (Task 4 Step 6) — record whether `url.PathUnescape` was needed.
2. certStorageDir injection (Task 3) — wired from main.go:453.
3. Orphan matcher — reused `caddymgr.IsHostCoveredByManagedDomain` (no hand-rolled matcher).
4. Reload no-op on ghost row — Task 4 test `TestDeleteCertificate_GhostRow_Idempotent_200` proves the 200 path; note whether the reload was a no-op (tracker purge alone cleared the row).

---

## Self-Review

**1. Spec coverage:** endpoint (Task 4) ✓; orphans-only incl. wildcard + disabled (Task 4 tests) ✓; all-issuers delete (Task 1) ✓; idempotent 200 (Task 4) ✓; local-only/no-revoke (nothing calls revoke — by omission) ✓; backend-authoritative check (Task 4, frontend just renders 409) ✓; audit cert_deleted (Task 2) ✓; UI confirm + blocked dialogs (Task 7) ✓; i18n EN/FR (Task 6) ✓; auto memory eviction via reload (Task 4 reload call, spec §4) ✓.

**2. Placeholder scan:** the handler (Task 4 Step 3) carries an explicit "adapt to real helper names" instruction (Step 3b) rather than inventing `writeJSONWithHint`/`reloadFromStore`/`appendAudit` — these are real-but-unverified names; the implementer MUST confirm them against `toggleRouteDisabled`. This is intentional scaffolding, not a placeholder, and is called out as a hard step. Frontend Tasks 5/7 similarly instruct mirroring the file's existing fetch/Modal/toast rather than assuming names.

**3. Type consistency:** `DeleteCertFiles(storageDir, domain) (int, error)` used identically in Task 1 (def) and Task 4 (call). `deleteCertificate` client returns `{domain, deleted}` in Tasks 5 and 7. `blockingRoutes` string[] consistent across Task 4 (Go response), Task 5 (client error), Task 7 (dialog).

**Known adaptation points (flagged for implementers, not gaps):** exact API helper names (`writeError`/`writeJSON`/409-writer/`appendAudit`/`reloadFromStore`/`logger`) and the test-env field names (`env.handler`/`env.store`/`env.router`) must be confirmed against the live package before finalizing each Go task — the route-disable work established these exist but the reviewer must verify names, not assume.
