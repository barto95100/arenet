# Certificate Deletion — Design Spec

**Date:** 2026-07-16
**Target version:** v2.16.0 (feature → minor bump)
**Status:** approved design, ready for implementation plan

## Goal

Let an operator permanently delete a certificate they no longer need from the Certificates (`/certs`) page — for any cert type (HTTP-01, DNS-01 wildcard, internal self-signed). Deletion removes the on-disk cert material AND clears the `/certs` list entry. Today no such capability exists: the wildcard/apex "delete" button only removes the *managed-domain config* and leaves the cert files orphaned on disk; a plain HTTP-01 route cert has no delete affordance at all.

## Locked decisions

1. **One "Delete certificate" button** per `/certs` row, visible on **all** certs (ACME, wildcard, internal). Deletes the on-disk files AND removes the domain from Arenet's emitted config path (via the orphan rule below, the domain is already unreferenced, so there's nothing to remove from routes — the delete is disk + tracker + reload).
2. **Orphans only.** A cert is deletable ONLY if **no route (host or alias) and no managed-domain** references its domain. Otherwise the API returns **409 Conflict** naming the blocking route(s); the operator must delete/disable those first. This strict definition sidesteps the internal-CA catch-all re-issue trap (a still-served domain would get a fresh self-signed cert instead of being evicted).
   - **"References" includes wildcard coverage.** A cert for `sub.darro.ovh` is considered referenced (→ blocked) if an active managed-domain `*.darro.ovh` (or a route whose host/alias is `*.darro.ovh`) covers it — because deleting it while the wildcard is live would just trigger re-issuance. The orphan check matches both exact domain equality AND wildcard-apex coverage.
   - **A disabled route still counts as a reference (→ blocked).** Per decision: orphan = "no route NOR managed-domain references the domain", and a `disabled=true` route still *references* the domain (its config is preserved and it can be re-enabled). Blocking is conservative: the operator disables-then-deletes-the-route if they truly want the cert gone. (This is the strict reading chosen in brainstorming Q5 — "aucune route NI managed-domain", not "aucune route active".)
3. **Local only.** Delete the disk files + evict from Caddy's in-memory cache (automatic, see §4) + purge the tracker. **No ACME revocation** (backlog v2).
4. **Dedicated endpoint** `DELETE /api/v1/certificates/{domain}` (admin-gated).
5. **All issuers of the domain** are removed: `certificates/*/<domain-safe>/` across every issuer dir (a domain may have both `acme-v02…` and `local` self-signed material).
6. **Idempotent:** deleting a cert whose files are already gone (e.g. a ghost `/certs` row) returns **200**, still purges the tracker.
7. **Backend is the source of truth** for the orphan check. The frontend does NOT duplicate the orphan logic; it attempts the DELETE and renders the blocked dialog from the 409 response.

## Architecture

### Cert storage layout (verified — certmagic v0.25.3)

Certs live at `<certStorageRoot>/certificates/<issuerSafe>/<domainSafe>/<domainSafe>.{crt,key,json}`.
- `<certStorageRoot>` = `caddy.AppDataDir()` = `$HOME/.local/share/caddy` (Docker: `HOME=/var/lib/arenet`). Already resolved and used by `internal/certinfo` (`listener.go:294`, `reconcile.go:70`).
- `<domainSafe>` = `certmagic.StorageKeys.Safe(domain)` — lowercases, and maps `*` → `wildcard_`. So `*.darro.ovh` → `wildcard_.darro.ovh`. **Reuse the exported `certmagic.StorageKeys` helpers — do NOT hand-roll the transform** (verified exported at certmagic `storage.go:269`).

### The eviction reality (verified — supersedes an earlier assumption)

Arenet reloads via `caddy.Load(cfgJSON, false)` — an **in-place graceful reload**, not stop+start (`internal/caddymgr/manager.go:862`). On reload, the NEW TLS app starts and populates its `managing` set; then the OLD TLS app's `Cleanup()` (`caddytls/tls.go:478-553`) diffs old-vs-new managed subjects and calls `certCache.RemoveManaged(noLongerManaged)` / `Remove(noLongerLoaded)` on the singleton cache (`certmagic/cache.go:411,429`). **So a cert whose domain is no longer referenced by any route is auto-evicted from memory on the next reload — no explicit eviction call needed.** Because we only delete orphans (§decision 2), the domain is absent from the new config's `managing` set, so eviction fires correctly. (If we allowed deleting a still-served domain, the internal catch-all policy `manager.go:2257` would keep it "managed" under the `local` issuer and it would NOT evict — hence orphans-only.)

### Delete flow (`deleteCertificate` handler)

1. Extract + normalize `{domain}` from the URL (`chi.URLParam`). Wildcard encoding: the frontend must URL-encode `*.darro.ovh`; the handler decodes and normalizes. **Plan must verify the exact encode/decode roundtrip empirically** (chi path param + `*`).
2. **Orphan check** (backend, authoritative): scan `store.ListRoutes()` for any `Host == domain`, any `alias == domain`, and any managed-domain whose apex/wildcard covers `domain`. If any match → **409** with body `{"error": "...", "blockingRoutes": ["arenet.darro.ovh", ...]}`.
3. **Delete disk files across all issuers**: new storage/certinfo helper `DeleteCertFiles(certStorageRoot, domain) (deleted int, err error)` — reuses `internal/certinfo`'s path logic (`reconcile.go:70,97,129`): compute `domainSafe`, glob `certificates/*/`, and `os.RemoveAll(<issuerDir>/<domainSafe>)` where present. Idempotent (0 deleted = fine).
4. **Purge the tracker entry**: `certInfo.Remove(domain)` (existing, `tracker.go:352`).
5. **Reload**: `ReloadFromStore` → `applyLocked` → `caddy.Load`. Auto-eviction (§4) clears the memory cache. (Reload runs even when 0 files were deleted, so a ghost row is cleared consistently — but note `caddy.Load` no-ops if the config hash is unchanged, `manager.go:823`; the tracker purge in step 4 is what clears the `/certs` row in the 0-files case.)
6. **Audit**: new action `cert_deleted`, target = domain, message includes issuer-dir count deleted.
7. **Response**: `200 {"domain": "...", "deleted": <count>}`.

### Error cases

| Case | Response |
|---|---|
| Domain referenced by route/alias/managed-domain | **409** `{error, blockingRoutes:[...]}` |
| Files already absent (ghost row) | **200** `{domain, deleted:0}` — still purge tracker (idempotent, decision 6) |
| `os.RemoveAll` fails (perms) | **500** `{error}` — log which issuer-dir failed; partial deletion possible, logged |
| Non-admin caller | **403** (RequireAdmin middleware) |

## Storage layer (net-new)

New function (location: `internal/certinfo/` alongside `reconcile.go`, reusing its path helpers):

```go
// DeleteCertFiles removes all on-disk cert material for domain across
// every issuer directory under <storageDir>/certificates/. Returns the
// number of issuer-dirs from which the domain's cert dir was removed.
// Idempotent: a domain with no material returns (0, nil). Uses
// certmagic.StorageKeys.Safe for the domain-dir name so wildcards map
// identically to how certmagic wrote them.
func DeleteCertFiles(storageDir, domain string) (int, error)
```

- Glob `filepath.Join(storageDir, "certificates", "*")` for issuer dirs.
- For each, `dir := filepath.Join(issuerDir, safeDomain)`; if it exists, `os.RemoveAll(dir)` and count++.
- Never touches `pki/`, `locks/`, or other domains' dirs.

## Audit

Add `ActionCertDeleted = "cert_deleted"` to `internal/audit/actions.go` (const + `allActions`), bump `internal/audit/actions_test.go` `wantCount` 58 → 59 and update the `ExactSet` test.

## Frontend (UI)

### /certs page (`web/frontend/src/routes/certs/+page.svelte`)

Today read-only ("Force-renew button intentionally absent"). Add a **Delete** row action on every cert row.

**Confirm dialog (Modal, mirrors the existing delete-route dialog pattern):**

- **On click → attempt is gated by a confirm dialog first** (variant A copy). On confirm → `DELETE /api/v1/certificates/{domain}`.
- **If 200** → toast success, refresh the list (the row disappears).
- **If 409** → show the blocked dialog (variant B) listing `blockingRoutes` from the response.

**Variant A — deletable (confirm):**
> **Delete certificate** — Permanently delete the certificate for `<domain>`? The `.crt/.key/.json` files will be removed from disk. This is irreversible; a new certificate may be requested if you recreate a route for this domain.
> [Cancel] [Delete certificate]

**Variant B — blocked (from 409):**
> **Cannot delete** — The certificate for `<domain>` is in use by route(s): `<blockingRoutes>`. Delete or disable those route(s) first.
> [Got it]

### API client (`web/frontend/src/lib/api/certificates.ts`)

Add `deleteCertificate(domain: string): Promise<{domain: string; deleted: number}>` → `DELETE /certificates/{encodeURIComponent(domain)}`. On 409, surface the parsed `{error, blockingRoutes}` so the page shows variant B.

### i18n (EN + FR, parity guard)

New keys: `certs.delete.action`, `certs.delete.confirm.{title,text,action}`, `certs.delete.blocked.{title,text}`, plus a success toast key. Both `en.json` and `fr.json`.

## Testing

- **Storage:** `DeleteCertFiles` — removes across multiple issuers, wildcard domain (`*.x` → `wildcard_.x`), idempotent (absent = 0), never touches `pki/`/`locks/`/other domains. Use `t.TempDir()` with a fabricated certmagic-shaped tree.
- **API:** `deleteCertificate` handler — 200 happy path (files gone + tracker purged + audit), 409 when a route host/alias/managed-domain references the domain (+ `blockingRoutes` populated), 200 idempotent on ghost row, 403 non-admin. Reuse `newTestEnv`.
- **Audit:** count 58→59 + ExactSet.
- **Frontend:** /certs delete action → confirm → success refresh; 409 → variant B with blocking routes; i18n parity.

## Non-goals (explicit)

- **No ACME revocation** (the cert stays technically valid at the CA until expiry; backlog v2).
- **No bulk delete.**
- **No deletion of still-served domains** (orphans only — blocked with 409).
- **No change to the existing managed-domain delete** (that removes config; this new feature is cert-file deletion — they compose: delete the managed-domain first if needed, then the now-orphan cert).

## Open items for the implementation plan (verify empirically)

1. **Wildcard URL encoding** through chi path param: confirm `DELETE /certificates/*.darro.ovh` (encoded) decodes correctly and `certmagic.StorageKeys.Safe` yields `wildcard_.darro.ovh` matching the on-disk dir. Targeted test.
2. **certStorageRoot resolution in the handler**: the handler needs the same root `internal/certinfo` uses (`caddy.AppDataDir()` / the pinned `$HOME`). Confirm how to inject it (the Handler already wires a certInfo reader — extend that seam rather than re-resolving).
3. **Orphan check completeness**: the rule is settled (§decision 2 — exact equality + wildcard-apex coverage + disabled routes count). The plan must find the EXACT matching helper to reuse: how managed-domain wildcard coverage is computed (`buildAutomateList` / managed-domain matching logic) so the orphan check uses the same coverage predicate the config emitter uses — no divergent hand-rolled matcher.
4. **Reload no-op interaction**: when 0 files deleted (ghost row), `caddy.Load` may no-op on unchanged config; confirm the tracker purge alone clears the `/certs` row and no reload is strictly required in that path.
