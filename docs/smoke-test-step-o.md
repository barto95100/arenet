# Step O — Smoke test

**Date**: 2026-05-31.
**Binary**: built from commit `861418e` HEAD (Step O.1-O.4 + backlog).
**Mode**: `--dev`.

## 1. Environment

| Component | Where |
|-----------|-------|
| Arenet admin API | `:9994` |
| Arenet HTTP data plane | `:8080` (dev default) |
| Arenet HTTPS data plane | `:8443` (dev default) |
| Backend (Python http.server) | `:19999` (200 on `/`, 404 on `/404*`) |
| Data dir | `/tmp/arenet-o5/data` |

**Option B per the O.5 plan arbitrage**: no Pebble container. Live wildcard
cert ISSUANCE against a real ACME validator is structurally blocked by
the caddymgr→OVH-provider coupling (see backlog `#O.5-1`). The harness
therefore exercises the JSON-emission + REST API + reconcile + reload-
preservation surface end-to-end against a real binary. Live cert
issuance ACs (#1 / #2 / #8) are PARTIAL with citation to the unit tests
that pin the JSON shape + the loud-unconfigured fallback.

## 2. Method

End-to-end against a real binary, single interactive harness:

1. Build `go build -o /tmp/arenet-o5/arenet ./cmd/arenet` ✓.
2. Backend stub on `:19999` ✓ (200 on `/`, 404 on `/404*`).
3. Boot arenet with `-dev -data-dir=/tmp/arenet-o5/data -admin-port=:9994`.
4. Verify the four pre-O boot lines preserved (no new boot-log surface in O — managed domains are read silently per `applyLocked`).
5. Setup admin + login ✓.
6. **OVH credentials seed**: `PUT /settings/dns-providers/ovh` with fake-content credentials (Endpoint=`ovh-eu` + non-empty AK/AS/CK). Configured=true. Validator only checks non-empty + endpoint enum, so no live OVH call.
7. **Phase C — Managed-domain CRUD validation**:
   - Empty list on fresh install ✓ (`{domains: []}`).
   - POST `{apex: "smoke-o5.test", includeApex: true, provider: "ovh"}` → 201 + wire shape mirroring spec.
   - GET list returns the row ✓.
   - Overlap conflict (POST `app.smoke-o5.test` covered by existing wildcard) → 409 with message naming both apexes.
   - Wildcard form (POST `*.other.test`) → 400 (storage validator rejects `*.` prefix).
   - Unknown provider (POST `provider: "fly"`) → 400 (D3.B enum check).
   - Duplicate apex → 409.
8. **Phase D — Routes + reconcileManagedDomainCoverage + AC #4**:
   - Create 3 routes under `*.smoke-o5.test` with TLS enabled and NO explicit acmeChallenge → backend reconcile rewrites to `"inherited"`, response carries `effectiveCertSource: "managed-domain:smoke-o5.test"` ✓.
   - D1.B opt-out: POST `payments.smoke-o5.test` with `useDedicatedCert: true` + `acmeChallenge: "dns-01"` → 201 with `acmeChallenge: "dns-01"`, `useDedicatedCert: true`, `effectiveCertSource: "per-route-acme:dns-01"` ✓.
   - Defensive cross-rule: uncovered route + `useDedicatedCert: true` → 400 ✓.
   - Uncovered route on `other.org` with `acmeChallenge: "dns-01"` → 201 as J-era.
9. **Phase E — D8.A retroactive migration**:
   - Declare `other.org` as managed (after the uncovered route already exists) → POST returns 201.
   - GET `/routes` → `other.org` route now has `acmeChallenge: "inherited"`, `effectiveCertSource: "managed-domain:other.org"` ✓. **D6.A multi-domain coexistence**: 2 managed domains in the list simultaneously, each emitting its own wildcard policy.
10. **Phase F — AC #14 reload-preserve**: 9 `applying caddy config` reload lines in the arenet log (one per route mutation + managed-domain mutation). The full route list AND the managed-domains list survive every reload — managed-domain policies are re-emitted on every applyLocked (the central invariant the spec §3.5 + §3.6 pins).
11. **Phase G — AC #21 revertTo dropdown** (the operator-facing AC #21 mitigation for the spec §3.8 silent-fallback footgun):
    - `DELETE /settings/managed-domains/other.org?revertTo=dns-01` → 200 with `mutatedRoutes: 1`. The `other.org` route now has `acmeChallenge: "dns-01"`, `effectiveCertSource: "per-route-acme:dns-01"`. Operator-chosen revert value lands cleanly.
    - `DELETE /settings/managed-domains/smoke-o5.test` (no revertTo) → 200 with `mutatedRoutes: 3`. All 3 covered routes revert to `acmeChallenge: ""` (stored), read back as `"http-01"` via toResponse normalisation, `effectiveCertSource: "per-route-acme:http-01"`. **The `payments.smoke-o5.test` D1.B opt-out route is left at `dns-01` — opt-out routes are NOT in the inherited set, so the reverse migration ignores them.** Correct per the O.1 storage invariant.
    - `DELETE … ?revertTo=garbage` → 400 with explicit error message.
    - `DELETE … missing.test` → 404.
12. **Phase H — AC #13 sabotage (nuanced D4.A path)**:
    - PUT with all-blank fields erases OVH credentials → `configured: false`.
    - arenet stays alive (pid 73454 → 207 MB RSS, no crash, no restart).
    - `/routes` and `/settings/managed-domains` still answer 200.
    - Declare a NEW managed domain `loud.test` while credentials are unconfigured → 201 (the row persists). The caddymgr emits the wildcard TLS policy with the `internal` issuer (per D4.A), confirmed by absence of any ACME-related error specific to `loud.test` in the log.
    - **Background observation**: the wildcard policy for `smoke-o5.test` triggered actual ACME traffic to LE staging (logs show `tls.obtain` errors for `app.smoke-o5.test` / `blog.smoke-o5.test` / `api.smoke-o5.test` rejected because `.test` isn't a valid TLD). This is **expected fail-open** — the data plane stayed alive while background ACME failed.
13. **Phase J — Regression**:
    - `go test ./... -count=1 -timeout=180s` → all 12 packages green.
    - `go vet ./...` clean.
    - `gofmt -l -s` flags only `internal/api/oidc.go` — pre-O residue from Step K (waiver documented in N.5 §M).
    - `npm run check` → 0 errors, 0 warnings on 544 files.
    - `npm run build` → green.
    - Bundle delta: `settings/_page.svelte.js` 8.67 → 10.31 kB gz (+1.64 kB), `routes/_page.svelte.js` 9.51 → 10.33 kB gz (+0.82 kB). **Total = +2.46 kB gz under the 3 kB AC #19 budget**.

## 3. AC matrix

| AC | Spec id | Status | Evidence |
|----|---------|--------|----------|
| #1 | Single ACME challenge covers N routes | **PARTIAL** | Live cert issuance against a real ACME validator is structurally blocked by the caddymgr→OVH provider coupling (backlog #O.5-1). JSON shape pinned by `TestBuildConfigJSON_LoadsCleanly_WithManagedDomain` (`internal/caddymgr/managed_domain_emission_test.go`) — provisions every module via `caddy.Validate`. Live observation: 9 reload cycles emitted the wildcard policy without error. |
| #2 | Apex SAN included when IncludeApex=true (D2.C) | **PARTIAL** | Same constraint as #1. Pinned by `TestBuildConfigJSON_ManagedDomain_EmitsWildcardPolicy` (verifies subjects `["*.<apex>", "<apex>"]` when IncludeApex=true) + `TestBuildConfigJSON_ManagedDomain_IncludeApexFalse_OmitsApexSAN`. |
| #3 | Anti-regression on per-route certs (D5.A byte-equality) | **PASS** | Phase F runtime sanity: after `DELETE` of both managed domains, the emitted Caddy config matches the J-era shape (no `*.smoke-o5.test` or `*.other.org` subjects). Pinned by `TestBuildConfigJSON_NoManagedDomains_EqualsStepJ_Bytes`. |
| #4 | effectiveCertSource surfacing | **PASS** | Phase D every covered route's GET response carries `effectiveCertSource: "managed-domain:<apex>"`; opt-out route reports `"per-route-acme:dns-01"`. |
| #5 | Per-route override (D1.B) | **PASS** | Phase D `payments.smoke-o5.test` created with `useDedicatedCert: true` + `acmeChallenge: "dns-01"` → response shape correct; the route is left untouched by the subsequent managed-domain DELETE (Phase G). |
| #6 | Managed-domain CRUD endpoints | **PASS** | Phase C — all 4 method/status combos exercised. |
| #7 | Provider abstraction (D3.B) | **PASS** | Phase C — `provider: "fly"` rejected with the expected 400 message. The `provider` field round-trips on the wire. |
| #8 | DNS-01 unavailable disables wildcard issuance (D4.A) | **PARTIAL** | Phase H exercised the loud-unconfigured state: managed domains accept new declarations even without OVH credentials, the wildcard policy emits with the internal-CA issuer. Pinned by `TestBuildConfigJSON_ManagedDomain_NoProvider_InternalIssuer`. Live cert issuance through Caddy's internal CA path is the same J fall-back; not separately exercised this round. |
| #9 | Multiple managed domains (D6.A) | **PASS** | Phase E — 2 managed domains coexist in the list; routes under each correctly report the right `effectiveCertSource`. |
| #10 | Inherited-challenge migration (D8.A) | **PASS** | Phase E — `other.org` route created BEFORE the managed-domain declaration, with `acmeChallenge: "dns-01"`. Post-declaration: `acmeChallenge: "inherited"`. The migration ran in the same BoltDB tx as the managed-domain Put (atomic, per O.1). |
| #11 | Frontend covered-route UI | **PASS (by build)** | `npm run check` 0 errors / 0 warnings; `npm run build` green. Visual confirmation deferred (matches M.5 / Q.5 / N.5 carry-forward pattern — no human-in-loop browser sweep this round). |
| #12 | Frontend uncovered-route UI unchanged | **PASS (by build)** | Same. |
| #13 | Data plane integrity (LAPI/credential failure does not block data plane) | **PARTIAL** | Phase H — OVH credentials erased mid-process; arenet stayed alive, /routes and /settings/managed-domains still answered 200. New managed-domain POST still accepted (201). Background ACME failures (LE staging rejecting `.test` apex) confirmed the fail-open posture. Marked PARTIAL rather than PASS because the original spec AC #13 covers a runtime ACME outage (not testable without a live ACME validator in the harness, see #O.5-1). The D4.A loud-unconfigured path tested here is the closest analog. |
| #14 | Caddy reload preserves managed-domain policies | **PASS** | Phase F — 9 reload cycles, both managed-domain rows + all routes survived every reload, `effectiveCertSource` correctly resolved across the multi-mutation sequence. Pinned by `TestBuildConfigJSON_ManagedDomain_ReloadPreserves`. |
| #15 | Step J unchanged (per-route DNS-01 + HTTP-01) | **PARTIAL** | The J anti-regression contract is byte-equality at the no-managed-domains baseline (already pinned by AC #3). Live J-era per-route HTTP-01 issuance is not separately re-tested (same Pebble-blocked surface as AC #1). Carry-forward from Step J's own smoke (`docs/smoke-test-step-j.md`). |
| #16 | Tests pass | **PASS** | Phase J — 12/12 packages green. |
| #17 | Lint clean | **PASS (with pre-N waiver)** | Phase J — `go vet` clean; `gofmt -l -s` flags only `internal/api/oidc.go` (pre-O residue from Step K, already documented). `svelte-check` 0/0 on 544 files. |
| #18 | BoltDB bucket creation idempotent | **PASS** | Phase A — the data dir was fresh (no existing `managed_domains` bucket); CreateBucketIfNotExists at startup landed cleanly. Idempotency on existing-bucket reopen is pinned by `TestNewStore_CreatesAllBuckets` (amended in O.1 to include `managed_domains`). |
| #19 | Bundle budget < 3 kB gz | **PASS** | Total +2.46 kB gz across both files. |
| #20 | Viewer-accessible reads | **PASS by code** | `GET /settings/managed-domains` mounted in the hardAuthNoAdmin group; PUT/DELETE under the admin group (`internal/api/routes.go`). |
| #21 | Managed-domain DELETE exposes revertTo | **PASS** | Phase G — all three revertTo branches (default, "dns-01", invalid → 400) exercised. The opt-out (`payments.smoke-o5.test`) was correctly left alone by the reverse migration. |

## 4. Items intentionally PARTIAL / N/A

- **AC #1, #2, #8, #15 — live wildcard cert issuance**: structurally blocked. The caddymgr emits the wildcard TLS policy with `provider.name = "ovh"`, which certmagic dispatches to the OVH provider module. Without real OVH credentials + a real OVH-managed DNS zone, the DNS-01 challenge cannot complete. Pebble (validator-only) would not unblock this because the bottleneck is the provider module's outbound API call, not the ACME server. The trade-off and design options are documented in `docs/backlog-step-o.md` #O.5-1. The JSON-emission shape that would feed a live cert issuance IS pinned by `TestBuildConfigJSON_LoadsCleanly_WithManagedDomain` + `TestBuildConfigJSON_ManagedDomain_EmitsWildcardPolicy` (both exercise `caddy.Validate` on the emitted config, provisioning every module incl. `dns.providers.ovh`).
- **AC #13 — runtime ACME outage** vs the nuanced "credentials erased" path: per the O.5 arbitrage. The spec AC #13's "data plane integrity when LAPI/ACME goes silent mid-process" is impossible to test without a live ACME validator we can stop / restart. The closest analog tested here is D4.A loud-unconfigured: arenet stays alive in a degraded state, accepts new managed-domain declarations, and the wildcard policy emits with internal-CA issuer. Marked PARTIAL to avoid overclaiming the AC.
- **AC #11, #12 — frontend visual confirmation**: deferred (same pattern as M.5 / Q.5 / N.5). The build + svelte-check are clean; a human browser sweep is part of the broader UI polish phase, NOT this step's spec-shipping smoke.

## 5. Findings / fix-before-tag

**None.** The wiring works end-to-end against the live binary:

- Managed-domain CRUD respects all spec invariants (uniqueness, overlap detection, wildcard-form rejection, provider enum check).
- Routes under a managed domain get their ACMEChallenge atomically flipped to `"inherited"` (D8.A); the API surface reports `effectiveCertSource` correctly across covered, opt-out, and uncovered routes.
- The reverse migration on DELETE honors the operator-chosen revertTo value (AC #21).
- Caddy reload preserves the wildcard policies across 9 mutations.
- D4.A loud-unconfigured: erased OVH credentials leave arenet alive and the managed-domain row still accepts new declarations.
- M/Q/N/J carry-forward endpoints unchanged.

## 6. Verdict

**PASS — tag `v1.2.0-step-o`.**

Six PARTIAL items (AC #1 / #2 / #8 / #13 / #15 + the visual UI confirmation for #11 / #12) are all spec-acknowledged trade-offs documented in §4. The functional invariants of Step O — managed-domain CRUD, reconcile, AC #21 revertTo, AC #14 reload-preserve, AC #4 effectiveCertSource — are PASS end-to-end. The remaining PARTIAL items are the inherent limit of single-host smoke against a managed-domain feature that depends on a real DNS provider + zone for full cert issuance; the JSON shape that would drive that issuance is pinned by unit tests + REST integration tests.

## 7. Teardown

```sh
kill -TERM $(pgrep -f "/tmp/arenet-o5/arenet")
kill -TERM $(pgrep -f "tmp/arenet-o5/backend.py") || true
rm -rf /tmp/arenet-o5
```
