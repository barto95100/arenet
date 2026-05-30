# Step O — Wildcard certificates

**Status**: FROZEN 2026-05-30 — all 9 decisions arbitrated, rationale-of-record locked.
**Author**: Ludo + Claude.
**Predecessor**: Step J (DNS-01 / OVH per-route ACME).
**Successor of**: backlog-step-j.md §"Domain-level wildcard certificate management" (deferred from Step J → scheduled here).

---

## 1. Goal & scope

### 1.1 Goal

Extend the per-route ACME model from Step J to support **wildcard certificates** (`*.example.com`) that cover **multiple sibling routes** under one managed domain via a single DNS-01 challenge. The current per-route model emits N ACME challenges for N sub-domains under one apex; this step collapses that to **one cert per managed domain**, dramatically lowering Let's Encrypt rate-limit consumption (50 certs / domain / week production cap) and serialised boot latency for homelabs with ≥10 routes under one apex.

### 1.2 Scope (5 sub-tasks — mirror of N's cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| O.1 | Storage + validation | `ManagedDomain` BoltDB type, list/get/put/delete via API, validation rules (RFC 1035 apex, unique, must not overlap), schema migration. |
| O.2 | Caddymgr | Wildcard cert provisioning in `buildConfigJSON`: when a managed domain exists, emit ONE TLS policy with subject `*.<domain>` (+ optional apex SAN per D5), make per-route HTTP-01 / DNS-01 challenges INHERIT from the wildcard when the host is covered. Anti-regression unit tests: existing per-route DNS-01 + HTTP-01 routes still work. |
| O.3 | REST API | `GET / PUT / DELETE /api/v1/settings/managed-domains` + per-route response field surfacing `effectiveCertSource: "managed-domain:<apex>" \| "per-route-acme" \| "per-route-internal"`. |
| O.4 | Frontend | Settings → SSL section gets a "Managed domains" widget (declare apex, see coverage list, see cert expiry). Route-edit modal's TLS section becomes contextual: hide the ACME challenge selector when a managed domain covers the host (show "inherits wildcard from `<apex>`"), show it otherwise. |
| O.5 | Smoke + tag | Live ACME issuance against a real OVH DNS zone (or Pebble + a fake DNS provider for CI-friendly path): 3 routes under `*.example.com`, verify one issuance covers all 3, kill-DNS-provider AC #13 fallback, tag `v1.2.0-step-o`. |

### 1.3 Locked decisions

(All decisions arbitrated 2026-05-30; rationale of record preserved.)

#### D1 — Managed-domain model → **B (inheritance with explicit per-route opt-out)**

Once a managed domain `*.example.com` is declared, a route on `app.example.com` is covered by the wildcard. The arbitration was whether to allow an operator to OVERRIDE that — request a per-route ACME cert for `app.example.com` separately.

- **D1.A — Strict inheritance.** Any route under a managed domain inherits the wildcard. NO per-route override. Simpler UI; smaller surface; but an operator who wants cert separation for e.g. `payments.example.com` (separate key pair so a wildcard-key compromise doesn't expose payments) is forced to NOT declare the apex as managed, losing the benefit for the other 9 sub-domains.

- **D1.B — Inheritance with explicit per-route opt-out.** Default behaviour: route under managed apex inherits the wildcard. Route can flag `useDedicatedCert: true` to fall back to the per-route ACME path (HTTP-01 or DNS-01 from the same OVH provider). 2 modes to test; UI shows a third option; route-edit needs the toggle.

**Decision: B.** The cert-separation use case is a real operator concern: a wildcard-key compromise blast-radius covers ALL sub-domains under the apex. Banking / payments / staging-vs-prod separation are legitimate reasons to want dedicated keys for specific sub-domains. The complexity cost is one boolean field + one UI checkbox + one validation rule — proportional to the value gained.

**Rejected — D1.A:** strict inheritance forces an all-or-nothing choice that doesn't match operator reality. Cert separation is too common a concern to push back to "declare per-route HTTP-01 separately and don't use the managed-domain feature for that apex".

#### D2 — Apex coverage → **C (operator-chosen `includeApex`, default true)**

RFC 6125: a wildcard `*.example.com` does NOT cover the bare apex `example.com`. A route on the apex needs separate handling.

- **D2.A — Wildcard-only.** Managed domain emits a cert for `*.example.com` ONLY. Routes on the bare apex fall through to per-route ACME — they're not "covered". 1 DNS-01 challenge per managed domain; cleanest separation. But operators who want `example.com` covered too must declare both a managed domain AND configure a per-route cert on the apex route.

- **D2.B — Wildcard + apex SAN unconditionally.** Managed domain emits a multi-SAN cert covering BOTH `*.example.com` AND `example.com`. One cert covers everything; matches LE best practice for apex-+-wildcard sites. 2 DNS-01 challenges during issuance.

- **D2.C — Operator-chosen `includeApex: bool`.** Toggle in the managed-domain config: true → D2.B path; false → D2.A path.

**Decision: C.** Defaulting `includeApex: true` matches what most homelab operators expect — most homelabs have a landing page on the apex AND a swarm of sub-domain apps. But the toggle gives operators who explicitly want apex separation (e.g. apex serves a static site managed by a different system, sub-domains are Arenet-routed apps) the clean off-path. The cost of the toggle is one bool field + one checkbox.

**Rejected — D2.A:** forces two surfaces (managed domain + per-route apex cert) for what is one mental model in operator terms.
**Rejected — D2.B:** removes operator choice for the apex-separation case at zero implementation saving.

#### D3 — DNS provider scope → **B (provider abstraction from the start)**

Step J wired only the OVH DNS provider. Step O extends this surface.

- **D3.A — OVH only for v1.2.** Wildcard provisioning uses the existing `DNSProviderConfig.OVH` config; no abstraction. Smallest possible change; matches J's posture. When the next provider lands, the managed-domain schema needs to grow a `provider` field — and that's a BoltDB migration.

- **D3.B — Provider abstraction from the start.** `ManagedDomain` carries a `provider: "ovh"` field today; the value space is currently `{"ovh"}` but the schema reads as "future-proof". No second migration when the next provider arrives.

**Decision: B.** A 1-field "future-proofing" string costs nothing at write time and saves a real migration cost when the next provider (likely Cloudflare, second-most-requested in homelab forums) lands. Same posture as Step N's D5 (the `scope`/`scenario` fields where we explicitly noted "future-additive without migration"). Validation today accepts only `"ovh"`; expanding the value space is a one-line enum add.

**Rejected — D3.A:** the migration we'd avoid is a real one (renaming the column requires a BoltDB scan, route-state freezing during the migration, and an idempotency invariant test). Deferring it for zero implementation gain is the wrong trade.

#### D4 — HTTP-01 fallback when DNS-01 unavailable → **A (no silent fallback — wildcards EXIGENT DNS-01)**

Operator declares `*.example.com` as managed, but OVH credentials are unconfigured or wrong. What happens?

- **D4.A — Fail to issue, surface the state loudly.** No HTTP-01 fallback for wildcards (HTTP-01 can't issue them anyway — the CA cannot verify control of `*.example.com` via a single concrete host). Routes under the managed domain serve the internal-CA self-signed cert until credentials are fixed. The Settings UI shows `provider unconfigured — wildcard issuance disabled` with a CTA.

- **D4.B — Per-route HTTP-01 fallback for covered routes.** When the managed domain's DNS-01 path is unavailable, the routes under it transparently fall back to per-route HTTP-01. No operator-visible downtime if credentials lapse. But silently changes from "1 wildcard cert" to "N per-route certs" — exactly the rate-limit problem the step is solving.

**Decision: A.** HTTP-01 is a fundamentally different challenge type that cannot issue wildcard certs by protocol design — the CA's HTTP-01 verifier requires the challenge response served from `http://<concrete-host>/.well-known/acme-challenge/...`, and there is no concrete host for `*.example.com`. D4.B is not even a true fallback; it would only "work" by silently rewriting `*.example.com` → N per-host certs, which is exactly the rate-limit failure mode (50 certs / week / registered domain) this step exists to prevent. The operator declared a managed domain *because they wanted wildcard*; degrading to per-route silently breaks that mental model AND triggers the rate limit they were trying to avoid.

**Rejected — D4.B:** the failure mode it claims to prevent (downtime when credentials lapse) is itself a louder failure mode (rate-limit exhaustion that takes a week to clear). The right operator-facing surface is a loud unconfigured state, not silent degradation.

#### D5 — Anti-regression invariant → **A (byte-equality unit test)**

Step J users with running per-route ACME certs must NOT see their certs reissued / re-challenged when O ships.

- **D5.A — Pure additivity invariant.** Without any managed domain declared, the emitted Caddy JSON is byte-equal to J's. Pinned by a unit test: `TestBuildConfigJSON_NoManagedDomains_EqualsStepJ_Bytes`.

- **D5.B — Equivalence by behaviour, not bytes.** Caddy JSON may differ structurally, but `caddy.Validate()` accepts both and certmagic emits no new challenges.

**Decision: A.** Byte-equality is the strongest invariant we can write: any structural drift in the no-managed-domain path triggers test failure at PR time, before any operator hits it. We already hit this exact discipline at N.1 (`TestBuildConfigJSON_WithoutCrowdSec_NoAppsBlock`), and the M-era `TestBuildConfigJSON_WithoutCrowdSec_HandlerNotPrepended` is the broader pattern: the additive feature's no-op state MUST produce byte-equal output to the pre-feature baseline. Step J's snapshot is committed in the repo; the new test diffs against it.

**Rejected — D5.B:** behavioural equivalence is testable but with a broader and harder-to-pin surface. "caddy.Validate() succeeds + cert manager emits no new challenges" requires a runtime test environment; byte-equality is a pure-Go string compare with deterministic input.

#### D6 — Multiple managed domains → **A (allow N)**

Operator declares `*.example.com` AND `*.example.org` as managed (different OVH zones, same OVH credentials).

- **D6.A — Allow.** N managed domains → N TLS policies → N DNS-01 challenges during issuance. The provider config is shared (one set of OVH credentials per provider).

- **D6.B — Limit to 1.** Simplifies UI and JSON emission. Defers multi-domain to a later step.

**Decision: A.** Limiting to 1 forces operators with 2+ apex domains to pick which one gets the wildcard treatment — a non-decision that the implementation cost of `for _, md := range mds { ... }` does not justify. The OVH credentials cover all zones on that OVH account, so the credential-sharing concern is a non-issue. Multiple managed domains is the COMMON homelab shape (one personal domain + one project domain + possibly a `.lan` apex routed via DNS-01 against an internal Bind), not an edge case.

**Rejected — D6.B:** the saved complexity is illusory (the loop is 5 lines); the lost capability is real and frequent.

#### D7 — Cert key separation → **A (per-cert keys, certmagic default)**

Each managed domain's wildcard cert has its own private key (certmagic default).

- **D7.A — Per-cert keys.** Each managed domain gets its own key. No operator surface.

- **D7.B — Shared key across managed domains.** Operator opts into a shared key (e.g. for HSM integration).

**Decision: A.** B is a YAGNI surface for the homelab target. Shared keys are an enterprise-tier concern (HSM amortisation, hardware-bound CSRs) that has no homelab cousin. If a future enterprise need arises, it's an additive change to the managed-domain config that doesn't conflict with A — operators of A see no migration when B lands.

**Rejected — D7.B:** zero operator value at the homelab tier; introducing the surface now bloats the managed-domain config struct for an unused path.

#### D8 — Covered-route ACMEChallenge enum → **A (new `"inherited"` value)**

When `*.example.com` is managed and a route is created with host `app.example.com`, the route's `ACMEChallenge` field becomes derived.

- **D8.A — New enum value `"inherited"`.** Route struct's existing enum `{"", "http-01", "dns-01"}` gets a fourth value. Migration: any existing route whose host is suddenly covered by a newly-declared managed domain gets `ACMEChallenge = "inherited"`.

- **D8.B — Leave ACMEChallenge ignored when covered.** The field stays at its current value but is silently overridden at config-build time. No migration.

- **D8.C — Validation error on conflict.** Hard error; operator must explicitly clear ACMEChallenge before declaring a managed domain that covers the route.

**Decision: A.** Implicit overrides (D8.B) make the route-edit UI lie about what's happening — the operator sees `acmeChallenge: "dns-01"` in the route detail but the cert is actually inherited from the managed domain. That gap between displayed-state and actual-state is the exact kind of silent UX rot that costs trust. Hard errors (D8.C) make the managed-domain declaration flow hostile — declaring a managed domain that covers 30 routes would require clearing 30 routes' ACMEChallenge first. Explicit `"inherited"` enum value with a one-pass migration in the managed-domain create handler is the honest middle ground: the route detail shows `acmeChallenge: "inherited"`, the operator reads it as "this route's cert comes from a managed domain", and clicking the route opens a contextual UI that links to the managed-domain settings.

**Rejected — D8.B:** displayed-state divergence from actual-state is a trust-eroding UX antipattern.
**Rejected — D8.C:** hostile flow for the operator declaring a managed domain on an existing apex.

#### D9 — Settings UI placement → **B (new top-level "SSL / Certificates" section)**

Where does the "Managed domains" widget live in the Settings page?

- **D9.A — Under existing "DNS provider" section.** Inline with the OVH credentials form. Short navigation; the dependency is visually obvious. But the section grows.

- **D9.B — New top-level "SSL / Certificates" section.** Sibling of "DNS provider". Room for future cert-related widgets.

**Decision: B.** The "DNS provider" section is, conceptually, ONE layer of the cert stack (the validation transport). "Managed domains" is the policy layer that USES the DNS provider — different conceptual surface. Co-locating them in one section creates a navigation hint that says "DNS provider = certificates", which it isn't (HTTP-01 routes don't need a DNS provider). Splitting them surfaces the dependency cleanly (the SSL section's empty state explains "requires DNS provider — go configure it") without conflating the two concepts. The "SSL / Certificates" section is also the natural home for follow-up cert-related widgets the backlog mentions (manual cert upload, expiry alerts, OCSP status) — backlog-step-j.md §"Domain-level wildcard certificate management" already calls out the "Settings → SSL section" name.

**Rejected — D9.A:** conflates DNS provider (transport) and managed domains (policy) under one heading at the cost of mental-model clarity.

---

## 2. Acceptance criteria

(Frozen 2026-05-30, reflects D1-D9 arbitration outcomes.)

**AC #1 — Single ACME challenge covers N routes.** With managed domain `*.example.com` declared and 3 routes (`app.example.com`, `blog.example.com`, `api.example.com`), boot triggers ONE DNS-01 challenge. Verified by: `caddy.Validate` on emitted JSON shows ONE acme issuer policy for `*.example.com` and three route entries all referencing it.

**AC #2 — Apex SAN included when `includeApex: true` (per D2.C).** The emitted cert's SAN list contains BOTH `*.example.com` AND `example.com`. Verified live via `openssl x509 -text -in <cert>`.

**AC #3 — Anti-regression on per-route certs (D5.A).** Without any managed domain declared, `buildConfigJSON(...)` returns bytes identical to the Step-J snapshot. Pinned by a byte-equality unit test.

**AC #4 — `effectiveCertSource` surfacing.** `GET /routes/<id>` response includes a derived `effectiveCertSource` field: `"managed-domain:example.com"` when covered, `"per-route-acme:dns-01"` / `"per-route-acme:http-01"` when not, `"per-route-internal"` for internal-CA hosts.

**AC #5 — Per-route override (D1.B).** Route with `host: payments.example.com` + `useDedicatedCert: true` emits its OWN ACME challenge despite the apex being managed. The wildcard cert does NOT contain `payments.example.com` (it's still `*.example.com`).

**AC #6 — Managed-domain CRUD endpoints.** `POST /settings/managed-domains` with `{apex, includeApex}` → 201. `GET /settings/managed-domains` → array. `DELETE` → 204. Validation rules (RFC 1035, unique, no overlap).

**AC #7 — Provider abstraction (D3.B).** Schema includes a `provider` field; valid value space currently `{"ovh"}`; unknown values rejected with 400.

**AC #8 — DNS-01 unavailable disables wildcard issuance (D4.A).** When OVH credentials are unconfigured AND a managed domain exists, the Settings UI shows the "unconfigured" state. Caddy config emits the wildcard policy but the issuer falls back to internal CA (same posture as J's "no provider configured → internal CA" path). Routes serve self-signed certs until credentials are configured.

**AC #9 — Multiple managed domains (D6.A).** Two managed domains coexist; the emitted Caddy JSON contains two distinct ACME policies for `*.example.com` and `*.example.org`.

**AC #10 — Inherited-challenge migration (D8.A).** Existing route with `host: app.example.com` + `ACMEChallenge: "dns-01"` automatically becomes `ACMEChallenge: "inherited"` when `*.example.com` is declared managed. Migration is a single BoltDB scan.

**AC #11 — Frontend covered-route UI.** Route-edit modal hides the ACME challenge selector when a managed domain covers the host. Shows a labeled badge `Inherits wildcard from *.example.com` with a link to the managed-domain settings.

**AC #12 — Frontend uncovered-route UI unchanged.** Route-edit modal for a host with no managed-domain coverage shows the same UI as Step J (HTTP-01 / DNS-01 choice).

**AC #13 — Data plane integrity (mirror M/Q/N AC #13).** Boot with malformed managed-domain config (e.g. apex containing invalid chars) → reject at storage layer, log INFO line, continue boot without that managed domain. Boot with valid managed-domain but unreachable OVH → log WARN, no panic, routes serve internal-CA certs until OVH recovers.

**AC #14 — Caddy reload preserves managed-domain TLS policies.** Every `caddymgr.applyLocked` includes all managed-domain TLS policies in the JSON. Adding/removing a route does NOT drop the wildcard policy. Pinned by `TestBuildConfigJSON_ManagedDomain_ReloadPreserves`.

**AC #15 — Step J unchanged.** Re-run J.5 smoke matrix subset: per-route DNS-01 issuance still works against a host with no managed-domain coverage. Per-route HTTP-01 issuance still works.

**AC #16 — Tests pass.** `go test ./... -count=1` clean.

**AC #17 — Lint clean.** `go vet`, `gofmt`, `svelte-check`.

**AC #18 — BoltDB bucket creation idempotent.** Re-running boot on an already-O-aware DB is a no-op — `CreateBucketIfNotExists` short-circuits when the bucket exists. No SQLite migration in this step (observability/metrics.db is untouched).

**AC #19 — Bundle budget < 3 kB gz.** Combined frontend addition.

**AC #20 — Viewer-accessible reads.** `GET /settings/managed-domains` available to viewer role; PUT / DELETE require admin. (Same posture as DNS-provider endpoints in J.)

---

## 3. Architecture

### 3.1 Where the new logic lives

```
internal/storage/
  managed_domain.go (NEW)     — ManagedDomain BoltDB type + CRUD
  storage.go                  — + bucketManagedDomains constant + entry in the startup CreateBucketIfNotExists loop
  routes.go                   — + ACMEChallenge: "inherited" enum value (D8.A)
                              — + UseDedicatedCert bool field (D1.B opt-out)
internal/caddymgr/
  managed_domain.go (NEW)     — Wildcard TLS policy emission + IsHostCoveredByManagedDomain predicate (§3.2)
  manager.go                  — partition routes by "covered-by-managed-domain" before existing DNS-01/HTTP-01 partition
internal/api/
  managed_domain_handlers.go (NEW) — CRUD endpoints + the on-create route-mutation pass (D8.A)
  routes.go                   — mount /settings/managed-domains; surface effectiveCertSource on GET responses
  validation.go               — + validateACMEChallenge extended for the "inherited" + useDedicatedCert combinations
web/frontend/src/routes/settings/
  ssl/ (NEW)                  — top-level "SSL / Certificates" section (D9.B), contains managed-domains widget
web/frontend/src/routes/routes/
  +page.svelte                — contextual UI per AC #11/#12 (ACMEChallenge selector hides when covered)
```

### 3.2 The coverage predicate

A single function — `isHostCoveredByManagedDomain(host string, mds []ManagedDomain) (ManagedDomain, bool)` — used by FOUR call sites:

1. **caddymgr** at config-build time to pick wildcard vs per-route TLS policy.
2. **api/routes.go** to compute `effectiveCertSource` for the GET response (per AC #4).
3. **api/routes.go** validation: when a route is created/edited and is covered, reject `ACMEChallenge != "inherited"` UNLESS `useDedicatedCert: true` (the D1.B opt-out path).
4. **api/managed_domain_handlers.go** at managed-domain CREATE time: scan all existing routes, mutate `ACMEChallenge → "inherited"` for the newly-covered set (per D8.A migration discipline).

Predicate logic, per RFC 6125 §6.4.3: host `app.example.com` is covered by managed domain `example.com` iff host is exactly `<single-label>.example.com` (one DNS label removed yields the apex). Host `deep.app.example.com` is NOT covered — wildcards do not match multiple labels. Host `example.com` (bare apex) is covered iff `includeApex: true` (per D2.C). Empty managed-domain list → false for every host (the D5.A byte-equality short-circuit).

The predicate is a pure function (host string + slice) and is unit-tested with the multi-label edge case explicitly named in §5 risks.

### 3.3 Caddy JSON emission (descends from D2 + D3 + D4)

For each managed domain `<apex>` with `includeApex: true` (D2.C path), the manager emits ONE TLS policy:

```json
{
  "subjects": ["*.<apex>", "<apex>"],
  "issuers": [{
    "module": "acme",
    "challenges": {"dns": {"provider": {"name": "ovh", ...}}}
  }]
}
```

For `includeApex: false`: subjects = `["*.<apex>"]` — single SAN, single DNS-01 challenge per issuance.

The `provider.name` field is sourced from `ManagedDomain.Provider` (the D3.B abstraction); the field's value space is currently `{"ovh"}` but the JSON-emission code reads it as `mgr.Provider` rather than hardcoding `"ovh"`, so a future Cloudflare path is a one-line provider-config lookup.

When the operator declares a managed domain but the corresponding DNS provider credentials are unconfigured (D4.A "loud unconfigured state" path), the issuer block falls back to `{"module": "internal"}` instead of `acme` — the wildcard policy stays in the JSON (so the Caddy reload doesn't drop it), but the cert is internal-CA self-signed until credentials arrive. The Settings UI surfaces this state via the `provider unconfigured — wildcard issuance disabled` banner (AC #8).

Per-route TLS policies for covered routes are NOT emitted: the wildcard policy serves the cert at handshake-match time via certmagic's `AllMatchingCertificates` wildcard expansion (verified empirically in certmagic@v0.25.3 `match.go`). This is the central efficiency gain of the step — N covered routes share one ACME issuance instead of triggering N.

For covered routes with `useDedicatedCert: true` (the D1.B per-route opt-out), the per-route TLS policy IS emitted alongside the wildcard policy — the dedicated cert covers the specific host, the wildcard covers the rest. Operator-side, this is exactly two ACME issuances (one for the wildcard, one for the dedicated host).

### 3.4 Storage initialisation (descends from D8.A)

The storage delta is intentionally minimal. BoltDB has no versioning model in Arenet (unlike the SQLite observability schema_version table in N) — buckets are created via `CreateBucketIfNotExists` at startup. Adding `managed_domains` follows that pattern:

1. Add `bucketManagedDomains = "managed_domains"` constant in `storage.go`.
2. Include it in the existing startup `CreateBucketIfNotExists` loop.
3. On a fresh DB → bucket created empty. On an upgraded DB → bucket created empty (no-op if it already exists). observability/metrics.db is untouched.

**Idempotency** (AC #18): re-running boot is trivially idempotent because `CreateBucketIfNotExists` is itself idempotent. No version check needed.

The route-side `ACMEChallenge → "inherited"` mutation that DOES happen at managed-domain CREATE time is wrapped in a single BoltDB transaction with the managed-domain Put — atomic against partial failure (per §5 risks "D8.A migration" row). The handler iterates existing routes, identifies the covered subset via the §3.2 predicate, mutates each one's `ACMEChallenge` field, and writes both the new managed domain AND the mutated routes in one tx commit. AC #10 pins this behaviour live.

**Reverse path on managed-domain DELETE**: when an operator removes a managed domain, the covered routes' `ACMEChallenge` reverts. The choice: revert to `""` (the J-era default → HTTP-01) OR keep `"inherited"` (broken state, no covering managed domain). The handler reverts to `""` in the same tx as the Delete — a route shouldn't be able to be in `"inherited"` state without a covering managed domain. This is the inverse of the create-path migration and is unit-tested.

### 3.5 The Step-J anti-regression invariant (descends from D5.A)

The empty-managed-domains case MUST produce byte-equal Caddy JSON vs Step J. This means:

- The "managed-domain partition" step in `buildConfigJSON` short-circuits when `len(managedDomains) == 0`. The early-return placement is critical: it must happen BEFORE any new map-key insertion or field initialization that would change the JSON marshalling order. The N.1 pattern (`if csConfig == nil { return existingJSON }`) is the discipline to follow.

- The new `effectiveCertSource` field in route responses is OMITTED when empty (zero-value Go string with omitempty), preserving JSON shape compatibility for J-era frontends. This is a backend-cleanliness nicety even though the O frontend reads the field — it costs nothing and prevents accidental drift.

- The byte-equality unit test (`TestBuildConfigJSON_NoManagedDomains_EqualsStepJ_Bytes`) is the regression gate. The Step-J snapshot is committed in `internal/caddymgr/testdata/step-j-snapshot.json`; the new test asserts `bytes.Equal(buildOutput, snapshot)`. Any drift fails the test at PR time.

### 3.6 Multiple managed domains (descends from D6.A)

The architecture treats `[]ManagedDomain` as the operating unit throughout — caddymgr emits N TLS policies for N managed domains, the predicate iterates the slice, the migration handler loops over the slice. No "the managed domain" singular shortcut anywhere in the code. This is the cheapest defense against accidentally restricting to 1 later.

The OVH credentials are shared across all managed domains using the OVH provider (per D3 + the certmagic OVH-provider design where one `OVHProvider` instance handles all zones on one account). The future Cloudflare path will follow the same shape: one `DNSProviderConfig.Cloudflare` shared across all Cloudflare managed domains.

### 3.7 Dependency direction

```
api/managed_domain_handlers.go
    ↓ reads
storage/managed_domain.go
    ↑ read by
caddymgr/managed_domain.go
    ↓ uses predicate from
caddymgr/managed_domain.go (isHostCoveredByManagedDomain)
    ↑ called by
api/routes.go (effectiveCertSource computation + validation)
```

The predicate function lives in `caddymgr/` because caddymgr is the primary consumer; api/ imports caddymgr (existing import direction from Step J, untouched). The predicate is package-public (`caddymgr.IsHostCoveredByManagedDomain`) so api/ can call it without an import cycle.

---

## 4. Sub-task ordering & cadence

Same cadence as M / Q / N: present results before commit, accumulate without push until O.5, tag locally only when verdict = PASS.

| Sub | Surface | Estimated lines (Go + frontend) | Tests added |
|-----|---------|---------------------------------|-------------|
| O.1 | Storage + validation + migration | ~400 + ~0 | 8-10 (managed_domain + migration) |
| O.2 | Caddymgr wildcard emission | ~250 + ~0 | 10-12 (covered/uncovered partition, JSON shape, reload-preserves, byte-equal) |
| O.3 | REST API + effectiveCertSource | ~350 + ~0 | 6-8 (CRUD + filter + AC #13 disabled paths) |
| O.4 | Frontend Settings widget + contextual route-edit | ~0 + ~600 | minimal (svelte-check + 1 e2e in O.5) |
| O.5 | Live smoke + tag | doc only | live verification per AC matrix |

---

## 5. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| **D5.A regression**: byte equality breaks unintentionally on a future Step (operator with managed domains undeclared sees cert re-issuance) | AC #3 byte-equality unit test pinned against `internal/caddymgr/testdata/step-j-snapshot.json`. Any caddymgr.buildConfigJSON change that touches the no-managed-domains path fails CI. PR review diff highlights the snapshot drift. |
| **§3.2 predicate regression**: RFC 6125 wildcard depth bug (`*.example.com` matching `deep.app.example.com`) | Predicate function table-driven unit test with the multi-label case, the bare-apex case (covered iff `includeApex: true`), the case-sensitivity case (DNS is case-insensitive — predicate normalises to lowercase before compare), and the trailing-dot case (`example.com.` ≡ `example.com`). |
| ACME rate-limit hit during live smoke (Let's Encrypt: 50 certs / registered domain / week) | Use Pebble for AC #1-9 live verification (Pebble has no rate limits). Reserve real Let's Encrypt only for AC #15 (J carry-forward) on the staging endpoint, which has a 30-certs-per-3-hour limit but resets fast. Document the fallback ladder in O.5's smoke doc. |
| **D4.A "unconfigured" path**: managed domain declared with no OVH credentials → certmagic could enter an infinite ACME retry loop | AC #8: emit wildcard policy with `{"module": "internal"}` issuer instead of `acme` when provider config is unconfigured. The wildcard policy stays in the JSON (so a subsequent reload doesn't drop it), routes serve internal-CA self-signed certs, no ACME traffic. Settings UI loud banner per D4 decision. |
| **D8.A migration**: BoltDB managed-domain Put + N route ACMEChallenge mutations not atomic → operator could see partial state on a crash mid-handler | Single BoltDB transaction wraps BOTH the managed-domain Put AND the route mutations. BoltDB's write tx is all-or-nothing; a crash mid-tx rolls back cleanly on next boot. Unit test: inject a fault between the managed-domain Put and the route iteration, assert post-recovery state is pre-handler state (no managed domain, no mutated routes). |
| **D1.B opt-out parsing**: operator forgets to set `useDedicatedCert: true` AND clears `ACMEChallenge` from `inherited`, expecting per-route ACME | Validation rule at route POST/PUT: if host is covered AND `ACMEChallenge` is not in `{"inherited", "", "http-01", "dns-01"}`, reject. If host is covered AND `ACMEChallenge == "inherited"` AND `useDedicatedCert: true`, reject (inconsistent — pick one). The route-edit modal disables the ACMEChallenge selector when covered, only re-enabling it when the operator ticks `useDedicatedCert`. |
| **D3.B provider abstraction abuse**: future contributor adds `"cloudflare"` to the value-space enum without wiring the certmagic Cloudflare provider in caddymgr → 500 at config-build time | Validation rejects unknown provider values at storage layer (one switch statement). The unit test `TestManagedDomain_Provider_RejectsUnknown` pins this. Adding a new provider becomes a 3-step change: storage validator + caddymgr emission + DNS-provider config schema — all visible in one PR. |
| **D6.A multi-domain edge case**: operator declares overlapping managed domains (e.g. `example.com` AND `app.example.com`) | Reject at managed-domain POST: if a candidate apex is itself covered by an existing managed domain's wildcard, return 409 Conflict. The §3.2 predicate is reused for the check. |
| Operator confusion: "I declared a managed domain but my route still serves the per-route cert" (race: managed domain just declared, Caddy reload pending) | The `effectiveCertSource` field in `GET /routes/<id>` (AC #4) reflects the BUILD-TIME computed source, which updates synchronously with the next caddymgr.applyLocked. The frontend route-list view shows it as a badge column; operators can see the transition. The Settings → SSL section also shows the "last issuance" timestamp per managed domain so the operator can verify the wildcard cert has actually issued. |
| Wildcard cert key compromise blast radius (one stolen key → ALL sub-domains) | The D1.B opt-out path exists exactly for this scenario: operators with payments / staging / SSO subdomains that warrant key separation flag those routes as `useDedicatedCert: true`. Documented in the Settings UI help text alongside the managed-domain declaration form. |
| **D2.C apex coverage UX**: operator ticks `includeApex: true` but the apex DNS A record isn't actually pointing at Arenet → ACME apex challenge fails, wildcard portion succeeds, operator sees half-broken cert | At managed-domain POST time, do a best-effort DNS resolution of the bare apex; if it doesn't resolve to a public IP that matches any known interface, log a WARN line `apex includeApex=true but DNS resolution returned <unexpected>` and continue. The cert may still issue if the operator fixes DNS after Arenet boots; this is informational, not a block. |

---

## 6. Out of scope (for v1.2)

- Manual cert upload (operator pastes PEM). Separate feature with its own design surface (key storage, expiry warnings).
- Multi-provider DNS (Cloudflare, Route53). D3.B leaves the door open for v1.3+.
- Per-route cert expiry alerting / dashboard widget. Step P candidate (parallel to "observability" backlog).
- ACME EAB (External Account Binding) for private CAs. Step J-era backlog.
- Wildcard with multi-label depth (`*.*.example.com`). Not supported by Let's Encrypt; not on roadmap.

---

## 7. Appendix — references

- backlog-step-j.md §"Domain-level wildcard certificate management" (the original design sketch).
- certmagic source: `cache.go:333-347`, `match.go` (wildcard handshake expansion verified empirically).
- RFC 6125 §6.4.3 (wildcard label depth).
- Let's Encrypt rate limits: 50 certs / registered domain / week (production); Pebble unlimited for local smoke.
- Step J smoke doc: `docs/smoke-test-step-j.md` §3.5 B.4 (the live wildcard issuance baseline against `*.worldgeekwide.fr`).
