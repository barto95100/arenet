# Step O — Backlog

Items deferred from Step O work. Same convention as
`docs/backlog-step-n.md` / `docs/backlog-step-m.md` / `docs/backlog-step-q.md`.

## 1. Frontend / type cohesion

### Finding #O.4-1 — Manual TS port of `IsHostCoveredByManagedDomain` risks silent drift

O.4 added `findCoveringManagedDomain(host)` in
`web/frontend/src/routes/routes/+page.svelte` as a pure JS port
of the Go predicate `caddymgr.IsHostCoveredByManagedDomain`
(spec §3.2 + RFC 6125 §6.4.3).

Both implementations encode the same coverage rules
(single-label wildcard, includeApex toggle, case-insensitive +
trailing-dot canonical, wildcard route-host rejected). A future
edit to the Go version — e.g. when a follow-up step extends the
predicate with country/AS scopes, or adjusts the case-folding
rule — has no compile-time link to the TS port. The frontend
would silently fall out of sync; symptoms would be a route
whose backend `effectiveCertSource` says "managed-domain:foo"
while the route-edit modal shows the J-era ACME selector
(because the TS predicate disagreed about coverage).

**Mitigation options.**

- **Option A — Codegen the TS predicate from Go.** A small Go
  program that emits the predicate body into a generated
  `web/frontend/src/lib/api/managed-domain-coverage.gen.ts`
  file, run as part of `make generate`. The TS file ships
  with a "DO NOT EDIT — generated from caddymgr.go" banner.
  Pros: single source of truth; PR review surfaces the diff
  on both sides. Cons: yet another codegen surface.

- **Option B — Cross-check test on a shared fixture set.** A
  JSON file under `internal/caddymgr/testdata/coverage-cases.json`
  containing input/output cases is consumed by BOTH the Go test
  (`TestIsHostCoveredByManagedDomain_FixtureFile`) and a vitest
  test that runs the same cases against the TS port. A drift
  between the two implementations fails ONE of the two tests
  in CI. Pros: no new codegen; the fixture file is a readable
  spec artifact. Cons: vitest isn't currently wired in this
  repo — adding a frontend test harness is a separate setup.

- **Option C — Server-driven coverage.** Expose
  `effectiveCertSource` (already done in O.3) and also a
  `coveringManagedDomainApex` field on the route response.
  The frontend reads the server's decision instead of
  re-deriving it locally. The contextual route-edit modal
  then has no predicate at all — it just reads
  `route.coveringManagedDomainApex` on form load. Pros:
  cleanest single source of truth. Cons: requires re-fetching
  on every form-state change (the form's host field is
  edit-bound; the predicate runs every keystroke). Server
  round-trips per keystroke is hostile; a derived-on-save
  shape would lose the contextual UI.

**Recommendation.** Option B (shared fixture file + a vitest
harness) — adds the test cost where we want it (CI-time drift
detection) without per-keystroke server traffic and without a
new codegen. Acceptable to defer until either implementation
actually changes; today's TS port is a 20-line function
matching the Go shape line-for-line. The unit tests added in
O.1 (`internal/caddymgr/managed_domain_test.go`) already pin
the Go shape; an analogous TS test ships when vitest is added.

**Triage.** Cosmetic / future-maintenance hardening. No
functional bug today.

### Finding #O.4-2 — `acmeChallenge:"inherited"` form-load normalisation loses prior per-route choice

O.4 loads `r.acmeChallenge` into the route-edit `formData`. When
the stored value is `"inherited"` (D8.A: route covered by a
managed domain, no opt-out), the form normalises to `"http-01"`
so the per-route selector — hidden by the inheritance branch —
has a valid base state if the operator opens it via the
`useDedicatedCert` opt-out toggle.

Problem: the normalisation is destructive of the operator's
*previous* per-route choice. Walk-through:

1. Operator creates route `app.example.com` on DNS-01.
2. Operator declares `example.com` as managed domain → backend
   atomic migration flips the route's ACMEChallenge to
   `"inherited"`.
3. Operator re-opens the route-edit modal. Form loads
   `acmeChallenge: "inherited"` → frontend rewrites to
   `"http-01"` (the J-era default). Selector hidden.
4. Operator toggles `useDedicatedCert: true`. Selector appears,
   defaulting to `"http-01"` — the original DNS-01 choice is
   lost.

The operator now has to remember they were on DNS-01 and pick
it again from the dropdown. On a wildcard apex this is
recoverable (the dropdown is there), but it's a silent UX
regression vs. the J-era behaviour where the stored choice
round-trips through every form load.

**Mitigation options.**

- **Option A — Persist the pre-coverage value in a sidecar
  field.** Storage adds an optional `ACMEChallengePreManaged`
  field that captures the value at the moment of the
  managed-domain create-time migration; the form reads from
  it when populating the selector on opt-out toggle. Pros:
  exact restore. Cons: schema growth + the sidecar value
  decays over time (a route created post-managed-domain has
  no "pre-managed" value, so the field is empty for it; the
  form has to fall back to a default anyway).

- **Option B — No default on opt-out toggle; force explicit
  choice.** When `useDedicatedCert` flips from false → true,
  the form clears the ACMEChallenge to `""` and the
  selector renders with no option pre-selected. The submit
  button is disabled until the operator picks one. Pros:
  no silent data loss; the operator's intent is fresh on the
  next ACME challenge. Cons: one extra click on every opt-out.

- **Option C — Local-storage / IndexedDB cache of the last
  per-route choice keyed by route id.** Survives across form
  loads. Pros: best continuity. Cons: per-browser state; an
  operator working from a second device sees the default.

**Recommendation.** Option B — the "force explicit choice"
shape matches the spec's broader posture of surfacing
operator decisions where they matter (D4.A loud unconfigured,
AC #21 revertTo dropdown). The single extra click is
proportional to the consequence — picking the wrong cert
type triggers a real ACME challenge with rate-limit cost.

**Triage.** UX paper-cut. Not a blocker for O.5 / tag. Worth
fixing in a follow-up chunk before any external user faces it.

## 2. Testability trade-offs

### Finding #O.5-1 — Live wildcard issuance smoke is structurally blocked by the caddymgr→OVH coupling

Surfaced during the O.5 plan review and confirmed by the live
smoke. The caddymgr emits the wildcard TLS policy with
`provider.name = "ovh"`, which certmagic dispatches to the
upstream OVH provider module (`certmagic-dns/ovh` via
`dns.providers.ovh`). That module makes outbound HTTP calls to
the OVH API (`https://eu.api.ovh.com`) to set / clear the
`_acme-challenge` TXT record during the DNS-01 dance.

Without real OVH credentials + a real OVH-managed DNS zone,
the DNS-01 challenge cannot complete. The Pebble-only path
considered in the O.5 plan (Option A) does NOT unblock this:
Pebble would be a happy ACME server, but the OVH provider
module would still try to call the real OVH API with fake
credentials and fail before the TXT record ever lands.

**Result for the smoke:** AC #1 (single ACME challenge covers
N routes), AC #2 (apex SAN included), AC #8 (DNS-01 unavailable
fallback), and AC #15 (J unchanged — live J-era per-route
HTTP-01) all stayed PARTIAL with citation to:

- `internal/caddymgr/managed_domain_emission_test.go::TestBuildConfigJSON_LoadsCleanly_WithManagedDomain` — exercises `caddy.Validate` on the emitted config, provisioning every module including `dns.providers.ovh`.
- `internal/caddymgr/managed_domain_emission_test.go::TestBuildConfigJSON_ManagedDomain_NoProvider_InternalIssuer` — pins the D4.A internal-CA fallback when DNS provider is unconfigured.
- `internal/caddymgr/managed_domain_emission_test.go::TestBuildConfigJSON_ManagedDomain_EmitsWildcardPolicy` — pins the multi-SAN cert shape (D2.C IncludeApex toggle).
- `internal/caddymgr/managed_domain_emission_test.go::TestBuildConfigJSON_ManagedDomain_ReloadPreserves` — pins AC #14 deterministic JSON across reloads.
- `internal/api/managed_domain_test.go` — pins the full REST integration surface.

**Future paths to a true live cert-issuance smoke.**

- **Option A — Refactor caddymgr for a mockable provider at
  test time.** Introduce a provider-name → certmagic-module
  registry on `*CaddyManager` that tests can override with a
  fake-DNS provider (uses challtestsrv internally; updates the
  TXT record at a local DNS responder Pebble can validate
  against). Pros: full live issuance in CI / smoke; no
  external dependencies. Cons: caddymgr surface change; the
  test-only override must not leak to production code paths.

- **Option B — Real LE-staging account + dedicated DNS zone.**
  Spin up an LE staging registration + a real OVH (or
  Cloudflare via D3.B forward-compat) zone reserved for
  Arenet smoke. Pros: end-to-end fidelity. Cons: costs (zone
  registration), LE-staging rate-limit account-bound, test
  determinism harmed by network flakiness, secrets management
  for CI.

- **Option C — Manual periodic smoke against a homelab
  operator's real zone.** Document the steps in this backlog;
  the project maintainer runs them quarterly. Pros: zero CI
  cost. Cons: not deterministic, no regression gate.

**Recommendation.** Option A when (a) a second DNS provider
lands (Cloudflare via D3.B forward-compat) and there's
genuine integration to test, OR (b) a J→O regression bug
surfaces in the wild that the existing unit tests didn't
catch. Until then, the layered defence (unit tests +
caddy.Validate provisioning + REST integration tests) is the
right ROI for a homelab project.

**Triage.** Architectural trade-off, documented for future
reference. No functional bug today. The O.5 smoke verdict
PARTIAL on AC #1/#2/#8/#13/#15 reflects this trade-off
honestly per the spec §5.5 "PARTIAL acceptables sur cas
documentés" guidance.
