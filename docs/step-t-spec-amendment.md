<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step T — Amendment: Force-Renew Deferred (2026-06-05)

## Context

After spec freeze at `v1.2.0-step-t-spec` (commit `9a34eb1`),
T.1 (backend cert-info bridge) shipped successfully at commit
`1350777`. T.2 (POST /api/certificates/renew) required per-domain
`*certmagic.Config` access to call `RenewCertSync(force=true)`.
Spec §9 explicitly parked the seam-discovery question for
implementation time. The empirical recon during T.2 kickoff found
the seam is not cleanly reachable from a public API.

## Seam Recon Findings (file:line citations)

Recon performed against vendored modules in `$GOMODCACHE`
(`github.com/caddyserver/caddy/v2@v2.11.3` and
`github.com/caddyserver/certmagic@v0.25.3`).

- `caddytls.TLS.getConfigForName` at `modules/caddytls/tls.go:853`
  — **UNEXPORTED**. The only method that maps a domain name to
  its per-policy `*certmagic.Config`.
- `caddytls.AutomationPolicy.magic` at
  `modules/caddytls/automation.go:174` — **UNEXPORTED**. The
  field holding the `*certmagic.Config` instance built by
  `AutomationPolicy.Provision`.
- `certmagic.Config.RenewCertSync(ctx, name, force bool)` at
  `config.go:809` — exported, but reachable only via a
  `*certmagic.Config` we cannot obtain from the public Caddy API.
- `certmagic.NewDefault()` at `config.go:184` — returns a `Config`
  populated from the package-level `Default` plus the default
  `defaultCache`. The resulting Config has the package default
  Issuers, Storage, ACME accounts, DNS provider — NOT the
  AreNET-configured ones. Using it would either fail (no DNS
  provider for our DNS-01 policies) or silently issue against
  Let's Encrypt prod using the wrong account, bypassing the
  staging/prod separation we maintain via `--dev`.
- No admin API endpoint for renewal exists in `caddytls` — a
  search of the package for `Manage`-class methods on `*TLS`
  yields only `Manage(subjects)` at `tls.go:561`, which calls
  `ManageAsync` and only renews if the cert is near expiry; it
  has no `force` parameter and cannot trigger a forced
  re-issuance of a still-valid cert.

Result: no clean public path exists from `caddy.GetApp("tls")`
to `RenewCertSync(force=true)` against the AreNET-configured
`*certmagic.Config`.

This is the same shape of "unexported boundary" as the
`caddytls.certCache` constraint already noted in spec §1.7 —
the same architectural friction that drove §1.7's locked decision
to use the event-driven + on-disk reconcile pattern for T.1.

## Workarounds Considered

1. **`go mod vendor` + patch**. Materialize the full vendor tree
   (~hundreds of MB across thousands of files), patch
   `vendor/github.com/caddyserver/caddy/v2/modules/caddytls/tls.go`
   to add an exported `GetConfigForName` delegating to the private
   method. Largest repo bloat; re-apply on every Caddy bump.
2. **Local fork via `replace` directive**. Add
   `vendor-patches/caddy-v2/` containing a full module copy with
   the same patch. Smaller blast radius than option 1 but still
   ~100MB; complicates Caddy bump workflow.
3. **Upstream fork on GitHub** (`barto95100/caddy-arenet`). Cleanest
   semantics but adds a second repo to maintain across every
   Caddy bump.
4. **Storage-delete approach**. Delete cert files at
   `<storage>/certificates/<issuer-safe>/<domain-safe>/`, let
   certmagic re-obtain on next TLS handshake (handshake path
   confirmed at `certmagic/handshake.go:782`). Not synchronous;
   introduces a downtime window where TLS handshakes fail.
   Operator-rejected for production-impact risk.
5. **Unsafe reflection / `go:linkname`**. Reach `getConfigForName`
   or `ap.magic` via the runtime. Fragile across Caddy versions,
   breaks on internal renames, hostile to empirical verification.
   Operator-rejected.

## Decision

**Defer force-renew functionality. Drop from Step T.**

certmagic already retries failed renewals automatically with
exponential backoff (`certmagic/maintain.go` renewal loop). For
the real-world failure cases the force-renew button was meant
to address, restart-Arenet or delete+recreate the managed domain
provides equivalent unblock without the seam constraint. The
force-renew button was UX convenience, not safety.

## What's Dropped

From the frozen spec (`v1.2.0-step-t-spec`):

- AC #3 (POST /api/certificates/renew endpoint contract)
- AC #7 (per-row "Forcer renouvellement" frontend action)
- AC #8 (header global "Forcer renouvellement" frontend action)
- §1.8 (Locked rate-limit posture — moot without an endpoint)
- §3.2 (force-renew endpoint contract — moot)
- §5.2 (T.2 implementation details — sub-task dropped)
- §9 (RenewCert seam reconnaissance — recon completed; result
  is this amendment, not an implementation)
- **T.2** (Force-renewal endpoint) — SKIPPED
- **T.3** (Force-renewal storage + rate limiting) — SKIPPED

## Operational Equivalents

Replacing the dropped feature operationally:

- **certmagic built-in retry**: exponential backoff
  (~2 min → 5 min → 15 min → 30 min, capped at the renewal
  window's cadence), continues until success or cert expiry.
  This already runs against every managed domain — no operator
  action needed.
- **Immediate retry after fixing root cause** (e.g. DNS-provider
  credentials repaired): restart Arenet. The next maintenance
  tick re-attempts every renewal-pending cert, clearing any
  pending backoffs.
- **Fresh obtain**: delete + recreate the managed domain via
  the Pack A SSL editor (already shipped, commit `06ba97a`).
  Triggers a brand-new cert request with no backoff history.
- **Let's Encrypt rate limits** are respected automatically by
  certmagic (50 orders / 3h / account, 5 failed orders / h /
  account).

Functionally complete without the button.

## Remaining Step T Scope

- **T.1** ✅ DONE — backend cert-info bridge (commit `1350777`)
- **T.2** SKIPPED — this amendment
- **T.3** SKIPPED — this amendment
- **T.4** Frontend unified Domaines table + tabs (no force-renew
  button in header or rows; the rest of the table layout is
  unchanged)
- **T.5** Frontend reframe + "+ Wildcard apex" wizard
- **T.6** Audit annotations + backlog seeding (incl this
  amendment)
- **T.7** Live smoke test (simplified — no force-renew
  verification phase)

Revised effort: ~8-12h remaining (was ~12-18h with T.2 + T.3 in
scope).

## Future Revisit Conditions

The force-renew feature may be reintroduced in a future step if
any of the following becomes true:

1. Upstream Caddy accepts a PR exporting `GetConfigForName`
   (or equivalent renewal entry point) — eliminates the seam
   constraint entirely.
2. Operator decides to maintain a `barto95100/caddy-arenet`
   fork with the patch, accepting the bump-maintenance tax.
3. A new Caddy minor version exposes a cleaner renewal API
   (e.g. a public `ForceRenew(name string) error` on `*TLS`,
   or a `RenewSubjects(map[string]struct{}, force bool)`
   variant of the existing `Manage`).

Until one of those holds, this amendment is canonical for
Step T scope.

## Frozen References

- **Spec freeze**: `v1.2.0-step-t-spec` (commit `9a34eb1`) —
  UNCHANGED. The spec file
  `docs/superpowers/specs/2026-06-04-step-t-certificates-runtime-refactor.md`
  remains the planned-shape record; this doc captures the
  shipped-shape divergence.
- **T.1 ship**: commit `1350777`.
- **Amendment commit**: this commit.
- **Backlog entry**: `docs/backlog-step-t.md` —
  `#R-CERTS-force-renew`.

This matches the closeout pattern established by Step J (commit
`f8b9c4b`): when the implementation diverges from a frozen spec,
the spec stays frozen as historical record and a sibling
amendment doc carries the diff.
