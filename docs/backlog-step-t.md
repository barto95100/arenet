# Step T — Backlog

Items deferred from Step T work. Same convention as
`docs/backlog-step-s.md` / `docs/backlog-step-r.md`.

## 1. Deferred features

### Finding #R-CERTS-force-renew — Force-renew button + endpoint — DEFERRED (Step T amendment, 2026-06-05)

**Status**: DEFERRED.

- Originally part of Step T (AC #3, #7, #8 / T.2 / T.3 of the
  frozen spec `v1.2.0-step-t-spec`, commit `9a34eb1`).
- Dropped because Caddy v2.11.3's renewal seam is unexported:
  `caddytls.TLS.getConfigForName` at
  `modules/caddytls/tls.go:853` is private, and no public
  `ForceRenew` / `RenewSync` method exists on `*caddytls.TLS`.
  `certmagic.NewDefault()` returns a `Config` with package
  defaults (wrong issuers/storage/DNS provider), so it would
  fail or accidentally issue against LE prod with no DNS-01
  support.
- Workarounds considered (vendor patch, local fork, upstream
  fork, storage-delete, `go:linkname`) all have unacceptable
  trade-offs for current bandwidth — full table in
  `docs/step-t-spec-amendment.md`.
- certmagic's built-in automatic-retry mechanism (exponential
  backoff in `certmagic/maintain.go`) covers the functional
  cases. Operator workflows for the recovery paths the button
  was meant to address (restart Arenet after fixing root cause;
  delete + recreate the managed domain via the Pack A SSL
  editor) remain available.

**Revisit conditions** (documented in full in
`docs/step-t-spec-amendment.md` §"Future Revisit Conditions"):

1. Upstream Caddy accepts a PR exporting `GetConfigForName` —
   eliminates the seam constraint.
2. Operator decides to maintain a `barto95100/caddy-arenet`
   fork with the patch, accepting the bump-maintenance tax.
3. A new Caddy minor version exposes a cleaner renewal API.

Cross-references:

- Amendment: `docs/step-t-spec-amendment.md`
- Frozen spec (unchanged):
  `docs/superpowers/specs/2026-06-04-step-t-certificates-runtime-refactor.md`
  at tag `v1.2.0-step-t-spec` (commit `9a34eb1`).
- T.1 ship: commit `1350777`.

## 2. Followups

### Finding #R-CERTS-reconcile-from-managed-domains — Periodic tracker reconcile against authoritative apex list

**Status**: deferred (post-T.5 hotfix scope).

Today the certinfo tracker is purged in only two ways:

- API DELETE managed-domain handler calls
  `tracker.Remove(domain)` for `*.<apex>` (+ `<apex>` when
  `includeApex`) after a successful caddy reload. Shipped in
  the post-T.5 purge hotfix.
- Restart (the tracker is process-local, reconciled from
  disk at boot via `ReconcileFromDisk`).

Gap: any path that mutates the managed-domain set BEHIND the
HTTP handler's back — bbolt corruption recovery, manual
storage edit, future bulk-import endpoint, future
`/api/v1/settings/managed-domains` PATCH that flips
`includeApex` without going through the DELETE → POST cycle
— would leave a ghost tracker entry that only a restart can
clear. The current scope has no such path, so the gap is
latent, not active.

**Shape of the fix** when needed:

A periodic `ReconcileFromManagedDomains(tracker, []ManagedDomain)`
walker that, given the authoritative apex list, purges any
tracker entry whose domain isn't covered by ANY current apex
AND whose status is `OBTAIN_FAILED`. Restricting to
`OBTAIN_FAILED` is the safety belt: a `VALID` entry for a
non-managed route (a route with TLSEnabled=true but no apex
matching) is legitimate and must not be purged.

**Triggers** (when to revisit):

1. A second purge path lands (bulk-import, PATCH, restore-
   from-backup) — at that point the per-handler
   `tracker.Remove` pattern becomes too narrow.
2. Operator reports a ghost row that survived a managed-
   domain delete without a restart — would mean the
   per-handler path missed an edge case.

Until then the per-handler purge is sufficient and avoids
the periodic-tick footprint.

Cross-references:

- Post-T.5 hotfix: `tracker.Remove` introduction +
  `internal/api/managed_domain.go` purge call.
- T.1 ship: commit `1350777` (the tracker the reconcile
  would walk).

### Finding #R-CERTS-challenge-heuristic — Per-cert ACME challenge inferred from domain string instead of backend-supplied

**Status**: known limitation (works correctly in 100% of
AreNET-configured paths today; promotion is a UX-purity
exercise, not a bug fix).

The Domaines table's `<source> · <challenge>` sub-line uses
`inferChallengeLabel(source, status)` (in
`web/frontend/src/lib/utils/certificate-format.ts`):

- `wildcard` → `DNS-01` (the only path certmagic can use
  for `*.x.tld`).
- `specific` / `apex` → `HTTP-01` (the default).
- `OBTAIN_FAILED` non-wildcard → `—` (no successful obtain
  to learn from; added by the c6013f2 polish hotfix to
  avoid claiming "HTTP-01" for a cert that hasn't actually
  reached that challenge).

The heuristic is operator-correct in every shipped AreNET
configuration because the codebase only ever issues DNS-01
for wildcards. The promotion path — when warranted — is to
have the backend stash the actual challenge used per cert
on the `CertRuntimeInfo` wire shape (would require
certmagic Issuer introspection at cert-obtained time, plus
schema migration on the JSON tag).

**Triggers** (when to promote):

1. A future cert source ships that doesn't follow the
   wildcard-DNS-01 / specific-HTTP-01 split (e.g.
   per-route DNS-01 for staging zones; pre-loaded certs
   from non-ACME issuers).
2. Operator reports a cert misclassified — the heuristic
   doesn't have a fallback for "this cert was obtained
   via a challenge that conflicts with our rule of thumb",
   so a misreport surfaces as a sub-line that lies.

Until then the heuristic stays. Cross-reference:
`web/frontend/src/lib/utils/certificate-format.ts`
`inferChallengeLabel` — the polish that gave it the
status-aware `—` fallback is commit `c6013f2`.

### Finding #R-API-boot-log-audit — Generalize the `purger_present` boot-log pattern to other API setters

**Status**: actionable cleanup (latent risk only; no
incident reported beyond the one HF4 already addressed).

The 2026-06-05 smoke that drove HF4 (commit `30418ea`)
revealed a class of bug: an API setter is wired in
`cmd/arenet/main.go`, the build is clean, the unit tests
use a stub that satisfies the interface — but the deployed
binary silently no-ops the setter call (binary version
mismatch, refactor that dropped the wire-up, interface
narrowing). HF4 fixed the specific case by emitting
`msg="api handler wired with cert tracker"
purger_present=true` at boot.

Other API setters carry the same shape and would benefit
from the same boot-log signal:

- `SetMetricsReader` — `h.metrics` field; observability
  store pointer.
- `SetWafEventReader` — `h.wafEvents` field.
- `SetThrottleEventReader` — `h.throttleEvents` field.
- `SetDecisionReader` — `h.decisions` field.
- `SetAuthFailureReader` — `h.authFailures` field.
- `SetHCStatusReader` — `h.hcStatus` field.
- (`SetCertInfoReader` already covered by HF4.)

**Shape of the fix** when scheduled:

Pattern-match HF4: add `Has<Reader>Wired() bool` getters
on `*Handler`, log a single structured line in
`cmd/arenet/main.go` after the setter cluster:

```go
logger.Info("api handler wired with readers",
    "metrics_present",      apiHandler.HasMetricsReader(),
    "waf_events_present",   apiHandler.HasWafEventReader(),
    "throttle_present",     apiHandler.HasThrottleEventReader(),
    "decisions_present",    apiHandler.HasDecisionReader(),
    "auth_failures_present", apiHandler.HasAuthFailureReader(),
    "hc_status_present",    apiHandler.HasHCStatusReader(),
    "cert_info_present",    apiHandler.HasCertInfoPurger(),
)
```

One log line at boot; any future wire-up regression
surfaces as `..._present=false` in journalctl instead of
a silent degraded-mode response.

**Why latent, not urgent**: every reader above already has
a nil-tolerance contract in its consuming handler (AC #13
degraded-mode policy applied uniformly across Step L / M /
Q). A missing setter degrades the endpoint but doesn't
crash anything. The risk is *operator confusion* when
debugging a degraded endpoint, not a data-integrity bug.

**Effort**: ~30-45 minutes (mechanical — 6 getters + 1
log line + 6 trivial unit tests mirroring
`TestHasCertInfoPurger_NilWhenUnset`).

Cross-references:

- HF4 precedent: commit `30418ea` —
  `internal/api/handler.go` `HasCertInfoPurger` getter +
  `cmd/arenet/main.go` boot log.
