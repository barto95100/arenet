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
