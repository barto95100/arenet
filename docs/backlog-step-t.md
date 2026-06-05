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
