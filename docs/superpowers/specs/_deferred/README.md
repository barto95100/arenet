# Deferred specs

Specs drafted and then set aside before freeze + implementation.
Two reasons a spec ends up here:

- **Better candidate found**: the work was pushed back so a higher-
  priority feature could take its step slot.
- **Pre-arbitration**: the spec was drafted but the decisions
  matrix never got arbitrated. Reopening the file later just
  needs the D1-Dn arbitrage to resume.

Each file here keeps its original filename + a `> **Status: DEFERRED**`
note prepended at the top with the date + the reason. If a
deferred spec gets reopened later, the file moves back to
`../` (the active specs directory) and the deferred-banner is
stripped during the un-defer commit.

## Historical un-defers

- **Step R alerting** un-deferred 2026-06-15 → see
  `specs/2026-06-15-step-al-alerting.md` (renamed **Step AL**
  to avoid collision with the Step R OKLCH visual migration
  shipped May 2026 at
  `specs/2026-05-31-step-r-oklch-migration.md`). The active
  ADR capturing the eight V1 decisions is at
  `decisions/2026-06-15-step-al-decisions.md`.
