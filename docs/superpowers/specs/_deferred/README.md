# Deferred specs

Specs drafted and then set aside before freeze + implementation.
Two reasons a spec ends up here:

- **Better candidate found**: the work was pushed back so a higher-
  priority feature could take its step slot (e.g. the alerting
  spec drafted as "Step R" was deferred when the OKLCH visual
  migration became the next priority instead).
- **Pre-arbitration**: the spec was drafted but the decisions
  matrix never got arbitrated. Reopening the file later just
  needs the D1-Dn arbitrage to resume.

Each file here keeps its original filename + a `> **Status: DEFERRED**`
note prepended at the top with the date + the reason. If a
deferred spec gets reopened later, the file moves back to
`../` (the active specs directory) and the deferred-banner is
stripped during the un-defer commit.
