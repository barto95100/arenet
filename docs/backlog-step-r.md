# Step R — Backlog

Items deferred from Step R work. Same convention as
`docs/backlog-step-p.md` / `docs/backlog-step-o.md` / etc.

## 1. Naming debt

### Finding #R-1 — `--accent-cyan` token name drift

After R.1's OKLCH migration, the CSS token `--accent-cyan` (and its
companion `--accent-cyan-d`, plus `--shadow-glow-cyan` and the
`--badge-info-*` family that derives from it) no longer holds a
cyan hue. Its OKLCH value is `oklch(68% 0.21 255)` — a purple-blue
accent matching the new mock direction. The identifier was kept
unchanged in R.1 because 90+ component references consume it; a
rename would be a wide cosmetic refactor with regression risk
during a step that explicitly aims for "aesthetic migration PURE,
zero functional change".

A new mock-naming alias `--accent` was added pointing at
`--accent-cyan` so new code (R.2 chrome, R.4 page markup) writes
the semantically correct identifier without touching the existing
references. Both names resolve to the same OKLCH value.

**Operational consequence**: a future maintainer reading
`tokens.css` will see `--accent-cyan: oklch(68% 0.21 255)` and
may be confused. R.1 prepends a comment block in
`web/frontend/src/lib/styles/tokens.css` flagging the drift
explicitly to mitigate.

**Cleanup shape** (focused future step, light but wide):

- Find-and-replace `--accent-cyan` → `--accent` across
  `web/frontend/src/` (~90 occurrences in `.svelte` / `.css` /
  `.ts` files).
- Same for `--accent-cyan-d` → `--accent-strong` (or similar —
  the `-d` suffix in Step F meant "darker" but the OKLCH
  equivalent is rather "more saturated", so the rename can
  also refine the semantic).
- Same for `--shadow-glow-cyan` → `--shadow-glow-accent`.
- Remove the now-pointless alias group from `tokens.css`.
- Run `npm run build` + `npm run check` to catch any reference
  miss.
- Visual smoke pass: confirm no page lost the accent
  (the rename is mechanical but a typo would result in a
  silently transparent or fallback-coloured element).

**Recommendation.** Bundleable into a future cleanup-themed step
(or a "Step T : visual debt" if one lands), OR run as a
standalone PR whenever the rename pressure builds. Low priority
operationally — the drift is documented in `tokens.css` so a
maintainer is warned before reading the surprising value.

**Triage.** Naming debt, no functional impact. Acceptable as a
known limitation of R.1's "preserve role-names to keep 90
references valid" tradeoff. Documented up front so it doesn't
surface as a surprise during R.4 per-page work or future
visual debt sweeps.

---

## 2. (Reserved for further items discovered during R.2-R.5)

The bulk of Step R's backlog candidates is the feature-gap list
already enumerated in the spec §6.3 "Backlog seeding" of
`docs/superpowers/specs/2026-05-31-step-r-oklch-migration.md`
(OWASP CRS granular toggles, manual IP lists, geo-blocking with
MaxMind, global TLS config UI, security headers UI, CSP nonce
injection, per-route paranoia, Caddyfile import, topology
historical replay, Logs GeoIP column, full Map page). Those are
listed in the spec to avoid duplication; they migrate to this
backlog file at the R.5 verdict commit, mirroring the M/N/O/P
pattern.
