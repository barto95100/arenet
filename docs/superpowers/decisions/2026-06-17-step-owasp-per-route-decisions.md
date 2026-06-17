<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step X — OWASP CRS per-route V1: five design decisions

Date: 2026-06-17
Status: ACCEPTED (operator-pending, pre-code)
Related spec: `docs/superpowers/specs/2026-06-17-step-owasp-per-route.md`
Predecessors: Step I.4 (per-route WAFMode), Step M.1 (CRS category
taxonomy), Phase 4.5 (`UploadStreamingMode` additive per-route WAF
flag pattern).

## Context

The pre-v1.0 audit surfaced three operator-visible gaps around
the per-route WAF posture (cf. spec §1.1). The spec
proposes four architectural options (a/b/c/d). This ADR records
the five binding decisions for V1: scope, storage shape, pool
dedup strategy, security-reducing UX policy, and migration
plan.

The spec stays the audit trail for the options analysis. The
ADR is the active reference for implementation — the binding
values live here.

---

## D1 — V1 scope: Option (a) alone

**Decision**: V1 ships **Option (a) only** — the binary
`load_owasp_crs` toggle per route.

**Rejected**:
- Option (b) per-category exclusion — defer V2 batch, second
  tranche (~1-2 days). Reason: the category → CRS rule-range
  mapping has a sleeping-debt dependency on CRS minor-version
  stability (see spec §2 Option (b) risks). V1 avoids opening
  that drawer until the homelab user count justifies the
  maintenance burden.
- Option (c) per-rule-ID exclusion — defer V2 batch, third
  tranche (~1 day). Reason: surgical false-positive fixing is
  a power-user case (<5% of homelab operators per the
  pre-v1.0 audit's signal). Ship when the issue tracker has
  a concrete reproduction.
- Option (d) per-route paranoia level — defer indefinitely.
  Reason: blocked upstream — Coraza's CRS implementation
  evaluates paranoia at WAF construction time, not per-
  request. Tracked as `#R-WAF-PARANOIA-PER-ROUTE` in the
  Step X V2 backlog.

**Reasoning**:
- Smallest blast radius : 3-4 h backend + 1-2 h frontend, fits
  the homelab Day 16 cadence budget.
- Resolves the single loudest operator pain point empirically
  signalled by the pre-v1.0 audit ("turn CRS off for an
  internal trusted API but keep WAF mode wired").
- No category-mapping fragility (Option b debt).
- No power-user-only surface (Option c).

**Audit trail**:
- Spec §8 "Recommendation V1" lays out the rationale.
- The other options stay documented in spec §2 so a V2 work
  item can re-enter mid-stream without an audit re-run.

---

## D2 — Storage field polarity: `WAFDisableCRS` (inverted opt-in)

**Decision**: the new storage field is named
**`WAFDisableCRS`** and is **inverted** (default zero =
"don't disable" = CRS loaded). Wire shape:

```go
type Route struct {
    // ...
    WAFDisableCRS bool `json:"waf_disable_crs,omitempty"`
}
```

**Rejected**: the positive shape `WAFLoadCRS bool` with
default-true semantics. Reason: positive polarity requires
either a boot-time migration to backfill pre-X rows (extra
migrate function in `internal/storage/migrate.go`) or a
decode-time "explicit" tracker hack on the struct. The
inverted shape gives a free byte-equivalent default — pre-X
rows decode `false` ⇒ "not disabled" ⇒ load CRS ⇒ byte-equal
to pre-X behaviour. **No migration needed at all.**

**Reasoning**:
- Mirror of the `UploadStreamingMode` opt-in shape established
  in Phase 4.5 (`#R-WAF-BUFFER-OOM-ON-LARGE-UPLOADS`). Same
  zero-value-safe additive pattern.
- `omitempty` on the JSON tag keeps the wire shape pre-X-
  client-clean (the field is absent for routes that keep the
  default, which is the homelab norm).

**Audit trail**:
- Spec §4.1 "Option (a) — no migration needed" explains the
  polarity choice and its consequence for the migration
  surface.

---

## D3 — Pool dedup: canonical normalisation at directive emit time

**Decision**: when the directive string passed to
`buildWAFHandler` includes any operator-controlled list
(rule IDs, categories — future V2), the list is **sorted
canonically** in the `directivesForRoute` helper BEFORE the
string is built. The `computePoolKey` function stays
unchanged — it hashes the already-canonical directive
string.

**Rejected**: extend `computePoolKey` to take the raw lists
and sort there.

**Reasoning**:
- The directive string is what the WAF instance actually
  loads — two routes with the same canonical directive string
  share semantically-identical WAF state and MUST share the
  pool.
- Sorting at emit time is the right boundary: the storage
  layer keeps the operator-supplied order (audit trail),
  the emit layer normalises (deterministic pool keying), the
  pool keying stays a dumb hash.
- Avoids duplicate sort code if a future surface (e.g.
  diagnostics endpoint) wants to display the canonical
  directive string.

**Forward applicability**: this rule is V1-relevant only as a
forward-looking invariant — V1 = Option (a) has no
operator-controlled list, so the canonical-normalisation step
is a no-op. Captured here so V2 (Options b / c) inherit the
rule without re-debating.

**Audit trail**:
- Spec §3.3 "Canonical normalisation (mitigation)" describes
  the pool blast it avoids.

---

## D4 — Security-reducing toggle UX: confirm dialog + audit log

**Decision**: when the operator flips `WAFDisableCRS` from
`false` → `true` (and only in this direction), the route
form surfaces a confirm dialog **before** the save fires :

> ⚠️ Vous désactivez les règles OWASP CRS sur cette route.
> Cette action réduit votre posture de sécurité. Confirmez si
> vous comprenez les conséquences.

The save is gated on the operator confirming. The PUT also
emits an audit log entry with action `waf_load_crs_disabled`
(symmetric `waf_load_crs_enabled` on the reverse flip,
without dialog) carrying route ID + previous value + new
value + actor user ID.

**Rejected**:
- Silent save with audit-log-only trail. Reason: the audit
  log surfaces the change post-hoc; the dialog catches the
  fat-fingered click BEFORE the security regression lands in
  Caddy.
- Dialog on every save (including the reverse flip). Reason:
  re-enabling CRS is a security-IMPROVING action; gating it
  adds friction without benefit.

**Reasoning**:
- Mirror of the Step W (country block) confirm-dialog
  pattern shipped for the `default-allow` security-reducing
  mode flip. Same operator mental model: "Arenet warns when
  I'm about to weaken my posture, stays silent when I
  strengthen it."
- The audit log entry serves the post-hoc forensics use case
  (operator A enabled CRS, operator B disabled it 3 weeks
  later — who, when, on which route).

**Audit trail**:
- Spec §6.2 documents the dialog copy and the audit log
  action name.
- `internal/audit/*` already has `waf_mode_changed`; the
  new `waf_load_crs_disabled` / `waf_load_crs_enabled`
  actions land next to it.

---

## D5 — Migration plan: idempotent decode-time default, no boot migration

**Decision**: Step X V1 ships **without** a boot-time
migration function in `internal/storage/migrate.go`.
The default-zero semantics of `WAFDisableCRS = false` (D2)
makes pre-X rows decode to byte-equivalent runtime state:
"not disabled" = CRS loaded.

**Rejected**: add a `migrateRoutesBackfillWAFLoadCRS` helper.
Reason: with the inverted polarity (D2) there's nothing to
backfill — the zero value IS the correct pre-X state.

**Reasoning**:
- Each migrate helper added to `migrate.go` adds boot-time
  overhead (full bucket scan, even if no mutation needed).
  Avoiding the empty-work case respects the homelab Pi-class
  boot-time budget.
- Future polarity-change cases (e.g. if Option b adds
  `WAFExcludeCategories` later) get the same zero-value-safe
  treatment: `nil` slice = empty exclusion list = no SecRule
  emitted = pre-X-equivalent runtime.

**Audit trail**:
- Spec §4 "Storage migration plan" walks through the no-
  migration case for each future option.
- Spec §1.1 (under "Predecessors") notes the
  `UploadStreamingMode` precedent for the same pattern.

---

## Open items deferred to V2

- **Option (b) per-category exclusion** — `#R-WAF-CATEGORY-
  TOGGLES` in `docs/backlog-step-x.md` (file to be created
  at V1 ship).
- **Option (c) per-rule-ID exclusion** — `#R-WAF-RULE-ID-
  EXCLUSIONS`.
- **Option (d) per-route paranoia level** — `#R-WAF-
  PARANOIA-PER-ROUTE` (blocked upstream).
- **Visibility for disabled-CRS routes** — `#R-WAF-DISABLED-
  ROUTE-COUNTER` (dashboard widget surfacing "N routes have
  CRS disabled").
- **Per-exclusion metrics** — `#R-WAF-METRICS-PER-CATEGORY-
  EXCLUSION` (V2-relevant only once Option b/c ships).
- **Recommendations engine** — `#R-WAF-RECOMMENDATIONS-
  ENGINE` (auto-suggest exclusions based on observed false-
  positive rate).

The V2 batch processes these once the issue tracker has
real-world signal on which gaps the homelab community hits.

---

## Cross-references

- Active spec: `docs/superpowers/specs/2026-06-17-step-owasp-
  per-route.md`.
- Predecessor specs:
  `docs/superpowers/specs/2026-05-21-step-i-reverse-proxy-v1.md`
  (Step I.4 WAFMode), `docs/superpowers/specs/2026-05-28-step-
  m-security.md` (Step M.1 CRS taxonomy).
- Existing WAF surface: `internal/waf/module.go` (handler +
  pool key), `internal/caddymgr/manager.go:buildWAFHandler`
  (emit), `internal/waf/category.go:CategoryForRule` (rule-
  range → category mapping).
