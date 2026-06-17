# Step X — OWASP CRS per-route customisation

> **Status: DESIGN 2026-06-17.** Spec only — no implementation
> in this commit. Workstream un-tagged because the letter-naming
> convention (Step A..AL) is contiguous and the next free slot
> depends on which un-deferred step ships next. Referenced as
> "Step X" in this document; the tag is assigned at
> implementation time.
>
> The active reference for V1 scope is
> `docs/superpowers/decisions/2026-06-17-step-owasp-per-route-decisions.md`.

---

**Author**: Ludo + Claude.
**Predecessors**:
- Step I.4 — WAF mode (off / detect / block) per-route. Established
  the `Route.WAFMode` storage field and the per-route `arenet_waf`
  Caddy handler chain slot.
- Step M.1 — WAF events + per-rule categorisation
  (`internal/waf/category.go`). Established the operator-facing
  CRS rule taxonomy (SQLi 942xxx, XSS 941xxx, RCE 932/933/934/944,
  LFI 930/931, Protocol 911/920-922) that this step reuses for
  Option (b) category toggles.
- Phase 4.5 — `Route.UploadStreamingMode` (`#R-WAF-BUFFER-OOM-ON-
  LARGE-UPLOADS`). Established the additive per-route WAF flag
  pattern: storage field default-zero, idempotent migration not
  required (zero-value semantically matches pre-flag behaviour),
  emit conditional on the flag in `buildWAFHandler`.
- `internal/waf/module.go:adminAPIExclusionDirective` — the
  hardcoded CRS false-positive guard that today drops rule
  families 911/930/931/949 under `/api/v1/*`. The same Coraza
  primitive (`ctl:ruleRemoveById=<range>`) is the basis of
  Options (a)/(b)/(c) below.

---

## 1. Goal & scope

### 1.1 Goal

Today the OWASP CRS load (`load_owasp_crs: true` in every
`arenet_waf` handler) is **binary and global**: every route
with `WAFMode != off` loads the full CRS rule set. The directive
chain hardcoded in `caddymgr/manager.go:buildWAFHandler` is
identical across routes:

```
Include @coraza.conf-recommended
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
```

This is the right default for a homelab admin who wants
"protect everything", but it leaves three operator-visible
gaps :

1. **Legacy / private APIs** that don't need the CRS overhead.
   Loading the full rule set costs ~10 ms per request (cold
   path) and ~50 MB RAM per Coraza instance (warm pool). For a
   trusted internal API ("nas.lan", "prometheus.local") the
   protection / cost ratio is wrong — operator wants WAF off
   for CRS but still wants the per-route handler chain wired
   (so a future tighten is one toggle away).
2. **False-positive bursts** on a specific route. The operator
   sees rule 942100 firing on a legitimate SQL-heavy POST every
   request, knows the route is safe, but today's only fix is
   `WAFMode=off` for the whole route. That kills the OTHER rule
   families too (XSS, RCE, LFI). They want surgical exclusion.
3. **Wildcard routes serving many sub-apps** with heterogeneous
   threat profiles. A single `Route.WAFMode` covers every host
   in the route's matcher set, but the operator may want
   category-level differentiation by use case ("strict for
   the public PHP app, light for the static asset CDN").

Step X closes these gaps with **per-route CRS customisation**.

### 1.2 Sub-scope (3 sub-tasks — mirror M/Q/N/O/P/AL cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| X.1 | Storage + caddymgr emit | New `Route.WAF*` fields (exact set depends on the V1 option decision below). Idempotent boot migration (no schema version bump; Arenet's `internal/storage/migrate.go` pattern is per-field idempotent — zero-value defaults backfill at decode time). `buildWAFHandler` extended to consume the new fields and emit the right `load_owasp_crs` + directive chain. `computePoolKey` extended to include the new fields so the pool dedup stays sound. |
| X.2 | REST API + frontend UX | `POST/PUT /api/v1/routes` accept the new fields (additive; absent fields default-zero so pre-X clients keep working). Route form's "WAF" section gains the new controls. Confirm-dialog pattern reused from Step W (country block) when the operator toggles a security-reducing setting. |
| X.3 | Smoke + tag | Live smoke: create a route with the V1 option exercised, hit a known-CRS-tripping payload, verify the rule is in/out as configured. Multi-route smoke: verify `wafPool` size stays bounded (canonical normalisation, §4). Tag `v1.X-step-x`. |

### 1.3 OPEN decisions (to arbitrate at draft review)

The active arbitration moves to the ADR cited at the top of
this document; the "OPEN" section is preserved verbatim so the
audit trail explains the rationale.

#### D1 — Which option(s) ship in V1

Four options on the table. The ADR records the V1 choice; the
options stay documented here so V2 work can re-enter mid-stream
without an audit re-run.

---

## 2. Architecture options

### Option (a) — Toggle `load_owasp_crs` on/off per-route

**Effort estimate**: ~3-4 h backend (storage field + migration
no-op + caddymgr emit + tests) + 1-2 h frontend (toggle + tests).

**Storage shape**:

```go
type Route struct {
    // ...existing fields...

    // WAFLoadCRS (Step X.1) is the per-route opt-out from the
    // OWASP CRS rule set. true (default) = CRS loaded; false =
    // arenet_waf handler runs with @coraza.conf-recommended
    // only, no CRS families. Pre-X rows decode the zero-value
    // false → operator-visible "CRS off everywhere" which is
    // wrong; so the storage decode applies a default-true
    // backfill at read time (same pattern as the J.4
    // ACMEChallenge zero-value → "http-01").
    WAFLoadCRS bool `json:"waf_load_crs"`
}
```

**Backfill rule** (idempotent decode-time):

```go
// After deserialise — pre-X rows have zero-value WAFLoadCRS.
// Default to true so the security posture pre/post-X is
// byte-equivalent for routes that haven't been touched.
if !r.wafLoadCRSExplicit {
    r.WAFLoadCRS = true
}
```

The "explicit" tracking dodge is **not** added to the struct —
it's a decode-time helper. Alternative simpler shape: encode
the inverted flag.

```go
// WAFDisableCRS = true means "skip CRS loading". Zero-value
// (false) keeps the pre-X "load CRS" behaviour byte-equal
// without needing an explicit-tracking helper.
WAFDisableCRS bool `json:"waf_disable_crs,omitempty"`
```

The inverted-flag approach is the cleaner pattern (mirrors
`UploadStreamingMode`'s opt-in shape from Phase 4.5). The ADR
records the chosen polarity.

**Caddymgr emit**:

```go
out := map[string]any{
    "handler":  "arenet_waf",
    "route_id": routeID,
    "host":     host,
    "mode":     mode,
    "load_owasp_crs": !route.WAFDisableCRS,  // ← changed
    "directives": directivesForRoute(route), // see below
}
```

`directivesForRoute` returns:
- The current three Includes when `WAFDisableCRS = false` (most
  routes).
- Only `Include @coraza.conf-recommended` when `WAFDisableCRS =
  true` (CRS skipped).

`Coraza.conf-recommended` is the Coraza engine baseline — it
enables ModSecurity-compatible parsing but ships NO rules. So
"WAF on, CRS off" means "the handler is wired, request goes
through Coraza, but no rule fires" — which is exactly what
the operator wants for a "trusted internal API" route.

**Pool key change**:

```go
func (h *ArenetWafHandler) computePoolKey() string {
    hash := sha256.New()
    hash.Write([]byte(h.Mode))
    hash.Write([]byte{0})
    hash.Write([]byte(h.Directives))
    hash.Write([]byte{0})
    if h.LoadOWASPCRS {
        hash.Write([]byte("crs"))   // ← already present
    }
    return fmt.Sprintf("arenet-waf-%x", hash.Sum(nil))
}
```

Already CRS-aware (Step I.4 design captured this future
extension). **No code change to `computePoolKey` for Option
(a)** — the Directives diff (3 Includes vs 1) is enough; the
`LoadOWASPCRS` flag is the redundant safety net.

**Pool blast**: existing M ≤ 4 distinct (mode, directives,
crs) tuples. Option (a) multiplies the directives surface by
2 (full chain vs recommended-only). Worst case: M × 2 = 8
pools. Memory at 50 MB / pool warm = 400 MB peak. Acceptable
on the 4-8 GB homelab target; tight on 2 GB. Mitigation:
canonical normalisation (§4) keeps the pool count at the
number of distinct CRS-on/CRS-off pairs the operator
**actually configures**, not the theoretical max.

**Use case**: route API privée → CRS off → ~10 ms latency
savings per request + ~50 MB RAM freed once the cold pool is
GC'd. Posture clear: "WAF infrastructure wired (mode-aware
event sink + audit log + dashboard counter still fire on rule
trips IF any rule were loaded), but no rules → no trips → no
overhead beyond the per-request Coraza dispatch (sub-ms)".

---

### Option (b) — Per-route category toggles

**Effort estimate**: ~1-2 days (backend storage + migration + 7
distinct directive emit branches + frontend multi-select + tests
+ smoke).

**Storage shape**:

```go
type Route struct {
    // ...
    // WAFExcludeCategories (Step X) lists CRS category names
    // the operator wants STRIPPED for this route. Empty (default)
    // = every category active. Element values are the canonical
    // OwaspCategory strings from internal/waf/category.go
    // ("SQLi", "XSS", "RCE", "LFI", "Protocol", "Other").
    //
    // Implementation note : the underlying CRS rule ranges are
    // mapped from the category name via the SAME rule-range
    // table that CategoryForRule uses, so the operator-facing
    // category taxonomy in /security stays aligned with what
    // they can toggle here.
    WAFExcludeCategories []string `json:"waf_exclude_categories,omitempty"`
}
```

**Category → CRS rule-range table** (mirror of the empirical
mapping in `internal/waf/category.go:CategoryForRule`):

| Category | CRS rule IDs |
|---|---|
| `Protocol` | 911000-911999, 920000-922999 |
| `LFI` | 930000-931999 |
| `RCE` | 932000-934999, 944000-944999 |
| `XSS` | 941000-941999 |
| `SQLi` | 942000-942999 |
| `Other` | anything outside the ranges above (catch-all in `CategoryForRule`) |

The "Other" category exists in the operator's mental model
(via the `/security` WAF events table) but **excluding "Other"
is meaningless** — by construction it covers rules CRS itself
didn't categorise, so the rule-id space is not enumerable. V1
hides "Other" from the exclusion UI and rejects it
server-side as a 400 with `code: WAF_CATEGORY_NOT_EXCLUDABLE`.

**Caddymgr emit**:

```
SecRule REQUEST_URI "@rx ^.*$" \
    "id:200000,phase:1,nolog,pass,\
    ctl:ruleRemoveById=941000-941999,\
    ctl:ruleRemoveById=942000-942999"
```

(One generated SecRule per route, listing every range the
operator excluded as a comma-separated `ctl:ruleRemoveById=...`
chain. The 200000-range ID is reserved for Arenet-generated
exclusion directives.)

**Pool key change**: `computePoolKey` must hash the canonical
sorted exclusion set. Two routes with `[XSS, SQLi]` and
`[SQLi, XSS]` share a pool (sort lexicographically before
hashing).

**Pool blast**: 2^5 = 32 distinct combinations theoretically;
typically the operator uses 1-3 distinct patterns per
deployment so practical pool count stays under 6. With M=4
modes ⇒ up to 24 pools theoretical, ~10 typical. Memory
budget: 500 MB peak with the upper bound.

**Use case**: surgical operator who knows their threat model
("static asset CDN doesn't need SQLi rules") and wants a
mid-grain control between "all on" (Option a default) and
"specific rule IDs" (Option c).

**Risks**:
- Category mapping fragility: if upstream CRS adds a 945xxx
  range, Arenet's mapping table needs an update. Currently
  `CategoryForRule` falls through to `Other` for unknown
  ranges, so the operator's exclusion list silently misses
  new threats. Mitigation: pin the CRS minor version in
  go.mod with the doc'd category table, audit on bump.
- Inversion risk: an operator who excludes `Protocol` thinks
  "no protocol rules" but the inclusive range 911-922 also
  catches some "Other" rules that share IDs. Documentation
  needs to be explicit.

---

### Option (c) — Per-route rule-ID exclusion list

**Effort estimate**: ~1 day (backend + frontend freeform input
with validation + tests).

**Storage shape**:

```go
type Route struct {
    // ...
    // WAFExcludeRules (Step X) lists individual CRS rule IDs
    // the operator wants STRIPPED for this route. Empty
    // (default) = every loaded rule active. Each element is
    // a 6-digit decimal CRS rule ID (e.g. 942100).
    //
    // Use case : surgical false-positive fix. The operator
    // sees rule 942100 firing on legitimate traffic, knows
    // the route is safe, adds 942100 to this list.
    WAFExcludeRules []int `json:"waf_exclude_rules,omitempty"`
}
```

**Validation**: each ID must be in `[100000, 999999]`. Reject
duplicates server-side. Reject IDs in the Arenet-reserved
range `[100000, 200000)` (used by `adminAPIExclusionDirective`
+ future Arenet-generated SecRules).

**Caddymgr emit**:

```
SecRule REQUEST_URI "@rx ^.*$" \
    "id:200001,phase:1,nolog,pass,\
    ctl:ruleRemoveById=942100,\
    ctl:ruleRemoveById=920280"
```

**Pool key change**: canonical sort + hash of the rule-ID set.

**Pool blast**: practically unbounded by construction (the
operator can list any combination), but **realistically** the
operator only ever excludes 1-3 rule IDs per route after
hitting a real false-positive. Pool count typically ~5
distinct combinations in a fully-tuned deployment.

**Use case**: power user / SOC analyst tuning a specific
false-positive without the category nuke.

**Risks**:
- Operator footgun: the rule-ID space isn't discoverable from
  the form. Mitigation: link the form to a "recent WAF events"
  drawer so the operator can copy a tripping rule ID directly
  from the `/security/waf` event row.
- Drift: when CRS upstream renumbers a rule (rare but
  happens between major CRS versions), the operator's
  exclusion silently no-ops. Mitigation: Arenet logs a warning
  at boot when an excluded rule ID is not found in the loaded
  CRS rule set.

---

### Option (d) — Per-route paranoia level

**Effort estimate**: blocked upstream. Skip V1.

Coraza's CRS implementation reads the paranoia level from a
`tx.paranoia_level` setVar in `crs-setup.conf` evaluated at
**WAF construction time**, not per-request. Setting it per-
route would require either:
1. A separate WAF instance per (mode, paranoia, ...) tuple,
   which is what the pool already does — so in principle Option
   (d) is a `computePoolKey` extension. BUT the directive
   chain depth multiplies by the number of paranoia values (1
   through 4 = 4 variants), explosing the pool count by ×4.
2. A Coraza patch landing per-request paranoia support
   upstream. Out of scope for Arenet.

**Decision**: defer to V2 backlog. Document as `#R-WAF-
PARANOIA-PER-ROUTE` in `docs/backlog-step-x.md` once that
backlog file is created. Not on the V1 critical path.

---

## 3. Pool blast analysis

### 3.1 Current state (pre-Step X)

`wafPool` is a `caddy.UsagePool` keyed by `computePoolKey()` =
`sha256(Mode || Directives || crs?)`. Today:
- Mode ∈ {detect, block} (off-mode short-circuits before
  pool acquisition).
- Directives: hardcoded constant = identical across all
  routes.
- LoadOWASPCRS: hardcoded `true` across all routes.

⇒ Practical pool count = **2** (one per non-off mode).
Memory at 50 MB/pool warm = ~100 MB. Empirically validated
during Step I.7 smoke (5-route deployment).

### 3.2 Worst-case after each option

| Option | Distinct pool tuples added | Max practical pool count |
|---|---|---|
| (a) | × 2 (CRS on / off) | 4 |
| (b) | × 2^5 = 32 (category subsets) | ~ 8 (typical operator only tunes 1-3 patterns) |
| (c) | × (combinations of excluded IDs) | ~ 6 (typical operator excludes 1-3 IDs / route) |
| (a) + (c) | × 2 × 6 = 12 | ~ 8 typical |
| (a) + (b) | × 2 × 8 = 16 | ~ 10 typical |
| all three | × 2 × 8 × 6 = 96 | ~ 12 typical |

Memory at 50 MB/pool warm:
- typical Option (a) only : 200 MB
- typical Option (a)+(c) : 400 MB
- typical all three : 600 MB

Verdict: **(a) alone fits comfortably on the 2 GB lower
bound**. (a)+(c) needs the 4 GB homelab target as a soft
floor. Triple stack OK on 8 GB.

### 3.3 Canonical normalisation (mitigation)

**Critical for (b) and (c).** Without normalisation, two
routes with semantically-identical configs in syntactically
different shape would build separate pools:
- `WAFExcludeCategories: ["SQLi", "XSS"]` vs `["XSS", "SQLi"]`
- `WAFExcludeRules: [942100, 920280]` vs `[920280, 942100]`

Pre-pool-key step: sort the input slices in a canonical order
(lexicographic for categories, ascending for rule IDs), THEN
hash. Same-config routes share pool regardless of operator
input order. Cuts pool blast by O(N!) worst case.

Implementation lands in `buildWAFHandler` (canonical encode
before stuffing the JSON map) so the directive string the
handler reads is itself canonical — `computePoolKey` then
hashes the canonical directive string and stays unchanged.

---

## 4. Storage migration plan

**Correction to brief**: Arenet storage doesn't use numeric
schema versions ("V14 → V15" in the brief is the wrong
mental model). It uses **idempotent boot migrations** —
`internal/storage/migrate.go` registers per-field migration
helpers that scan the bucket, mutate any pre-format rows in
place, and are safe to re-run on every boot.

Examples already shipped: `migrateWAFEnabledToWAFMode` (I.4),
`migrateUpstreamURLToPool` (J.1), `migrateBasicAuthToAuthMode`
(K.1), `migrateUsersAuthSourceAndRole` (later).

**Step X plan**:

### 4.1 Option (a) — no migration needed

The polarity of the storage field decides this:
- **`WAFDisableCRS bool`** (inverted, default zero) ⇒ pre-X
  rows decode to `false` ⇒ "CRS not disabled" ⇒ load CRS ⇒
  byte-equivalent to pre-X behaviour. **No migration.**
- **`WAFLoadCRS bool`** (positive, default zero) ⇒ pre-X rows
  decode to `false` ⇒ "CRS not loaded" ⇒ regression. Requires
  either a migration (backfill `true` on pre-X rows) or a
  decode-time backfill helper.

ADR records the polarity choice; the inverted shape avoids
needing a migration at all.

### 4.2 Options (b) and (c) — slice fields, zero-value sound

`WAFExcludeCategories []string` and `WAFExcludeRules []int`
both decode as `nil` for pre-X rows. `nil` slice = "no
exclusions" = identical to pre-X "load all categories / all
rules" behaviour. **No migration needed.**

### 4.3 Boot-time validation

On every boot, the `internal/storage/routes.go` decode path
gains a defensive validator that:
- Rejects `WAFExcludeRules` IDs outside `[100000, 999999]`.
- Rejects `WAFExcludeRules` IDs in the Arenet-reserved range
  `[100000, 200000)` (collision with `adminAPIExclusionDirective`
  IDs 100001-100099, future-reserved 100100-199999).
- Rejects `WAFExcludeCategories` strings outside the
  enumerated `internal/waf/category.go` set, excluding
  `"Other"` (cf. §2 Option (b) rationale).

The validator runs on read AND on write (the API handler
shares the same validator). A stored row that violates a
validator added later (e.g., a future CRS-version bump
narrows the rule-id range) logs a warning and falls back to
the safe shape (treat the route as if the invalid exclusion
weren't there). No boot failure on invalid stored data —
operator-visible warning instead.

---

## 5. API shape change

### 5.1 GET `/api/v1/routes` (list + single)

Additive — new fields surface in the response, never absent:

```json
{
  "id": "...",
  "host": "...",
  "wafMode": "block",
  "wafDisableCRS": false,           // ← Option (a)
  "wafExcludeCategories": ["XSS"],  // ← Option (b), if shipped
  "wafExcludeRules": [942100],      // ← Option (c), if shipped
  ...
}
```

`omitempty` on the JSON tags so pre-X clients deserialising
to a struct without these fields don't fail. Existing
clients (Arenet's own frontend, `arenet-cli` if/when it
exists) ignore unknown fields.

### 5.2 POST/PUT `/api/v1/routes`

Additive — accept the new fields, default to zero / nil if
absent. The validator from §4.3 runs on POST/PUT and rejects
invalid input with a 400 carrying `code` =
`WAF_EXCLUDE_RULE_RESERVED` / `WAF_EXCLUDE_RULE_OUT_OF_RANGE`
/ `WAF_CATEGORY_NOT_EXCLUDABLE` etc., matching the existing
spec §11.9 error-code convention.

### 5.3 Backward compatibility

- Pre-X frontend (no awareness of the new fields) keeps
  working: server emits the new fields, frontend ignores
  them. CRUD round-trips lose the new fields, which the
  operator can re-set via the new frontend.
- Pre-X CLI (curl POST without the new fields): server
  defaults to zero / nil ⇒ CRS loaded everywhere ⇒
  byte-equivalent to pre-X behaviour.

---

## 6. Frontend UX

### 6.1 Route form — WAF section extension

Existing WAF section (`web/frontend/src/routes/routes/+page.svelte`)
has:

- Mode select : Off / Detect / Block
- Upload streaming toggle (Phase 4.5)

Step X adds (gated on V1 option scope):

- **(a) toggle "Disable OWASP CRS rules"** — labeled
  *"Désactiver les règles OWASP CRS pour cette route
  (recommandé seulement pour les APIs internes de confiance)"*.
- **(b) multi-select "Exclude categories"** — checkboxes for
  SQLi / XSS / RCE / LFI / Protocol. Tooltip on each one
  references `docs/wildcards.md`-style guidance.
- **(c) freeform input "Excluded rule IDs"** — comma-
  separated 6-digit IDs. Live validation (regex
  `^\d{6}$` + range check). Link to the `/security/waf`
  drawer so the operator can copy a tripping rule from a
  recent event.

### 6.2 Confirm dialog on security-reducing toggle

When the operator flips `WAFDisableCRS` from `false` → `true`,
OR adds entries to either exclusion list, surface a confirm
dialog **before** the save fires:

> ⚠️ Vous désactivez tout ou partie des règles OWASP CRS sur
> cette route. Cette action réduit votre posture de sécurité.
> Confirmez si vous comprenez les conséquences.

Mirror of the Step W (country block) confirm-dialog pattern.
Implements the "security regression risk" mitigation from §10.

### 6.3 Tooltip / helper copy

- *"CRS load_owasp_crs"* tooltip : "OWASP Core Rule Set — un
  ensemble de règles génériques qui détectent les attaques
  courantes (SQLi, XSS, RCE, LFI). Recommandé activé sauf
  pour des routes que vous contrôlez entièrement."
- *"Catégories exclues"* tooltip : "Désactive les règles CRS
  d'une famille spécifique. Conserve les autres familles
  actives. Utile quand une catégorie produit des
  false-positives récurrents."
- *"Exclusions par règle"* tooltip : "Désactive des règles
  individuelles par ID. Plus chirurgical que les catégories.
  Référez-vous aux événements WAF dans /security pour
  identifier les IDs à exclure."

---

## 7. Test strategy

### 7.1 Go unit tests (Step X.1)

Mirror of `internal/caddymgr/manager_test.go` patterns. New
file `internal/caddymgr/manager_waf_per_route_test.go`:

- `TestBuildWAFHandler_LoadCRS_Default_True` — pre-X-compatible
  route (zero-value WAFDisableCRS) → handler emits
  `load_owasp_crs: true` + three Includes.
- `TestBuildWAFHandler_DisableCRS_True` — WAFDisableCRS=true →
  handler emits `load_owasp_crs: false` + only
  `Include @coraza.conf-recommended`.
- `TestBuildWAFHandler_ExcludeCategories_Sorted` — input
  `["XSS", "SQLi"]` → emitted directive chain is the
  lexicographically-sorted shape (so pool key dedup works).
- `TestBuildWAFHandler_ExcludeRules_Sorted` — input
  `[942100, 920280]` → emitted directive lists IDs in
  ascending order.
- `TestComputePoolKey_DedupsByCanonicalDirectives` — two routes
  with same exclusions in different operator-input order
  produce the SAME pool key.
- `TestComputePoolKey_DistinctForDistinctCRSState` — Option
  (a) CRS-on and CRS-off routes produce DIFFERENT pool keys.
- `TestStorage_DecodePreXRoute_BackfillsSafely` — encode an
  old shape route (no new fields), decode, verify the runtime
  state is "CRS loaded, no exclusions".

### 7.2 Go integration tests

`internal/caddymgr/buildconfig_test.go` style:
- `TestBuildConfigJSON_PerRouteWAF_LoadsCleanly` — emit JSON
  for a multi-route deployment with mixed CRS state + verify
  `caddy.Validate()` passes.
- `TestBuildConfigJSON_PerRouteWAF_HandlersAllResolvable` —
  every emitted handler ID resolves against the registered
  Caddy module set (`internal/caddymgr/buildconfig_handlers_test.go`
  pattern from the J.7-era empirical-verification rule).

### 7.3 Vitest frontend tests

- `RouteForm.test.ts` extended: the new toggle / multi-select
  / freeform input render with the right initial state +
  validate input correctly.
- `RouteForm.test.ts` confirm-dialog : flipping
  `WAFDisableCRS` true triggers the dialog; cancelling
  reverts; confirming saves.
- `CertSourceBadge.test.ts` style snapshot for the badge
  variants the route table will surface to show the per-route
  WAF customisation state at a glance (deferred V2 polish).

### 7.4 E2E smoke (Step X.3)

Mirror of the Step I.7 + Step M.1 smoke harness :

- Boot arenet → create a route with `WAFDisableCRS: true` →
  hit `http://host/?id=1' OR '1'='1' --` → response is the
  upstream's normal response (no WAF block). Confirms CRS
  is actually OFF.
- Same boot → create a second route with
  `WAFExcludeRules: [942100]` → hit the same SQLi payload →
  the request passes BUT a different rule (920280, protocol
  enforcement) trips → confirms surgical exclusion works.
- Same boot → create a third route with default state →
  hit the SQLi → request blocked. Confirms baseline still
  enforces.
- `curl /api/v1/security/recent` → verify only the third
  route emitted a WAF event (the first two are silent by
  construction).
- Pool count smoke : the three routes above MUST share at
  most 3 distinct pools (one per distinct exclusion shape +
  one for CRS-off). Read the `wafPool` size via the existing
  observability hook.

---

## 8. Recommendation V1

Per the brief, the ADR records the V1 choice; this section
summarises the reasoning.

**V1 = Option (a) only.** Reasoning:

1. **Smallest blast radius**: 3-4 h backend + 1-2 h frontend.
   Fits the homelab-cadence Day 16 budget.
2. **Resolves the loudest operator pain point**: "I want to
   turn CRS off for one internal API but keep WAF on for the
   public ones". Empirical signal from the pre-v1.0 audit.
3. **No category-mapping fragility**: Option (b) takes a
   dependency on the CRS rule-id-range stability that's
   already a sleeping debt (see §2 Option (b) risks). V1
   avoids opening that drawer.
4. **No power-user-only surface**: Option (c) is the right
   tool for the surgical false-positive case but only ~5%
   of homelab operators ever hit one. Defer until the
   forum/issue tracker shows the use case is real.

**V2 candidates** (defer):
- Option (c) granular rule IDs — second tranche, ~1 day.
  Ship when the issue tracker has a real false-positive
  case on a stable arenet deployment.
- Option (b) per-category — third tranche, ~1-2 days.
  Ship when the user count justifies the
  category-mapping-table maintenance burden (Arenet stays
  pinned to one CRS minor version per release).
- Option (d) paranoia level — blocked upstream. Track via
  `#R-WAF-PARANOIA-PER-ROUTE` and revisit when Coraza ships
  per-request paranoia.

---

## 9. Backlog post-V1 (V2.x candidates)

`docs/backlog-step-x.md` will be created at V1 ship and seeded
with:

- `#R-WAF-CATEGORY-TOGGLES` — Option (b) ship plan.
- `#R-WAF-RULE-ID-EXCLUSIONS` — Option (c) ship plan (likely
  shipped as second tranche, may already be `RESOLVED` by
  the time V2 batch processes).
- `#R-WAF-PARANOIA-PER-ROUTE` — Option (d), blocked upstream.
- `#R-WAF-METRICS-PER-CATEGORY-EXCLUSION` — surface in the
  `/security/waf` dashboard which exclusions are configured
  per-route + how many trips were silenced by them. Visibility
  is currently zero ("the rule didn't fire" looks identical
  to "no attack"; without per-exclusion metrics the operator
  can't audit the exclusion's continuing necessity).
- `#R-WAF-RECOMMENDATIONS-ENGINE` — read the recent WAF event
  log + suggest exclusions when a single rule trips on a
  single route N times per hour with the operator-visible
  click-to-exclude pattern.

---

## 10. Risks + caveats

### 10.1 Security regression risk

An operator who toggles CRS off without understanding the
posture impact reduces their defence in depth. **Mitigation**:
the §6.2 confirm dialog + the audit log entry
(`waf_load_crs_changed`) + the dashboard surfacing of
"routes with CRS disabled" (deferred V2 polish, tracked as
`#R-WAF-DISABLED-ROUTE-COUNTER`).

### 10.2 Pool blast OOM on small server

The §3.2 worst case for the triple stack lands at ~600 MB
warm. Mitigation: V1 ships Option (a) alone (cap at ~200 MB)
+ canonical normalisation (§3.3) for any future stacking. The
2 GB lower-bound deployment target stays comfortable.

### 10.3 Category-mapping fragility (Option b only)

Already covered in §2 Option (b) risks. Mitigation: V1 doesn't
ship Option (b), so the risk is deferred. When Option (b)
ships, pin the CRS minor version in `go.mod` + add a boot-
time validation step that checks the configured CRS file
catalogue against the expected ranges.

### 10.4 Rule-ID drift on CRS upgrade (Option c only)

When upstream CRS renumbers a rule, the operator's
`WAFExcludeRules` entry silently no-ops. Mitigation: when
Option (c) ships, log a warning at WAF construction time for
every excluded rule ID NOT found in the loaded CRS rule set.
The boot log surfaces "rule 942100 excluded on route X but
not present in loaded CRS" so the operator can update.

### 10.5 Coraza onMatch callback unaffected

The mode-aware sink in `internal/waf/sink.go` keys on rule
ID, not category, so adding category-level exclusion (Option
b) doesn't break the event emission logic. The mode-aware
filter still applies: a Detect-mode route with `XSS`
excluded silently drops XSS rule trips before they reach the
sink (because Coraza's `ctl:ruleRemoveById` removes the
rule BEFORE the engine evaluates it).

---

## 11. Effort budget (mirror Step AL §1.2)

| Sub | Hours (V1 = Option a only) | Hours (V1 = a + c) | Hours (V1 = a + b + c) |
|---|---|---|---|
| X.1 storage + caddymgr | 3 | 5 | 8 |
| X.2 API + frontend | 2 | 4 | 7 |
| X.3 smoke + tag | 1 | 2 | 3 |
| Docs (this spec + ADR + backlog seed) | — (this commit) | +1 | +2 |
| **Total** | **6 h** | **12 h** | **20 h** |

Step AL took 4 days end-to-end (D14-D15 in the v1.x cycle);
Step X V1 = Option (a) lands in a single afternoon of focused
work. The estimate matches the pre-v1.0-audit signal
("3-4 h" for Option (a) alone) once frontend tests + smoke
are factored.

---

## 12. ADR cross-ref

Active decisions captured in
`docs/superpowers/decisions/2026-06-17-step-owasp-per-route-decisions.md`
(this commit). The decisions cover :

- V1 scope (Option (a) alone).
- Storage field polarity (`WAFDisableCRS` inverted opt-in vs
  `WAFLoadCRS` positive).
- Pool dedup strategy (canonical normalisation at directive-
  emit time, not at `computePoolKey` level).
- Confirm-dialog policy for the security-reducing toggle.
- Migration: none (idempotent decode-time default).

The doc is the active reference for implementation; this spec
is the audit trail for the options analysis + V1 / V2 split.
