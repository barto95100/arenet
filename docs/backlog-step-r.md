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

### Finding #R-2 — Sidebar collapsed/expanded state removed

Step F shipped a localStorage-persisted collapsed sidebar mode
(`arenet_sidebar_collapsed`, 64px collapsed / 256px expanded).
R.2 removes it: the new mock at
`docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:54-88`
specifies a fixed 232px sidebar with no collapse button, by
design. The R.2 sidebar matches that.

**Operational consequence**: operators who used the Step F
collapse (smaller screens, multi-monitor workflows where the
sidebar felt heavy) lose that affordance. The chrome footprint
in v1.4 is 232px fixed at all viewport sizes ≥ the desktop
threshold.

**Re-introduction shape** (if demand emerges):

- Restore the `collapsed` bindable prop on `Sidebar.svelte` and
  the `arenet_sidebar_collapsed` localStorage key.
- Design the collapsed state: 64px-ish width, icon-only nav
  items, sidebar-foot reduced to avatar only, no nav-section
  labels. The mock provides NO design for this — a fresh
  micro-design pass is needed to match the OKLCH visual.
- Re-add the chevron toggle button. The mock's sidebar has no
  obvious place for it; design choice required.
- Re-introduce the Tooltip wrap on collapsed items so labels
  surface on hover.
- Update `Sidebar.test.ts` with the collapse-cycle test
  coverage (the Step F tests for this lived at lines 75-112 of
  the old test file — removed in R.2.5 because the feature is
  gone).

**Recommendation.** Don't re-introduce speculatively. If a user
asks for it (or smoke testing on smaller laptop screens reveals
the friction), open a focused step to do the design + impl
together. Until then the fixed-width sidebar is the v1.4 norm.

**Triage.** Acknowledged feature regression. The mock-driven
brief takes precedence in R; if the regression is felt, the
fix path is well-scoped here.

### Finding #R-3 — Topbar notifications icon hidden

R.2's Topbar omits the notifications bell icon entirely. The
mock shows it (`docs/superpowers/mocks/2026-05-31-step-r-
aesthetic.html:739`) with a badge count. The omission is
deliberate: with the alerting step deferred to
`docs/superpowers/specs/_deferred/2026-05-31-step-r-alerting.md`,
there is no `/alerts` endpoint or route to deep-link from the
bell. Pointing it at `/security/decisions` would be
semantically wrong — notifications represent operator-facing
alerts (something needs attention), decisions represent
enforcement actions (a block was applied). Different surfaces.

**Re-introduction shape** (alongside the alerting step):

- Restore the notifications button in `Topbar.svelte`.
- Wire the badge count to the alerting source (whatever the
  alerting step lands — likely a `/v1/alerts/unread` count
  endpoint).
- Deep-link to the new `/alerts` route or a notifications
  panel overlay (the alerting spec covers the choice).

**Triage.** Mock-feature visually hidden, no functional regression
(the feature didn't exist before R either). Re-emerges with the
alerting step.

### Finding #R-7 — Per-route metrics drill-down at /observability/[routeId]

R.4.5 redirects `/observability` (index) to `/dashboard` but
PRESERVES `/observability/[routeId]/+page.svelte` — the
per-route metrics drill-down (Step L.4). Reason: the new
`/dashboard` shows global aggregates; it does NOT replace the
per-route metrics view (timeseries per single route, p95 per
route, etc.). Folding it into `/dashboard` would have expanded
R.4.1 scope significantly.

The drill-down currently:
- Sits at the legacy URL (no longer reachable from the new
  sidebar — `/observability` index redirects).
- Renders in the legacy HEX-cyan visual (R.1 token swap means
  the cyan reads as the new purple-blue, but the layout is
  still Step F-era).
- Lacks an explicit entry point in v1.4 — operators must
  type the URL directly OR get there via a future Dashboard
  drill-down link.

**Completion shape** (focused future step):

- Either restyle `/observability/[routeId]` in the new visual
  + add a "Drill down →" link from Dashboard's "Top routes"
  rows OR fold the content into a `/dashboard/[routeId]`
  route (more aggressive IA reorg).
- Tracks alongside the topology time-window selector + log
  GeoIP work in a future observability-themed step.

**Triage.** Hidden but functional. Tokens cascade so the
visual isn't broken, only stale. No regression (the page
worked before, works now, just not surfaced).

### Finding #R-6 — Move SSL editor from /settings to /certs

D5's strict reading was "move `/settings/certificates` → top-level
`/certs`": full extraction of the SSL editor (managed-domains
CRUD form) to the new top-level route.

R.4.4.b adopted a **softer split** for v1.4 — the SSL Card
(managed-domains CRUD form + DNS provider unconfigured banner)
stays in `/settings`, and `/certs` ships as a read-only summary
that links back to `/settings` for editing. Reason: moving the
editing workflow in the same step that restyles the whole UI
would compound the operator disruption (visual change + workflow
displacement landing together = two unrelated migrations
colliding). The read-only `/certs` summary already satisfies the
IA reorg goal (top-level Sécurité entry for cert visibility).

**Completion shape** (focused future step):

- Move the entire SSL/Certificates Card from
  `web/frontend/src/routes/settings/+page.svelte` to
  `web/frontend/src/routes/certs/+page.svelte`.
- Move associated state from settings's `<script>` block:
  `managedDomains`, `managedDomainsLoading`,
  `managedDomainsLoadError`, `sslDNSUnconfigured`, all the
  `md*` form state, the declare/delete actions, the
  `ConfirmDialog` for `mdDeleteApex`.
- Update the link copy in `/settings`'s now-empty section
  ("Managed domains live at /certs" — or remove the section
  entirely).
- Verify the DNS provider unconfigured banner still cross-
  references the DNS provider section in `/settings`.
- Update `docs/backlog-step-r.md` to close this finding.

**Recommendation.** Bundle into a focused future step OR roll
into the next cert-themed work (e.g. when adding ACME provider
diversity beyond OVH, or when extracting per-cert runtime
metadata per #R-CERT-meta). Until then the softer split is
the v1.4 norm: operators edit in `/settings`, view in `/certs`.

**Triage.** D5 deviation acknowledged. The IA reorg goal IS
met (top-level Sécurité entry, separation of viewing from the
settings configuration grid). Only the editor location is
deferred for operator-disruption hygiene.

### Finding #R-5 — Service registry / route-by-service tagging

R.4.1's Dashboard "Services amont" card aggregates by distinct
upstream URL (e.g. `10.0.4.12:8080`, `s3://arenet-static`)
because that's what the backend exposes today. The mock at
`docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:914-928`
aggregates by service *name* (`api-core`, `web-app`, `auth-svc`,
`media-cdn`, `ws-gateway`, `billing-api`, `notification`) with a
per-service health rollup and instance count. The backend has no
concept of a "service" today — only routes pointing at upstream
URLs.

**Operational consequence**: the v1.4 Services amont card reads
as a list of backend URLs rather than the higher-level service
inventory operators think in. Acceptable for v1.4 (the data IS
real), but the operator mental model "I have 3 api-core
instances, 1 currently degraded" can't be surfaced.

**Feature shape** (future step):

- Add a `Service` entity: `internal/storage/service.go` with
  `id` / `name` / `description` / `tags`. CRUD endpoints under
  `/api/v1/services`.
- Add `serviceId` (nullable) on `Route` (and via cascade on
  `Upstream`), plus an optional UI affordance to tag a route
  with its owning service.
- Health rollup endpoint: `GET /api/v1/services` returns each
  service with `instanceCount` (count of upstreams across all
  routes tagged with it), `degradedCount`, `medianP95Ms`
  derived from observability per-route metrics.
- Update the dashboard card to render the service-name view
  when at least one service is defined; fall back to the
  current per-upstream-URL view otherwise.

**Recommendation.** Bundle into a focused future step if/when
operators ask for the service-inventory mental model in preprod
or production. Until then the per-URL view is the operator-
truth surface.

**Triage.** Backend feature gap, not a regression. Documented up
front to track the resolution shape if demand appears.

### Finding #R-4 — Topbar Déployer button is cosmetic

R.2's Topbar ships the Déployer button disabled with a "Bientôt
disponible" tooltip. The mock shows it as the primary action
button on every page. The real action — reload Caddy / apply
staged config / commit pending route changes — is feature work
outside the aesthetic migration scope.

**Implementation shape** (future step):

- Wire the button to a backend action that flushes any staged
  configuration. Today route mutations write through directly
  to Caddy (`internal/caddymgr/`); the "staged config" concept
  doesn't currently exist as a first-class entity. The button
  implies a workflow where edits accumulate and require an
  explicit deploy gesture — that workflow needs design work
  before implementation.
- Likely surfaces: `internal/caddymgr/staging.go` (new), `/api/
  v1/config/deploy` (new), Topbar.svelte action handler, status
  feedback while the deploy runs (loading bar via the existing
  `loading` store).
- Disabled state when no pending changes: read a `pendingChanges`
  count from a new endpoint; button disabled when count=0.

**Recommendation.** This is a meaningful UX/architecture step on
its own (staging concept + apply gesture). Bundle into a future
step focused on configuration workflow if/when operators ask for
the staged-edits pattern. Until then the direct-write model is
the v1.x behaviour.

**Triage.** Mock-feature shown as disabled visual; no functional
regression. Clear future-feature shape documented.

---

## 2. (Reserved for further items discovered during R.3-R.5)

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
