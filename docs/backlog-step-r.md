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

## 2. Feature gaps (migrated from spec §6.3 at R.5 verdict)

Each entry was a mock-promised widget without a backend
implementation today. Step R shipped them as either omitted
sections or read-only placeholders; the resolution paths below
document what a future focused step would implement.

### Finding #R-WAF-categories — OWASP CRS category granular toggles

Mock promises per-category on/off + paranoia per category.
Backend has no toggle API (Coraza rule registry is read-only
from Arenet's perspective). Spec §6.1 /waf audit OUT-OF-SCOPE.
R.4.3.a shipped read-only event-count tiles with explicit
"granular control deferred" banner.

**Completion shape**: new `/api/v1/waf/categories` endpoint with
GET (list with enabled/disabled state) + PUT (toggle); BoltDB
storage for the override set; Coraza configuration emission
filtered by the override map.

### Finding #R-WAF-manual-iplist — Manual IP allow/deny lists

Mock shows operator-curated allow/deny IP/CIDR lists separate
from CrowdSec auto-decisions. Backend has no storage. Spec
§6.1 OMITTED.

**Completion shape**: new storage entity + CRUD endpoints, Caddy
matcher integration for the deny side, allow side bypasses both
WAF + CrowdSec gates (carefully scoped — allow-list overrides
are powerful).

### Finding #R-WAF-geo — Geo-blocking via MaxMind GeoLite2

Zero `geoip|maxmind|GeoLite` references in `internal/`. Requires
external dep (MaxMind SDK), DB file shipping/download, IP→country
middleware, country-list storage, handlers. Spec §6.1 OMITTED.

**Completion shape**: focused step given the MaxMind licensing
footprint (GeoLite2 is free with attribution; SaaS API or DB
download both have constraints to design around).

### Finding #R-SEC-tls — Global TLS config UI

`MinVersion|TLSVersion|Curves|CipherSuites|http3` returns ZERO
hits in `internal/caddymgr/`. Caddy supports all as built-ins
but Arenet uses Caddy defaults (no exposure). Spec §6.1 /security
shipped a read-only "Caddy defaults" card.

**Completion shape**: TLS policy storage + emission in caddymgr
config translation. Likely "edge TLS policy" step bundling with
#R-SEC-headers.

### Finding #R-SEC-headers — Security headers controller

HSTS / X-Frame-Options / X-Content-Type-Options / Referrer-Policy
/ Permissions-Policy: zero header injection middleware in the
handler chain. Spec §6.1 /security OMITTED (the page shows a
"not yet exposed" empty-state).

**Completion shape**: per-route + global header policy storage,
Caddy handler emission, frontend editor in `/security` (or
`/routes` detail for per-route override).

### Finding #R-SEC-csp — CSP with dynamic nonce injection

More substantial than static headers — per-request nonce gen +
template injection + CSP middleware coordination. Spec §6.1
/security OMITTED.

**Completion shape**: own focused step. Templating implications
(the nonce must propagate into emitted HTML responses).

### Finding #R-ROUTES-paranoia — Per-route WAF paranoia override

Coraza supports per-route paranoia internally but Arenet's
caddymgr emits a global setting only. Spec §6.1 /routes
flagged as a "static info" pill in v1.4.

**Completion shape**: extend `Route` shape with `wafParanoia`
field, caddymgr emission per-route, frontend control in routes
detail.

### Finding #R-ROUTES-caddyfile — Caddyfile import

`backup_handlers.go` has JSON import; symmetric Caddyfile import
not implemented. Spec §6.1 /routes OMITTED (the Import button
was removed from the mock-promised UI).

**Completion shape**: Caddyfile parser (Caddy's parser is
available as a library) + storage translation. Light backend
step.

### Finding #R-TOPO-window — Topology time-window selector + replay

Mock shows 5min / 1h / 24h selector + historical replay. Current
topology WS emits live-only. Spec §6.1 /topology OMITTED (live
view shipped without the selector).

**Completion shape**: historical topology data query against
observability aggregator, frontend replay player.

### Finding #R-LOGS-geoip — GeoIP country annotation per log row

Depends on #R-WAF-geo (MaxMind dep). Spec §6.1 /logs OMITTED
(country column empty in v1.4).

**Completion shape**: lands with #R-WAF-geo since both share the
MaxMind dep.

### Finding #R-MAP — Full Map page

`/map` ships as ComingSoon placeholder in v1.4. Full feature
needs MaxMind GeoLite2 + map rendering + marker logic for
sources of traffic + CrowdSec decisions geo-distribution.

**Completion shape**: future step bundling #R-WAF-geo +
#R-LOGS-geoip + the map UI itself.

---

## 3. Migration map

| Spec §6.3 seed | Backlog entry |
|---|---|
| WAF: OWASP CRS granular toggles | #R-WAF-categories |
| WAF: manual IP lists | #R-WAF-manual-iplist |
| WAF: geo-blocking MaxMind | #R-WAF-geo |
| Security: TLS config | #R-SEC-tls |
| Security: headers controller | #R-SEC-headers |
| Security: CSP nonce | #R-SEC-csp |
| Routes: per-route paranoia | #R-ROUTES-paranoia |
| Routes: Caddyfile import | #R-ROUTES-caddyfile |
| Topology: window + replay | #R-TOPO-window |
| Logs: GeoIP column | #R-LOGS-geoip |
| Map: full page | #R-MAP |

---

## 4. Topology v2 Stage B

### Finding #R-TOPO-upstream-metrics — real per-upstream instrumentation + p95 fanout

`#R-TOPO-v2-phase2` shipped Stage A: wire types + endpoints (HTTP
GET + WebSocket) with best-effort synthesised values where the
metrics pipeline doesn't expose them yet. The wire contract is
locked, the frontend consumes the payload directly — but some
fields reflect operator INTENT (configured weights) rather than
measured reality. Stage B replaces those without changing the
wire shape.

**Field-by-field gap (what Stage A ships vs what Stage B fixes)**:

| Wire field | Stage A | Stage B target |
|---|---|---|
| `upstreams[].reqPerSec` | route reqPerSec × weight share | real per-upstream counter |
| `upstreams[].p99LatencyMs` | route-level p95 echoed | per-upstream histogram |
| `upstreams[].fairnessRatio` | weight share | derived from real counts |
| `routes[].p99LatencyMs` | latest-tick p95 from the 60-slot ring | **true window p95** from raw bucket counts + p99 instead of p95 |

**Two-track implementation shape**:

**Track 1 — per-upstream measurement**. Caddy's `reverse_proxy`
selector chooses an upstream then dispatches; our metrics
middleware sees `RouteID` only (the chosen upstream isn't passed
back). Two viable paths:

- (a) Custom selector hook — register an Arenet wrapper around
  Caddy's selector that increments a per-(routeID, upstreamURL)
  counter on each pick. Cleanest, hottest path stays in-process.
  Requires understanding Caddy's selector module interface +
  registering as a Caddy module.
- (b) Admin-API polling — the existing `/reverse_proxy/upstreams`
  Caddy endpoint already returns `{address, num_requests, fails}`
  (Stage A uses it for the `status` field). Compute deltas
  between polls. Simpler, no Caddy module work, but address
  uniqueness across routes is a concern (one upstream URL
  shared by 2 routes lands in one cache entry).

Recommendation: (b) for v1 — the delta-polling against the
existing admin endpoint can ship without touching Caddy's
internals. If address-uniqueness becomes a problem in practice
(operators with shared backends), upgrade to (a).

**Track 2 — `metrics.TickConsumer` fanout for true window
p95**. The current `metrics.Ticker.SetConsumer` slot is single-
consumer (Step L's observability owns it). A small fanout
wrapper in `cmd/arenet/` would let both the observability
consumer AND the new topology consumer receive ticks. The
topology consumer's job: push the `Delta.LatencyP95Ms` field
(currently dropped from `RouteSnapshot`) into the
`SlidingWindow` so the per-tick p95s are kept and true window
percentiles can be computed.

Alternative: keep per-tick raw bucket counts in the window
instead of the post-p95 values. Then a window aggregate can
compute a real percentile across the merged distribution.
Heavier (17 buckets × 60 slots × N routes = 1020 × N counters
in memory) but statistically correct.

**Operational consequence of staying on Stage A**:

- Per-upstream traffic-share visuals (fairness bars) reflect
  configured weights, not actual picks. An operator wondering
  "why is upstream X getting less traffic than Y?" can't
  diagnose imbalance from the canvas — the bars just show the
  weight ratio.
- Per-upstream latency is uniform across a cluster on the
  canvas. A single slow backend within a healthy cluster
  doesn't visually stand out.
- `routes[].p99LatencyMs` is actually p95 — the spec permits
  this substitute. Numerically the gap is small for healthy
  routes; for tail-latency outliers (long-tail p99 distinct
  from p95), Stage A under-reports.

**Recommendation.** Focused future step when operator feedback
makes one of the above pain points concrete. Until then,
Stage A is honest about its limitations (documented in the
wire contract at `docs/api/topology.md` §Stage A) and the
canvas reads as designed.

**Triage.** Backlog feature, not a regression. The wire
contract stays stable across the Stage A → Stage B transition;
no frontend changes will be needed.

### Finding #R-TOPO-health-coherence — status "healthy" misleading without configured health check — RESOLVED in C6 (2026-06-03)

**Status**: RESOLVED in `#R-TOPO-v2-phase2` C6 with the v1.1.0
compromise scope. See "Resolution" block at the end of this
entry. Stage B follow-up tracked separately as
`#R-TOPO-real-health-probe` below.

---


Surfaced during the C4 browser smoke (`#R-TOPO-v2-phase2`).
`CaddyStatusProber` (in `internal/api/topology/caddyprobe.go`)
polls Caddy's `/reverse_proxy/upstreams` admin endpoint for ALL
routes regardless of whether the operator configured an active
health check on the route. The endpoint reports per-upstream
`num_requests` + `fails` counters maintained by Caddy
internally — those are NOT a user-configured health check; they
reflect whatever passive accounting Caddy does on its own
(`UnhealthyRequestCount` threshold, request fail count, etc.).

**Operational consequence**: a route with `healthCheck.enabled
= false` (no active health check configured) still shows
`status: "healthy"` in the topology canvas as long as Caddy
hasn't accumulated `fails > 0` for the upstream. Operators
reading the canvas could misinterpret this as "Arenet is
actively probing this upstream and it's healthy" when in
reality Arenet is doing no probing at all — the "healthy"
badge is just "Caddy hasn't tripped its passive failure
counter on this address yet".

The same issue applies on the `/api/v1/topology/snapshot`
HTTP endpoint and the stream WS — both call
`status.Status(url)` per upstream and inherit the same
ambiguity.

**Fix shape** (focused future step):

- `topology.BuildSnapshot` reads the route's
  `HealthCheck.Enabled` field. When false, force the
  upstream `status` to `"unknown"` regardless of what the
  `StatusLookup` reports.
- When true, keep the current behaviour (Caddy admin probe
  drives healthy/unhealthy).
- Frontend `_types.ts` `HealthStatus` enum already includes
  `"unknown"` — no wire-shape change.
- Update `docs/api/topology.md` §Stage A limitations to
  reflect the new semantics: "status is meaningful only for
  routes with active health check configured; routes
  without health-check config report `unknown`".

**Operational consequence of the fix**: routes with no health
check land in "unknown" by default. Operators wanting healthy/
unhealthy signal must enable the per-route active health
check in `/routes`. That's a feature-discoverability nudge,
not a regression — today's "always healthy until Caddy
notices" is silent dishonesty; "unknown until you configure"
is honest about the state.

**Triage.** UX/correctness gap, not a crash. Backlog
candidate for the next topology-themed step.

**Resolution (C6, 2026-06-03)** — operator's C6 browser smoke
elevated this from backlog to v1.1.0 blocker. The investigation
surfaced a deeper issue: even when the route has a health check
configured, the `/reverse_proxy/upstreams` admin endpoint
doesn't surface the active health-probe outcome, only the
passive `num_requests` + `fails` proxy-error counters. Mapping
`fails == 0 → healthy` was lying even for monitored routes
(Caddy stops sending traffic to an unhealthy upstream → its
`fails` counter stays at 0). The original fix shape (gate the
prober on `HealthCheck.Enabled`) was therefore necessary but
insufficient.

The v1.1.0-shipped compromise:

- `BuildSnapshot` ALWAYS emits `status: "unknown"` for every
  upstream. The prober is still polled (so the wire shape stays
  stable for Stage B) but the result is intentionally dropped
  in `buildRoute` — see `internal/api/topology/builder.go`
  docstring.
- A new wire field `Upstream.HealthCheckConfigured` (bool)
  mirrors the parent route's `HealthCheck.Enabled`. The
  frontend renders a small Lucide Activity (ECG-line) glyph
  next to the upstream URL when true, signalling "this
  upstream is being watched" without claiming anything about
  the probe outcome. (Originally specced as a shield glyph;
  swapped to Activity per Critique 12 — shield reads as
  security/WAF, Activity is the universal monitoring metaphor.)
- A companion wire field `Route.HasHealthCheck` (bool) carries
  the same signal at route granularity (currently consumed only
  via the denormalised upstream field, but available for any
  future per-route UI affordance).
- UpstreamNode lost its inner status dot in the same C6 pass
  (Critique 8) — the left-edge accent is now the sole status
  signal, color-coded gray for the universal `unknown` state.

**Operational consequence post-fix**: every upstream renders
gray-accented "unknown" until Stage B lands; routes with a
configured health check additionally show a Lucide Activity
(ECG-line) glyph so the operator can tell "this is monitored"
from "this isn't". No more misleading-green. Tracked in
`#R-TOPO-real-health-probe` below for the real probe
ingestion follow-up.

Files touched:
- `internal/api/topology/types.go` — added `Route.HasHealthCheck`,
  `Upstream.HealthCheckConfigured`. Both non-omitempty.
- `internal/api/topology/builder.go` — drop probe result,
  populate the new bools.
- `internal/api/topology/builder_test.go` — new
  `TestBuildSnapshot_HealthCheckConfiguredPropagates`,
  updated the canned-status test to expect unknown.
- `web/frontend/src/routes/topology/_types.ts` — TopologyRoute,
  TopologyUpstream, UpstreamNodeData widened.
- `web/frontend/src/routes/topology/_components/nodes/UpstreamNode.svelte`
  — dropped status dot, added lock + shield glyphs.

### Finding #R-TOPO-real-health-probe — surface real per-upstream health-probe outcome

Surfaced as the residual scope of `#R-TOPO-health-coherence`'s
v1.1.0 resolution (2026-06-03). The topology canvas currently
emits `status: "unknown"` for every upstream because the only
data source available — Caddy's `/reverse_proxy/upstreams`
admin endpoint — exposes the passive `num_requests` + `fails`
counters, NOT the active health-probe outcome. Even for routes
with a configured health check, mapping `fails == 0 → healthy`
was unsound (Caddy stops routing to an unhealthy upstream,
keeping its `fails` counter at 0).

**Fix shape**: ingest the actual probe outcome. Two viable
approaches:

1. **Caddy events** (`caddy.fs.events` / module-level events on
   the reverse-proxy module): subscribe via the admin events
   stream `GET /events` and update a per-upstream status
   cache when probe-success / probe-failure events arrive.
   Pros: zero polling, push-based, matches Caddy's idiomatic
   integration. Cons: Caddy's event surface for active health
   checks must be confirmed via the upstream source — not
   every internal probe outcome necessarily emits an event.
2. **Custom Caddy selector module** that wraps the standard
   selectors (`first`, `round_robin`, `random`, etc.), records
   per-upstream success/failure in an in-memory map, and
   exposes the map via either a new admin route or a method
   call from the Arenet binary (Caddy is embedded as a library
   here, so direct Go-API access is on the table). Pros: full
   control, no Caddy-version event-schema dependency. Cons:
   requires shipping and maintaining a Caddy module.

**Empirical-verification reminder** (CLAUDE.md): before
committing to an approach, verify the Caddy events surface
actually emits health-probe events with a small probe
harness. The Step I.7 history (`docs/smoke-test-step-i.md`)
shows audit-time assumptions about Caddy internals have a
track record of being wrong.

**Frontend ripple when this lands**:

- `UpstreamNode` already handles healthy/unhealthy/draining/
  unknown via the left-accent color — wire the real statuses
  in and the Activity glyph (currently the only "monitored"
  signal) can stay or be removed depending on whether the
  operator still wants the visual distinction.
- `internal/api/topology/builder.go` — re-enable the probe
  result propagation (currently intentionally dropped, see
  the in-file docstring).

**Triage.** Quality-of-life, not a crash. Land after
`#R-TOPO-upstream-metrics` Stage B; the two share the
"real per-upstream data" theme and the probe ingestion is
cheaper after the metrics fanout is in place.

### Finding #R-TOPO-probe-logging — 1 Caddy admin probe log/second is too noisy for prod

`CaddyStatusProber.Refresh` (called every 1 s by the background
refresher in `cmd/arenet/topology_wiring.go`) hits Caddy's admin
endpoint `/reverse_proxy/upstreams`. Caddy's admin module logs
every received request at `info` level:

```
{"level":"info","ts":1780500917.566231,"logger":"admin.api",
 "msg":"received request","method":"GET",
 "host":"127.0.0.1:2019","uri":"/reverse_proxy/upstreams",
 "remote_ip":"127.0.0.1","remote_port":"63748",
 "headers":{"User-Agent":["arenet-topology-probe"]...}}
```

That's **86,400 log lines per day** from the probe alone, on a
production install. Operators using journalctl / docker logs
will have a hard time finding actual events.

**Fix shape options**:

- **Option A — silence at Caddy's admin logger**. Configure a
  Caddy log filter that drops `admin.api` messages where
  `headers.User-Agent` contains `arenet-topology-probe`.
  Requires emitting a Caddy log config block alongside the
  HTTP/HTTPS app config that `caddymgr` already builds. The
  filter shape lands in Caddy v2's logging.encoders/.filters
  surface.
- **Option B — bump Caddy admin log level**. Caddy's admin
  logger has its own level knob; setting it to `warn` would
  drop the per-request info lines but also other admin-
  facing info we might want. Probably too broad.
- **Option C — switch from HTTP probe to in-process API**.
  Caddy's `reverseproxy.Upstream.Healthy()` is callable
  in-process via the `caddyhttp.GetUpstreamHosts()` accessor
  IF we register a module that has access to the pool.
  Bypasses the admin endpoint entirely — no log lines, no
  HTTP overhead. Larger surgery (custom Caddy module
  registration), more invasive than warranted for a logging
  cleanup.

**Recommendation**: Option A. Caddy log filters are configured
declaratively in the same JSON Arenet already emits via
`caddymgr`; the change adds maybe 10 lines to the config
emitter + a Caddy module side-effect import for the
`filter.delete` filter type. No runtime overhead, no
production log noise.

**Triage.** Operational noise, not a correctness issue. The
probe itself is doing the right thing (1 s cadence matches the
metrics tick) — only the logging side-effect needs muting.
