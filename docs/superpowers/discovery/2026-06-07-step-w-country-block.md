<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step W — Discovery: Country-block matcher

**Date**: 2026-06-07
**Status**: Discovery — no decisions locked yet. Operator answers to §5 → spec freeze in a follow-up.
**Builds on**: Step V (v1.4.0-step-v) layered GeoIP architecture (spec §3.9) + Step V.1 (v1.5.0-step-v1) normal-traffic monitoring (the 5-color enum on the threat map).

## §0 Intent

Step V told operators **where threats are** (geographic origin of every security event, rendered as colored arcs on the `/map` page). Step W lets them **block traffic from selected countries at the edge** — operator-defined per-route country allow/block lists, traffic from non-matching countries short-circuits BEFORE the proxy chain reaches the upstream.

This is observability → action: V is the dashboard, W is the gate. Both layers share the same MMDB lookup file (`/var/lib/arenet/GeoLite2-City.mmdb`) and the same operator-managed lifecycle (no auto-update in v1).

**Brief premise correction**: the V.8 brief described `porech/caddy-maxmind-geolocation` as "already vendored into the Caddy fork". **It is NOT vendored.** See §1.1 below for the empirical confirmation. The Step V spec §3.9 documents porech as a *library candidate* for Step W (commit `c9ff5e9`, line 285: "Library candidate: `porech/caddy-maxmind-geolocation` vendored into the Caddy module set OR a hand-rolled matcher that reuses Step V's `*geoip2.Reader` instance") — i.e. Step W has to pick between vendoring porech OR hand-rolling. §7 below recommends a path.

## §1 Pre-existing wiring recon

### 1.1 porech vendoring status

**NOT vendored.** Empirical checks:

- `grep "porech\|caddy-maxmind\|maxmind-geolocation" go.mod go.sum` → zero matches.
- `find ~/go/pkg/mod -name "*maxmind*"` → only `oschwald/maxminddb-golang@v1.12.0` (transitive from V.1's `oschwald/geoip2-golang@v1.9.0`) and its cache entry. No porech directory.
- `grep -rn "porech\|maxmind" cmd/arenet internal/` (excluding the oschwald references) → only one hit, a documentation comment in `internal/geo/lookup.go:52` referring to `maxminddb.Reader` thread-safety.
- The vendored Caddy modules registered via side-effect import in `cmd/arenet/main.go` are: `github.com/corazawaf/coraza-caddy/v2` (WAF, Step I.4), `github.com/caddy-dns/ovh` (DNS-01 provider, Step J.4), and the arenet-internal modules (`arenet_routemetrics`, `arenet_waf`, `arenet_cert_info`, `arenet_topology_hc`). No geo / country matcher.

**Conclusion**: Step W's first sub-task must decide whether to vendor porech or hand-roll. §7 covers both options with trade-offs.

### 1.2 MMDB file deployment

`/var/lib/arenet/GeoLite2-City.mmdb` IS deployed (Step V), opened by `geo.NewLookup` at `internal/geo/lookup.go:71`, env-overridable via `ARENET_GEOIP_MMDB`. The `*geoip2.Reader` lives on the `geo.Lookup` struct (`internal/geo/lookup.go:58`) and is goroutine-safe per upstream docs.

**Step W reuse path**: the existing `geo.Lookup` instance is available in `main.go`'s scope at the point where caddymgr is constructed. If we hand-roll the matcher, it can accept the same `*geo.Lookup` (or a thinner `Country(net.IP) string` interface) and skip MMDB-double-open.

### 1.3 porech upstream surface

(Source: github.com/porech/caddy-maxmind-geolocation README — must be confirmed if we vendor.)

The upstream module advertises a single Caddy HTTP matcher: `maxmind_geolocation` with JSON schema like:

```json
{
  "match": [{
    "maxmind_geolocation": {
      "db_path": "/path/to/GeoLite2-Country.mmdb",
      "allow_countries": ["FR", "DE"],
      "deny_countries": ["RU", "CN"]
    }
  }],
  "handle": [ ...your block/respond handler... ]
}
```

The matcher is a **negative-match short-circuit**: when the request's source IP resolves to a country in `deny_countries` (or absent from `allow_countries` when set), the matcher returns FALSE, and Caddy skips the route → the request falls through to the next route or the catch-all 404. Combining the matcher with a route whose `handle` block emits a 403 (via `static_response` or similar) gives the country-block UX.

**Behavioral implications**:
- The matcher provisions the MMDB at Caddy `Provision` time (once, not per-request). Performance footprint: same ~1-5 µs warm lookup as V.1's enricher.
- Hot-reload: Caddy's standard config reload re-runs Provision → re-opens the MMDB. So a country-list change applied via `mgr.Apply` is hot-reloadable for free.
- Concurrency: upstream `maxminddb.Reader` is goroutine-safe (same library V.1 uses).

### 1.4 Module registration mechanism

If we vendor porech, registration follows the same side-effect-import pattern as Coraza + DNS-OVH in `cmd/arenet/main.go`:

```go
import _ "github.com/porech/caddy-maxmind-geolocation"
```

Once imported, the matcher is available in JSON config as `http.matchers.maxmind_geolocation` (Caddy's standard dotted module ID). `caddymgr.buildConfigJSON` would emit it per-route in the route's `match` array.

If we hand-roll, we register a custom `arenet_country_block` matcher via `caddy.RegisterModule` (mirror of how `internal/metrics/middleware.go:53` registers `arenet_routemetrics`).

## §2 Integration points

### 2.1 Where the matcher slots into the Caddy route JSON

Today's per-route handler chain in `caddymgr/manager.go:910-925` (read in §1 recon, abridged):

```
route.match    = [{ host: [r.AllHosts()] }]
route.handle   = [ subroute {
    arenet_routemetrics   (V.1.2 — observes the final status)
    crowdsec_handler      (Step N — IP reputation block, when configured)
    auth_handler          (Step K — basicauth / forward_auth / OIDC)
    arenet_waf            (Step I.4 — Coraza)
    headers_handler       (Step I.6 — request/response header mutations)
    reverse_proxy         (Step J.1 — upstream pool + LB)
} ]
```

**Step W's matcher placement options**:

**Option A — Add `maxmind_geolocation` to the route's `match` array.** If the country matcher rejects, the whole route doesn't match → Caddy moves to the next route or returns 404. **Problem**: 404 is misleading (the route exists, the client is just from a blocked country). Operators would see legitimate-looking 404 spikes in their access logs from "real" customers who happen to be in the blocked country.

**Option B — Add an upstream `country_block` handler at the TOP of the subroute chain, BEFORE `arenet_routemetrics`.** The handler short-circuits with a 403 (or chosen status) when the country is in the block list. Cleaner UX: the operator sees explicit 403s in `/logs` instead of mysterious 404s.

**Option C — Split: matcher in the `match` array + a fallback route for blocked countries emitting an explicit 403.** Requires emitting TWO routes per arenet route: one for allowed countries (the normal chain) + one as a fallback that produces a custom 403. Verbose JSON; doubles the route count.

**CC recommendation**: **Option B**. Single route, explicit status, no 404 ambiguity. Concretely: a new `arenet_country_block` handler (hand-rolled, hosted in `internal/countryblock/`) slots BEFORE `arenet_routemetrics` so the V.1.2 metrics middleware never sees blocked requests (avoids polluting the success metric with rejected traffic — important for the V.1 normal-arc layer).

### 2.2 Chain order (V.1.2 ordering preserved)

Spec V.1.2 documents that `arenet_routemetrics` must be FIRST so it observes the FINAL upstream status code via its `defer`. Step W's country-block handler MUST run BEFORE `arenet_routemetrics` so:

1. Blocked traffic doesn't bump per-route counters (otherwise the operator sees "successful" 403-responses inflating their req/s tile).
2. Blocked traffic doesn't emit V.1 normal-traffic geo events (status 403 → V.1.2's status gate rejects anyway, but skipping the middleware entirely is cleaner).
3. Caddy's `http.log` still records the 403 (Caddy's access log runs at the server level, outside the per-route subroute).

Proposed handler chain post-W:

```
arenet_country_block      (Step W — country gate, returns 403 + emits W event)
arenet_routemetrics       (V.1.2 — observes final status, INCLUDING the 403)
crowdsec_handler          (Step N)
auth_handler              (Step K)
arenet_waf                (Step I.4)
headers_handler           (Step I.6)
reverse_proxy             (Step J.1)
```

Wait — if `arenet_routemetrics` runs AFTER `arenet_country_block`, blocked requests DO bump the per-route counter (the `defer` fires after Step W's handler returns its 403). That's fine: the metrics handler increments `errs` (4xx counter) per spec §3.3, and the operator sees the block volume in the `/topology` dashboard's per-route error rate. **No conflict with point (1) above** — I had the chain order backwards in my head; let me re-check.

Re-reading `internal/metrics/middleware.go:107-130`: `arenet_routemetrics.ServeHTTP` wraps the response writer, calls `next.ServeHTTP`, then in `defer` increments based on the final status. So if `arenet_country_block` runs **after** `arenet_routemetrics` (as `next` in the chain), the metrics defer DOES observe the 403 — desired behavior.

**Corrected proposed chain**:

```
arenet_routemetrics       (V.1.2 — first; defer observes any final status)
arenet_country_block      (Step W — second; 403 short-circuits here)
crowdsec_handler          (Step N)
auth_handler              (Step K)
arenet_waf                (Step I.4)
headers_handler           (Step I.6)
reverse_proxy             (Step J.1)
```

The country-block handler is positioned between `arenet_routemetrics` and `crowdsec_handler` — same logical layer as a security gate (block-class), but BEFORE crowdsec because country-block is a static operator-config decision (cheap to evaluate) while crowdsec is a dynamic LAPI-fed decision (LRU lookup). Country first: fail fast on the cheap check.

### 2.3 V.1 normal-traffic interaction

The V.1.2 `eligibleForNormal` gate rejects status >= 400. Step W's 403 responses ALWAYS fall outside V.1's emission window — so no green arcs ever fire from blocked-country traffic.

**Side effect for the threat map**: if Step W decides to emit a 6th-category "country-block" GeoEvent (see §4 below), it would go through a NEW sink path, NOT through the V.1 normal-traffic pipeline.

## §3 Existing arenet infrastructure

### 3.1 Route storage schema

`internal/storage/routes.go:164` declares `Route` (74 lines covering 15+ fields: Host, Upstreams, LBPolicy, TLSEnabled, RedirectToHTTPS, Aliases, AuthMode, BasicAuth, ForwardAuth, RequestHeaders, ResponseHeaders, WAFMode, ACMEChallenge, UseDedicatedCert, ...). All persisted as a single JSON-encoded blob per route in the `routes` bucket (`internal/storage/storage.go:33`).

**Adding a country-block field is a 1-line schema addition + 1 boot-migration entry** (if older rows must default cleanly). Mirror of how `WAFMode` was added in Step I.4: zero-value Go string decodes for pre-W rows; the API + caddymgr emit treat empty string as "no country block".

Proposed field shape (subject to §5 operator decision on allow vs deny vs both):

```go
// CountryBlock (Step W) — operator's per-route country
// gating config. Mode is one of:
//   - ""            : disabled (default; pre-W rows decode here)
//   - "allow-list"  : Allow contains the ONLY accepted ISO codes;
//                     everything else returns 403
//   - "deny-list"   : Deny contains the REJECTED ISO codes;
//                     everything else passes through
type CountryBlockConfig struct {
    Mode  string   `json:"mode"`            // ""|"allow-list"|"deny-list"
    Allow []string `json:"allow,omitempty"` // ISO 3166-1 alpha-2
    Deny  []string `json:"deny,omitempty"`  // ISO 3166-1 alpha-2
}
```

Plus a single new field on `Route`:

```go
CountryBlock CountryBlockConfig `json:"country_block"`
```

### 3.2 API surface for per-route mutation

`internal/api/handler.go`'s `createRoute` / `updateRoute` endpoints already parse the Route JSON. Adding `country_block` to the wire shape + validation (mode enum, country-code regex for entries) is the V.1.2-pattern extension — same model as how `WAFMode` was added.

### 3.3 Frontend per-route UI

`web/frontend/src/routes/routes/+page.svelte` (the per-route table) + the per-route edit modal pattern. Step W adds a "Country block" section to the edit modal with:

- Mode toggle: Disabled / Allow-list / Deny-list (radio or segmented control).
- Country selector: multi-select dropdown over ISO codes (a few hundred entries — render via virtualized list or simple `<select multiple>`).

The `/security/country-block` global page mentioned in the brief is OUT of scope for v1 — per-route config is sufficient and matches the existing per-route pattern. A global toggle would duplicate state with per-route, creating "which wins" ambiguity. CC recommends per-route only; if operators ask for a global default later, V+N can add it as a Settings entry that applies to routes that haven't set their own mode.

### 3.4 Operator-IP allowlist (anti-self-block)

Operators administering Arenet from a country in their own deny-list would lock themselves out of `/admin`. The existing `ARENET_TRUSTED_PROXIES` env var doesn't help — it gates X-Forwarded-For trust, not country bypass.

Three protection options:

**Option A — Implicit admin-route exclusion.** Hardcode `/api/v1/*` and `/` (admin SPA) to bypass the country matcher. Simple but couples the country-block module to arenet's admin URL shape (which has been stable since Step C but is theoretically refactorable).

**Option B — Trusted-IP allowlist env var.** `ARENET_COUNTRY_BLOCK_TRUSTED_IPS=10.0.0.5/32,1.2.3.4/32` — IPs in this list bypass the country matcher entirely. Mirrors the existing trusted-proxies pattern; operator-managed; no admin-URL coupling.

**Option C — Per-route admin flag.** A route's `country_block.bypass_admin=true` flag opts the route out of the country block when the request hits arenet's admin paths. Most flexible but exposes the most surface to misconfiguration.

CC recommends **Option B + the admin SPA route is excluded by virtue of being served by arenet's catch-all on the same Host as the admin API, which the operator typically doesn't put through the country-block config**. The trusted-IP env var is the operator's escape hatch when they configure country-block on the admin host by accident.

## §4 Event emission considerations

### 4.1 Should country-block emit GeoEvents?

**Two camps**:

- **For**: operators want to see WHERE the blocked traffic came from. Map's threat layer was designed to surface security events; country-block fits.
- **Against**: country-block emission is potentially HIGH-VOLUME (a single bot scanner from a blocked country can hit thousands of routes/second). Even with sampling, the visual noise may dominate the actual interesting threats (waf / crowdsec / auth).

**CC recommendation**: **emit AS A 6th CATEGORY** with sampling DEFAULT-ON. Mirror V.1's approach: env var `ARENET_COUNTRY_BLOCK_SAMPLE_PCT` (default 5 — much lower than V.1's default 0 because blocked traffic IS what the map is meant to show). Same per-IP cooldown (`ARENET_COUNTRY_BLOCK_PER_IP_COOLDOWN`, default 30s).

### 4.2 6th category color

The current 5-color enum (Step V §5.6) locks `normal / throttle / waf / crowdsec / auth`. Adding `country-block` extends the enum by 1. Color options:

- `--status-meta` (gray) — distinguishes "policy block" from "threat detection". Subdued, fits the "this isn't a hot incident, it's a policy match" semantic.
- A new token (e.g., `--accent-magenta`) — visually distinct from all 5 existing categories.

CC recommends `--status-meta` (gray): no new tokens, semantically honest (it's a static policy enforcement, not a dynamic threat detection).

### 4.3 LAN handling

Same as V.1: count in the V.6 LAN pill (if we wire it post-V.1.5 #R-NORMAL-TRAFFIC-lan-counter; otherwise skip silently); never emit a global arc. LAN traffic shouldn't be country-blocked anyway (RFC1918 doesn't have a country), so this is degenerate — the matcher returns "no country found" and the operator's block-list never matches.

**Sub-decision**: if a route's allow-list is set and an RFC1918 IP arrives, the matcher would block (RFC1918 isn't in any country's allow-list). Operator-facing surprise. CC recommends: **always bypass for RFC1918 sources** (same logic as V.1 — LAN traffic is implicitly trusted). Document this in the spec.

### 4.4 Sampling: where does the gate apply?

Country-block fires at the edge (handler chain position #2, before crowdsec/auth/waf). The block emission would go through a NEW sink (mirroring V.1.1's `NormalSink` shape: `CountryBlockSink` with sample + cooldown + LRU). Reusing V.1.1's pipeline machinery is the obvious win — extract the sampling-LRU-cooldown infrastructure into a `geo.SampledSink` base type if it's used a 3rd time, but for now copy-paste-with-modification at 100 LOC is faster than a refactor.

## §5 Scope-boundary questions for the operator

CC pre-answers with recommendations; operator confirms or overrides.

### Q1 — Per-route vs global toggle?

**Options**: per-route only; global only; both (global default + per-route override).

**CC recommendation**: **per-route only** for v1. Global adds DB state, UI surface for the global page, and the "which wins" ambiguity. Per-route matches the existing WAF / auth config pattern. If operators ask for a global default later, V+N can add it as a Settings entry.

### Q2 — Allow-list vs block-list vs both modes?

**Options**: allow-only, deny-only, both modes per route.

**CC recommendation**: **both modes per route** via the `Mode` enum (§3.1). Some operators want "only my country plus 2 trusted ones" (allow-list); others want "everywhere except Russia and China" (deny-list). Two modes covers both ergonomics without adding combinatorial complexity (a route is in exactly one mode at a time; the empty `Mode` string is the disabled state).

### Q3 — HTTP status for blocked

**Options**: 403 Forbidden, 451 Unavailable for Legal Reasons, 444 (nginx-style drop), 404, custom?

**CC recommendation**: **403 by default, env-overridable**. 403 is the canonical "you can't access this" status; operators understand it; clients (especially Cloudflare-class CDN scanners) handle it correctly.

- 451 is semantically more honest ("we're blocking you for policy reasons, not because the resource doesn't exist") but operators may not want to legally signal "we're explicitly blocking your country" — depends on jurisdiction sensitivity.
- 444 (nginx) sends no response at all — saves bandwidth on bot traffic but may confuse legitimate misclassified users.
- 404 is misleading (Option A from §2.1 risk).

Env var `ARENET_COUNTRY_BLOCK_STATUS` (default `403`, accepts `403|451|444`) gives operators the choice without exposing it per-route.

### Q4 — Trusted-IP allowlist that bypasses country block?

**CC recommendation**: **YES, via `ARENET_COUNTRY_BLOCK_TRUSTED_IPS`** (§3.4 Option B). Critical anti-self-lockout safeguard. Comma-separated CIDR list; matches before the country lookup; defaults to RFC1918 ranges automatically (LAN bypass per §4.3). Operator can extend with their VPN exit IPs etc.

### Q5 — Logging: every block to the activity log, count only, throttled?

**Options**: log every block to the activity log (high volume risk), aggregate count only, sampled log entries.

**CC recommendation**: **same model as V.1 normal-traffic — sampling + per-IP cooldown for the GeoEvent emission**. The Activity log (`/logs`) gets a 5th source (alongside waf/throttle/crowdsec/auth/cert) for country-block events, populated from the same sampled stream. Operators who want full-fidelity logging can set `SAMPLE_PCT=100` + cooldown=0 (with the documented load warning).

A separate question is whether to PERSIST country-block events to a database table (the V.1.5 deferral pattern says NO for normal-traffic). For country-block, the events ARE security-relevant (an unexpected spike in country-block traffic from a "trusted" country could signal IP-spoofing attacks) — CC recommends **YES, persist to a new `country_block_event` table** (mirror of `auth_event`, 30 d retention). Bus volume is bounded by the sampling.

### Q6 — Frontend visualization: arcs on the map?

**Options**: render as 6th-category arcs on the threat map (with `--status-meta` gray), counter-only (a new pill), or both.

**CC recommendation**: **both — gray arcs on the map AND a counter pill near the V.6 WS pill / V.7 LAN pill stack**. Arcs surface the geographic origin (the whole point of the map); the counter gives the operator's-attention number ("234 country-blocked requests since page open").

### Q7 — Hot-reload: country list updates require restart or hot-reload via API?

**CC recommendation**: **hot-reload via the existing route PUT API**. Caddy's config reload re-runs Provision on the country matcher, which re-opens the MMDB and re-reads the country list from the route's JSON config. No restart needed; matches the pattern for WAF mode / auth mode / headers updates today.

### Q8 — Country source: MMDB City DB (already deployed) vs MMDB Country DB?

**Options**: reuse the existing City DB (~50 MB), require operator to deploy the Country DB (~6 MB, faster lookup).

**CC recommendation**: **reuse the City DB**. Step V already shipped it; deploying a second DB doubles the operator's update burden + the AGPL release-notes complexity (MMDB attribution per file). Lookup cost is ~1-5 µs warm regardless of which DB (the MaxMind reader uses the same mmap path); the City DB carries extra fields we don't use but that's a memory footprint trade-off (~44 MB extra RSS) the homelab can absorb.

If smoke shows the City DB lookup is noticeably slower on hot paths, V+N can ship a Country-DB-only mode behind an env var. v1 reuses what V deployed.

## §6 Sub-tasks proposal

CC's reading of the right breakdown. **6 sub-tasks** (one more than V.1's 5 because Step W adds an event-source category which V.1 didn't have to invent).

| Sub-task | Scope | Effort |
|---|---|---|
| **W.1** | Vendor decision: vendor `porech/caddy-maxmind-geolocation` OR hand-roll `arenet_country_block` Caddy module. CC recommends **hand-roll** (see §7). Ships the matcher / handler module in `internal/countryblock/` reusing the V.1 `geo.Lookup`. Tests: country-resolution against fixture MMDB, allow/deny mode logic, RFC1918 bypass, trusted-IP allowlist. | ~3 h |
| **W.2** | Storage + API: add `CountryBlockConfig` to `Route`, validation (mode enum, country-code regex), wire-shape tests. Boot migration: pre-W rows decode with empty Mode (no behavior change). | ~1.5 h |
| **W.3** | caddymgr emit: thread `r.CountryBlock` into per-route handler chain at chain position #2 (after `arenet_routemetrics`, before `crowdsec_handler`). Trusted-IP env-var parsing + threading. Tests: emit shape, chain order, omitempty when disabled. | ~1.5 h |
| **W.4** | Event emission: new `CountryBlockSink` + `geoForwardingCountryBlockSink` (mirror V.1.1/V.1.3 sampling+cooldown+LRU pipeline). 6th category in `geo.GeoEvent`. New `country_block_event` storage table (mirror `auth_event`, 30 d retention). Sink wire-up in `cmd/arenet/main.go`. | ~2.5 h |
| **W.5** | Frontend per-route UI: country-block section in the route edit modal (Mode toggle + country multi-select). Update `MapLegend.svelte` with 6th `country-block` row. Update `WorldMap.svelte` to render gray arcs (already universal). Activity log gets a 5th source. New per-page "blocked countries" counter pill on `/map`. | ~3 h |
| **W.6** | Smoke + release notes: live smoke (curl from a VPN exit in a blocked country, confirm 403 + gray arc). Operator-facing doc at `docs/operations/country-block.md`. Release notes at `docs/release-notes/v1.6.0-step-w.md`. Operator validation gate before tag. | ~1.5 h |

**Total Step W effort estimate**: ~13 h, deliverable in 3-4 sessions. Single tag after W.6: `v1.6.0-step-w`.

## §7 Key architecture questions

### 7.1 Vendor porech or hand-roll?

**Vendor porech**:
- ✅ Saves ~150 LOC of MaxMind lookup boilerplate (Country-DB record parsing).
- ✅ Battle-tested by other Caddy users.
- ❌ Adds a transitive dependency that's a one-person project (porech). Long-term maintenance risk.
- ❌ Forces us to vendor a SECOND MMDB-reader path alongside our V.1 `oschwald/geoip2-golang`. Same library family but different abstraction layer. License + redistribution cost duplicated.
- ❌ Operator-facing config (`db_path`) duplicates the `ARENET_GEOIP_MMDB` env var. Two sources of truth for the same file.
- ❌ Doesn't easily share the V.1 `geo.Lookup` (the porech module opens its own reader).

**Hand-roll `arenet_country_block`**:
- ✅ Reuses the V.1 `*geo.Lookup` instance — zero new MMDB-open path.
- ✅ Single source of truth for the MMDB file via `ARENET_GEOIP_MMDB`.
- ✅ Easier to extend with arenet-specific behavior (trusted-IP bypass, RFC1918 short-circuit, event emission integration).
- ✅ No new external dep.
- ❌ ~150-200 LOC to write + test.
- ❌ Maintenance burden is on us, not the porech maintainer.

**CC recommendation**: **hand-roll**. The V.1 `geo.Lookup` already does the City-DB country resolution we need (the `LookupIP` returns `Location{Country: "FR", ...}`). The W.1 module is a thin Caddy-side wrapper that:
1. Resolves the request's client IP (reusing the V.1.3 `ClientIPFunc` for trusted-proxy awareness).
2. Calls `geo.Lookup.LookupIP(ip)` → `loc.Country`.
3. Compares against the route's allow / deny list.
4. Short-circuits with the configured status code on match.
5. Submits to the W.4 `CountryBlockSink` on every block (sampling applies).

Effort: 150-200 LOC for the module + ~250 LOC of tests. Same magnitude as V.1.1.

### 7.2 Module configuration shape

The brief asks: "env vars (Step V.1 pattern), JSON in caddymgr builder, or DB-backed per-route?"

**CC's split**:

- **Per-route config (allow/deny lists, mode)**: DB-backed via the `Route.CountryBlock` field (§3.1). Persistence + edit-UI lives here. Mirrors how WAFMode / AuthMode are stored.
- **Global env vars**: trusted-IP allowlist (`ARENET_COUNTRY_BLOCK_TRUSTED_IPS`), status code (`ARENET_COUNTRY_BLOCK_STATUS`), event sampling (`ARENET_COUNTRY_BLOCK_SAMPLE_PCT`, `ARENET_COUNTRY_BLOCK_PER_IP_COOLDOWN`). These are deployment-level concerns, not per-route.

### 7.3 Dynamic reload

Caddy's `mgr.Apply(routes)` already calls `caddy.Load(cfgJSON)` which re-Provisions every module on every reload. So a country-list update via the route PUT API triggers an `Apply` → the matcher re-reads its config from JSON → MMDB stays open (the matcher holds the reader). Effectively hot-reload-free at the matcher layer.

The MMDB FILE update (operator replaces `/var/lib/arenet/GeoLite2-City.mmdb`) is NOT auto-detected by V.1 OR by W today. Operator must restart Arenet for a new MMDB to take effect. This is documented in Step V's known limitations and carries forward to W.

### 7.4 Anti-self-block escape hatch

Three layers of protection (cumulative):

1. **RFC1918 bypass** — implicit. Hardcoded in the matcher.
2. **Trusted-IP allowlist** — `ARENET_COUNTRY_BLOCK_TRUSTED_IPS` env var. Operator's own egress IPs.
3. **The admin SPA is typically NOT under country-block** — operators don't put their admin host through the matcher. If they do, the recovery path is: SSH to the box, `unset` the var or edit the route via `arenet` CLI (future tooling) or directly via BoltDB (low-level escape).

**CC recommendation**: ship all 3 in v1. The 30-second cost of writing the trusted-IP env handler saves a 30-minute self-lockout recovery from an operator who toggled deny-list on their admin route by mistake.

## §8 References

- **Step V spec** (locks the layered GeoIP architecture this builds on): `docs/superpowers/specs/2026-06-06-step-v-geographic-threat-map.md` (commit `c9ff5e9`), §3.9 (lines 269-308) — the Step W forward-reference.
- **Step V.1 spec** (the sampling-LRU-cooldown pipeline pattern Step W.4 will mirror): `docs/superpowers/specs/2026-06-07-step-v1-normal-traffic-monitoring.md` (commit `e87269f`).
- **Step V.1 release notes** (operator-facing context for the existing GeoIP layer): `docs/release-notes/v1.5.0-step-v1.md`.
- **`internal/geo/lookup.go`**: the V.1 MMDB reader Step W reuses.
- **`internal/geo/normal_sink.go`** (commit `f657a11`): the sampling-LRU-cooldown template for W.4's `CountryBlockSink`.
- **`internal/storage/routes.go:164`**: the `Route` schema W.2 extends.
- **`internal/caddymgr/manager.go:910-925`**: the per-route handler chain W.3 inserts the country-block handler into.
- **`internal/metrics/middleware.go`**: the V.1.2 `RouteMetricsHandler` chain-position invariant Step W respects.
- **Step R spec**: `docs/superpowers/specs/2026-05-31-step-r-oklch-migration.md:64-69, 305, 321, 361, 368` — the original geo-blocking mock-promise that Step W finally honors.
