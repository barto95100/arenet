<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step W — Spec: Country-block via hand-rolled `internal/countryblock` module

**Date frozen**: 2026-06-07
**Status**: Locked. Implementation follows the §6 sub-task plan.
**Builds on**: v1.5.0-step-v1 (V.1 NormalSink sampling pipeline) + v1.4.0-step-v (geo bus + WS).
**Discovery**: `docs/superpowers/discovery/2026-06-07-step-w-country-block.md` (commit `f9f29fe`).

## §1 Intent + scope

Step V shipped the threat-visualization layer (operators see WHERE traffic comes from). Step W ships the ACTION layer: per-route country allow/deny lists short-circuit unwanted traffic at the Caddy edge before the proxy chain reaches the upstream. Hand-rolled Caddy middleware `arenet_country_block` slots at chain position #2 (between V.1.2's `arenet_routemetrics` and the existing `arenet_crowdsec` handler), so the V.1.2 `defer` block observes the 403 status and surfaces block volume in the per-route error rate metric **with zero new metric plumbing**.

**Architectural correction from brief**: `porech/caddy-maxmind-geolocation` is NOT vendored in arenet (`grep "porech" go.mod` → empty). Discovery doc §1.1 confirmed this empirically. Step W ships a hand-rolled module that **reuses the V.1 `geo.Lookup` singleton** — zero new MMDB-open path, single source of truth for the file via `ARENET_GEOIP_MMDB`.

Out of scope (deferred): global default toggle (`#R-COUNTRY-BLOCK-global-default`), dry-run preview mode (`#R-COUNTRY-BLOCK-dry-run`), country-list templates (e.g. "block GDPR-non-compliant", `#R-COUNTRY-BLOCK-templates`).

## §2 Locked decisions

### §D1 — Per-route only, no global toggle

Each route declares its own `Mode` + `CountryList` via the new `Route.CountryBlock` field (§3.4). Mirrors the per-route `WAFMode` / `AuthMode` pattern (Step I.4 / K.1). No global default. Operators wanting a fleet-wide policy set it explicitly on every route — same as WAF / auth. A global default would create the "which wins" ambiguity that V.1.5's spec §D6 deferral already documented for normal-traffic.

If operators ask for a global default later, V+N can add it as a Settings entry that applies only to routes whose `CountryBlock.Mode == ""` (the canonical disabled state).

### §D2 — Mode enum: `"off" | "allow" | "deny"`

| Value | Semantics |
|---|---|
| `""` (zero value) | Same as `"off"`. Pre-W rows decode to empty Go string → handler skipped entirely. |
| `"off"` | Country logic disabled for this route. caddymgr emits NO country-block handler in the per-route chain. Zero per-request cost. |
| `"allow"` | Whitelist. Only requests resolving to a country code in `CountryList` pass. Everything else is blocked with `D3` status. Empty `CountryList` + `Mode="allow"` blocks EVERYTHING from a non-RFC1918 source (operator-facing footgun; the API layer rejects this combo with a 400 at edit-time — see §3.4). |
| `"deny"` | Blacklist. Requests resolving to a country code in `CountryList` are blocked; everything else passes. Empty `CountryList` + `Mode="deny"` allows everything (legal but no-op; API logs a `Warn` at edit-time but accepts). |

Mutually exclusive: a route is in exactly ONE mode. The handler-skipped `""` / `"off"` state is the canonical default for pre-W rows and new routes.

### §D3 — Block status code

Default `403 Forbidden`. Operator-overridable via `ARENET_COUNTRY_BLOCK_STATUS` env var. Accepted values: `403`, `451`, `444`.

- `403` (default): canonical "you can't access this"; well-handled by CDN scanners + browser caches.
- `451 Unavailable for Legal Reasons` (RFC 7725): semantically honest for jurisdiction-driven blocks. Operators who want to explicitly signal "we're blocking your country" pick this; operators worried about exposing the block reason stay on 403.
- `444` (nginx convention): close connection without sending any response. Saves bandwidth on bot scanners; may confuse legitimate misclassified users.

Invalid values (anything not in the set) WARN at boot and fall back to `403`. NO fatal-on-invalid — operator typo shouldn't keep arenet from booting.

### §D4 — Trusted-IP allowlist + RFC1918 auto-bypass

Anti-self-lockout safeguard. Two layers:

1. **Auto-bypass for RFC1918 / loopback / link-local sources** (hardcoded; same `isLAN()` check as V.1's `geo.NormalSink`). LAN traffic isn't country-resolvable anyway (`geo.Lookup.LookupIP(LAN_ip)` returns `Country: "LAN"`); without the bypass, a route with `Mode="allow"` would block all LAN traffic (since `"LAN" ∉ CountryList`).
2. **Operator-supplied trusted-IP allowlist** via `ARENET_COUNTRY_BLOCK_TRUSTED_IPS` — comma-separated CIDR list (`10.0.0.5/32,1.2.3.4/32,2001:db8::/32`). Source IPs in this list bypass the country matcher entirely. Operators add their VPN exit IPs / static admin IPs here to prevent self-lockout when they configure deny on their own country.

Both layers checked BEFORE the country lookup. Invalid CIDR strings WARN at boot and the malformed entry is dropped (other entries still apply); empty / unset = only RFC1918 bypass active.

### §D5 — Event emission: sampling + cooldown + persistence

Mirror of V.1's pipeline pattern (sampling + LRU per-IP cooldown), but **defaults are different** because block volume is structurally bounded:

- Block-rate is typically << normal traffic (the whole point of country-block is to suppress unwanted volume).
- Operators want to SEE every block class (a country pattern is the actionable signal).

```
ARENET_COUNTRY_BLOCK_SAMPLE_PCT    default 100   (full capture; 0..100)
ARENET_COUNTRY_BLOCK_PER_IP_COOLDOWN default 60s  (cooldown longer than V.1's 30s — blocked sources retry less interestingly)
```

Persistence: new `country_block_event` table in `metrics.db` (mirror of `auth_event` schema). 30-day retention via the existing observability retention pruner (extend the V.2 `pruneAuthEvents` runner to also prune `country_block_event`). Schema:

| Column | Type | Notes |
|---|---|---|
| `id` | INTEGER PK AUTOINCREMENT | |
| `ts` | INTEGER (epoch seconds) | Indexed for retention scan + activity-log queries |
| `src_ip` | TEXT | The resolved client IP |
| `country` | TEXT | ISO 3166-1 alpha-2 ("RU", "CN", "UNK" if degraded) |
| `route_id` | TEXT | The arenet route that fired the block |
| `mode` | TEXT | "allow" or "deny" — which mode produced this block |
| `status_code` | INTEGER | The configured `D3` status (403/451/444) |

Indexes: `(ts)`, `(country, ts)`, `(route_id, ts)`.

### §D6 — Frontend visualization: 6th category, gray

`GeoEvent.Category` enum extends from 5 to 6 values: `"normal" | "throttle" | "waf" | "crowdsec" | "auth" | "country_block"`. The 6th category renders on the threat map as **gray arcs** via the existing CSS token `--status-meta`. Counter pill added to the V.6 pill stack (top-right of `/map`) showing the per-session block count.

Why gray (and not a louder color): country-block is a STATIC POLICY decision (operator declared "block RU" → traffic gets blocked). It's not a dynamic threat detection like waf or crowdsec. The gray tone reads as "expected enforcement", reserving the louder colors for actual threat signals.

If smoke shows the gray reads as "inactive" or "disabled" rather than "blocked", we revisit with a dedicated `--color-blocked` token at HF1 (cited at §7).

### §D7 — Hot-reload via existing `mgr.Apply`

Country list updates land via the existing `PUT /api/v1/routes/{id}` endpoint. The handler validates + persists + calls `mgr.Apply(ctx)`, which re-emits the full Caddy config via `buildConfigJSON` and runs `caddy.Load(cfgJSON, true)`. Caddy re-Provisions every module → the country-block matcher re-reads its config from the per-route JSON → the next request from the affected source country sees the new behavior. **No process restart, no MMDB re-open** (the `geo.Lookup` singleton stays open across reloads).

### §D8 — MMDB source: reuse V.1's City DB

Reuses `/var/lib/arenet/GeoLite2-City.mmdb` (env-overridable via `ARENET_GEOIP_MMDB`) and the same `geo.Lookup` singleton V.1 constructed. No second MMDB path, no second open, no second attribution requirement (single MaxMind CC BY-SA 4.0 mention covers both V and W).

`geo.Lookup.LookupIP(net.IP)` already returns `Location{Country: "FR", ...}` for non-LAN sources. The country-block matcher reads `.Country` and runs the §D2 evaluation. If V+N adds a Country-only MMDB profile for faster lookups, that's a separate concern — Step W's contract uses whatever `geo.Lookup.LookupIP` returns.

### §D9 — Hand-rolled module, NOT porech

`internal/countryblock/` ships a Caddy HTTP middleware module registered as `arenet_country_block` (module ID `http.handlers.arenet_country_block`). Estimated size: ~150-200 LOC for the module + ~250 LOC of tests.

Rationale for hand-rolling vs vendoring `porech/caddy-maxmind-geolocation`:

| Vendor porech | Hand-roll arenet_country_block |
|---|---|
| Saves ~150 LOC of MaxMind boilerplate | Reuses V.1 `geo.Lookup` — zero MMDB-double-open |
| Battle-tested by other Caddy users | Single source of truth for MMDB via `ARENET_GEOIP_MMDB` |
| Forces a second MMDB-reader path (porech opens its own reader) | Easier to extend with arenet-specific behavior (trusted-IP bypass, RFC1918 short-circuit, event emission integration) |
| New transitive dep (one-person project; maintenance risk) | No new external dep |
| Operator-facing `db_path` config duplicates `ARENET_GEOIP_MMDB` | Maintenance burden on us, not porech maintainer |

Hand-roll wins on integration depth (event emission, trusted-IP bypass) and operator surface clarity (one MMDB env var, not two). The LOC saved by vendoring is recovered by the reduced integration glue.

### §D10 — Chain position #2

Inside the per-route subroute at `caddymgr/manager.go:910-925`, the country-block handler emits at position #2, AFTER `arenet_routemetrics` and BEFORE `arenet_crowdsec`:

```
arenet_routemetrics       (V.1.2 — first; defer observes any final status)
arenet_country_block      (Step W — second; 403 short-circuits here)
crowdsec_handler          (Step N — third; IP reputation block)
auth_handler              (Step K — fourth; basicauth / forward_auth)
arenet_waf                (Step I.4 — fifth; Coraza)
headers_handler           (Step I.6 — sixth; mutations)
reverse_proxy             (Step J.1 — last; upstream pool + LB)
```

Why between routemetrics and crowdsec:

- Routemetrics MUST stay #1 so its `defer` observes the FINAL status (Step V.1.2 invariant). Step W's 403 is the "final" status when the country gate trips — the metrics defer records it as a 4xx, and the per-route error rate tile surfaces the block volume **with no new plumbing**.
- Country-block is a CHEAP static-config check (operator's allow/deny list — ~1 µs MMDB lookup + 2-byte string compare). CrowdSec is a DYNAMIC LAPI-fed decision (LRU lookup against a 100k+ entry decision set). Fail-fast on the cheaper check.
- Country-block is also more PERMANENT than CrowdSec (operator declares "block RU forever"; CrowdSec decisions expire after their TTL). Permanent gates come first.

Skip the handler emission entirely when `route.CountryBlock.Mode == "" || "off"` — zero per-request cost for routes that don't use the feature.

## §3 Architectural components

### §3.1 `internal/countryblock/` (NEW package)

Three files, total ~400 LOC:

**`module.go`** — Caddy middleware registration + `ServeHTTP`:

```go
package countryblock

const (
    ModuleID    = "http.handlers.arenet_country_block"
    HandlerName = "arenet_country_block"
)

// Handler is the Caddy middleware. Provisioned once per
// route; reads the per-route Mode + CountryList from JSON
// config; resolves dependencies (geo lookup + sink +
// trusted-IP allowlist + status code) from package-level
// globals (mirror of metrics.GlobalRegistry pattern).
type Handler struct {
    RouteID     string   `json:"route_id"`
    Mode        string   `json:"mode"`         // "allow" | "deny" (never "off" — caddymgr skips emission)
    CountryList []string `json:"country_list"` // ISO 3166-1 alpha-2, uppercase

    // Resolved at Provision.
    lookup      *geo.Lookup
    sink        CountryBlockSubmitter
    trustedIPs  []*net.IPNet
    statusCode  int
    clientIP    metrics.ClientIPFunc
    allowSet    map[string]struct{} // built from CountryList for O(1) match
}

func (h *Handler) Provision(ctx caddy.Context) error
func (h *Handler) Validate() error
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error
```

`ServeHTTP` flow:

1. Resolve client IP via the shared `metrics.GlobalClientIPFn()` (already trusted-proxy aware per V.1.3).
2. Check trusted-IP allowlist (operator-supplied + RFC1918 auto-bypass). On hit → `next.ServeHTTP(w, r)` (pass through).
3. Look up country via `h.lookup.LookupIP(net.ParseIP(srcIP))`. If `loc.Country == "LAN"` → pass through (RFC1918 already short-circuited above, this is a defense-in-depth path).
4. Evaluate Mode:
   - `"allow"`: `loc.Country ∈ allowSet` → pass; else → block.
   - `"deny"`: `loc.Country ∈ allowSet` (here "allowSet" is the deny list — name is misleading; we'll call it `countrySet` in code) → block; else → pass.
5. On block: emit `Submit(srcIP, country, routeID, mode, statusCode)` to the sink (sampling/cooldown handled inside the sink — V.1.1 pattern). Write the status code + close. Return `nil` (handled).
6. On degraded mode (`h.lookup == nil` or `loc.Country == ""`): **fail-open** per AC #18. Log a `WARN` once per Provision; pass the request through. Operator-visible signal that GeoIP is degraded without blocking legitimate traffic.

**`config.go`** — Mode enum + validation:

```go
const (
    ModeOff   = "off"
    ModeAllow = "allow"
    ModeDeny  = "deny"
)

// ValidateConfig is the shared validator called by both
// the API layer (at PUT /routes/:id time) and the module's
// Provision (defense-in-depth — catches JSON malformations
// at Caddy load time).
func ValidateConfig(mode string, countries []string) error
```

Validation rules:
- `Mode` ∈ `{"", "off", "allow", "deny"}` (empty == "off").
- Each `CountryList[i]` is 2 uppercase ASCII chars (`/^[A-Z]{2}$/`).
- No duplicates in `CountryList`.
- `Mode == "allow" && len(CountryList) == 0` → ERROR (operator-facing footgun: would block everything from non-RFC1918 sources).
- `Mode == "deny" && len(CountryList) == 0` → ACCEPTED with `Warn` (legal no-op).

**`matcher.go`** — pure-Go evaluation logic, extracted for testability:

```go
// Evaluate returns true when the request should be BLOCKED
// (not when it should be allowed — the name reflects the
// caller's action). Pure function; no IO.
func Evaluate(mode string, countrySet map[string]struct{}, requestCountry string) bool

// IsTrusted reports whether srcIP is in the operator-
// supplied trusted-IP allowlist OR in any RFC1918 /
// loopback / link-local range.
func IsTrusted(srcIP net.IP, trustedIPs []*net.IPNet) bool
```

Tests in `internal/countryblock/*_test.go`:
- `TestEvaluate_AllowMode`, `TestEvaluate_DenyMode`, `TestEvaluate_EmptyCountrySet` (Mode + edge-case matrix)
- `TestIsTrusted_RFC1918`, `TestIsTrusted_OperatorAllowlist`, `TestIsTrusted_PublicIP`
- `TestServeHTTP_BlocksCountryNotInAllowSet` (full HTTP path with stub Lookup)
- `TestServeHTTP_PassesThroughTrustedIP`
- `TestServeHTTP_DegradedFailsOpen` (nil Lookup → pass + WARN logged once)
- `TestServeHTTP_EmitsSinkEvent` (block → sink.Submit called with correct args)
- `TestValidateConfig_*` (Mode enum + country-code regex + duplicate detection + footgun rejection)
- `TestNilHandler_NoCrash` (V.1.1 nil-safety contract carried forward)
- `TestConcurrentBlock_RaceFree` (-race coverage)

### §3.2 `internal/geo/` (EXTEND)

Three additions to the existing V.1 / V.1.1 surface:

**`enricher.go`** — new `EnrichCountryBlock`:

```go
// EnrichCountryBlock builds a GeoEvent for a country-block
// hit. Called by the W.4 CountryBlockSink AFTER sampling +
// cooldown + LRU. mode is "allow" or "deny" (which mode
// produced this block); routeID identifies the arenet
// route. countryCode is ISO 3166-1 alpha-2 (the matcher
// already resolved it; this avoids a second MMDB lookup).
func (e *Enricher) EnrichCountryBlock(srcIP, routeID, countryCode, mode string, statusCode int) GeoEvent {
    out := e.enrichBase(srcIP, time.Now().UTC(), CategoryCountryBlock)
    out.SourceCountry = countryCode // override the LAN/UNK default with the matcher's value
    out.StatusCode    = statusCode
    out.RouteID       = routeID
    out.Details       = mode        // "allow" or "deny" — frontend tooltip surfaces it
    return out
}
```

**`enricher.go`** — extend the category enum:

```go
const (
    CategoryNormal       = "normal"
    CategoryThrottle     = "throttle"
    CategoryWAF          = "waf"
    CategoryCrowdsec     = "crowdsec"
    CategoryAuth         = "auth"
    CategoryCountryBlock = "country_block"  // V.W
)
```

**`country_block_sink.go`** (NEW, ~150-200 LOC) — sampling pipeline:

Mirror of `normal_sink.go` from V.1.1 (commit `f657a11`). Same 3-gate pipeline (sampling, RFC1918 short-circuit, per-IP cooldown), same LRU, same nil-receiver safety. Differences:

- `Submit(srcIP, routeID, country, mode string, statusCode int)` (5 args vs V.1's 3 — country + mode + statusCode are the country-block-specific dimensions).
- Defaults: `SamplePct=100`, `Cooldown=60s` (per §D5).
- After passing all gates, calls `e.EnrichCountryBlock(...)` + `bus.Publish(event)` + persists to the new `country_block_event` table (V.1's `NormalSink` is bus-only; W persists per §D5).

```go
type CountryBlockSubmitter interface {
    Submit(srcIP, routeID, country, mode string, statusCode int)
    Close() error
}

type DefaultCountryBlockSink struct {
    bus            *Bus
    enricher       *Enricher
    inserter       CountryBlockEventInserter // persistence seam — *observability.Store satisfies it
    samplePct      int
    cooldown       time.Duration
    cache          *ipCooldownCache  // reused from normal_sink.go
    prngMu         sync.Mutex
    prng           *rand.Rand
}

// CountryBlockEventInserter mirrors the V.2 CertInserter /
// AuthInserter shape so the sink can be tested without a
// real *observability.Store.
type CountryBlockEventInserter interface {
    InsertCountryBlockEventBatch(ctx context.Context, events []CountryBlockEventRow) error
}
```

### §3.3 `internal/observability/` (EXTEND)

New `country_block_event.go`:

- `CountryBlockEventRow` struct mirroring the §D5 schema.
- `InsertCountryBlockEventBatch(ctx, rows)` — same batch-insert pattern as `InsertAuthEventBatch`.
- `PruneCountryBlockEventsOlderThan(ctx, cutoff)` — called by the retention runner.
- Migration `migrateV6toV7` in `migrate.go` — `CREATE TABLE country_block_event` + 3 indexes (`ts`, `country+ts`, `route_id+ts`).

`retention.go` extension:

- Add `RetainCountryBlockEvents = 30 * 24 * time.Hour` const.
- Add `PruneCountryBlockEventsOlderThan` call to the existing prune loop alongside the auth event prune.

`metrics.db` schema bump: v6 → v7. Pre-W databases auto-migrate on first boot.

### §3.4 Route schema (EXTEND `internal/storage/routes.go`)

```go
// CountryBlock (Step W) — per-route country gating config.
// Zero value (Mode="") = "off" (handler skipped).
type CountryBlock struct {
    Mode        string   `json:"mode"`         // "off" | "allow" | "deny"
    CountryList []string `json:"country_list"` // ISO 3166-1 alpha-2, uppercase
}

// Add to Route struct:
CountryBlock CountryBlock `json:"country_block"`
```

API validation in `internal/api/handler.go`'s `createRoute` / `updateRoute`:
- Reject Mode outside `{"", "off", "allow", "deny"}` with 400.
- Reject CountryList entries that don't match `/^[A-Z]{2}$/` with 400.
- Reject duplicate country codes with 400.
- Reject `Mode == "allow" && len(CountryList) == 0` with 400 (the §D2 footgun).

BoltDB persistence: the existing `routes` bucket already stores the full `Route` as JSON. Adding the `country_block` field is **automatic** — pre-W rows decode with zero-value `CountryBlock{}`, which the caddymgr treats as `Mode="off"`. No migration code needed (Go's JSON decoder handles missing fields by leaving the zero value in place).

### §3.5 `cmd/arenet/main.go` (EXTEND)

Env-var parsing (in a new `country_block_config.go` sibling, mirror of V.1.3's `normal_traffic_config.go`):

```go
func parseCountryBlockStatus(raw string) (int, error)       // default 403; accept 403/451/444; WARN-and-fallback on others
func parseCountryBlockTrustedIPs(raw string) ([]*net.IPNet, error)  // CIDR list; malformed entries WARN and skip; valid entries always include RFC1918 baseline
func parseCountryBlockSamplePct(raw string) (int, error)    // [0, 100]; default 100; FATAL on invalid
func parseCountryBlockCooldown(raw string) (time.Duration, error)   // default 60s; FATAL on invalid
```

Wire-up (in `cmd/arenet/main.go`):

```go
// Parse env (before mgr.Start).
cbStatus, _   := parseCountryBlockStatus(os.Getenv("ARENET_COUNTRY_BLOCK_STATUS"))
cbTrustedIPs  := parseCountryBlockTrustedIPs(os.Getenv("ARENET_COUNTRY_BLOCK_TRUSTED_IPS"))
cbSamplePct, _ := parseCountryBlockSamplePct(os.Getenv("ARENET_COUNTRY_BLOCK_SAMPLE_PCT"))
cbCooldown, _  := parseCountryBlockCooldown(os.Getenv("ARENET_COUNTRY_BLOCK_PER_IP_COOLDOWN"))

mgr.SetCountryBlockStatus(cbStatus)
mgr.SetCountryBlockTrustedIPs(cbTrustedIPs)

// AFTER geoBus + geoEnricher exist:
cbSink := geo.NewDefaultCountryBlockSink(geoBus, geoEnricher, obsStore, geo.CountryBlockSinkConfig{
    SamplePct: cbSamplePct,
    Cooldown:  cbCooldown,
})
countryblock.SetGlobalSink(geoForwardingCountryBlockSink{inner: cbSink})
countryblock.SetGlobalLookup(geoLookup)
countryblock.SetGlobalStatusCode(cbStatus)
countryblock.SetGlobalTrustedIPs(cbTrustedIPs)

logger.Info("country block sink wired",
    "present", true,
    "status_code", cbStatus,
    "trusted_ips_count", len(cbTrustedIPs),
    "sample_pct", cbSamplePct,
    "cooldown", cbCooldown.String(),
)
```

All `countryblock.SetGlobal*` setters use `atomic.Pointer` for the same V.1.3 late-install reason: the country-block module's `Provision` may run during `mgr.Start` (the first `applyLocked`) BEFORE the geo bus / enricher / sink are constructed. Setters MUST be observable post-Provision via lock-free atomic reads.

### §3.6 `caddymgr/manager.go` (EXTEND)

Threading + per-route emit:

```go
// Two new fields on CaddyManager:
countryBlockStatus     int
countryBlockTrustedIPs []*net.IPNet

// Two new setters (mirror of SetCrowdSecConfig):
func (m *CaddyManager) SetCountryBlockStatus(status int)
func (m *CaddyManager) SetCountryBlockTrustedIPs(ips []*net.IPNet)

// In buildOpts:
CountryBlockStatus     int
CountryBlockTrustedIPs []*net.IPNet
```

In the per-route chain (lines ~910-925), AFTER the `arenet_routemetrics` handler is appended and BEFORE the `crowdsec_handler`:

```go
if r.CountryBlock.Mode != "" && r.CountryBlock.Mode != "off" {
    handlers = append(handlers, map[string]any{
        "handler":      "arenet_country_block",
        "route_id":     r.ID,
        "mode":         r.CountryBlock.Mode,
        "country_list": r.CountryBlock.CountryList,
    })
}
```

The per-handler emit is OMITTED entirely when Mode is empty or `"off"` — zero per-request cost for routes that don't use the feature. The trusted-IPs + status code are READ from package-level globals inside the module's Provision (NOT threaded via JSON), so the per-route JSON shape stays minimal.

### §3.7 Frontend (EXTEND)

**`web/frontend/src/lib/components/Map/categoryColors.ts`**: add 6th entry.

```ts
export const CATEGORY_COLORS = {
    normal:       'var(--status-up)',     // green
    throttle:     'var(--status-warn)',   // amber
    waf:          'var(--status-down)',   // red
    crowdsec:     'var(--accent-cyan)',   // purple-blue
    auth:         'var(--status-info)',   // cyan
    country_block: 'var(--status-meta)',  // gray — V.W
};
```

**`MapLegend.svelte`**: 6th row.

```ts
{ category: 'country_block', label: 'Pays bloqué — règle opérateur (HTTP 403)' }
```

**`/map` page** (`web/frontend/src/routes/map/+page.svelte`): new counter pill alongside the V.6 WS pill + V.7 LAN pill (top-right of the map frame). Increments on every `country_block` event received via the WS stream. Tooltip explains "Compteur des requêtes bloquées par règle de pays depuis l'ouverture de la page."

**Per-route edit modal**: new "Pays bloqués" section with:
- Mode segmented control: `Désactivé` / `Autoriser uniquement` / `Bloquer`.
- CountryList multi-select with ISO-code autocomplete (operator types "FR" or "France" — both resolve).
- Footgun warning when `Mode="allow" && CountryList=[]`: red banner "Cette configuration bloquera tout le trafic externe. Ajoutez au moins un pays."
- Save button disabled while the footgun condition holds (defense-in-depth — API rejects too).

**Activity log** (`/logs`): new event source row for `country_block` entries. Reuses the existing aggregator pattern (waf/throttle/auth/cert sources). Row shape:

```
[ts] [country flag emoji] [route name] [src IP] [country] [mode badge: ALLOW/DENY] [status code]
```

## §4 Acceptance criteria

**AC #1** — Route with `Mode="off"` (or empty) routes traffic identically to v1.5.0-step-v1. Zero behavior change for pre-W rows and operators who don't enable the feature. caddymgr emit-config diff against pre-W = ONLY the new field on the route JSON (no per-route handler addition).

**AC #2** — Route with `Mode="allow"` + `CountryList=["FR", "DE"]` passes traffic from FR and DE source IPs, blocks all others with the configured status code (default 403). Verified by integration test: fixture MMDB with known IPs in FR/DE/RU/US, request from each → expected pass/block.

**AC #3** — Route with `Mode="deny"` + `CountryList=["RU", "KP"]` blocks traffic from RU/KP source IPs, passes all others. Same integration test shape as AC #2.

**AC #4** — Block fires BEFORE crowdsec/auth/waf. Verified by a chain-position test that mounts the V.1.2 `RouteMetricsHandler` → country-block → fake crowdsec/auth/waf handlers and asserts the inner handlers are NOT called on a block.

**AC #5** — Block status code respects `ARENET_COUNTRY_BLOCK_STATUS`. Test: env var unset → 403; env=`451` → 451; env=`444` → connection closed without body; env=`999` (invalid) → WARN log + fallback to 403.

**AC #6** — Trusted-IP allowlist bypasses the country block. Test: `ARENET_COUNTRY_BLOCK_TRUSTED_IPS=203.0.113.5/32`; route has `Mode="deny" CountryList=["FR"]`; request from 203.0.113.5 (geographically in FR per fixture MMDB) → passes through.

**AC #7** — RFC1918 sources auto-bypass regardless of allow-list. Test: `Mode="allow" CountryList=["FR"]`; request from `10.0.0.5` → passes (RFC1918 short-circuit fires before country lookup).

**AC #8** — Block emits `GeoEvent{category: "country_block"}` on the bus (subject to sampling + cooldown). Test: fixture sink + 100 blocks → ~100 events with `SamplePct=100`; ~5 events with `SamplePct=5`; ~1 event with `Cooldown=1h` (per-IP cooldown collapses repeats).

**AC #9** — Country-block event persists to `country_block_event` table. Test: trigger one block, query the table, assert one row with the correct columns.

**AC #10** — 30-day retention pruner removes old `country_block_event` rows. Test: insert row with `ts = now - 31d`, run pruner, assert row removed.

**AC #11** — Hot-reload: change `Mode` from `"off"` to `"deny"` via `PUT /api/v1/routes/{id}`, next request from a blocked-country source gets the new behavior without Arenet process restart. Test exercises the full API → mgr.Apply → next-request path.

**AC #12** — Boot signal `country block sink wired` fires at boot with `status_code`, `trusted_ips_count`, `sample_pct`, `cooldown` fields. Visible in journalctl regardless of whether any route uses country-block.

**AC #13** — Frontend renders `country_block` events as gray arcs on the threat map. Test: WS feeds a `country_block` event into the page, assert arc rendered with `stroke="var(--status-meta)"`.

**AC #14** — Counter pill increments per `country_block` event received. Test: WS feeds 5 events, assert pill shows "5 bloqué(s)".

**AC #15** — Activity log shows `country_block` rows. Test: backend fixture inserts 3 `country_block_event` rows, frontend `/logs` page fetches → renders 3 rows with the expected shape.

**AC #16** — Per-route UI saves `Mode` + `CountryList` correctly via the existing `PUT /routes/{id}` flow. Test: UI form submit → API receives validated payload → BoltDB row reflects the change.

**AC #17** — API validation rejects (with 400 + clear message):
- Mode outside the enum (e.g. `"block"` instead of `"deny"`).
- Country codes that don't match `/^[A-Z]{2}$/` (e.g. `"fr"`, `"FRA"`, `"123"`).
- Duplicate country codes in the list.
- `Mode="allow" && CountryList=[]` (the §D2 footgun).

**AC #18** — Degraded mode: when `geo.Lookup` is nil (MMDB missing) OR the lookup returns no country (`""`), the country-block handler FAILS OPEN — passes the request through with a single `Warn` log line per Provision ("country-block: GeoIP unavailable; bypassing all routes"). Tested with a nil-Lookup fixture.

## §5 Operator config surface

| Env var | Type | Default | Notes |
|---|---|---|---|
| `ARENET_COUNTRY_BLOCK_STATUS` | int (403\|451\|444) | `403` | HTTP status emitted on block. Invalid values WARN at boot, fall back to 403. |
| `ARENET_COUNTRY_BLOCK_TRUSTED_IPS` | CSV CIDR string | `""` | Comma-separated CIDR list. Source IPs in this list bypass the country matcher. RFC1918 / loopback / link-local are auto-bypassed regardless. Malformed entries WARN at boot and are dropped (other valid entries still apply). |
| `ARENET_COUNTRY_BLOCK_SAMPLE_PCT` | int `0..100` | `100` | Random sample percentage for `country_block` GeoEvent emission. Default 100 because block volume is structurally << normal traffic and operators want full visibility. Invalid values FATAL at boot. |
| `ARENET_COUNTRY_BLOCK_PER_IP_COOLDOWN` | Go duration | `60s` | Per-IP cooldown for event emission. Longer than V.1's 30s — blocked sources retry less interestingly. `0s` disables the cooldown gate. |

Per-route JSON shape (added to `Route`):

```json
{
  "country_block": {
    "mode": "deny",
    "country_list": ["RU", "KP", "CN"]
  }
}
```

Interaction semantics:

- All `mode != "off"` routes share the SAME global `STATUS`, `TRUSTED_IPS`, `SAMPLE_PCT`, `COOLDOWN` — these are deployment-level concerns, not per-route.
- `mode == "off"` (or `""`) routes are NOT inspected at all — the country-block handler isn't even emitted in the per-route chain.
- Hot-reload: changing the env vars requires a process restart; changing the per-route `Mode` + `CountryList` via the API is hot-reloadable (§D7).

## §6 Sub-task plan

| Sub-task | Scope | Files | ACs | Effort |
|---|---|---|---|---|
| **W.1** | `internal/countryblock/` package (NEW): Caddy module + ServeHTTP gate logic + ValidateConfig + pure-Go evaluator + tests covering the Mode matrix + trusted-IP + RFC1918 + degraded mode + sink emission. | `internal/countryblock/module.go`, `internal/countryblock/config.go`, `internal/countryblock/matcher.go`, `internal/countryblock/*_test.go` | #1, #2, #3, #4, #7, #17, #18 | ~3 h |
| **W.2** | Storage + API: `Route.CountryBlock` field + API validation (`createRoute` / `updateRoute`) + wire-shape tests. Zero-value decode preserves pre-W behavior. | `internal/storage/routes.go`, `internal/api/handler.go`, `internal/api/handler_test.go` | #1, #16, #17 | ~1.5 h |
| **W.3** | caddymgr emit + env-var parsing + global setters. Thread `Route.CountryBlock` into the per-route handler chain at position #2. Skip emission when `Mode == ""\|"off"`. `mgr.SetCountryBlockStatus` / `SetCountryBlockTrustedIPs`. | `internal/caddymgr/manager.go`, `cmd/arenet/country_block_config.go` (NEW), `cmd/arenet/main.go` | #4, #5, #6 | ~1.5 h |
| **W.4** | GeoEvent emission: `CountryBlockSink` + `EnrichCountryBlock` + 6th category constant + `country_block_event` table (migration v6→v7) + retention extension + `geoForwardingCountryBlockSink` wrapper + boot signal. | `internal/geo/enricher.go`, `internal/geo/country_block_sink.go` (NEW), `internal/observability/country_block_event.go` (NEW), `internal/observability/migrate.go`, `internal/observability/retention.go`, `cmd/arenet/geo_forwarders.go`, `cmd/arenet/main.go` | #8, #9, #10, #11, #12 | ~2.5 h |
| **W.5** | Frontend: 6th legend entry + counter pill on `/map` + per-route UI section (Mode segmented + CountryList chip input with footgun warning) + activity-log row source for `country_block` events. | `web/frontend/src/lib/components/Map/categoryColors.ts`, `web/frontend/src/lib/components/Map/MapLegend.svelte`, `web/frontend/src/routes/map/+page.svelte`, `web/frontend/src/routes/routes/+page.svelte` (or the modal component), `web/frontend/src/routes/logs/+page.svelte`, `web/frontend/src/lib/api/types.ts` | #13, #14, #15, #16 | ~3 h |
| **W.6** | Live smoke (deploy + curl from a real VPN exit in a blocked country; confirm 403 + gray arc + activity-log entry) + operator-facing doc + release notes + tag gate. | `docs/operations/country-block.md` (NEW), `docs/release-notes/v1.6.0-step-w.md` (NEW) | Validation only | ~1.5 h |

**Total Step W effort estimate**: ~13 h, deliverable in 3-4 sessions. Single tag after W.6: `v1.6.0-step-w`.

## §7 Known limitations (cite, don't fix)

- **Country detection precision tied to MMDB freshness** (`#R-COUNTRY-BLOCK-mmdb-staleness`): a stale MMDB produces stale block decisions. Operator must replace `/var/lib/arenet/GeoLite2-City.mmdb` on a cadence appropriate to their threat model; arenet does NOT auto-update. Same limitation Step V documents for the threat map.
- **Hand-rolled module ≠ standard Caddy module** (`#R-COUNTRY-BLOCK-non-portable-config`): operators can't drop in upstream `caddy-maxmind-geolocation` as a replacement without rewriting their JSON config to use `maxmind_geolocation` instead of `arenet_country_block`. Acceptable trade-off — we gain integration depth (reuse of `geo.Lookup`, event emission, trusted-IP bypass) by losing the standard-ecosystem path.
- **Gray color may read as "inactive"** (`#R-COUNTRY-BLOCK-color-confusion`): `--status-meta` was chosen for the "policy enforcement, not threat" semantic. If smoke shows operators interpret gray as disabled / no-traffic, HF1 will add a dedicated `--color-blocked` token.
- **Sampling default 100 is appropriate at block volumes** (`#R-COUNTRY-BLOCK-volume-sample`): typical block volumes are << normal traffic. Operators running country-block on high-volume scrape-target routes (e.g. blocking all of CN on a public API) should lower `SAMPLE_PCT` manually. No automatic detection.
- **No dry-run preview mode** (`#R-COUNTRY-BLOCK-dry-run`): operators can't `Mode="dry-run"` to see what WOULD be blocked without actually blocking. Deferred to Step W+1 if operator feedback shows demand. Workaround: enable `Mode="deny"` with a single test country (e.g. one the operator can reach from a known VPN), watch the activity log for 5 minutes, decide whether to commit.
- **Country-by-IP is imperfect** (`#R-COUNTRY-BLOCK-vpn-mobile-cgnat`): VPN exits, mobile carriers, and CGNAT pools all routinely misattribute country. The MMDB is best-effort. Operators MUST NOT rely on country-block for legal compliance — only as a noise filter / first-line gate. Document this prominently in the operator-facing doc at W.6.
- **No `--no-trusted-ips` audit endpoint** (`#R-COUNTRY-BLOCK-audit-trusted-ips`): operators can't see at runtime which IPs are in their trusted allowlist. The env var is visible via the existing `/api/v1/admin/config` shape if we surface it, but Step W doesn't add that surface. Defer to a future operator-tooling sweep.
- **Global env vars require restart to change** (consistent with the V.1 pattern): operators changing `ARENET_COUNTRY_BLOCK_STATUS` / `TRUSTED_IPS` / `SAMPLE_PCT` / `COOLDOWN` need to restart Arenet. Per-route `Mode` + `CountryList` are hot-reloadable via the API.

## §8 References

- **Step V spec** (the layered GeoIP architecture this builds on): `docs/superpowers/specs/2026-06-06-step-v-geographic-threat-map.md` (commit `c9ff5e9`), §3.9 — the Step W forward-reference that mentioned porech as a *candidate*, NOT a shipped dep.
- **Step V.1 spec** (the sampling-LRU-cooldown pipeline pattern W.4 mirrors): `docs/superpowers/specs/2026-06-07-step-v1-normal-traffic-monitoring.md` (commit `e87269f`).
- **Step W discovery** (the empirical recon + porech-not-vendored correction + 8 §5 Q&A): `docs/superpowers/discovery/2026-06-07-step-w-country-block.md` (commit `f9f29fe`).
- **V.1.1 `normal_sink.go`** (commit `f657a11`): the sampling-LRU-cooldown template for W.4's `CountryBlockSink`.
- **V.1.2 `RouteMetricsHandler`** (commit `09ea2c1`): the chain-position #1 invariant Step W respects (W is #2).
- **V.1.3 atomic.Pointer globals** (commit `b778424`): the late-install pattern W's `countryblock.SetGlobal*` setters mirror.
- **`internal/geo/lookup.go`**: the V.1 MMDB reader W reuses.
- **`internal/storage/routes.go:164`**: the `Route` schema W.2 extends.
- **`internal/caddymgr/manager.go:910-925`**: the per-route handler chain W.3 inserts position #2 into.

## §9 Frozen tag

Tag after merge: `v1.6.0-step-w-spec`.
