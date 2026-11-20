<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Security Automation — pre-LRU volume signal for the threshold check

**Status:** proposed (awaiting operator sign-off)
**Target version:** v2.83.1 (bugfix, no new user-facing surface) — operator confirms the tag
**Related:** `[[crowdsec-three-parts]]`, memory `automation-threshold-per-tick-bug`

## Problem

The WAF and throttle observability sinks apply a **60 s sliding LRU dedup**
per triple before persisting to their event tables:

- WAF: `(routeID, srcIP, ruleID)` — `internal/waf/lru.go`
- Throttle: `(srcIP, tier)` — `internal/throttle/lru.go`

Both exist for one reason: cap event-table storage (the §1.6.6 hazard — a
sustained 100 req/s attack would fill ~150 GB at the 30 d retention horizon).
The bucket/volume counters are bumped on **every** event (bump-then-suppress),
so the dashboard timeline still reflects true attack volume.

The **automation trigger** counts *table rows* per `(srcIP, Source)` inside the
rule `Window` and compares to `Threshold`
(`cmd/arenet/automation_adapters.go:43` → `internal/automation/trigger.go`
`tick`). Because the table is LRU-deduplicated, a single attack vector (same
srcIP, same rule) contributes **at most one row per 60 s**. Any `Threshold ≥ 2`
is therefore **unreachable from a single vector** within a short window.

### Empirical confirmation (2026-11-20, diag v3 on AreNET-test)

Burst of 4 parallel identical RCE curls from a public IP (185.23.40.4) →
`whatsapp.worldgeekwide.fr/?cmd=;cat…`:

```
flushTxBuffer mode=block interruptionNil=false action=BLOCK statusCode=403   # action correct
lru.shouldEmit ruleID=932160 decision=emit-firstsight                         # 1st event
lru.shouldEmit ruleID=932160 decision=suppress ageMs=0 ttlMs=60000            # 2nd
lru.shouldEmit ruleID=932160 decision=suppress ageMs=0 ttlMs=60000            # 3rd
lru.shouldEmit ruleID=932160 decision=suppress ageMs=0 ttlMs=60000            # 4th
… next tick …
DIAG group srcIP=185.23.40.4 source=waf-rce n=1 ruleEnabled=true threshold=2
DIAG skip.threshold.batch n=1 threshold=2                                     # never bans
```

Invalidated along the way (do not re-raise): `action=DETECT` (that was the
webhooks route, legitimately in detect mode), "LRU inverted" (it works as
designed), "srcIP overwritten to 192.168.1.206" (the public IP transits
correctly). **One real product bug: the LRU dedup is too coarse for the
threshold logic.**

### Secondary bug subsumed

The trigger evaluates the threshold only over **the current tick's batch**:
`readWaf` reads `[cursor, now]` and advances the cursor to `max(ts)` each tick,
so events are read once and never accumulate across ticks. Even without the
LRU, a burst would have to land inside one ~5 s tick to be counted together.
An in-memory sliding window naturally accumulates across ticks and fixes this.

## Root cause (confirmed)

The LRU is correct for storage capping; it is the **wrong source** for a
"distinct events in window" count. The trigger needs the *pre-LRU* volume. The
fix gives it exactly that, without touching either LRU.

## Design (validated direction)

Tap the **pre-LRU** event flux and feed an in-memory, bounded, sliding-window
**volume tracker** keyed by `(srcIP, Source)`. The trigger reads WAF/throttle
volume from the tracker instead of the deduplicated tables. The tables stay the
forensic/UI record; the LRUs are untouched.

```
WAF match → flushTxBuffer → waf.GetGlobalSink().Emit(e)
                                    │
             geoForwardingWafSink.Emit  ──► volume tracker.Observe(srcIP, Source, ts)   [NEW, pre-LRU]
                                    │
                              inner sink → channel → absorb → LRU → waf_event table  [unchanged]

trigger.tick() → readWaf/readThrottle → tracker.Query(maxWindow)  [was: obsStore DB count]
              → group (srcIP, Source) → per-rule window recount → cooldown → dedupe → intent
```

### Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| D1 | Signal | In-memory sliding-window counter per `(srcIP, Source)`, fed pre-LRU | Validated. Table stays deduped for the storage cap. |
| D2 | Tap point | `geoForwardingWafSink.Emit` + `geoForwardingThrottleSink.Emit` (package `main`) | Every event passes here before the inner sink's channel+LRU; zero change to `internal/waf` / `internal/throttle` sink internals. |
| D3 | Scope | **WAF + throttle** (both carry the 60 s LRU). Audit (auth failures) unchanged — no LRU. | WAF-only would ship the throttle path still broken. |
| D4 | Trigger read | **Replace** the WAF/throttle DB reads in `tick()` with tracker reads; drop their cursor. Audit keeps its DB + cursor read. | Also fixes the per-tick/cross-tick accumulation bug. Audit is low-volume, undeduped, correct as-is. |
| D5 | What counts | WAF: `ActionBlock` only (preserves the v2.58.4 detect-exclusion rationale — detect must never ban). Throttle: every throttle event (all are refusals). | Matches today's `Action=BLOCK` filter semantics. |
| D6 | `TriggeringEventID` | Synthetic ref (`source + srcIP + firstTs`). The representative row is still in the table for correlation. | The DB row id isn't known at `Emit` time; the audit message stays readable. |
| D7 | Memory bound | Per-key ring capped at K timestamps; global key cap with LRU eviction; prune to `maxEnabledWindow` on observe/tick. | `Window` has no upper bound (`rules.go:224`). Automation targets single-vector persistent attackers; volumetric/DDoS is the bouncer + rate-limit's job. |
| D8 | Re-emit guard | On intent emit, record the local dedupe as active immediately. | Tracker events linger for `Window` (unlike the cursor model), so without this the same `(srcIP, Source)` would re-emit every tick until the LAPI mirror catches up. |
| D9 | Restart | Tracker empty on restart; a burst straddling a restart may undercount. | Acceptable — the live signal rebuilds within one `Window`; forensic rows persist. |
| D10 | Degraded mode | Tracker is pure memory (no `obsStore` dependency); works even when `obsStore` is nil. | Strictly better than today (nil obsStore → WAF reader returns nil → never bans). |

### Non-goals

- Not touching either LRU (storage cap preserved).
- Not changing the audit / auth-failure path.
- Not addressing distributed/volumetric attacks (many srcIPs) — the bouncer and
  rate-limit own that layer.
- Not changing rule semantics (threshold/window/duration/cooldown) or any UI.
- Not persisting the counter across restarts.

## Empirical validation gates

- **G1 (fails first)** — feed N identical WAF block events (same srcIP, rule,
  route) within `Window` through the tracker path: the engine emits **exactly
  one** intent when `N ≥ Threshold`, **none** when `N < Threshold`. On
  current `main` (table-count path) the same burst emits none — the test MUST
  fail before the fix, per `[[guard]]` (reinject the table-count read).
- **G2** — throttle equivalent (same srcIP, same tier).
- **G3 (cross-tick)** — events spread across several ticks within `Window` still
  sum to `≥ Threshold` and trigger exactly once (proves the secondary bug fixed,
  and D8's re-emit guard holds — not once per tick).
- **G4 (memory bound)** — M distinct srcIPs at high rate stays under the
  configured caps; eviction + prune unit-tested on the tracker in isolation.
- **G5 (dogfood)** — the same 4-curl burst that produced no ban now produces
  **exactly one** `arenet/` decision in `cscli decisions list`, `threshold=2`.
- **G6 (non-regression)** — audit/auth-failure path unchanged; detect-mode WAF
  events still never ban; `/healthz` and the automation health block untouched.

## A. Memory bounds (D7 concrete values)

Package-level constants, no UI knob (tune via the B metrics if saturation shows):

| Constant | Value | Meaning |
|----------|-------|---------|
| `maxEventsPerKey` | **64** | Ring per `(srcIP, Source)`; drop-oldest when full. Far above the max default `Threshold` (10). Once at cap, the count is known `≥` any realistic threshold, so dropping older events never flips a decision. |
| `maxKeysGlobal` | **4096** | Distinct `(srcIP, Source)` pairs retained; LRU-evict the oldest when full (oldest ⇒ least likely still inside a window). |
| retention | `maxEnabledWindow` | Entries older than the largest enabled rule `Window` are pruned each observe/tick. |

**Memory envelope** (per-event record ≈ a `time.Time`, 24 B; per-key overhead ≈
key string + map/list node):

- **Idle / normal homelab (10 routes):** WAF/throttle events fire only on an
  actual match or refusal, so the tracker holds a handful of keys with a few
  events each — **< 100 KB**, near zero when nothing is being attacked.
- **Under active attack:** one attacking IP = **one key** regardless of volume
  (capped at 64 events). A broad scan from N IPs = N keys until `maxKeysGlobal`,
  then LRU eviction. Hard ceiling ≈ `4096 × 64 × 24 B` + overhead ≈ **~8 MB**;
  steady-state far below, because prune-to-`maxWindow` drops idle keys.

Single-vector persistent attackers (the automation target) are always captured;
volumetric/DDoS saturation is explicitly out of scope (bouncer + rate-limit).

## B. Observability of the tracker (Prometheus)

Mirror the existing `automationCollector` pattern
(`internal/api/metrics_prometheus.go` reads `automation.HealthSnapshot`): extend
the snapshot with the tracker's atomic stats; the collector emits:

| Metric | Type | Meaning |
|--------|------|---------|
| `arenet_automation_memcounter_keys_total` | gauge | Current retained `(srcIP, Source)` key count. |
| `arenet_automation_memcounter_dropped_capkey_total` | counter | Events dropped because a key hit `maxEventsPerKey`. |
| `arenet_automation_memcounter_dropped_capglobal_total` | counter | Keys evicted because the tracker hit `maxKeysGlobal`. |
| `arenet_automation_memcounter_pruned_window_total` | counter | Entries pruned by window-expiry. |

Zeros emitted in degraded mode (series always exist for alerting). `keys_total`
climbing toward 4096 or `dropped_capglobal` rising ⇒ widen the cap. Added to
`docs/operations/monitoring.md` and the OpenAPI metrics note.

## C. Test shapes (G1/G2 — both levels)

- **G1 WAF — unit** (`volume_test.go`): `Observe` N identical
  `(srcIP, waf-rce, ts≈now)` → `Query(now, window)` returns **N** records (NOT
  1) — proves no dedup. Plus cap/evict/prune/concurrency (`-race`) = G4.
- **G1 WAF — integration** (`volume_trigger_test.go`): feed N identical WAF
  block events through the tracker-backed `readWaf`, drive `tick()` with a fake
  writer capturing intents → **exactly one** intent when `N ≥ Threshold`, none
  when `N < Threshold`. This is the test that must **fail first** on the
  table-count path (reinject per `[[guard]]`).
- **G2 throttle** — the same two levels for `(srcIP, tier)`: unit proves
  identical bursts traverse the tracker **without** dedup; integration proves
  the throttle rule fires at `N ≥ Threshold`.
- **G3 cross-tick** — identical events delivered across several `tick()` calls
  inside `Window` trigger **exactly once** (D8 guard: not once per tick).

## D9–D11. LAPI visibility of auto-bans

- **D9 scenario — ALREADY DONE.** `Source.Scenario()` returns `"arenet/" +
  source` (`rules.go:71`): `arenet/waf-rce`, `arenet/waf-sqli`,
  `arenet/throttle-tier1`, … The Posture page's `scenario.startsWith("arenet/")`
  filter already distinguishes them from native/CAPI scenarios. No change.
- **D10 origin — ALREADY DONE.** The pushed `AlertDecision.Origin = "arenet"`
  (`watcher_client.go:295-301`), distinct from `cscli`/`crowdsec`/`CAPI`; LAPI
  accepts it. The Live LAPI tab can filter `origin=arenet`. No change.
- **D11 UI deep-link + 24 h counter — OUT OF SCOPE for v2.83.1 (recommended
  follow-up v2.84.0).** The health block already exposes `LastPushAt`
  (≈ "did a ban just fire?") and `LastPushError` (PR #350). The genuinely new
  surface — `totalBansIssued24h` and a deep-link to Posture › Live LAPI filtered
  on `origin=arenet` — is a UI feature, not part of the threshold bugfix.
  Bundling it would contradict "patch, no new user-facing surface" and widen the
  blast radius of the critical fix. Recommendation: ship the fix as v2.83.1, add
  D11 as a small follow-up. (Operator may elect to bundle; flagged, not decided.)

## Rollout

Fix on `fix/automation-prelru-volume`, distinct from the throwaway
`diag/automation-trigger-trace` (which the operator drops after this lands). PR →
merge → operator tags v2.83.1 → dogfood gate G5 on AreNET-test before closing.

**Mandatory release note (operator's wording, behaviour-change warning):**

> Fix : le seuil de la Security Automation est maintenant compté **par requête**
> au lieu d'être dédupliqué par `(srcIP, ruleID)` sur 60 s. Les auto-bans vont se
> déclencher là où rien ne se passait avant — c'est le comportement promis.

This is a behaviour change, not a silent fix: operators who enabled rules and saw
nothing will suddenly see bans. The note must be prominent in the v2.83.1 release.
