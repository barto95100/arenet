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

## Rollout

Fix on `fix/automation-prelru-volume`, distinct from the throwaway
`diag/automation-trigger-trace` (which the operator drops after this lands). PR →
merge → operator tags v2.83.1 → dogfood gate G5 on AreNET-test before closing.
