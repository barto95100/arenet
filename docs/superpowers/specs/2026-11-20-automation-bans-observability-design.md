<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Security Automation — ban observability (D11 + D12)

**Status:** proposed (awaiting operator sign-off before T0)
**Target version:** v2.84.0 (minor — new API + UI surfaces, non-breaking)
**Follows:** v2.83.1 (`[[automation-threshold-per-tick-bug]]` — the fix that made
bans actually fire). Related: `[[crowdsec-three-parts]]`,
`[[automation-ban-observability-backlog]]`.

## Problem

Two observability gaps on the bans the auto-classify writer pushes to CrowdSec
LAPI (`origin=arenet`), surfaced once v2.83.1 made single-vector bans fire:

- **D11 — no in-UI view of recent bans.** The operator can only confirm bans by
  reading `cscli` or hunting through Posture › Live LAPI among thousands of
  mixed-origin decisions. The health block (PR #350) shows writer health but no
  "what did I ban, when".
- **D12 — arenet decisions lack Country/AS.** `cscli`/UI show Country from
  `source.cn` and AS from `source.as_number`/`as_name`
  (CrowdSec `models.Source` v1.6.3). These are **populated by the client**; LAPI
  does NOT enrich `/v1/alerts` on ingest (the `geoip-enrich` parser runs in the
  agent, upstream — arenet posts directly and bypasses it). `buildAlert`
  (`internal/automation/trigger.go:721`) sets only `scope`/`value`/`ip`, so
  `cn`/`as_number`/`as_name` stay empty — the audited root cause (2026-11-20).
  The comment at `watcher_client.go:284-285` ("LAPI uses it for geo enrichment")
  is the wrong assumption behind the gap.

Both are **UX/reporting, not security** — bans fire and the bouncer enforces
them today. One workstream: "observabilité des bans AreNET".

## Decisions

| # | Decision | Choice | Rationale |
|---|----------|--------|-----------|
| D11.a | 24h count storage | **In-memory sliding ring** (ts of successful pushes), precise window, drop-oldest | Zero schema change; semantically = what the writer issued. Resets on restart (self-heals in 24h; LAPI is the ledger). `decision_event` has no `origin` column and only exact-match scenario filtering, so the persistent route would need a new prefix-count store method + carries 60s bouncer lag — not worth it for an activity gauge. |
| D11.b | Deep-link | **CORRECTED after grounding, operator-confirmed (2026-11-20).** The panel lives at `/security` (tab=crowdsec), `/security/decisions` is a deliberate 404 guard (deleted CS.3). The live view filters by **origin** (all/local/capi/manual) — there was **no `arenet` bucket**, so arenet bans only showed under "Toutes". So: **add an "AreNET" origin filter tab** (`origin === 'arenet'` + count), positioned **right after "Toutes"** (the operator's own product is the first filter they reach for); the panel pre-selects it (Live sub-tab + arenet origin) **only** when `?origin=arenet` is explicitly present — arriving without it leaves the default (snapshot tab, "Toutes") untouched (**no hijack**). The settings link points to **`/security?tab=crowdsec&origin=arenet`**. Filter by origin, not scenario (live decisions carry origin; the `decision_event` mirror does not). |
| D11.c | Widget placement | **In the existing Security Automation health panel** (`settings/+page.svelte`) | `LastPushAt` + badge + push counters already live there; keep one place. |
| D11 naming | `lastBanIssuedAt` | **(c) reuse `LastPushAt`**, relabel "Dernier ban" in the UI; no new API field for the timestamp | In v1.3 the writer only issues `type=ban`, so a successful push *is* a ban issued — `LastPushAt` is that instant. Renaming (a) breaks the badge consumers; a duplicate alias (b) is noise. |
| D12.a | Geo lookup failure | **Soft-fail** (push proceeds with empty cn/as) | The lookup is already degraded-mode safe (`geoLookup = &geo.Lookup{}` → empty `Location`). Enrichment is a bonus; a ban must never be blocked by a geo-DB problem. |
| D12.b | Country vs AS | **Independent** | `geo.Lookup` (country MMDB) and `geo.ASNLookup` (ASN MMDB) are separate DBs; each soft-fails to empty on its own, like CrowdSec's geoip-enrich vs ASN. |
| Bonus 1 | `lastBanScenario` + `lastBanSrcIP` | **Yes** — add to the health block | Drives an actionable "Dernier ban: `<scenario>` depuis `<ip>` à `<time>`" line. Recorded at the same instant as `LastPushAt`, so always consistent with it. |
| Bonus 2 | New Prometheus metric | **No** | `arenet_automation_pushes_total{result="success"}` already counts bans issued; `increase(...[24h])` gives the 24h rate in Grafana. A `bans_issued_total` would duplicate it. |

## Design

### D11 backend (`internal/automation`)

- **`banTimeline`** — a tiny in-memory sliding-window ring on the Engine. Each
  entry is **a `time.Time` only** (24 B) — NOT `{ts, scenario, srcIP}`; the ring
  exists solely to count. Cap **2048** entries (drop-oldest), pruned to 24h on
  read. Worst-case memory ≈ `2048 × 24 B` + slice overhead ≈ **~48–50 KB**. Bans
  are low-volume (the D8 re-emit guard collapses a flood from one vector to one
  ban). Mutex-guarded; the writer goroutine appends, the HealthSnapshot reads.
- **`lastBan{Scenario,SrcIP}`** — **single** values (the most recent ban only),
  not per-ring-entry, so the string sizes (scenario ~16 B, IPv4/IPv6 srcIP
  ≤ 45 B) are paid once, not × 2048.
- **`lastBan{Scenario,SrcIP}`** — recorded together with `lastPushSuccessNano`
  in the push-success path (`recordPushSuccess`), so all three are always the
  same event. Read into HealthSnapshot.
- **`HealthSnapshot`** gains: `TotalBansIssued24h int`, `LastBanScenario *string`,
  `LastBanSrcIP *string`. The timestamp stays `LastPushAt` (decision c).

### D11 frontend

- **Health panel** (`settings/+page.svelte`, the Security Automation card):
  - Line: *"Dernier ban : `<scenario>` depuis `<srcIP>` à `<LastPushAt>`"*.
  - Line: *"Bans émis sur 24h : N"* + a **"Voir tous les bans"** link to
    `/security?tab=crowdsec&origin=arenet`.
  - Graceful empty state when `N == 0` / no ban yet (no "last ban" line).
- **Deep-link filter**: `/security` reads `?origin=` and forwards it to
  `CrowdSecDecisionsPanel` as the `initialOrigin` prop. When it is `arenet`,
  the panel opens the Live sub-tab with the new **AreNET** origin tab
  pre-selected; the table filters client-side to `origin === "arenet"`. Any
  other value (or none) opens the default. No API change.
- i18n: every new string in FR **and** EN (`lib/i18n/locales/*.json`, parity
  test must pass).

### D12 enrichment (`internal/automation` + `cmd/arenet`)

- **`AlertSource`** (`watcher_client.go`) gains `Cn string json:"cn,omitempty"`,
  `AsNumber string json:"as_number,omitempty"`, `AsName string json:"as_name,omitempty"`
  — matching `models.Source` v1.6.3. **Fix the false comment** at lines 284-285.
- **`GeoEnricher`** interface in `EngineConfig` (nil-safe, optional):
  `EnrichSource(ip string) (cn, asNumber, asName string)`.
- **`buildAlert(intent, now, geo GeoEnricher)`** populates the three fields when
  `geo != nil` (stays a pure, testable function).
- **Adapter** in `cmd/arenet` over `geo.Lookup.LookupIP` (ISO `Country`, skipped
  when `!Found` or `"LAN"`) + `geo.ASNLookup.LookupASN` (`ASN` → decimal string,
  `Name`), wired into `wireAutomation` → `EngineConfig.GeoEnricher`. Both lookups
  already exist in `main.go` (`geoLookup` ~`main.go:631`). Soft-fail: a degraded
  lookup yields empty strings and the push proceeds.
- No change to push/retry semantics.

## Known limitations

- **24h counter is in-memory** — resets to 0 on restart and rebuilds as new bans
  fire over the following 24h. LAPI remains the accounting ledger.
- **Overflow past the ring cap** — if more than **2048** bans land inside the 24h
  window (e.g. a broad distributed attack), drop-oldest means
  `totalBansIssued24h` **under-reports** (caps at 2048). The UI 24h count is an
  *activity gauge*, approximate beyond 2048; `cscli` / Live LAPI stay exact.
- **Enrichment is best-effort** — a degraded or missing GeoIP/ASN DB yields empty
  `cn`/`as_number`/`as_name` (soft-fail); the ban still fires. A private/LAN
  srcIP (`Found:false` or `Country=="LAN"`) gets no `cn`.

## Non-goals

- No persistence of the 24h counter (in-memory; resets on restart).
- No new Prometheus metric.
- No change to the v2.83.1 threshold/volume logic, the LRUs, or the event tables.
- No new frontend route.
- No change to the `/healthz` contract or the badge tri-state semantics.

## Empirical validation gates (guard)

- **G1 (D11, fails first)** — push N bans through the writer path →
  `TotalBansIssued24h == N`; entries older than 24h are pruned; overflow past the
  cap drops oldest. Reinject: a cumulative counter (no window) fails the prune
  assertion.
- **G2 (D12, fails first)** — `buildAlert` with a fake enricher populates
  `Cn`/`AsNumber`/`AsName`; with a nil enricher the three stay empty (soft-fail,
  non-regression). Reinject: dropping the enricher call fails the populated case.
- **G3 (D12, the wire)** — marshal the alert from `buildAlert` + fake enricher and
  assert the JSON carries `cn`/`as_number`/`as_name` (per
  `[[test-the-wire-not-the-struct]]` — the struct test alone missed a camelCase
  mismatch once).
- **G4 (frontend)** — `CrowdSecDecisionsPanel`: the AreNET origin tab renders
  with its count and sits right after "Toutes"; `initialOrigin="arenet"`
  pre-selects the Live sub-tab + AreNET filter and shows only `origin==="arenet"`
  rows; clicking AreNET filters client-side with no re-fetch; the filtered-empty
  state shows when AreNET has 0 matches but LAPI has data; **no hijack** — no (or
  a non-arenet) `initialOrigin` opens the default snapshot tab and never polls
  LAPI on mount. Health panel renders the last-ban line + 24h count, and the
  empty state when zero; the "Voir tous les bans" link points at
  `/security?tab=crowdsec&origin=arenet`. (Reinjected: count→0, ignore
  initialArenet, filter→true, wrong href — each fails only its own guard.)
- **G5 (dogfood)** — on AreNET-test: trigger a ban, confirm the UI shows "Dernier
  ban …" + "Bans émis sur 24h : 1", the deep-link lands pre-filtered, and
  `cscli decisions list` shows the arenet decision **with** Country/AS populated.
- **G6 (non-regression)** — push payload without an enricher is byte-identical to
  today (the three fields `omitempty` out); badge/health, `/healthz`, i18n parity
  untouched.

## Rollout

Branch `fix/automation-bans-observability` from `main` (post-v2.83.1). Workflow
`diag-binary` reusable for mid-dev traces. PR → merge → operator tags **v2.84.0**
→ dogfood G5. No `Co-Authored-By`, no 🤖 footer (operator standing rule).
