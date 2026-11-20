<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke test — Security Automation ban observability (v2.84.0)

Spec: `docs/superpowers/specs/2026-11-20-automation-bans-observability-design.md`.
Two observability gaps on the bans the auto-classify writer pushes to CrowdSec
LAPI (`origin=arenet`), once v2.83.1 made single-vector bans fire:

- **D11** — no in-UI view of recent bans. Now: a "Dernier ban / Bans émis sur
  24h" card in the Security Automation panel, plus an **AreNET** origin filter
  tab in Posture › CrowdSec › Live LAPI, reachable by deep-link.
- **D12** — arenet decisions lacked Country/AS. Now: `buildAlert` populates
  `cn` / `as_number` / `as_name` (CrowdSec `models.Source`) from the local
  GeoIP/ASN DBs — LAPI does **not** enrich `/v1/alerts` on ingest, so the
  client must. Soft-fail: a degraded DB yields empty fields and the ban still
  fires.

Both are reporting/UX, not security: bans fire and the bouncer enforces them
regardless.

## Automated guards (CI)

### Backend
```
go test -race -count=1 ./internal/automation/... ./internal/api/... ./cmd/arenet/...
```

- `TestBanTimeline_CountSinceWindow` (**G1**) — N pushes → `TotalBansIssued24h
  == N`; entries older than 24h are pruned. **Reinjection proof:** a cumulative
  counter (no window prune) fails the prune assertion.
- `TestBanTimeline_Cap` — beyond the 2048 cap, drop-oldest keeps the newest
  2048 (documented under-report past the cap).
- `TestEngine_RecordBan` — `lastBanScenario` / `lastBanSrcIp` are recorded at
  the same instant as the push success (`lastPushAt`), so the three are always
  consistent.
- `TestBuildAlert_GeoEnrichment` (**G2**) — with an enricher the alert source
  carries `cn`/`as_number`/`as_name`; with a **nil** enricher they stay empty
  (soft-fail / non-regression). **Reinjection:** dropping the enricher call
  fails the populated case.
- `TestBuildAlert_GeoEnrichment_Wire` (**G3**) — asserts the marshaled JSON
  carries `"cn"`/`"as_number"`/`"as_name"` when enriched and omits them
  (`omitempty`) when not — a pre-v2.84.0 push is byte-identical on the wire.

### Frontend
```
cd web/frontend && npm run check && npx vitest run \
  src/lib/components/CrowdSecDecisionsPanel.test.ts \
  src/routes/settings/page.test.ts \
  src/lib/i18n/index.test.ts
```

- **G4 panel** — the AreNET origin tab renders with its count and sits right
  after "Toutes"; `initialOrigin="arenet"` pre-selects the Live sub-tab + AreNET
  filter and shows only `origin==="arenet"` rows; clicking AreNET filters
  client-side with **no re-fetch**; the filtered-empty state shows when AreNET
  has 0 matches but LAPI has data; **no hijack** — no (or a non-arenet)
  `initialOrigin` opens the default snapshot tab and never polls LAPI on mount.
- **G4 card** — the health panel renders the last-ban line + 24h count, shows
  the empty state when zero, and links "Voir tous les bans" to
  `/security?tab=crowdsec&origin=arenet`.
- **Reinjection proof:** count→0, ignore `initialArenet`, filter case→`true`,
  and a wrong href each fail **only their own** guard (siblings stay green).
- i18n FR+EN parity (`index.test.ts`) — every new `settings.automation.bans.*`
  key present in both locales.

## Manual dogfood gate (G5) — AreNET-test

Preconditions: a WAF or throttle rule **Enabled** with `threshold>=2`, writer
healthy (badge **Active**), the GeoIP + ASN MMDBs present (Settings → GeoIP
shows them current). Attack from a **public** IP (private/LAN gets no `cn`).

1. Trigger a ban (e.g. repeat an RCE probe on a Block-mode route until the
   threshold is crossed within the window).
2. **Settings → Security → Security Automation card:**
   - "Dernier ban : `arenet/<category>` depuis `<your public IP>` à `<time>`".
   - "Bans émis sur les dernières 24 h : 1" (climbs with each distinct ban).
3. Click **"Voir tous les bans"** → lands on Posture › CrowdSec with the **Live
   LAPI** sub-tab open and the **AreNET** origin tab pre-selected, showing your
   decision and nothing else. Clicking **Toutes** shows the full list again.
4. On the LAPI host: `cscli decisions list -o human` → the arenet decision shows
   **Country** and **AS** columns populated (not blank).
5. Restart Arenet → the 24h count resets to 0 and rebuilds as new bans fire
   (in-memory gauge; LAPI remains the ledger). This is expected, not a bug.

## Non-regression (G6)

- A push built **without** an enricher (nil GeoEnricher — e.g. both MMDBs
  missing at boot) is byte-identical to a pre-v2.84.0 push: the three geo fields
  `omitempty` out of the JSON (asserted by `TestBuildAlert_GeoEnrichment_Wire`).
- The badge tri-state, `/healthz`, push/retry semantics, the LRUs, the event
  tables, and the v2.83.1 threshold/volume logic are untouched.
- No new frontend route, no new Prometheus metric (the 24h rate is
  `increase(arenet_automation_pushes_total{result="success"}[24h])`).
