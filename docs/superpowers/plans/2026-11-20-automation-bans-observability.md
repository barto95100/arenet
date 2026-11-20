<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Plan — Security Automation ban observability (D11 + D12)

Spec: `docs/superpowers/specs/2026-11-20-automation-bans-observability-design.md`.
Branch: `fix/automation-bans-observability` (from `main`, post-v2.83.1).
Discipline: `[[guard]]` — red tests first, reinject each defect (`cp`, never
`git checkout`), assert on the wire not the struct.

## T0 — Guard reds first (no production change)

- `internal/automation/bantimeline_test.go` (**G1**): against a `banTimeline`
  type that does not exist yet / a cumulative stub → push N, assert
  `TotalBansIssued24h == N`, prune > 24h, drop-oldest at cap. Watch it fail.
- `internal/automation/geoenrich_test.go` (**G2 + G3**): `buildAlert` with a
  fake `GeoEnricher` → `Cn/AsNumber/AsName` populated; nil enricher → empty;
  marshal → JSON carries `cn`/`as_number`/`as_name`. Watch the populated case
  fail before buildAlert is wired to the enricher.
- Commit the reds in their own commit so the diff shows the defect.

## T1 — D11 backend: banTimeline + health fields

- `internal/automation/bantimeline.go`: ring of success timestamps, cap 2048,
  prune-to-24h on read, mutex-guarded, injectable clock. `Observe(ts)` +
  `CountSince(now, 24h) int`.
- Engine: hold a `*banTimeline`; in the push-success path record the ban ts +
  `lastBanScenario` + `lastBanSrcIP` (extend/duplicate `recordPushSuccess` so the
  existing `trigger_lastpush_test.go` call still compiles — decide extend-vs-new
  during impl, note in commit).
- `HealthSnapshot` (+`health.go`): `TotalBansIssued24h`, `LastBanScenario *string`,
  `LastBanSrcIP *string`. `DefaultManager.HealthSnapshot` populates them.
- API: surface the three in `GET /api/v1/settings/automation` health (+ the
  OpenAPI schema entry; `[[openapi-route-must-be-documented]]`).

## T2 — D12 enrichment: AlertSource + GeoEnricher + wiring

- `watcher_client.go`: add `Cn`/`AsNumber`/`AsName` to `AlertSource`
  (`cn`/`as_number`/`as_name`, `omitempty`). **Fix the false comment** at 284-285.
- `trigger.go`: `GeoEnricher` interface + `EngineConfig.GeoEnricher`; `buildAlert`
  takes it and populates the three fields (nil-safe, soft-fail).
- `cmd/arenet`: a `geoSourceEnricher` adapter over `geo.Lookup.LookupIP`
  (`Country`, skip `!Found`/`"LAN"`) + `geo.ASNLookup.LookupASN`
  (`strconv(ASN)`, `Name`); wire into `wireAutomation` → `EngineConfig.GeoEnricher`.
  Confirm an `asnLookup` is constructed in `main.go` (country-block uses ASN); if
  not wired to automation yet, pass it through.

## T3 — D11 frontend

- `CrowdSecDecisionsPanel.svelte`: read `?scenario=` (via `security/decisions`
  load/`$page.url`), filter client-side to `scenario.startsWith(value)` when set.
- `settings/+page.svelte` Security Automation card: the "Dernier ban …" line +
  "Bans émis sur 24h : N" + "Voir tous les bans" link to
  `/security/decisions?scenario=arenet`; graceful empty state at N=0.
- `lib/api/types.ts`: the three new health fields.
- i18n FR + EN for every new string; `lib/i18n/index.test.ts` parity must pass.
- Component tests (**G4**): filtered panel shows only `arenet/*`; card renders the
  last-ban line + count + empty state.

## T4 — Reinject + sibling isolation

- G1: swap the ring for a cumulative counter → prune/window assertion fails;
  restore (`cp`), `diff -q` RESTORED.
- G2: drop the enricher call in `buildAlert` → populated case fails, nil case
  still passes (one mechanism, one test).

## T5 — Full suite + non-regression (G6)

- `go build ./... && go vet ./...`
- `go test -race -count=1 ./internal/automation/... ./internal/api/... ./cmd/arenet/...`
- `cd web/frontend && npm run check && npm test`
- Byte-identity: a push payload with **no** enricher marshals exactly as today
  (the three fields `omitempty` out) — guard the `[[test-the-wire-not-the-struct]]`
  boundary.

## T6 — Docs / smoke

- `docs/smoke-test-automation-bans-observability.md`: the G5 dogfood (trigger a
  ban → UI last-ban line + 24h count + deep-link + Country/AS in `cscli`).
- `docs/operations/monitoring.md`: note `pushes_total{result="success"}` +
  `increase(...[24h])` as the scraper path for the 24h ban rate (no new metric).
- Update memory `[[automation-ban-observability-backlog]]` → shipped; add the D11
  + D12 lines to `docs/roadmap.md` (move from backlog to shipped v2.84.0).

## PR / tag

- PR → `main`. No `Co-Authored-By`, no 🤖 footer.
- Operator tags **v2.84.0**; dogfood gate G5 before closing.

## Open during impl (small, non-blocking)

- `recordPushSuccess` extend vs new recorder for the last-ban fields.
- Whether an ASN lookup is already constructed in `main.go` or needs adding to
  the automation wiring path.
