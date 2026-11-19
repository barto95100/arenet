<!-- Arenet design spec. CC-BY-SA-4.0 for docs; code AGPL-3.0. -->

# Auto-classify health in the API + dashboard badge (v2.83.0)

Point 3(a) of the "CrowdSec observability hardening" workstream. The
closing lot: it makes the auto-classify writer's health visible **inside
Arenet** — no external collector required — by enriching the existing
`GET /api/v1/settings/automation` response and turning the Security
Automation card's status badge into a tri-state signal.

This is the companion of 3(b) (the token-authed `/metrics` endpoint,
shipped in v2.82.0). 3(b) serves Zabbix/Prometheus/Nagios; 3(a) serves
the operator looking at Arenet's own Settings page. Same underlying
`HealthSnapshot`, two audiences.

## 1. Motivation

The auto-classify writer fails **silently** (see `internal/automation/
health.go` header). A bad machine credential, a rejected payload, an
unreachable LAPI — none of it surfaces anywhere an operator looks. The
Security Automation card shows a binary "Configured / Not configured"
badge driven only by whether credentials are *stored*, which says nothing
about whether banning actually *works*.

v2.82.0 exposed the signal on `/metrics`. But an operator who does not
run a scraper still has no in-product way to notice that auto-banning
stopped weeks ago. This lot closes that: the same health read, surfaced
in the API and rendered as a badge the operator already looks at.

## 2. Non-goals

- **No historical graph** in the dashboard. Trend/rate lives on
  `/metrics` for a real TSDB to scrape. The badge is a point-in-time
  state, not a chart.
- **No dedicated alerting rule** ("auto-ban degraded" as an Alerts →
  Rules entry). Out of scope; the badge + `/metrics` cover detection.
- **No change to `/healthz`.** Its contract `{"status":"ok",
  "uptime_seconds":N}` stays byte-identical — Zabbix reads it every
  minute. A guard test pins this.
- **No revisiting the `_per_hour` metric.** The sticky `login_failed`
  gauge is the right abstraction; the lying comment was already corrected
  in v2.82.0. We expose *state* + *cumulative counters*, never a rate.
- **No new metric on `/metrics`.** 3(b) is done and frozen.

## 3. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Health fields live in a **nested `health` object** under the GET response, not flat at the top level | Groups a read-only block the way `credentials` already is; keeps the top level (`rules`, `credentials`, `engineRunning`) stable. **Deviation from the locked scope's flat field list** — same field names, grouped. Flagged here so it is not a silent change. |
| D2 | `writerHealthy = WriterConfigured && !WriterLoginFailed` | The single bool the badge needs: the writer is wired AND its last LAPI login was not rejected. False whenever credentials are absent. Computed in the API from the existing snapshot — no new engine state. |
| D3 | `lastPushAt` = time of the last **successful** push (null if none) | "Auto-ban is actively working, last decision pushed at X." Null is honest for a freshly-configured writer that has not fired yet. |
| D4 | `lastPushError` = message of the most recent **failed** push, **cleared to null on the next success** | Makes `lastPushError != null` mean "the most recent completed push failed" — naturally *recent*, with no fuzzy time-window. A later success supersedes it. This is what lets the badge read "degraded" truthfully. |
| D5 | Two new engine fields are **atomics** (`atomic.Int64` for the nano timestamp, `atomic.Pointer[string]` for the error) | The writer loop is a separate goroutine; `HealthSnapshot` is read concurrently. Same discipline as the existing `TotalPush*` atomics. No new lock. |
| D6 | Badge tri-state is **derived in the frontend** from the API payload, not a server-computed label | The server ships facts (`writerHealthy`, counters, `lastPushError`, the rule set); the UI owns presentation. Keeps i18n and color on the frontend where it belongs. |
| D7 | Badge colors follow the locked scope: green `status-up` healthy, **orange** `status-warn` degraded, grey `neutral` inactive; the pre-existing "Not configured" (`status-warn`) is untouched | Honors the operator's explicit color choice. "Not configured" and "Degraded" share orange but carry distinct labels + tooltips — acceptable, documented. |
| D8 | "Inactive" (grey) = credentials configured **but no Trigger rule enabled** | A useful self-signal: the writer is wired but nothing will ever fire because every source rule is disabled. Computed from the rule set (`some rule.enabled`). |

## 4. Point 3(a) — the two surfaces

### 4.1 API — `GET /api/v1/settings/automation`

New nested field on the response:

```jsonc
{
  "rules": { ... },
  "credentials": { "lapiUrl": "...", "machineId": "...", "configured": true },
  "engineRunning": true,
  "health": {
    "writerHealthy": true,
    "totalPushSuccess": 42,
    "totalPushPermanent": 0,
    "totalPushDropped": 1,
    "lastPushAt": "2026-11-17T09:14:02Z",   // RFC3339, or null
    "lastPushError": null                     // string, or null
  }
}
```

Sources: `automation.HealthSnapshot` (extended with `LastPushAt
*time.Time`, `LastPushError *string`) ← Engine atomics
(`trigger.go`). The handler type-asserts `automation.GetManager()` to
`automation.HealthReporter`. **Boot-degraded / no-manager / writer not
configured → the `health` object is present with zero/null values, never
a 500 and never omitted.**

Role unchanged: `viewer`.

### 4.2 UI — Security Automation card badge

The existing header badge (`+page.svelte` ~:1141) becomes tri-state
*within the configured case*; the "Not configured" case is unchanged:

| Condition | Badge | Variant |
|-----------|-------|---------|
| `!credentials.configured` | "Not configured" | `status-warn` (unchanged) |
| configured, no rule enabled | **"Inactive"** | `neutral` (grey) |
| configured, rule(s) enabled, `!writerHealthy \|\| lastPushError` | **"Degraded"** | `status-warn` (orange) |
| configured, rule(s) enabled, healthy | **"Active"** | `status-up` (green) |

A `title` tooltip on the badge carries the counters + `lastPushAt` +
`lastPushError`. No new section, no modal — the existing badge is
enriched in place (locked scope). New labels/tooltip go through i18n
(FR + EN), parity test must stay green.

## 5. TDD + empirical gates

**Go (unit, `-race`):**

1. `TestHealthSnapshot_LastPushFields` — Engine success sets
   `LastPushAt`, clears `LastPushError`; a permanent failure sets
   `LastPushError`; a later success clears it again.
   *Guard (D4 is load-bearing):* reinject "do not clear on success" →
   test must fail.
2. `TestGetAutomation_HealthWhenConfigured` — GET returns the `health`
   object with the writer's real snapshot when a manager is registered.
3. `TestGetAutomation_HealthZeroWhenUnconfigured` — no manager / no
   writer → `health` present, `writerHealthy=false`, counters 0,
   `lastPushAt`/`lastPushError` null, status 200 (**not** 500).
   *Guard:* this is the "no 500" gate the locked scope demands.
4. `TestHealthz_ByteIdentical` — `/healthz` body is exactly
   `{"status":"ok","uptime_seconds":N}` with only N varying. Pins the
   non-goal.

**Frontend (Vitest):**

5. Badge tri-state render: four payloads (not-configured, inactive,
   degraded, active) → the right label + variant each. *Guard:* a payload
   with `writerHealthy=false` must render "Degraded", not "Active".

**Empirical smoke (dogfood on AreNET-test, post-merge):**

6. Disable all auto-classify rules → badge reads grey **"Inactive"**.
7. Configure + enable a rule, healthy writer → green **"Active"**; the
   tooltip shows `lastPushAt` once a real ban is pushed.
8. Break the machine credential → badge flips to orange **"Degraded"**,
   tooltip carries `lastPushError`.
9. `curl -H "Authorization: Bearer <token>" .../api/v1/settings/automation`
   → response carries the `health` block.

## 6. Non-regression gates

- `go test -race ./internal/automation/... ./internal/api/...` green.
- `/healthz` byte-identical (gate 4).
- Existing automation GET tests (`rules` + `credentials` shape) still
  pass — the `health` field is additive, no existing field changes.
- OpenAPI: `TestOpenAPI_CoversEveryRoute` + roles still pass; the
  `SettingsAutomation` schema gains `health` (and `engineRunning`, a
  pre-existing doc gap, documented at the same time). Role stays viewer.
- Frontend i18n parity test green (new keys in both en + fr).
- `gofmt -s`, `go vet`, `npm run check` clean.

## 7. File map

**Backend**
- `internal/automation/trigger.go` — 2 atomic fields on `Engine`, record
  on success/failure in `processIntent`, 2 getters.
- `internal/automation/health.go` — `HealthSnapshot.LastPushAt`,
  `.LastPushError`; populate from the new getters.
- `internal/api/automation_handlers.go` — `automationHealth` wire struct,
  populate in `getAutomation` (HealthReporter assert; zero on nil).
- `internal/api/openapi/settings.yaml` — `SettingsAutomation` gains
  `health` + `engineRunning`; new `SettingsAutomationHealth` schema.

**Backend tests**
- `internal/automation/health_test.go` — extend (gate 1).
- `internal/automation/trigger_test.go` — last-push record/clear (gate 1 guard).
- `internal/api/automation_handlers_test.go` — gates 2, 3.
- `internal/api/health_test.go` — gate 4 (add if absent).

**Frontend**
- `web/frontend/src/lib/api/types.ts` — `AutomationHealth` + `health?`.
- `web/frontend/src/routes/settings/+page.svelte` — state, derived badge
  state, tri-state render, tooltip.
- `web/frontend/src/lib/i18n/locales/en.json` + `fr.json` — badge labels
  + tooltip keys.
- `web/frontend/src/routes/settings/page.test.ts` — gate 5.

**Docs**
- `docs/superpowers/plans/2026-11-17-automation-health-ui.md` (companion).
- `docs/operations/monitoring.md` — a line pointing the in-UI badge at
  the same facts `/metrics` exposes.

## 8. Workstream closure

- Points 1+2 (journald leak + CrowdSec source): **v2.82.0** ✅
- Point 3(b) `/metrics` Prometheus: **v2.82.0** ✅
- Point 3(a) API + badge UI: **v2.83.0** (this lot)
- After v2.83.0 merges, the "CrowdSec observability hardening" workstream
  is **closed**. No v2.84.0 on this thread.
