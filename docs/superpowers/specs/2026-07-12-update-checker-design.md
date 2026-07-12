# Update checker (Priority 5, v2.12.3)

**Date**: 2026-07-12
**Status**: Design approved, pending implementation plan
**Target version**: v2.12.3 (additive feature)

## Motivation

Operators run Arenet as a single self-updated binary/container. There is
no signal today when a newer release ships — an operator only finds out
by manually checking GitHub. Add an **opt-in** update checker that
polls the GitHub releases API, surfaces "a newer stable version is
available" as an alerting source + a discreet topbar badge + a /settings
mini-card, and links to the release. Operator decides when to update.

**Dogfooding note**: shipping this in v2.12.3 means every subsequent
release (v2.12.4+) exercises the whole path (poll → semver compare →
alert dispatch → badge/toast → i18n) end-to-end on a live instance with
zero extra effort. Because the default is opt-in, the operator's own
v2.12.3 instance must enable the check once to receive the v2.12.4 notice.

## Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | Privacy default | **Opt-in** — OFF at first boot; enabled in /settings. No external call without consent. |
| D2 | Cadence | First check ~30s after boot, then every 24h; + manual "Check now" button. Etag cache. |
| D3 | Interval | Configurable via `ARENET_UPDATE_CHECK_INTERVAL` (Go duration); min 1h (values below are clamped/rejected). Default 24h. |
| D4 | Alert severity | Always **Info** (an available update is never an operational emergency). |
| D5 | Check failure | Silent — no alert. Store `lastChecked` + `lastError`, shown in the /settings mini-card. Warn-log the first failure only, then quiet. |
| D6 | Prereleases | Stable only, via `GET /releases/latest` (GitHub excludes prereleases from that endpoint). |
| D7 | Topbar badge | Discreet bell/dot, visible only when an update is available; click → deep-link to the release; tooltip names the version. |

## Existing infra reused (verified 2026-07-12)

- Alerting source pattern: `internal/alerting/source.go` (`Source` interface) + concrete sources like `source_cert_renewal_failed.go` — the exact template for the new `update_available` source.
- Ticker/goroutine pattern: `time.NewTicker` already used (metrics ticker, crowdsec mirror at `TickerInterval`) — the checker's poll loop follows it.
- Version: `var version` in `cmd/arenet/main.go`; `/system/*` endpoints exist (`/system/health`). `/system/version` slots in naturally.

## Architecture

### Backend

**1. `internal/updatecheck/` (new package)** — the checker, isolated from
main so it's unit-testable without a live binary.
- `type Checker` holding: current version, a `*http.Client`, the GitHub
  repo, an Etag cache, and a mutable `Status` (latest, updateAvailable,
  url, lastChecked, lastError).
- `Check(ctx)` — GET `https://api.github.com/repos/barto95100/arenet/releases/latest`
  with the stored Etag (`If-None-Match`); 304 → no change, refresh
  `lastChecked` only; 200 → parse `tag_name` + `html_url`, store Etag,
  semver-compare vs current, set `updateAvailable`. Network/parse error →
  set `lastError`, keep prior `latest`. Respects GitHub rate limits (Etag
  + 24h cadence keep it far under 60 req/h unauthenticated).
- Semver compare: parse `vX.Y.Z` (tolerate a leading `v`); an update is
  available iff `latest > current` by numeric major/minor/patch. A `DEV`
  current version never reports an update (dev builds opt out).
- `Status()` returns a snapshot for the API/UI.

**2. `internal/updatecheck` poll loop** — started from `main.go` ONLY when
enabled (D1). First tick at boot+30s, then `time.NewTicker(interval)`.
The manual "check now" path calls `Check` directly (bypassing the ticker,
ignoring cadence). Guarded so a slow HTTP call can't stack ticks.

**3. `internal/alerting/source_update_available.go` (new source)** —
mirrors `source_cert_renewal_failed.go`. `Name() == "update_available"`.
Its `SourceValue` is derived from the checker's `Status` (updateAvailable
bool → the rule fires when true). Severity fixed Info (D4). Params carry
`{current, latest, url}`. Native cooldown via the existing alerting infra
(no re-alert every 24h for the same version).

**4. `internal/api/version.go` (new endpoint)** —
`GET /api/v1/system/version` → `{current, latest, updateAvailable, url,
lastChecked, lastError, enabled}`. Admin-gated like the other settings
reads. A `POST /api/v1/system/version/check` triggers a manual check
(admin-only, bypasses cadence) and returns the refreshed status.

**5. Settings persistence** — an `update_check` settings row (BoltDB)
holding `{enabled bool, intervalOverride string}`. Read at boot to decide
whether to start the loop; toggled by the /settings UI. Env
`ARENET_UPDATE_CHECK_INTERVAL` overrides the interval (D3); the enabled
flag is UI/settings only (env could add `ARENET_UPDATE_CHECK_ENABLED`
later — backlog, not v1).

### Frontend

**1. Topbar badge** (D7) — a discreet bell/dot in the topbar, rendered
only when `GET /system/version` reports `updateAvailable`. Click →
opens the release `url` in a new tab. Tooltip: "vX.Y.Z available".
Polls `/system/version` on mount + on a light interval (or reuses the
existing app-level poll if one fits).

**2. /settings "Updates" mini-card** —
- Current version + latest available (or "up to date").
- Toggle "Check for updates automatically" (the D1 opt-in switch).
- "Check now" button (calls the manual POST; disabled while checking).
- `lastChecked` relative time + `lastError` line when the last check
  failed (D5), e.g. "Last check: failed (network) · 2h ago".
- Link to the changelog/release on GitHub.

**3. i18n (EN + FR)** — `settings.updates.*`, `topbar.updateAvailable`,
`alerting.sources.updateAvailable`. All via `t()`; the v2.12.1 parity
guard enforces EN/FR symmetry. Version identifiers, "GitHub", and semver
strings stay as-is (not translated).

## Data flow

```
ticker/boot+30s ──► Checker.Check ──► GitHub /releases/latest (Etag)
                          │
                          ├─► Status{latest, updateAvailable, url, lastChecked, lastError}
                          │        │
                          │        ├─► GET /system/version ──► topbar badge + settings card
                          │        └─► update_available Source ──► alerting rule (Info) ──► channels
                          └─► (manual "check now" calls Check directly)
```

## Error handling

- Network / non-2xx-non-304 / parse error → set `lastError`, keep prior
  `latest`, no alert (D5). First failure warn-logged; subsequent
  failures logged at debug to avoid spam.
- 304 Not Modified → normal, refresh `lastChecked` only.
- Rate-limited (403 + `X-RateLimit-Remaining: 0`) → treat as a soft
  failure (set `lastError`, back off to next cadence). Etag + 24h cadence
  make this practically unreachable.
- Disabled → the loop never starts; `/system/version` reports
  `enabled: false`, `updateAvailable: false`; badge hidden.

## Testing strategy

- **updatecheck package**: semver compare table (equal, patch/minor/major
  ahead/behind, `v` prefix, DEV current); `Check` against an `httptest`
  server returning 200 (new tag), 304, 500, malformed body, 403
  rate-limit — asserting `Status` transitions + Etag round-trip.
- **alerting source**: `update_available` fires Info when
  `updateAvailable`, silent otherwise; cooldown honored.
- **api**: `GET /system/version` shape (+ secrets none); `POST .../check`
  triggers a check; disabled → `enabled:false`.
- **frontend**: badge shows only when updateAvailable; click opens url;
  settings toggle persists; "check now" calls the endpoint; lastError
  rendered; i18n parity.
- **empirical smoke**: point the checker at a stubbed "latest" newer than
  current → badge + card + alert; then equal → up-to-date; then a
  failing endpoint → lastError shown, no alert.

## Scope

- Backend: new `internal/updatecheck` package, one alerting source, one
  API file (+ 1 route pair), a settings row, main.go wiring.
- Frontend: topbar badge component, settings mini-card, client API
  method, i18n EN/FR.
- No data migration (additive; the settings row defaults to disabled).

## Out of scope / backlog

- Auto-update / self-download (Arenet never downloads+executes; operator
  updates the binary/image themselves — deliberate).
- `ARENET_UPDATE_CHECK_ENABLED` env toggle (UI-only for v1).
- Prerelease opt-in toggle (stable-only for v1, D6).
- In-app changelog rendering (link out to GitHub for v1).
