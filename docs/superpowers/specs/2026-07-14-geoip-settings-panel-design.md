# GeoIP Auto-Update — Brick 4: Settings Panel + Docs — Design

**Date:** 2026-07-14
**Status:** Approved (design validated by operator)

## Context

Final brick of the GeoIP auto-update feature. Bricks 1-3 built the swappable
reader, the MaxMind credentials API (Brick 2), and the downloader + opt-in
scheduler + config/status API (Brick 3). This brick adds the **operator-facing
settings panel** that drives all of it, plus corrects the stale "embedded DB"
wiki docs discovered during Brick 1.

**All backend + API + client already exist.** This brick is frontend
(a Svelte component + i18n) + a small backend status-label clarification +
a docs fix. No new endpoints.

## Decisions (from brainstorming)

1. **One combined `GeoIPSettingsSection.svelte`** with two halves: MaxMind
   **credentials** (account_id + license_key + Test) on top, **auto-update**
   (opt-in toggle + interval + "Update now" + status) below. Both concern the
   one GeoIP database; the auto-update half depends on the creds.
2. **The auto-update toggle is disabled until credentials are configured**
   (`MaxMindConfig.configured === false`), with a hint ("Configure your
   MaxMind credentials first"). Prevents enabling an updater that can't
   download.
3. **Interval = a preset dropdown**: Daily (24h) / Weekly (168h, default) /
   Every 2 weeks (336h). Maps to the API's `intervalHours` (int). Avoids
   nonsensical free-form values.
4. **"Update now" = spinner + result toast** (+ status block refresh):
   status → message mapping below.

## Templates to mirror

- **Creds + Test half** → `$lib/components/CrowdSecSettingsSection.svelte` (secret
  preserve-on-edit, "leave blank to keep" placeholder off `configured`, Test
  button + `{reachable,error}` result, configured badge, DELETE/reset via
  ConfirmDialog).
- **Auto-update half** → `settings/UpdatesSection.svelte` (toggle wired to a
  config PUT, manual-action button, status line with `relativeTime`).

Two API clients: MaxMind creds in `$lib/api/settings` (`getMaxMind`,
`putMaxMind`, `deleteMaxMind`, `testMaxMind`), GeoIP update in
`$lib/api/system` (`getGeoIPUpdateConfig`, `putGeoIPUpdateConfig`,
`triggerGeoIPUpdate`, `getGeoIPStatus`). The component imports both.

## Component: `web/frontend/src/lib/components/settings/GeoIPSettingsSection.svelte`

Svelte 5 runes, Tailwind only, `language.current && t(...)` idiom. Shared
primitives: `Card`, `Button`, `Badge`, `Spinner`, `ConfirmDialog`,
`pushToast`, `relativeTime`. Raw `<input>` with the house Tailwind class
(no Input primitive).

### State
- `maxmind = $state<MaxMindConfig|null>(null)` (accountId, editionId, configured).
- `form = $state({ accountId: 0, licenseKey: '' })` — licenseKey blank on load (never round-trip the secret).
- `updateCfg = $state<GeoIPUpdateConfig|null>(null)` (enabled, intervalHours).
- `status = $state<GeoIPStatus|null>(null)`.
- `testResult = $state<MaxMindTestResult|null>(null)`.
- `loading/saving/testing/updating` booleans; `loadError`.

### Load (onMount)
Fetch all three in parallel: `getMaxMind()`, `getGeoIPUpdateConfig()`,
`getGeoIPStatus()`. Set `form.accountId` from `maxmind.accountId`, keep
`form.licenseKey` empty (redacted).

### Credentials half (top)
- **Account ID** number input, `bind:value={form.accountId}`.
- **License key** password input, `autocomplete="off"`; placeholder =
  `maxmind?.configured ? t('geoipSettings.licenseKeyPlaceholder')` ("••• set
  (leave blank to keep)") `: ''`. Mirror CrowdSec's `apiKeyPlaceholder`.
- **Configured badge** in the header: `Badge status-up` "Configured" when
  `maxmind?.configured`, else `status-warn` "Not configured".
- **Save**: `putMaxMind({ accountId: form.accountId, licenseKey: form.licenseKey })`
  — empty licenseKey → backend preserves. On success: re-clear
  `form.licenseKey = ''`, reload, success toast. `ApiError` → inline error, no toast.
- **Test**: `testMaxMind(...)`. If `form.licenseKey` is blank but
  `maxmind?.configured`, send `{ useStored: true }` (test the stored key
  without re-typing); else send the form fields. Show the result: green
  `role="status"` "Credentials valid" when `testResult.reachable`, else red
  `role="alert"` with `testResult.error`. Any field edit nulls `testResult`
  (stale-invalidation).
- **Reset/Remove** (ConfirmDialog danger): `deleteMaxMind()` → badge flips,
  toast. Hidden when not configured. Mirror CrowdSec's delete flow.

### Auto-update half (below, separated by a divider)
- **Enable toggle** (`<input type="checkbox">`, the light idiom): `checked={updateCfg?.enabled}`,
  **`disabled={!maxmind?.configured}`**. When disabled, show the hint
  `t('geoipSettings.enableNeedsCreds')` ("Configure your MaxMind credentials
  first"). `onchange` → `putGeoIPUpdateConfig({ enabled: next, intervalHours: updateCfg.intervalHours })`, reassign `updateCfg` from the response.
- **Interval preset dropdown** (`<select>`): options Daily(24)/Weekly(168)/
  Every-2-weeks(336). `value` bound to `updateCfg.intervalHours`; if the
  stored value isn't one of the presets (e.g. an env override), add a
  read-only "Custom (Nh)" option so the select still reflects reality.
  `onchange` → `putGeoIPUpdateConfig({ enabled: updateCfg.enabled, intervalHours: chosen })`.
  Disabled when the toggle is off (or when not configured).
- **"Update now" button**: `disabled={updating || !maxmind?.configured}`.
  Click → `updating=true`, `res = triggerGeoIPUpdate()`, map `res.status`
  to a toast (table below), then `status = getGeoIPStatus()` to refresh the
  status block, `updating=false`. Button label toggles to "Downloading…"
  with a Spinner while `updating`.
- **Status block**: shows the last run — `lastStatusLabel(status.lastStatus)`
  + `relativeTime(status.lastUpdated)` + a `text-down` `status.lastError`
  line when present. **Label the timestamp "Last checked", not "Last
  updated"** — see the backend note below.

### Status → message mapping (i18n keys under `geoipSettings.status.*`)
| API `status` | toast variant | message key |
| --- | --- | --- |
| `updated` | success | `geoipSettings.status.updated` — "GeoIP database updated" |
| `up_to_date` | info | `geoipSettings.status.upToDate` — "Already up to date" |
| `no_credentials` | danger | `geoipSettings.status.noCredentials` — "No MaxMind credentials configured" |
| `error` | danger | `geoipSettings.status.error` — "Update failed" (+ append `res.error` when present) |

The status *block* (not the toast) uses the same key set for `lastStatus`.

## Backend clarification (the review Minor #3)

`GeoIPStatus.lastUpdated` is stamped from `st.At`, which is set on **every**
`UpdateOnce` — including `up_to_date`, `no_credentials`, and `error` — so it
means "last **checked**", not "last successful update". Rather than change
the backend semantics (the field is a genuine "last run" timestamp),
**the UI labels it "Last checked"** (`geoipSettings.lastCheckedLabel`) to
avoid mislabeling. No backend change needed; this is a spec decision to
close the flagged Minor at the UI layer. (If a true "last successful
update" is ever wanted, that's a separate backend field — out of scope.)

## Mounting

`web/frontend/src/routes/settings/+page.svelte`: import
`GeoIPSettingsSection`, mount it **right after `<UpdatesSection />`**
(the app-update checker — GeoIP DB auto-update is its conceptual neighbor),
wrapped in `<div id="geoip">` for deep-link/hash-scroll (the existing
`afterNavigate` hash handler honors it).

## i18n

Add a top-level **`geoipSettings`** block (mirroring `crowdsecSettings`) to
**both** `en.json` and `fr.json`: title, subtitle, the creds labels
(`labelAccountId`, `labelLicenseKey`, `licenseKeyPlaceholder`,
`licenseKeyHelper`), badges (`statusConfigured`, `statusNotConfigured`),
test (`btnTest`, `btnTesting`, `testValid`, `testFailed`, `testUnknownError`),
save/reset (`btnSave`, `btnSaving`, `btnReset`, `resetDialog*`,
`saveAppliedToast`, `saveClearedToast`), auto-update (`autoUpdateTitle`,
`enableToggle`, `enableNeedsCreds`, `intervalLabel`, `intervalDaily`,
`intervalWeekly`, `intervalBiweekly`, `intervalCustom`, `btnUpdateNow`,
`btnUpdating`, `lastCheckedLabel`, `never`), and the `status.*` block above.
The parity guard test (`web/frontend/src/lib/i18n/index.test.ts`, the EN↔FR
parity block) hard-fails if any key is missing from either bundle.

## Docs fix (Brick 1 finding)

The wiki docs falsely claim the GeoIP DB is embedded in the binary. Correct
the operator-facing docs that describe `ARENET_GEOIP_MMDB` as an override for
an embedded DB (from Brick-1 research: `docs/wiki-seed/Country-Block.md:45`
"bundled in the Arenet binary ~6 MB", `:110-114` "ships embedded… not
user-replaceable"; `docs/wiki-seed/Home.md:100` / `Home-FR.md:100`). Update
them to describe the real model: the DB is operator-supplied at
`ARENET_GEOIP_MMDB` (default `/var/lib/arenet/GeoLite2-City.mmdb`), and — new
in this feature — can be **auto-downloaded** from MaxMind via
Settings → GeoIP once credentials are configured. Add a short "GeoIP
database" note. (Keep this a `docs/wiki-seed/` edit; sync to the wiki repo
is a separate push, as with the Certificates page.)

## Testing

`GeoIPSettingsSection.test.ts` (vitest + @testing-library/svelte), mocking
BOTH `$lib/api/settings` and `$lib/api/system` (+ `pushToast`):
- **Creds redaction:** load configured → license-key input value is `''` and
  its placeholder contains "set" ("leave blank to keep").
- **Save preserves:** blank license key + Save → `putMaxMind` called with the
  entered accountId and an empty licenseKey; success toast; field re-cleared.
- **Test button:** `testMaxMind` → `{reachable:true}` shows `role="status"`;
  `{reachable:false, error}` shows `role="alert"` with the error. Blank-key +
  configured → `testMaxMind` called with `{ useStored: true }`.
- **Toggle gating:** not configured → the auto-update checkbox is `disabled`
  and the hint renders. Configured → enabled; toggling calls
  `putGeoIPUpdateConfig({ enabled, intervalHours })`.
- **Interval preset:** changing the select calls `putGeoIPUpdateConfig` with
  the mapped hours (24/168/336).
- **Update now:** click → `triggerGeoIPUpdate` called; on `{status:'updated'}`
  a success toast; on `{status:'error', error}` a danger toast with the
  error; status block refreshes via `getGeoIPStatus`.
- **Reset:** ConfirmDialog → `deleteMaxMind` only on confirm; badge flips.
- Parity guard stays green (new keys in both bundles).

## Runtime verification

Build the frontend + binary; the panel renders in `/settings` under GeoIP.
Full drive (real creds, real download → status "updated" → geoblock uses the
new DB) is the operator hand-off, tying together the whole feature:
1. Enter MaxMind creds → Test → "valid".
2. Enable auto-update, pick Weekly.
3. "Update now" → toast "updated", status shows last-checked + the DB appears
   at the path, and a country-block rule reflects the fresh DB **without a
   restart**.
4. Set a wrong edition/creds → the error surfaces in the toast + status.

In-workspace (no creds): the component renders, the toggle-gating + preset +
button wiring are unit-tested; `npm run check` 0 errors.

## Non-goals (YAGNI)

- No new endpoints (all exist). No backend status-semantics change (UI labels
  it correctly instead).
- No multi-edition UI (single GeoLite2-City; the edition is a stored field,
  not surfaced as a picker — a mis-set edition is caught by Brick 3's guard).
- No scheduling beyond the 3 presets (the env override still works for power
  users; the UI shows it as "Custom").

## Files summary

| Action | File |
| --- | --- |
| Create | `web/frontend/src/lib/components/settings/GeoIPSettingsSection.svelte` |
| Create | `web/frontend/src/lib/components/settings/GeoIPSettingsSection.test.ts` |
| Modify | `web/frontend/src/routes/settings/+page.svelte` (import + mount under UpdatesSection) |
| Modify | `web/frontend/src/lib/i18n/locales/en.json` + `fr.json` (+`geoipSettings.*`) |
| Modify | `docs/wiki-seed/Country-Block.md`, `Home.md`, `Home-FR.md` (correct the embedded-DB claim + add the auto-download note) |

## Global constraints (from CLAUDE.md)

- Svelte 5 runes; Tailwind only; all interactive elements have ARIA labels;
  all user-facing text via `t()`; new i18n keys in BOTH en/fr.
- AGPL `//`-comment header on the new `.svelte`/`.ts` files.
- No new dependency; reuse the existing API clients + shared UI primitives.
