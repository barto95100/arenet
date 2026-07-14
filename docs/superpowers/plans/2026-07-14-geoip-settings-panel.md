# GeoIP Settings Panel (Brick 4) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A combined GeoIP settings section (MaxMind creds + Test on top, auto-update opt-in toggle + interval preset + "Update now" + status below), mounted in /settings, plus the i18n and a wiki-docs correction. All backend/API/client already exist (Bricks 2+3).

**Architecture:** One Svelte 5 component `GeoIPSettingsSection.svelte` importing both `$lib/api/settings` (MaxMind creds) and `$lib/api/system` (GeoIP update). Mirrors `$lib/components/CrowdSecSettingsSection.svelte` (creds+test) and `settings/UpdatesSection.svelte` (toggle+manual+status). i18n under a top-level `geoipSettings` block in both en/fr. Docs fix in `docs/wiki-seed/`.

**Tech Stack:** SvelteKit / Svelte 5 runes, Tailwind, vitest + @testing-library/svelte.

**Spec:** `docs/superpowers/specs/2026-07-14-geoip-settings-panel-design.md`

## Global Constraints

- Svelte 5 runes (`$state`/`$derived`/`onMount`); Tailwind only (no `<style>`); `language.current && t(...)` idiom; raw `<input>` with the house Tailwind class (no Input primitive).
- All interactive elements have ARIA labels; all user-facing text via `t()`; new i18n keys in BOTH `en.json` and `fr.json` (parity guard test hard-fails otherwise).
- AGPL HTML-comment header on the new `.svelte`, `//` header on the new `.test.ts`.
- Shared primitives: `Card`, `Button`, `Badge`, `Spinner`, `ConfirmDialog` (`$lib/components/*`), `pushToast` (`$lib/stores/toast`), `relativeTime` (`$lib/utils/audit-format`).
- Existing API (do not re-create): `settingsApi.getMaxMind/putMaxMind/deleteMaxMind/testMaxMind` (`$lib/api/settings`), `systemApi.getGeoIPUpdateConfig/putGeoIPUpdateConfig/triggerGeoIPUpdate/getGeoIPStatus` (`$lib/api/system`). Types: `MaxMindConfig{accountId,editionId,configured}`, `MaxMindRequest{accountId,licenseKey,editionId?}`, `MaxMindTestResult{reachable,error?}`, `GeoIPUpdateConfig{enabled,intervalHours}`, `GeoIPUpdateResult{status,error?,lastModified?}`, `GeoIPStatus{lastStatus,lastError?,lastUpdated?}`.
- Frontend build/test: `cd web/frontend && npm run check` (typecheck), `npm run test -- <path>` (vitest).

---

### Task 1: i18n keys (`geoipSettings.*`, EN + FR)

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json`
- Modify: `web/frontend/src/lib/i18n/locales/fr.json`

**Interfaces:** Produces the `geoipSettings.*` keys consumed by Task 2's component.

- [ ] **Step 1: Add the `geoipSettings` block to en.json**

Add a top-level `geoipSettings` object (next to `crowdsecSettings`, whichever alphabetical/positional slot matches the file's convention — place it near `crowdsecSettings`). Keys:

```json
"geoipSettings": {
  "title": "GeoIP database",
  "subtitle": "Download and auto-update the MaxMind GeoIP database used by geoblocking and the world map.",
  "statusConfigured": "Configured",
  "statusNotConfigured": "Not configured",
  "credsTitle": "MaxMind credentials",
  "labelAccountId": "Account ID",
  "labelLicenseKey": "License key",
  "licenseKeyPlaceholder": "••• set (leave blank to keep)",
  "licenseKeyHelper": "Your MaxMind license key. Leave blank to keep the stored one.",
  "btnTest": "Test credentials",
  "btnTesting": "Testing…",
  "testValid": "Credentials valid.",
  "testFailed": "Credentials rejected",
  "testUnknownError": "Unknown error",
  "btnSave": "Save",
  "btnSaving": "Saving…",
  "saveAppliedToast": "MaxMind credentials saved.",
  "btnReset": "Remove credentials",
  "resetDialogTitle": "Remove MaxMind credentials?",
  "resetDialogMessage": "This clears the stored account ID and license key. Auto-update will stop until you configure them again.",
  "resetDialogConfirm": "Remove",
  "resetDialogCancel": "Cancel",
  "resetAppliedToast": "MaxMind credentials removed.",
  "autoUpdateTitle": "Automatic updates",
  "enableToggle": "Enable automatic GeoIP database updates",
  "enableNeedsCreds": "Configure your MaxMind credentials first.",
  "intervalLabel": "Update frequency",
  "intervalDaily": "Daily",
  "intervalWeekly": "Weekly",
  "intervalBiweekly": "Every 2 weeks",
  "intervalCustom": "Custom ({hours}h)",
  "btnUpdateNow": "Update now",
  "btnUpdating": "Downloading…",
  "lastCheckedLabel": "Last checked",
  "never": "never",
  "loadFailed": "Failed to load GeoIP settings.",
  "status": {
    "updated": "GeoIP database updated.",
    "upToDate": "Already up to date.",
    "noCredentials": "No MaxMind credentials configured.",
    "error": "Update failed"
  }
}
```

- [ ] **Step 2: Mirror the exact same keys in fr.json** (French values):

```json
"geoipSettings": {
  "title": "Base GeoIP",
  "subtitle": "Téléchargez et mettez à jour automatiquement la base GeoIP MaxMind utilisée par le blocage par pays et la carte du monde.",
  "statusConfigured": "Configuré",
  "statusNotConfigured": "Non configuré",
  "credsTitle": "Identifiants MaxMind",
  "labelAccountId": "Account ID",
  "labelLicenseKey": "Clé de licence",
  "licenseKeyPlaceholder": "••• définie (laisser vide pour garder)",
  "licenseKeyHelper": "Votre clé de licence MaxMind. Laisser vide pour conserver celle enregistrée.",
  "btnTest": "Tester les identifiants",
  "btnTesting": "Test en cours…",
  "testValid": "Identifiants valides.",
  "testFailed": "Identifiants rejetés",
  "testUnknownError": "Erreur inconnue",
  "btnSave": "Enregistrer",
  "btnSaving": "Enregistrement…",
  "saveAppliedToast": "Identifiants MaxMind enregistrés.",
  "btnReset": "Supprimer les identifiants",
  "resetDialogTitle": "Supprimer les identifiants MaxMind ?",
  "resetDialogMessage": "Ceci efface l'account ID et la clé de licence enregistrés. La mise à jour automatique s'arrêtera jusqu'à ce que vous les configuriez à nouveau.",
  "resetDialogConfirm": "Supprimer",
  "resetDialogCancel": "Annuler",
  "resetAppliedToast": "Identifiants MaxMind supprimés.",
  "autoUpdateTitle": "Mises à jour automatiques",
  "enableToggle": "Activer les mises à jour automatiques de la base GeoIP",
  "enableNeedsCreds": "Configurez d'abord vos identifiants MaxMind.",
  "intervalLabel": "Fréquence de mise à jour",
  "intervalDaily": "Quotidienne",
  "intervalWeekly": "Hebdomadaire",
  "intervalBiweekly": "Toutes les 2 semaines",
  "intervalCustom": "Personnalisé ({hours}h)",
  "btnUpdateNow": "Mettre à jour maintenant",
  "btnUpdating": "Téléchargement…",
  "lastCheckedLabel": "Dernière vérification",
  "never": "jamais",
  "loadFailed": "Échec du chargement des paramètres GeoIP.",
  "status": {
    "updated": "Base GeoIP mise à jour.",
    "upToDate": "Déjà à jour.",
    "noCredentials": "Aucun identifiant MaxMind configuré.",
    "error": "Échec de la mise à jour"
  }
}
```

- [ ] **Step 3: Run the parity guard** — `cd web/frontend && npm run test -- src/lib/i18n/index.test.ts` → PASS (both bundles have identical key sets). Also confirm the JSON is valid.

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "i18n(geoip): add geoipSettings.* keys (EN+FR)"
```

---

### Task 2: `GeoIPSettingsSection.svelte` component + test

**Files:**
- Create: `web/frontend/src/lib/components/settings/GeoIPSettingsSection.svelte`
- Create: `web/frontend/src/lib/components/settings/GeoIPSettingsSection.test.ts`

**Interfaces:** Consumes the i18n keys (Task 1) + the two existing API clients. Produces the mounted-in-Task-3 component.

- [ ] **Step 1: Write the failing test**

`GeoIPSettingsSection.test.ts` — mock BOTH `$lib/api/settings` and `$lib/api/system` and `$lib/stores/toast` (mirror `$lib/components/CrowdSecSettingsSection.test.ts` for the mock scaffold + `settings/UpdatesSection.test.ts` for the system mock). Import the component AFTER the mocks (`await import`). Cover:
- **Creds redaction:** `getMaxMind` → `{accountId:1,editionId:'GeoLite2-City',configured:true}` → the license-key input value is `''` and its placeholder contains "set".
- **Save preserves blank secret:** enter accountId, leave license key blank, click Save → `putMaxMind` called with `{accountId, licenseKey:''}` (or without licenseKey) and a success toast fires.
- **Test button:** `testMaxMind` → `{reachable:true}` → a `role="status"` shows the valid message; `{reachable:false,error:'401'}` → a `role="alert"` shows the error. Blank license key + configured → `testMaxMind` called with `{useStored:true}`.
- **Toggle gating:** `getMaxMind` → `configured:false` → the auto-update checkbox (`data-testid="geoip-enable"`) is `disabled` and the `enableNeedsCreds` hint renders. `configured:true` → not disabled; toggling it calls `putGeoIPUpdateConfig({enabled:true, intervalHours:168})`.
- **Interval preset:** change the select (`data-testid="geoip-interval"`) to Daily → `putGeoIPUpdateConfig` called with `intervalHours:24`.
- **Update now:** click (`data-testid="geoip-update-now"`) → `triggerGeoIPUpdate` called; on `{status:'updated'}` a success toast; on `{status:'error',error:'boom'}` a danger toast containing the error; `getGeoIPStatus` re-called to refresh.

- [ ] **Step 2: Run test → RED** — `cd web/frontend && npm run test -- src/lib/components/settings/GeoIPSettingsSection.test.ts` → FAIL (component missing).

- [ ] **Step 3: Implement the component**

`GeoIPSettingsSection.svelte`. Structure (mirror the two templates; use the spec's state list). Key implementation points:

- AGPL HTML-comment header.
- Imports: `onMount`; `settingsApi`, types `MaxMindConfig`/`MaxMindTestResult` from `$lib/api/settings`; `systemApi`, types `GeoIPUpdateConfig`/`GeoIPStatus`/`GeoIPUpdateResult` from `$lib/api/system`; `t`, `language`; `relativeTime`; `Card`, `Button`, `Badge`, `Spinner`, `ConfirmDialog`; `pushToast`.
- State: `maxmind`, `form={accountId:0,licenseKey:''}`, `updateCfg`, `status`, `testResult`, `loading`, `saving`, `testing`, `updating`, `loadError`, `resetOpen`.
- `load()`: `Promise.all([getMaxMind(), getGeoIPUpdateConfig(), getGeoIPStatus()])`; set `form.accountId = maxmind.accountId`; keep `form.licenseKey=''`. `onMount(load)`.
- **Creds half:** account-id number input; license-key password input (`autocomplete="off"`, placeholder = configured ? `t('geoipSettings.licenseKeyPlaceholder')` : ''); a configured `Badge` in the header; Save button → `putMaxMind`, re-clear key, reload, success toast (ApiError → inline error, no toast); Test button → `testMaxMind` (useStored when blank+configured), render `role="status"`/`role="alert"`; any field `oninput` nulls `testResult`; Remove button (hidden if not configured) → `ConfirmDialog` → `deleteMaxMind`.
- **Divider** then **auto-update half:** enable checkbox `data-testid="geoip-enable"`, `checked={updateCfg?.enabled}`, `disabled={!maxmind?.configured}`, `onchange` → `putGeoIPUpdateConfig({enabled:next, intervalHours: updateCfg?.intervalHours ?? 168})`; the `enableNeedsCreds` hint shown when `!maxmind?.configured`. Interval `<select data-testid="geoip-interval">` with options 24/168/336 (+ a `Custom (Nh)` option when the stored value isn't a preset), `disabled={!updateCfg?.enabled || !maxmind?.configured}`, `onchange` → `putGeoIPUpdateConfig({enabled: updateCfg.enabled, intervalHours: chosen})`. "Update now" button `data-testid="geoip-update-now"` `disabled={updating || !maxmind?.configured}` → set `updating`, `res = triggerGeoIPUpdate()`, map `res.status` to a toast via a `statusToast(res)` helper (updated→success, up_to_date→info-ish/neutral, no_credentials→danger, error→danger + append `res.error`), then `status = await getGeoIPStatus()`, clear `updating`. Status block: `t('geoipSettings.status.'+key)` for `status.lastStatus`, `relativeTime(status.lastUpdated)` labeled `t('geoipSettings.lastCheckedLabel')`, and a `text-down` `status.lastError` line.
- A small `statusKey(s: string)` mapping the API status strings (`updated`/`up_to_date`/`no_credentials`/`error`) to the i18n leaf (`updated`/`upToDate`/`noCredentials`/`error`).
- ARIA labels on the inputs/select/buttons; all text via `t()`.

- [ ] **Step 4: Run test → GREEN + typecheck** — the test passes; then `cd web/frontend && npm run check` → 0 errors.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/settings/GeoIPSettingsSection.svelte web/frontend/src/lib/components/settings/GeoIPSettingsSection.test.ts
git commit -m "feat(web): GeoIP settings section — creds+test + auto-update toggle/interval/update-now"
```

---

### Task 3: Mount in settings page + wiki docs fix

**Files:**
- Modify: `web/frontend/src/routes/settings/+page.svelte` (import + mount)
- Modify: `docs/wiki-seed/Country-Block.md`, `docs/wiki-seed/Home.md`, `docs/wiki-seed/Home-FR.md`

**Interfaces:** Consumes the component (Task 2).

- [ ] **Step 1: Mount the component**

In `web/frontend/src/routes/settings/+page.svelte`: add `import GeoIPSettingsSection from '$lib/components/settings/GeoIPSettingsSection.svelte';` alongside the other settings imports (near the `UpdatesSection` import), and mount `<GeoIPSettingsSection />` **right after `<UpdatesSection />`** (the component's own root `<div id="geoip">` provides the anchor). Confirm the exact `UpdatesSection` mount line first, then insert after it.

- [ ] **Step 2: Typecheck + the settings page test (if any)** — `cd web/frontend && npm run check` → 0 errors; `npm run test -- src/routes/settings/` → still green (if a page test exists).

- [ ] **Step 3: Fix the wiki docs (the embedded-DB falsehood)**

Correct the stale "embedded GeoIP DB" claims to the real model (operator-supplied + now auto-downloadable via Settings → GeoIP):
- `docs/wiki-seed/Country-Block.md` — the "bundled in the Arenet binary ~6 MB" line and the "ships embedded… not user-replaceable" passage: replace with a description that the DB is operator-supplied at `ARENET_GEOIP_MMDB` (default `/var/lib/arenet/GeoLite2-City.mmdb`), NOT embedded, and can now be auto-downloaded/updated from MaxMind by configuring credentials in Settings → GeoIP (opt-in weekly, or "Update now").
- `docs/wiki-seed/Home.md` and `Home-FR.md` — the `ARENET_GEOIP_MMDB` line describing it as an override for an embedded DB: reword to "path to the operator-supplied (or auto-downloaded) GeoLite2-City database".
Read each file's current wording first and edit precisely; keep the surrounding structure. (Wiki-repo sync is a separate push, not part of this task.)

- [ ] **Step 4: Commit**

```bash
git add web/frontend/src/routes/settings/+page.svelte docs/wiki-seed/Country-Block.md docs/wiki-seed/Home.md docs/wiki-seed/Home-FR.md
git commit -m "feat(web,docs): mount GeoIP settings section + fix stale embedded-DB wiki claim"
```

---

### Task 4: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build** — `cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet` → clean.

- [ ] **Step 2: In-workspace surface** — confirm the built bundle contains the GeoIP section (grep the build output for a `geoipSettings` marker / `geoip-enable` testid). The full authed visual render + real-creds drive is operator hand-off.

- [ ] **Step 3: Operator hand-off** — per the spec's runtime verification: enter creds → Test → valid; enable auto-update + pick Weekly; "Update now" → toast "updated" + status shows last-checked + the DB installs and a country-block rule reflects it **without a restart**; a wrong edition/creds surfaces the error. Report the in-workspace parts PASS/FAIL and hand over the real-creds checklist.

---

## Self-Review

**Spec coverage:** combined section (creds+test / toggle+interval+update-now+status) → Task 2. Toggle-disabled-until-configured + hint → Task 2 Step 3. Interval presets (24/168/336 + Custom) → Task 2. Update-now spinner+toast + status→message mapping → Task 2 (statusKey/statusToast). lastUpdated labeled "Last checked" → Task 1 (`lastCheckedLabel`) + Task 2. i18n EN+FR + parity → Task 1. Mount after UpdatesSection → Task 3. Docs fix → Task 3. Runtime → Task 4. All spec sections covered.

**Placeholder scan:** No TBD/TODO. The full i18n key set is concrete (both bundles). The component code is described point-by-point with the exact templates, testids, API calls, and mappings — not pseudo-code gaps; the implementer transcribes the two templates with the spec's wiring. Docs edits say "read current wording first, edit precisely" — a real instruction, not a placeholder.

**Type consistency:** API method + type names match the existing clients exactly (`getMaxMind`/`putMaxMind`/`deleteMaxMind`/`testMaxMind`, `getGeoIPUpdateConfig`/`putGeoIPUpdateConfig`/`triggerGeoIPUpdate`/`getGeoIPStatus`; `MaxMindConfig`/`MaxMindTestResult`/`GeoIPUpdateConfig`/`GeoIPStatus`/`GeoIPUpdateResult`). i18n keys referenced in Task 2 all exist in Task 1's block. `intervalHours` values 24/168/336 consistent between the select and the PUT calls. `data-testid`s (`geoip-enable`/`geoip-interval`/`geoip-update-now`) consistent between component and test.
