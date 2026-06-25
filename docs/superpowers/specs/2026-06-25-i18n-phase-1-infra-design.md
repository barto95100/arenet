# i18n Phase 1 — infra-only foundation

**Ship target**: v2.9.11
**Author**: Ludovic Ramos
**Date**: 2026-06-25
**Status**: Approved — ready for implementation
**Follow-ups**: Phase 2 (v2.9.12 — 4 demo screens migrated + enriched bundles), Phase 3+ (bulk string extraction)

## Operator-observed symptom

The current UI mixes French and English strings in the same surfaces.
Empirical examples from the live build:

- `web/frontend/src/routes/+layout.svelte` carries both
  `"Your password has been found in a known data breach."` AND
  `"Mode lecture seule — votre compte a le rôle viewer"` in the same
  component.
- `web/frontend/src/lib/components/Topbar.svelte` displays
  `"Passerelle saine"` (French) next to UI elements whose labels are
  English elsewhere.
- 44 of 86 .svelte files contain French diacritics; ~509 visible-text
  strings overall; ~90 `pushToast()` call sites.

There is no per-user language preference; users cannot pick the
language their UI renders in.

## Goals (Phase 1)

Build the **infrastructure** for per-user language preference (FR + EN)
that mirrors the existing theme-preference pattern (`theme.svelte.ts`
+ `POST /auth/me/theme` + `arenet_theme` cookie). Ship the foundation
WITHOUT migrating any existing screens — that's Phase 2.

Phase 1 success = the round-trip works end-to-end (operator picks a
language in Settings, the choice persists across reloads/devices via
cookie+server, the next paint reads the new locale) but **the visible
UI strings don't change yet** (no `$t()` calls in screens — that
lands in Phase 2). The 30-key bootstrap bundle exists so a quick
manual smoke (e.g. one `$t('common.save')` call inserted ad-hoc)
proves the resolver wires correctly.

## Non-goals (Phase 1)

- Migrating existing components from hardcoded strings to `$t()` —
  Phase 2.
- Pluralization beyond the simplest `{count}` interpolation —
  `Intl.PluralRules` evaluated case-by-case in Phase 2+ where needed.
- Date/number locale formatting — browser default suffices for now.
- Lazy bundle loading — both `en.json` + `fr.json` ship in the
  initial JS chunk (~50 KiB combined, acceptable).
- Backend error-message i18n — backend keeps English for v1; Phase 3
  later for the ~50-80 strings the operator sees BEFORE the cookie is
  set (login + setup wizard).

## Approach

Mirror the theme-preference architecture exactly. Three layers:

1. **Backend** — new `User.LanguagePreference` field, new
   `POST /api/v1/auth/me/language` endpoint, new `arenet_language`
   cookie refreshed on every successful set, `GET /auth/me` extended
   to include `language_preference` for the reconcile path.
2. **Frontend store** — `LanguageStore` singleton in
   `lib/stores/language.svelte.ts`, byte-for-byte mirror of
   `theme.svelte.ts` with the same `.current`, `.set()`,
   `.applyLocally()`, `.persistLocally()`, `.reconcileFromServer()`
   shape.
3. **i18n module** — `$lib/i18n/index.ts` exposing a `t(key, params?)`
   function that resolves a dotted key against the active bundle,
   falls back to English, falls back to the raw key. Bundles live in
   `$lib/i18n/locales/en.json` and `fr.json`; both ~30 keys in v1.

## Components changed

| File | Change |
|---|---|
| `internal/auth/types.go` | +`LanguagePreference string` field on User; +`LanguageEnglish` / `LanguageFrench` consts; +validation helper |
| `internal/auth/userstore.go` | +`UpdateLanguagePreference(ctx, id, language)` mirror of `UpdateThemePreference`; +`ErrLanguageInvalid` |
| `internal/auth/errors.go` | +`ErrLanguageInvalid` |
| `internal/auth/userstore_test.go` | +tests for round-trip + validation |
| `internal/api/auth_handlers.go` | +`updateLanguage` handler (POST /auth/me/language); +`setLanguageCookie` helper; +inclusion in `/auth/me` JSON response |
| `internal/api/auth_handlers_test.go` | +tests for handler success/auth/validation/cookie-refresh |
| `internal/api/router.go` | +route registration for `/auth/me/language` |
| `web/frontend/src/app.html` | +bootstrap script reading `arenet_language` cookie → `localStorage` → default `en`, sets `document.documentElement.lang` |
| `web/frontend/src/lib/stores/language.svelte.ts` | NEW — `LanguageStore` singleton (mirror `theme.svelte.ts`) |
| `web/frontend/src/lib/stores/language.test.ts` | NEW — unit tests for set/reconcile/persist/normalize |
| `web/frontend/src/lib/i18n/index.ts` | NEW — `t(key, params)` resolver + fallback chain + active-bundle selection driven by `language` store |
| `web/frontend/src/lib/i18n/index.test.ts` | NEW — resolver tests (hit, fallback to en, missing-key warns + returns key, params interpolation) |
| `web/frontend/src/lib/i18n/locales/en.json` | NEW — ~30 bootstrap keys (common.save, common.cancel, common.delete, errors.unauthorized, settings.languageLabel, …) |
| `web/frontend/src/lib/i18n/locales/fr.json` | NEW — same 30 keys translated |
| `web/frontend/src/lib/api/auth.ts` | +`setLanguage(lang)` client (mirror `setTheme`) |
| `web/frontend/src/routes/+layout.svelte` | +reconcile call after `/auth/me` resolves (mirror existing theme reconcile) |
| `web/frontend/src/routes/settings/+page.svelte` (or wherever the theme toggle lives) | +language selector dropdown next to the theme toggle |

No migration of existing strings to `$t()`. Phase 2.

## Data flow

```
Operator opens Settings → Language → picks "Français"
  └→ languageStore.set('fr')
      ├→ applyLocally('fr')                              // document.documentElement.lang = 'fr'
      ├→ persistLocally('fr')                            // localStorage.arenet_language = 'fr'
      ├→ active bundle in i18n module flips to fr.json   // future $t() calls now resolve French
      └→ POST /api/v1/auth/me/language { language: "fr" }
          └→ handler validates ('fr' | 'en')
              ├→ users.UpdateLanguagePreference(...)
              ├→ setLanguageCookie(w, "fr")              // arenet_language=fr; HttpOnly=false
              └→ 204 No Content

Operator reloads tab:
  app.html bootstrap script (before first paint):
    cookie arenet_language=fr  →  document.documentElement.lang = 'fr'
  Svelte boots:
    languageStore.current initialised from document.documentElement.lang
    bundle = fr.json
  Layout calls /auth/me → reconcile silently (cookie matches server, no-op)
```

## API surface

### `POST /api/v1/auth/me/language`

Request: `{"language": "fr"}` or `{"language": "en"}`

Responses:
- `204 No Content` + `Set-Cookie: arenet_language=fr; Path=/; SameSite=Lax; Max-Age=31536000`
- `400 Bad Request` if `language` is anything but `"fr"` or `"en"`
- `401 Unauthorized` if session invalid

### `GET /api/v1/auth/me`

Extended JSON response:
```json
{
  "id": "...",
  "email": "...",
  "role": "...",
  "theme_preference": "dark",
  "language_preference": "fr"
}
```

Field is `""` for pre-migration users (rows that existed before
v2.9.11). The frontend reconcile maps `""` → bootstrap default
(`navigator.language` first match against supported locales, else
`"en"`).

## Frontend module surface

### `$lib/i18n/index.ts`

```ts
import { language } from '$lib/stores/language.svelte.ts';
import en from './locales/en.json';
import fr from './locales/fr.json';

const bundles = { en, fr };

/** Resolve a dotted key like "common.save" against the active
 *  bundle. Fallback chain:
 *    1. active bundle (current language)
 *    2. en bundle (source of truth)
 *    3. raw key (signals a missing translation visually)
 *  Optional params interpolate {name} placeholders in the result. */
export function t(key: string, params?: Record<string, string | number>): string {
  // see implementation below
}
```

The `t()` function is a regular function, NOT a Svelte store. To
recompute on language change, components consume it inside a
`$derived` rune:

```svelte
<script>
  import { t } from '$lib/i18n';
  import { language } from '$lib/stores/language.svelte.ts';
  let label = $derived(language.current && t('common.save'));
</script>
<button>{label}</button>
```

The `language.current &&` part is the dependency trigger — without
reading `language.current` in the derived, Svelte 5 has no signal to
recompute. We document this idiom in the i18n module's README so
Phase 2 callers follow the pattern.

### `LanguageStore` shape

```ts
export type Language = 'en' | 'fr';

class LanguageStore {
  current = $state<Language>('en');
  isApplying = $state(false);

  async set(lang: Language): Promise<void>;            // mirror theme.set
  applyLocally(lang: Language): void;                  // dataset.lang
  reconcileFromServer(serverLang: unknown): void;      // mirror theme.reconcile
  private persistLocally(lang: Language): void;        // localStorage
}

export const language = new LanguageStore();
```

## Edge cases & invariants

1. **Pre-migration users** (`LanguagePreference == ""`): on first
   `/auth/me`, reconcile receives `""`, normalizes to `'en'` (or
   `navigator.language`-derived if browser ships French locale —
   final decision: hardcode `'en'` for determinism; let the user
   change in Settings).
2. **Cookie/server divergence**: `reconcileFromServer` silently
   swaps; same pattern as theme. No toast on the reconcile case.
3. **Concurrent set across 2 tabs**: last-write-wins on the
   server; the loser tab keeps its locally-applied value until its
   next reload (acceptable, matches theme behaviour).
4. **Set fails (network error)**: store reverts locally, toast in
   English (the language toast can't depend on the language being
   set successfully).
5. **Unknown language string in cookie/localStorage** (e.g. user
   manually edits): bootstrap normalizes to `'en'`.
6. **Caddy-served error pages** (catch-all, per-route templates):
   stay in whatever language the HTML was authored — those don't
   transit through the Svelte runtime.
7. **Backend error messages** (e.g. validation errors from
   `/auth/me/language`): stay in English in v1; Phase 3 backlog.

## Test plan

### Backend
- `TestUserStore_UpdateLanguagePreference_Roundtrip`
- `TestUserStore_UpdateLanguagePreference_RejectsInvalidValue`
- `TestUpdateLanguageHandler_Success_RefreshesCookie`
- `TestUpdateLanguageHandler_BadRequest_OnInvalidLanguage`
- `TestUpdateLanguageHandler_Unauthorized_WithoutSession`
- `TestAuthMe_Returns_LanguagePreference`

### Frontend
- `LanguageStore.set('fr')` updates `current`, applies locally,
  persists locally, posts to backend
- `LanguageStore.set('fr')` reverts on backend failure
- `LanguageStore.reconcileFromServer('fr')` updates without
  re-posting
- `LanguageStore.reconcileFromServer('')` is a no-op (stays on
  bootstrap default)
- `t('common.save')` returns the FR string when language='fr'
- `t('common.save')` falls back to EN when key missing in FR
- `t('common.missing.key')` returns the raw key + logs a warn
- `t('toast.routeSaved', { name: 'traefik' })` interpolates `{name}`

### Manual smoke (post-deploy v2.9.11)
1. Login → Settings → switch to FR via the new selector → bandeau
   reste FR after page reload (cookie persists)
2. Logout → login as same user → re-check Settings shows FR
3. Inspect cookie `arenet_language=fr` is present (DevTools)
4. Inspect `document.documentElement.lang === 'fr'`
5. Inspect `localStorage.getItem('arenet_language') === 'fr'`
6. Insert one ad-hoc `{$t('common.save')}` somewhere → renders
   "Enregistrer" in FR, "Save" in EN, switching live on language
   change
7. Switch back to EN, verify symmetric behaviour

## What this does NOT change

- No `.svelte` file's visible strings (none migrate to `$t()` in
  Phase 1)
- No backend error messages (all stay in English)
- No theme behaviour (independent system)
- No existing API endpoint (only adds new one)

## Bootstrap bundle content (v2.9.11 ~30 keys)

`en.json`:
```json
{
  "common": {
    "save": "Save",
    "cancel": "Cancel",
    "delete": "Delete",
    "confirm": "Confirm",
    "loading": "Loading...",
    "error": "Error",
    "success": "Success"
  },
  "auth": {
    "loginButton": "Sign in",
    "logoutButton": "Sign out",
    "passwordLabel": "Password",
    "usernameLabel": "Username"
  },
  "errors": {
    "unauthorized": "Unauthorized",
    "forbidden": "Forbidden",
    "notFound": "Not found",
    "internal": "Internal server error",
    "networkOffline": "Network unreachable"
  },
  "settings": {
    "languageLabel": "Language",
    "languageEnglish": "English",
    "languageFrench": "Français",
    "themeLabel": "Theme",
    "themeDark": "Dark",
    "themeLight": "Light"
  },
  "toast": {
    "savedSuccess": "Saved successfully",
    "savedFailed": "Save failed",
    "languageChanged": "Language updated"
  }
}
```

`fr.json` mirror with French translations.

## Ship

- Tag: `v2.9.11`
- Title: `feat(i18n): infra for per-user language preference (Phase 1)`
- Body: backend `User.LanguagePreference` + endpoint + cookie;
  frontend `LanguageStore` + `i18n/` module + `en` + `fr` bootstrap
  bundles + Settings selector + app.html bootstrap. Zero existing
  string migrated — Phase 2 follows.

## Gates before push

1. `go vet ./...` clean
2. `go test ./internal/auth/... ./internal/api/... -run "Language\|UpdateLanguage\|AuthMe"` green
3. `go build ./cmd/arenet` clean
4. `cd web/frontend && npm run check` 0 errors 0 warnings
5. `cd web/frontend && npm run test -- --run language` green (new
   store + i18n tests)
6. `cd web/frontend && npm run build` clean
7. Operator manual smoke (the 7 steps in Test plan / Manual smoke)
   confirms the round-trip end-to-end
