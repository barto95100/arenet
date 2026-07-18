# Maintenance UX — friendly duration + global message (v2.18.0)

**Status:** decisions LOCKED by user (2026-07-18). Follows v2.17.2. Feature = minor bump.

**Goal:** Make the maintenance page config usable without hand-editing HTML or
mentally converting hours to seconds: (A) a human-friendly Retry-After input
(number + unit) and (B) a GLOBAL maintenance message rendered by the built-in
default via a `{arenet.maintenance.message}` placeholder.

**Governing memory:** `maintenance-v218-backlog`, `routes-maintenance-feature`,
`process-weight-calibration` (light process — direct implementation + final review).

---

## Scope discipline

- Message is **GLOBAL** (one text, same on every maintenance route), NOT per-route.
- Retry-After stays **per-route** and stays **seconds** in storage + header (RFC 9110).
  Only the UI *input* changes; the wire value is unchanged.
- NO per-route custom title/logo/color. That is what editing the global HTML page is for.
- No new Route field → no route wire-field-gap risk. The only new persisted field is
  a global `Message` on the maintenance-page singleton.

---

## A — Friendly Retry-After input (frontend only)

**Where:** route edit form Maintenance section, `web/frontend/src/routes/routes/+page.svelte`
(~line 2649, the existing `<Input type="number">` bound to
`formData.maintenanceConfig.retryAfterSeconds`).

**Change:** replace the single seconds input with a number field + a unit `<select>`
(seconds / minutes / hours / days). The component keeps storing seconds in
`formData.maintenanceConfig.retryAfterSeconds`; a local `{value, unit}` pair drives the
UI and converts to/from seconds.

- On mount / open-edit: pick the *largest* unit that divides the stored seconds evenly
  (300 → 5 minutes; 3600 → 1 hour; 90000 → 25 hours; 0 → 0 seconds), so a round value
  shows as a round value.
- On input change: `retryAfterSeconds = value * unitFactor` (s=1, min=60, h=3600, d=86400).
- Clamp to ≥ 0; blank/NaN → 0 (matches current behavior).
- No backend change. `payload.maintenanceConfig.retryAfterSeconds` is still seconds.

**Unit factors** — package-level const in the component (no magic numbers):
`{ seconds: 1, minutes: 60, hours: 3600, days: 86400 }`.

---

## B — Global maintenance message

### Storage (`internal/storage/maintenance_page_config.go`)

Extend the singleton:

```go
type MaintenancePageConfig struct {
    HTML    string `json:"html,omitempty"`
    Message string `json:"message,omitempty"`
}
```

Zero-migration (omitempty; existing rows unmarshal with Message==""). Get/Put already
round-trip the whole struct — no change to those funcs.

### caddymgr (`internal/caddymgr/maintenance.go` + `manager.go`)

New sentinel + substitution, parallel to the retry_after sentinel:

```go
const maintenanceMessageSentinel = "{arenet.maintenance.message}"
```

`buildMaintenanceBody(html string, retryAfter int, message string) string` substitutes
BOTH sentinels. The message is operator free text → **HTML-escape it** before substitution
(`html.EscapeString`) so a message can't inject markup into every 503. (The retry_after
value is an int, no escaping needed.)

- Empty message → substitute the sentinel with an **empty string** (the built-in default's
  message block collapses; see below). A custom page that references the placeholder with an
  empty message simply renders nothing there.

`buildMaintenanceRoute(...)` gains a `message string` param, threaded from
`buildConfigJSON` via a new `buildOpts.MaintenanceMessage` field, sourced in
`applyLocked` from `maintenancePage.Message` (alongside the existing
`MaintenancePageHTML: maintenancePage.HTML`).

### Built-in default page (`arenetDefaultMaintenancePage`)

Add a message line that renders the substituted message, with an **elegant empty-fallback**:
when the message is empty the substituted body is empty and the default shows its existing
generic sentence ("This service is undergoing scheduled maintenance…"); when a message is
present it appears as an operator-authored line. Simplest robust approach: keep the generic
sentence AND add a `<p>{arenet.maintenance.message}</p>` below it — empty message → the
paragraph renders empty (no visual noise); non-empty → the operator's line shows. Verify the
empty case looks clean in the live smoke (no stray empty box / border).

### API (`internal/api/maintenance_page.go`)

- `maintenancePageRequest`  → add `Message string \`json:"message"\``.
- `maintenancePageResponse` → add `Message string \`json:"message"\``.
- GET: echo `cfg.Message` (default branch: Message=""). PUT: persist `Message` alongside
  sanitized HTML. **The message is escaped at emission (caddymgr), not sanitized as HTML at
  the API layer** — it is plain text, stored verbatim, escaped when baked into the body.
  (Trim outer whitespace on PUT for tidiness; do not strip inner content.)
- `DisallowUnknownFields` is on → adding `Message` to the request struct is mandatory or a
  message-carrying PUT 400s (wire-field lesson, request side).

### Frontend

- `web/frontend/src/lib/api/error-templates.ts` + `types.ts`: add `message` to the
  maintenance-page GET/PUT types and the `putMaintenancePage(html, message)` call.
- `web/frontend/src/routes/settings/error-pages/+page.svelte`: a `maintenanceMessage`
  `$state`, loaded in `loadMaintenancePage`, sent in `saveMaintenancePage`, and a text
  `<input>`/`<textarea>` **above the HTML editor** in the maintenance section (~line 642,
  before the editor-card `.editor-pane`). Reset-to-default clears it too.
- i18n EN+FR: labels for the message field + help text explaining `{arenet.maintenance.message}`,
  and the unit selector options. Keep the parity guard green.

---

## Tests

- **storage**: round-trip `MaintenancePageConfig{HTML, Message}` (extend existing test or add one).
- **caddymgr**: `buildMaintenanceBody` substitutes message + escapes HTML in it; empty message →
  empty substitution. Extend `TestBuildConfigJSON_LoadsCleanly` fixture stays valid (Message on
  the opts). `caddy.Validate` still passes.
- **api**: PUT with `message` persists + GET echoes it; PUT without `message` still works
  (back-compat); a `<script>` in the message does not appear raw in the emitted body (escaped).
- **frontend**: unit ⇄ seconds conversion (300↔5min, 3600↔1h, 0↔0s, 90↔90s stays seconds),
  message field round-trips through save. i18n parity guard.

## Smoke (mandatory — Validate provisions but does not serve)

Live-serve against a real binary (docs/smoke-test-maintenance.md pattern):
1. Set a global message via PUT, put a route in maintenance → curl the 503, assert the message
   appears in the body AND `Retry-After` header is the per-route seconds value.
2. Empty message → 503 body shows the generic default line, no stray empty element.
3. `<b>` / `<script>` in the message → appears escaped in the body, not as live markup.
