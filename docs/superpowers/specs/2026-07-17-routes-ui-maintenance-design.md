# Routes UI + Maintenance Mode — Design Spec

**Date:** 2026-07-17
**Target version:** v2.17.0 (feature → minor bump; verify git-state at tag)
**Status:** approved design, ready for implementation plan

## Goal

Give a route a **third operational state — Maintenance** — alongside the existing Active / Disabled, and expose all three through **one inline control** on the Routes list. A route in maintenance keeps its TLS/host but serves a **503 + a custom maintenance page + `Retry-After`**, with an **IP bypass allow-list** so listed operators still reach the real upstream. This ships together with the UI overhaul that resolves the "Désactiver button read as a state" confusion (icons + a single segmented control + stronger state badges).

## Author context

Route enable/disable shipped in v2.15.0 (`Disabled bool` → route filtered before Caddy → catch-all 404). The route-disable spec §9 pre-scoped maintenance as a **separate `MaintenanceConfig *` field, NOT an enum refactor of `Disabled`**. A beta-tester then read the list's "Désactiver" action button as a *state* (it differs from the "Désactivée" badge by two letters, in an unlabeled column). The user's decision: **one 3-state control** (not a binary toggle + a separate maintenance menu), extending the segmented-control pattern, with icons to make it unmistakably a control.

## Locked decisions

1. **Three states in ONE control:** Active / Maintenance / Disabled. Not a binary toggle plus a menu.
2. **UI = a segmented control** (variant C): filled semantic color + an icon per state — ▶ Active (green `--status-up`), 🔧 Maintenance (amber `--status-warn`), ⏻ Disabled (red/grey `--status-down`). Inline per row; clicking a segment changes the state immediately.
3. **Storage = two independent fields, no migration.** `Disabled bool` (shipped) + new `MaintenanceConfig *MaintenanceConfig`. Mapping: Active = `Disabled=false && MaintenanceConfig==nil`; Maintenance = `MaintenanceConfig!=nil` (and `Disabled=false`); Disabled = `Disabled=true`.
4. **Emit priority (locked, extends the shipped filter):** `Disabled=true` → route filtered out → 404 (wins) ; else `MaintenanceConfig!=nil` → 503 maintenance ; else active reverse-proxy.
5. **Maintenance page is GLOBAL** (one shared template), customizable in a new **Maintenance** section of `/settings/error-pages`, with a **branded default** page matching Arenet's default error pages. Not per-route.
6. **Bypass = a per-route IP/CIDR allow-list** on `MaintenanceConfig`. Listed IPs reach the real upstream; everyone else gets the 503.
7. **`Retry-After` = a configurable fixed value** per route (seconds). **No auto-end / scheduler** — the operator returns the route to Active manually.
8. **MaintenanceConfig is preserved** even when the route is Active or Disabled (disable philosophy: keep all config; the control reflects what's *active*, storage holds what's *configured*). Re-entering maintenance reuses the last config.
9. **Config detail in the edit form:** the Retry-After value and bypass IP list live in a new "Maintenance" section of the route edit form. Switching to Maintenance with no prior config uses defaults.
10. **One ship, v2.17.0** — backend + UI together.

## Architecture

### Caddy emission (empirically verified against caddy v2.11.3)

A maintenance route is EMITTED (unlike Disabled, which is filtered out). Instead of the normal reverse-proxy subroute, `internal/caddymgr/manager.go` emits a subroute with two inner routes:

1. **Bypass route:** `{match: [{"client_ip": {"ranges": <bypassIPs>}}], handle: [<reverse_proxy>], terminal: true}` — listed IPs reach the real upstream.
2. **503 route (catch-all):** `{handle: [{"handler":"static_response", "status_code":503, "body":<maintenance HTML>, "headers":{"Retry-After":["<n>"], "Content-Type":["text/html; charset=utf-8"]}}]}` — everyone else.

Verified empirically (`caddy.Validate` on a real binary, all variants pass; source citations in the investigation): `static_response` accepts 503 + a multi-line HTML body + arbitrary headers; `client_ip` matcher (NOT `remote_ip` — future-proof for a future `trusted_proxies`, identical today since Arenet emits none); route order + `terminal:true` gives bypass-wins-then-503; TLS automation / `@host` matcher / HTTP→HTTPS redirect are all independent of the terminal handler, so swapping reverse_proxy → static_response keeps certs + SNI + redirect intact.

**Emission site:** `manager.go` per-route handler assembly (~lines 1508–1727; the `handlers` slice built from `metricsHandler` through the `proxyHandler` append, then `wrapInSubroute`). The maintenance branch is a **distinct subroute shape** (matcher-bearing inner routes), not a one-line handler swap. **Pattern to copy:** the forward-auth deny path (`manager.go:1667-1673`) already emits a `static_response` 503 as a terminal handler.

**Gate ordering in maintenance:** keep `metrics` first (so the 503 is counted, preserving the §11.5 invariant). WAF / auth / rate-limit / country-block do **NOT** run in front of the maintenance page (a maintenance page needs no inspection). The bypass route's reverse_proxy DOES keep the normal gate chain (bypass = "see the real app", so real protections apply).

**Filter integration:** the existing `applyLocked` route filter removes `Disabled` routes before build (unchanged — priority 4: Disabled wins). Maintenance routes are NOT filtered (they must be emitted to serve the 503); the maintenance branch is inside the per-route build.

### Storage (`internal/storage/routes.go`)

New field on `Route`:
```go
// MaintenanceConfig, when non-nil (and Disabled=false), puts the
// route in maintenance: Caddy serves a 503 + the global maintenance
// page + Retry-After, except for BypassIPs which reach the real
// upstream. Nil = not in maintenance (zero-value, migration-free).
// Preserved across Active/Disabled so re-entering maintenance reuses it.
MaintenanceConfig *MaintenanceConfig `json:"maintenanceConfig,omitempty"`
```
```go
type MaintenanceConfig struct {
    RetryAfterSeconds int      `json:"retryAfterSeconds,omitempty"` // 503 Retry-After header (0 = omit / a sane default)
    BypassIPs         []string `json:"bypassIps,omitempty"`         // IP/CIDR allow-list reaching the real upstream
}
```
Validation: each `BypassIPs` entry parses as an IP or CIDR (reject junk with a 400); `RetryAfterSeconds >= 0`.

### Maintenance page storage (global)

"Reuses the error-pages infra" means reusing the **settings UI location** (a tab in `/settings/error-pages`) and the **branded-default + custom-HTML editing pattern** — not necessarily the `ErrorPageTemplate` *struct* (Option A stores the maintenance HTML separately). Either option is migration-free.

The existing template type is `storage.ErrorPageTemplate` (`error_template.go:73`) with `Pages map[int]string` keyed by status code. Maintenance is a SINGLE 503 page, not a per-code map, so the design choice (resolve in the plan):
- **Option A (recommended):** a dedicated single-slot global maintenance template — a `MaintenancePage string` (the HTML) stored as an instance-level setting, with a branded default when empty. Simpler than shoehorning the per-code map; the "type" distinction becomes a separate storage key, not a `Type` field on ErrorPageTemplate.
- **Option B:** add `Type string ("error"|"maintenance")` to `ErrorPageTemplate` (omitempty → migration-free) and reuse the whole template CRUD, storing the maintenance HTML under a conventional key (e.g. `Pages[503]`).

The plan picks one after reading the error-template CRUD + the settings UI; both are migration-free. Either way there is a **branded default maintenance page** (blue/info "back soon", styled like Arenet's default error pages) served when the operator hasn't customized one.

**Retry-After in the page body:** the page is global but Retry-After is per-route. The `Retry-After` **HTTP header** is always set per-route (standard, bot/browser-visible). Displaying the value *inside* the HTML is done by **substituting `{arenet.maintenance.retry_after}` at config-emission time** (each route emits the global body with its own value already substituted into the static_response body) — no custom runtime Caddy placeholder needed. Plan verifies emission-time substitution vs a runtime placeholder and picks the clean one; if neither is clean, the header-only fallback (no in-page value) is acceptable.

### API (`internal/api/routes.go`)

- **State endpoints (mirror /disable + /enable):** `POST /routes/{id}/maintenance` (enter maintenance) + `POST /routes/{id}/maintenance/off` (return to active) — or a single endpoint taking the target; the plan mirrors `toggleRouteDisabled` (routes.go:1983). Idempotent. Entering maintenance with no stored config applies defaults.
- **Wire-field (MANDATORY — the recurring gap):** `MaintenanceConfig` must be added to the `routeRequest` wire struct (`handler.go`), mapped in BOTH `createRoute` and `updateRoute`, and added to `routeResponse` for the edit-form roundtrip. Without this, create/edit 400s with "unknown field". (See the route-wire-field-gap lesson: struct + create-map + update-map + response + a `routes_<field>_test.go`.)
- **Global maintenance page endpoints:** GET/PUT under the error-pages settings API (admin-gated), following the existing error-template endpoints.
- **Audit:** `route_maintenance_on` / `route_maintenance_off` (+ count bump + ExactSet).

### Frontend

**Routes list (`web/frontend/src/routes/routes/+page.svelte`):**
- A **segmented control** per row (variant C): 3 segments Active/Maintenance/Disabled, filled semantic color + icon. Either extend `Toggle.svelte` (currently 2 fixed options, controlled) to N options, or a new `StateControl.svelte` — plan decides. `role="radiogroup"`, each segment `role="radio"`, keyboard-navigable, aria-labelled.
- Clicking a segment calls the matching endpoint (`/maintenance`, `/maintenance/off`, `/disable`, `/enable`) and refreshes.
- **Last-HTTPS warning:** switching the last active TLS route to Maintenance OR Disabled removes `:443` — reuse the existing disable warning dialog (extend its trigger to the maintenance transition).
- **Folded UX fixes:** stronger state badge (amber "Maintenance" / red "Disabled" via `--status-warn`/`--status-down`, not neutral grey); dimmed row for disabled; a visible **"Actions"/"State" column header** (currently `sr-only`).
- The old separate "Activer/Désactiver" ghost button is **removed** — the segmented control replaces it.

**Route edit form:** a new **"Maintenance" section** — Retry-After (seconds) input + a bypass IP/CIDR list editor (add/remove rows). Bound to `MaintenanceConfig`. Seeded from the route on edit (wire-field lesson: the form must reflect stored state).

**Settings → Error Pages:** a new **"Maintenance" tab/section** to view + customize the global maintenance page (like the error-page editor), with a preview and a "reset to default" affordance.

**i18n:** new keys for the 3 states, the maintenance form section, the settings tab, EN + FR, parity guard.

## Testing

- **Storage:** `MaintenanceConfig` roundtrip + omitempty (backup back-compat); validation (bad CIDR → error); zero-value = not-in-maintenance.
- **caddymgr:** emit a maintenance route → `caddy.Validate` green; asserts the 503 static_response body + Retry-After header + `client_ip` bypass route + terminal ordering; NO ACME subject leak difference (host still issues); priority Disabled(404) > Maintenance(503) > Active; TLS/redirect intact.
- **API:** maintenance on/off endpoints (idempotent, audit), wire-field create/update/response roundtrip (the create-with-maintenance and edit-preserves-maintenance tests — the exact class that broke for `disabled`), 403 non-admin.
- **Frontend:** segmented control renders 3 states + fires the right endpoint per segment; edit form maintenance section seeds + submits; last-HTTPS warning on the maintenance transition; settings maintenance tab; i18n parity.
- **Empirical smoke (CLAUDE.md):** a live curl from a listed vs non-listed IP against a maintenance route (503 + Retry-After for non-listed; real upstream for listed) — the belt-and-suspenders the Caddy investigation flagged (Validate provisions but doesn't serve).

## Non-goals (explicit)

- **No auto-end / scheduled maintenance** (Retry-After is a fixed value; operator ends it manually).
- **No per-route maintenance page** (global only this ship).
- **No enum refactor of `Disabled`** (two independent fields — locked).
- **No maintenance for the HTTP→HTTPS redirect** (the `:80` redirect route stays; `:443` serves the 503).
- Metrics-dashboard dimming of maintenance routes, "show disabled/maintenance" filter — backlog.

## Open items for the implementation plan (verify empirically)

1. **Maintenance page storage shape** — Option A (dedicated single-slot setting) vs B (`Type` on ErrorPageTemplate). Read the error-template CRUD + settings UI, pick the migration-free one with least surface.
2. **Retry-After in-page value** — emission-time substitution of `{arenet.maintenance.retry_after}` vs runtime placeholder vs header-only. Verify what's clean; header is always set regardless.
3. **State endpoint shape** — one `/maintenance` toggle vs on+off, mirroring `toggleRouteDisabled` exactly. And how entering maintenance interacts with a route that has no stored MaintenanceConfig (apply defaults).
4. **Segmented control** — extend `Toggle.svelte` (2→N, currently controlled-not-bindable, hardcoded 2 options at :46) vs a new component. Decide based on how invasive the extension is.
5. **Gate chain in maintenance** — confirm metrics-first still counts the 503, and that skipping WAF/auth for the 503 path is expressible cleanly at the emission site.
6. **Live serve smoke** — the curl-from-two-IPs test (Validate doesn't exercise the serve path).
