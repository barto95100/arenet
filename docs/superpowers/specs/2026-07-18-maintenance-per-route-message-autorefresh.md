# Maintenance per-route message + auto-refresh (v2.18.1)

**Status:** decisions LOCKED by user 2026-07-18. Follows v2.18.0 (SHIPPED). Patch bump.

**Goal:** (A) move the maintenance message from global-only to **per-route, with the
global as fallback**; (B) make the built-in default page **auto-refresh** the browser
using the route's Retry-After value.

**Governing memory:** `maintenance-v218-backlog`, `routes-maintenance-feature`,
`process-weight-calibration` (light/direct + final review).

---

## A — Per-route message (global = fallback)

### Storage
- Add `Message string \`json:"message,omitempty"\`` to `storage.MaintenanceConfig`
  (`internal/storage/routes.go`) — the per-route message. Zero-migration (omitempty).
- Keep `MaintenancePageConfig.Message` (the global) exactly as-is — it becomes the
  **fallback** when a route has no message of its own.

### Resolution (the fallback rule)
`{arenet.maintenance.message}` renders: **route.MaintenanceConfig.Message if non-empty,
else the global MaintenancePageConfig.Message** (which may itself be empty → renders
nothing, `.msg:empty` collapses). Precedence is per-route-override-then-global, mirroring
error-page override→template→default.

### caddymgr
- `buildMaintenanceBody(pageHTML string, retryAfter int, message string)` already takes the
  final message string — the RESOLUTION happens at the call site in `manager.go` (emission
  loop ~1530), where both `r.MaintenanceConfig.Message` and `opts.MaintenanceMessage`
  (global) are in scope. Compute `effectiveMsg := r.MaintenanceConfig.Message; if
  effectiveMsg == "" { effectiveMsg = opts.MaintenanceMessage }` and pass it. Escaping +
  {env}/{file} neutralization + \n→<br> stay inside buildMaintenanceBody (unchanged).
- `opts.MaintenanceMessage` (global) plumbing stays; add nothing new to buildOpts.

### API — WIRE-FIELD GAP LESSON (mandatory, this is the recurring 400 class)
`MaintenanceConfig` is a nested struct on the route. Adding `Message` to it means:
- `routeRequest` maintenance sub-struct (handler.go) — else PUT/POST 400 "unknown field".
- create-map + update-map (handler.go) — else silently dropped on write.
- `routeResponse` maintenance sub-struct — else GET can't echo it (the v2.17.1 disabled-
  serialize regression class).
- A round-trip test (`routes_maintenance_test.go` or a new one) asserting the per-route
  message survives create→GET AND update→GET.
The `/maintenance` toggle endpoint defaults (enter-with-no-config → {RetryAfterSeconds:300})
leave Message="" — fine (falls back to global).

### Frontend
- Route edit form Maintenance section (`web/frontend/src/routes/routes/+page.svelte`, ~2680
  the maintenance block): add a **message textarea** (same pattern as Settings, multi-line)
  bound to `formData.maintenanceConfig.message`, with a help line noting "leave empty to use
  the global message (Settings → Error Pages → Maintenance)".
- Types: add `message?: string` to the `MaintenanceConfig` wire type (`types.ts`) + the form
  seed (openCreate default '', openEdit from `r.maintenanceConfig.message`).
- payload assembly (submitForm ~1985): ship `message` inside maintenanceConfig.
- The Settings global-message field stays; relabel its help to "default message, shown on
  routes that don't set their own".
- i18n EN+FR for the new route-form label + help.

---

## B — Auto-refresh via meta http-equiv (default page only)

### Built-in default page (`arenetDefaultMaintenancePage`)
- Add `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">` in `<head>`,
  so the browser reloads itself after the route's Retry-After seconds (the maintenance
  window's expected end).
- **GUARD: retry_after == 0 → NO meta refresh.** `content="0"` means reload instantly →
  hammering loop. When RetryAfterSeconds is 0 (operator omitted the header), the default page
  must NOT carry the meta. Since the page is a static template with the sentinel substituted
  by strings.ReplaceAll, the zero-guard can't live in the template — it must be handled where
  the body is built. Approach: the default page is emitted WITHOUT the meta baked in; instead,
  in buildMaintenanceBody (or resolveMaintenancePage), when the page IS the built-in default
  AND retryAfter > 0, inject the meta tag; when retryAfter == 0, inject nothing. Simplest
  robust form: keep a sentinel `{arenet.maintenance.refresh_meta}` in the default template's
  <head>, and substitute it with either `<meta http-equiv="refresh" content="N">` (N>0) or
  "" (N==0) at build time. This keeps the zero-guard in Go, not in the fragile template.
- Custom pages: NOT auto-injected (user's locked choice). The `{arenet.maintenance.retry_after}`
  placeholder is already available, so a custom page author can add their own
  `<meta http-equiv="refresh" content="{arenet.maintenance.retry_after}">` if they want it.
  Document this.

### Sentinel plumbing
- New const `maintenanceRefreshMetaSentinel = "{arenet.maintenance.refresh_meta}"`.
- buildMaintenanceBody substitutes it: `retryAfter > 0` → the meta tag string; else "".
- The sentinel lives in `arenetDefaultMaintenancePage` <head>. A custom page has no sentinel,
  so it's a no-op there (ReplaceAll of an absent substring = unchanged) — custom pages are
  untouched, matching the locked "default only" decision.

---

## Tests
- storage: MaintenanceConfig{Message} round-trips.
- caddymgr:
  - per-route message wins over global; empty per-route falls back to global; both empty →
    empty substitution.
  - refresh_meta: retryAfter>0 → `<meta http-equiv="refresh" content="N">` present in default
    page; retryAfter==0 → NO meta; custom page (no sentinel) → unchanged.
  - `TestBuildConfigJSON_LoadsCleanly` fixture still passes caddy.Validate with a per-route
    message + refresh meta.
- api: create/update route with maintenanceConfig.message → GET echoes it (wire-field round-trip).
- frontend: route-form message textarea round-trips through save; unit tests for the
  fallback aren't frontend (backend resolves) but the payload ships message.

## Smoke (mandatory — live-serve)
1. Route A with own message + Route B without, global message set → curl both 503s: A shows
   its own, B shows the global.
2. Retry-After 1800 on default page → `<meta http-equiv="refresh" content="1800">` present.
3. Retry-After 0 → NO meta refresh in the served body (no hammering loop).
4. {env.X} in a per-route message → neutralized (regression guard for the v2.18.0 fix).

## Docs
- Routes EN+FR: per-route message field + fallback rule; auto-refresh behavior.
- Custom-Error-Pages EN+FR: note the global is now a fallback; custom pages can add their own
  meta refresh with {arenet.maintenance.retry_after}.
