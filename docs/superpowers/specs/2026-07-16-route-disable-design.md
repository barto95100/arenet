# Route enable/disable (v2.14.3) — Design

**Status:** Approved design. Target release **v2.14.3** (patch — additive, backward-compatible).

**Author context:** Beta-tester request — an operator wants to temporarily take a route out of service (maintenance, migration, debugging) **without deleting its configuration** (upstreams, TLS, WAF, rate-limits, auth, health-checks all preserved for one-click re-enable).

**Design decisions below are all empirically verified against the codebase** (two audit passes, cited inline). This is the first of a progressive ship: v2.14.3 is the simple on/off; a richer **maintenance mode** (503 + custom HTML + Retry-After + IP bypass) is planned for v2.14.4 as a separate, additive layer (see §9).

---

## 1. Goal

Add a per-route **disabled** flag. A disabled route keeps its full stored config but is **not emitted into Caddy** — so it consumes zero CPU/memory, requests to its host hit the branded catch-all 404, and — critically — **no TLS certificate is requested or renewed for it** (avoids futile ACME challenges and Let's Encrypt rate-limit exposure). Re-enabling is a single toggle that re-emits the route unchanged.

**Non-goals for v2.14.3:** maintenance/503 pages, IP bypass, scheduled end, metrics-dashboard dimming, a "show disabled" filter toggle. All deferred (§9, §10).

## 2. Architecture decision: skip emission (not a runtime gate)

A disabled route is **filtered out before the Caddy config is built** — it never reaches Caddy. This beats a per-request "return 503" handler because:

- Zero Caddy overhead (a disabled route = 0 CPU/mem).
- The cert is removed from every ACME list for free (see §4).
- Rollback is trivial (toggle back → re-emit).
- Matches the codebase's established "not-emitted-when-off" pattern (WAF `off`, country-block `off`, unconfigured DNS providers).

## 3. Storage: `Disabled bool` (zero migration)

```go
// internal/storage/routes.go — Route struct
Disabled bool `json:"disabled,omitempty"`
```

**Why `Disabled` (default false = enabled), NOT `Enabled` (default true):**

- Every existing bool on `Route` picks its polarity so the **JSON zero-value equals legacy behavior** — precedent: `WAFDisableCRS` (routes.go:363), `InsecureSkipVerify` (:298), `UploadStreamingMode`, `RedirectToHTTPS`. There is **no precedent** for a bool that must default `true` on old rows.
- `Disabled bool` needs **NO migration**: a pre-feature row decodes `disabled=false` = enabled = correct.
- **Backup-restore safety (critical):** an *old backup* restored on the new binary decodes `disabled=false` = enabled = safe. With `Enabled bool`, that same old backup would import **every route disabled** — a silent data-loss class we've already been bitten by (multi-DNS-provider re-key bug). `Disabled` dodges it entirely.
- Backup round-trips the field automatically (`internal/backup/types.go:75` marshals the whole struct; no allowlist change; redaction untouched).

**No migration code is written.** The absence of the field on old rows IS the correct default.

**v2.14.4 forward-compat:** the maintenance state will be a **separate** field `MaintenanceConfig *MaintenanceConfig`, not an enum refactor of `Disabled`. Priority at emit time (v2.14.4): `Disabled=true` → 404 (wins) ; else `MaintenanceConfig != nil` → 503 ; else active. So `Disabled bool` does not block the future state.

## 4. caddymgr: a single filter point

**The whole emission change is one filter, immediately after routes are loaded in `applyLocked`** (`internal/caddymgr/manager.go:542`, where `ListRoutes` result flows into `buildConfigJSON` at :609).

```go
// after: routes, err := m.store.ListRoutes(ctx)   (manager.go:542)
liveRoutes := routes[:0:0]
for _, r := range routes {
    if r.Disabled {
        m.logger.Info("route skipped: disabled", "route_id", r.ID, "host", r.Host)
        continue
    }
    liveRoutes = append(liveRoutes, r)
}
routes = liveRoutes
```

**Why one point covers everything (audit-verified):** cert subjects accumulate **inside the same route loop** in `buildConfigJSON` (subjects appended at manager.go:1800/1817/1819, deny branch 1657/1659) — there is no separate cert path. So filtering the slice once removes the disabled route from **routing + HTTPS routes + ACME issuance** simultaneously. It also covers, because they all consume this same slice:
- `buildSkipList` (manager.go:2406) — `skip_certificates`
- `buildErrorRoutesForServer` (error_pages.go:520) — per-route error routes
- the WAF-diff / country-block-diff logs (manager.go:634/707)
- **the HC-tracker re-prime loop (manager.go:856-865)** — otherwise a disabled HC-enabled route leaves a **stale-green** entry Caddy never probes. Fixed for free.
- `syncRegistry` (manager.go:884) — the metrics counter registry drops the disabled ID.

**One extra site** (does its own `ListRoutes`, so needs the same check):
```go
// internal/caddymgr/manager.go:3369 — HasHTTPSServer
// must also skip r.Disabled when deciding whether an HTTPS server exists
```

## 5. Behavior when a disabled host is requested

- Route skipped → host no longer matched → falls to the **branded catch-all 404** (`catchAllRoute`, manager.go:3351), on both the HTTP and HTTPS servers. `curl http://disabled.host` → **branded 404**. ✅
- **Edge case (documented + warned in UI):** if the disabled route was the **only** TLS-enabled route, `httpsRoutes` is empty → the `arenet_https` server is **not emitted at all** (guard at manager.go:1902) → `curl https://disabled.host` → **connection refused on :443** (nothing listening), not a 404. This is a real behavior change → the confirm dialog warns (§7). With other TLS routes present, :443 stays up and the disabled host hits the HTTPS catch-all 404 with the cert no longer requested for it.
- **Managed-domain wildcard:** the wildcard cert is pre-acquired from `opts.ManagedDomains`, independent of route state — so a disabled route covered by a wildcard still has a valid TLS handshake, then 404s. Harmless.

## 6. API: two dedicated idempotent endpoints

```
POST /api/v1/routes/{id}/disable   → 200 (idempotent; disabling an already-disabled route is a no-op success)
POST /api/v1/routes/{id}/enable    → 200 (idempotent)
```

- No PATCH (the repo has none — verified; convention is POST/PUT/DELETE). Action-oriented endpoints match the existing `/alerting/channels/{id}/test` shape.
- No request body needed (the action IS the state).
- Handler mirrors `updateRoute` exactly: `GetRoute` → set `Disabled` → `UpdateRoute` → `ReloadFromStore(ctx)` → **roll back storage on reload failure** (the uniform pattern at routes.go:1458/1942/1992) → `appendAudit`.
- **Response includes a hint** so the frontend can pre-warn (§7):
  ```json
  { "id": "...", "disabled": true, "lastHttpsRouteAffected": true }
  ```
  `lastHttpsRouteAffected` = true when this disable removes the last active TLS route. The `/disable` handler computes it (count of `TLSEnabled && !Disabled` routes == 1 and target is TLS).
- **Distinct audit actions** `route_disabled` / `route_enabled` (past-tense D7 convention). Adding two constants requires updating **three** places or tests fail: the `const` block + `allActions` (actions.go:237) + `TestAllActions_Count` (56→58) + `TestAllActions_ExactSet` map (actions_test.go). This friction is the intended "force the conversation" guard.

## 7. Frontend

### /routes page (`web/frontend/src/routes/routes/+page.svelte`)
- Each row (`{#each filteredRoutes as r}` → `<tr class="route-row">`, :2073) gains:
  - a **"Disabled" badge** (same `<td>` badge pattern as the TLS/WAF badges at :2176/:2184),
  - **dimmed row** (`class:opacity-50` or similar) when `r.disabled`,
  - a **toggle action** (enable/disable) calling the new API client methods (one-liners beside `updateRoute`/`deleteRoute` in `lib/api/client.ts:186`).
- **Confirm dialog** (reuse the `ConfirmDialog` + `confirmTarget` pattern at :46/:387/:3741) with two variants:
  - **Normal disable:** "Disable route ? — This route will no longer serve traffic. Its configuration is preserved for re-enable."
  - **Last-HTTPS-route disable** (when the API/precomputed hint says so): a ⚠️ special dialog — "Disable the last HTTPS route ? — This is the last active HTTPS route. Disabling it stops the HTTPS server (port 443); requests to any HTTPS URL will fail with *connection refused*. Continue ?" Actions: Cancel (default) / **Disable anyway**. Warning ≠ block (legitimate for single-route dev/test).
  - Enable needs no confirm.
- The `Route` / `RouteRequest` types (`lib/api/types.ts:57/439`) gain `disabled?: boolean`.

### RouteForm (edit modal)
- A **"Disabled" checkbox** near the top (default unchecked = enabled for new routes). Lets the operator create a route pre-disabled, or flip it while editing (the existing PUT carries the field too — the dedicated endpoints are for the row-level toggle).

### Topology (`internal/api/topology/` + frontend)
- Backend, **2 lines**: add `Disabled bool json:"disabled"` to the wire struct `topology.Route` (types.go:55, beside `HTTPRedirect`/`HasHealthCheck`) and set `Disabled: r.Disabled` in `buildRoute` (builder.go:135 — the `*storage.Route` is in hand).
- Frontend: **dim / dashed-border** the node when `disabled === true`, with a tooltip ("Disabled — not serving traffic"). Prevents the conspicuous "phantom zero-traffic node" confusion (topology reads `store.ListRoutes` directly, so a disabled route WOULD otherwise render as a normal node).

### Metrics — deliberately NOT dimmed (backlog v2.14.5)
- Metrics dashboards read `store.ListRoutes` too, but a disabled route = zero traffic → naturally sorts to the bottom as a zero-row, same as any idle route. Harmless. Dimming it needs 4-site wiring (RouteMetadata + RouteSnapshot + ticker + summary handler) for a low-value cosmetic gain → deferred until beta feedback asks for it.

### i18n (EN + FR, parity guard `lib/i18n/index.test.ts:112` must pass)
New keys under `routes.*` and `topology.*`, in **both** `en.json` and `fr.json`:
- `routes.disabled.badge`
- `routes.disable.action` / `routes.enable.action`
- `routes.disable.confirm.title` / `.text` / `.action`
- `routes.disable.confirm.lastHttps.title` / `.text` / `.action`
- `routes.form.disabledLabel` / `.disabledHelper`
- `topology.disabled.tooltip`

## 8. Empirical validation gates (smoke, per CLAUDE.md)

Run against a real binary/`caddy.Validate`, not assumed:
1. Create route → `disabled` defaults false; route emitted.
2. `POST /disable` → dump live Caddy config → route absent from `apps.http.servers` AND from `apps.tls` (no ACME subject for the host). **No ACME request logged for the disabled host.**
3. `curl http://disabled.host` → branded catch-all **404**.
4. `POST /enable` → Caddy reload → route re-emitted identically.
5. **Edge:** a config with exactly one TLS route → disable it → `:443` server absent → `curl https://` = connection refused; the frontend showed the special warning pre-action.
6. **HC leak:** disable an HC-enabled route → no stale `RecordHealthy` entry remains.
7. **Backup round-trip:** export a config with a disabled route → `disabled:true` present in the snapshot → import → still disabled.
8. **Old-backup restore:** import a pre-feature snapshot (no `disabled` field) → all routes enabled (backward-safe).
9. **Idempotence:** `POST /disable` twice → same state, 200 both times.
10. **Topology:** disabled route renders as a dimmed node (not a normal phantom).

## 9. Out of scope — v2.14.4 maintenance mode (separate design)

A **third behavior** (not a state-enum change): `MaintenanceConfig *MaintenanceConfig` on Route. When set (and `Disabled=false`), the route IS emitted but its handler returns **503 + a custom maintenance HTML page** (blue/info, "back soon", `Retry-After`), with an **IP-bypass whitelist** (admin sees the real upstream) and an optional scheduled end. This reuses/extends the Custom Error Pages infra: a new **"Maintenance pages"** tab in `/settings/error-pages`, a `CustomTemplate.type` field (`"error" | "maintenance"`, migration-free via the same omitempty-default trick), and new `{arenet.maintenance.*}` placeholders. Designed separately after v2.14.3 beta feedback.

## 10. Backlog (noted, not v2.14.3)

- **Metrics-dashboard dimming** (v2.14.5, if beta feedback asks).
- **"Show disabled routes" filter toggle** on /routes.
- **V3 coherence audit** — the `applyLocked` filter doesn't reach storage-based read surfaces; enumerate every surface reading `store.ListRoutes()` directly (audit view, backup, cert view, CLI, metrics) and decide which need disabled-awareness for consistency.

## 11. File map (implementation targets)

| Area | File:line |
| ---- | --------- |
| Route struct field | `internal/storage/routes.go` (struct ~166) |
| caddymgr filter | `internal/caddymgr/manager.go:542-545` (filter) + `:3369` (HasHTTPSServer) |
| API endpoints + hint | `internal/api/routes.go` (router :333, handlers mirroring :1458/1942) |
| Audit constants | `internal/audit/actions.go:237` + `actions_test.go` (count 56→58) |
| Topology wire | `internal/api/topology/types.go:55` + `builder.go:135` |
| Frontend routes page | `web/frontend/src/routes/routes/+page.svelte` (row :2073, confirm :3741) |
| API client + types | `web/frontend/src/lib/api/client.ts:186` + `types.ts:57/439` |
| i18n | `web/frontend/src/lib/i18n/locales/{en,fr}.json` (guard `index.test.ts:112`) |
