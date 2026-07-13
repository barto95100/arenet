# Sidebar Notification Panel — Design

**Date:** 2026-07-13
**Status:** Approved (design sections 1 & 2 validated by operator)
**Milestone target:** v2.12.6

## Goal

Add a dedicated **sidebar notification entry** (bell icon + "Notifications"
label + unread count), placed just above the user/logout footer block, and
**remove the topbar `UpdateBadge`**. Clicking the sidebar entry opens a
panel listing the most recent alerting events **plus a synthetic
"update available" notification** derived directly from `/system/version`,
each with contextual navigation.

## Motivation

- Notifications currently have no first-class home in the nav. The only
  topbar signal is `UpdateBadge` — a discreet, update-only dot next to the
  "Gateway Healthy" pill — which the operator found easy to miss and too
  narrow (updates only). The operator wants it removed and superseded by
  the sidebar panel.
- The update-checker work (v2.12.3–v2.12.5) added `update_available` as an
  alerting source. Operators need a visible place where alert events
  (updates, cert expiry, WAF spikes…) surface at a glance, with a jump-off
  to the relevant page.
- **Guarantee to preserve:** `UpdateBadge` was zero-config — it showed an
  available update even with NO alerting rule. To keep that guarantee after
  removing it, the panel reads `/system/version` directly and synthesizes
  an update notification (see §2.6). So removing the badge does not regress
  the always-on update signal.

## Non-Goals (YAGNI)

- **No new backend endpoint.** The panel reads the existing
  `GET /api/v1/observability/alert-events`.
- **No new persistence.** Unread state lives in `localStorage` (per
  browser), not on the server.
- **No push/WebSocket.** Refresh is a light poll + fetch-on-open (matches
  how the rest of the settings UI already behaves).
- **No notification categories/filtering UI.** The full-featured history
  (filtering, pagination, channel status) already exists at
  `/alerting` → History tab. The panel is a lightweight summary + jump-off.

---

## Section 1 — Architecture & data source (APPROVED)

**Zero new backend.** The panel is a pure frontend feature built on
existing primitives:

| Primitive | Location | Role |
| --- | --- | --- |
| `GET /api/v1/observability/alert-events` | `internal/api/alert_events.go` | Source of notifications (already admin-gated) |
| `alertingApi.listAlertEvents(filter)` | `web/frontend/src/lib/api/alerting.ts` | TS client (supports `limit`) |
| `alertEventsStore` | `web/frontend/src/lib/stores/alerting.svelte.ts` | Existing store: `.load(filter, reset)`, `.events` |
| `AlertEvent` type | `web/frontend/src/lib/api/alerting.ts` | `{eventId, timestamp, ruleName, severity, category, subject, body, context, labels, ...}` |
| `relativeTime(iso)` | `web/frontend/src/lib/utils/audit-format.ts` | i18n-aware "il y a 3 min" |

**A notification = an alerting event.** The panel therefore only surfaces
what a configured **rule** produces. This is deliberate: it keeps the
subsystem single-sourced (no parallel "notification" concept to maintain).
The empty state guides the operator to `/alerting` to create rules.

**Unread model:**
- `localStorage` key `arenet.notifications.lastSeen` holds an RFC-3339
  timestamp (the moment the panel was last opened).
- **Unread count** = number of fetched events whose `timestamp > lastSeen`.
- Opening the panel sets `lastSeen = <now, from newest event or client
  clock>` and the count resets to 0.
- First-ever visit (no key): treat all currently-fetched events as read
  (set `lastSeen` to the newest event's timestamp, or "now" if none) so a
  fresh install doesn't show a spurious count for historical events.

**Fetch cadence:**
- Fetch on mount of the sidebar (so the count is populated at page load).
- Re-fetch when the panel is opened (fresh view).
- Light background poll every **60 s** while the app is open, reusing the
  existing store (`alertEventsStore.load({ limit: PANEL_LIMIT }, true)`).
  60 s matches "not real-time, but current enough"; the update checker
  itself runs hourly, so sub-minute polling would be wasteful.

**Volume:** `PANEL_LIMIT = 15`. The panel shows the 15 most recent events;
"Voir tout dans Alerting →" links to the full history.

---

## Section 2 — Frontend components (APPROVED)

Three new frontend pieces; one existing file modified.

### 2.1 Store: `notifications.svelte.ts` (NEW)

`web/frontend/src/lib/stores/notifications.svelte.ts`

A thin layer over `alertEventsStore` that owns unread bookkeeping. It does
**not** duplicate fetching — it delegates to `alertEventsStore.load(...)`
and derives from `alertEventsStore.events`.

A notification item, as consumed by the panel, is the existing `AlertEvent`
shape (the synthetic update item is constructed to satisfy that same shape,
so the panel renders both uniformly).

Public surface:
- `recent: AlertEvent[]` — `$derived`: the synthetic update item (§2.6,
  when `updateAvailable`) prepended to the `PANEL_LIMIT`-capped slice of
  `alertEventsStore.events`, then the whole list re-capped to `PANEL_LIMIT`
  and sorted newest-first by `timestamp`.
- `unreadCount: number` — `$derived`; items in `recent` with
  `timestamp > lastSeen`.
- `lastSeen: string` — the persisted RFC-3339 marker (localStorage-backed).
- `load(): Promise<void>` — runs both fetches: `alertEventsStore.load({
  limit: PANEL_LIMIT }, true)` and `systemApi.getVersion()`; updates the
  synthetic-update bookkeeping (`updateFirstSeen`, §2.6).
- `markAllRead(): void` — sets `lastSeen` to the newest item's timestamp
  in `recent` (or client "now" if list empty), persists to localStorage.
- `loading: boolean`, `loadError: string` — re-exposed from
  `alertEventsStore` state for the panel's loading/error UI. A failed
  version fetch is swallowed (like `UpdateBadge` did) and does not set
  `loadError` — the panel still shows alert events.

localStorage access is guarded (`typeof localStorage !== 'undefined'`) so
SSR/prerender (adapter-static build step) doesn't crash.

### 2.2 Contextual navigation helper (NEW, colocated in the component or a small util)

`notificationHref(ev: AlertEvent): { href: string; external: boolean }`

Derives the click destination from the event, best-effort:

1. If `ev.context?.url` is a non-empty string → `{ href: url, external:
   true }` (updates put the GitHub release URL here).
2. Else map on a coarse signal — prefer `ev.category`, fall back to a
   substring of `ev.ruleName` (lowercased):
   - contains `cert` → `/certs`
   - contains `waf` or `security` → `/security`
   - contains `update` → `/settings` (Updates section anchor)
   - contains `health` or `system` → `/` (overview)
3. Fallback → `/alerting` (History tab).

External URLs (`external: true`) open in a new tab with
`rel="noopener noreferrer"`; internal ones use SvelteKit navigation.

> **Nuance (from empirical check):** the event does NOT carry a raw
> `source` field. `context.url` is the reliable signal for updates; the
> category/ruleName heuristic is best-effort for the rest and always has a
> safe `/alerting` fallback. This is acceptable — worst case a
> notification lands the operator on the full history, never a dead link.

### 2.3 Component: `NotificationBell.svelte` (NEW)

`web/frontend/src/lib/components/NotificationBell.svelte`

- **Sidebar entry (variant A):** a button styled like a sidebar item —
  bell SVG + `t('notifications.label')` ("Notifications" / "Notifications")
  + a count badge (rendered only when `unreadCount > 0`; caps display at
  `99+`). Red badge using the existing danger token.
- **Panel (popover):** anchored to the sidebar, opens on click. Contents:
  - Header: title + "Tout marquer lu" action (calls `markAllRead()`),
    disabled when `unreadCount === 0`.
  - Body: up to 15 rows. Each row = severity glyph + `subject` +
    meta line (`severityLabel · relativeTime(timestamp)`), wrapped in the
    contextual link from §2.2. Unread rows (`timestamp > lastSeen`) get a
    subtle emphasis (left accent / brighter text); read rows are dimmed.
  - Loading state (`loading`) → spinner/skeleton; error (`loadError`) →
    inline error text.
  - **Empty state:** "Aucune notification" + CTA "Configurer des alertes
    dans Alerting →" linking to `/alerting`.
  - Footer: "Voir tout dans Alerting →" → `/alerting`.
- **Dismissal:** click-outside and `Escape` close the panel. The panel
  traps focus minimally (first focusable on open) and restores focus to the
  bell button on close. All interactive elements carry ARIA labels
  (project a11y convention).
- **i18n:** all strings via `t()`. New keys under `notifications.*` in both
  `en.json` and `fr.json` (parity guard test enforces both exist). The
  `topbar.updateAvailable` key becomes orphaned when `UpdateBadge` is
  deleted — remove it from both bundles. The new
  `notifications.updateAvailable` key (with a `{version}` param) replaces
  its role for the synthetic item.

### 2.4 Modified: `Sidebar.svelte`

`web/frontend/src/lib/components/Sidebar.svelte`

- Insert `<NotificationBell />` immediately **before** the `.sidebar-foot`
  block (the avatar/username/logout row, ~line 265).

### 2.5 Modified: `Topbar.svelte` — remove `UpdateBadge`

The "petite cloche à côté de Gateway Healthy" is **`UpdateBadge.svelte`**
(`Topbar.svelte:105`, shipped v2.12.3): a discreet, zero-config update dot
reading `GET /api/v1/system/version`, rendered only when `updateAvailable`.

**Remove it from the topbar** (operator's choice): delete the
`<UpdateBadge />` line and its `import` in `Topbar.svelte`. The
`UpdateBadge.svelte` component file itself is **deleted** (no other
consumer — verify with a grep at implementation time; if another consumer
exists, keep the file and only remove the topbar usage).

The always-on update guarantee it provided is preserved by §2.6.

### 2.6 The synthetic "update available" notification

`UpdateBadge` worked with **zero config** — it showed an available update
even when no alerting rule existed. Alert-events are rule-driven, so to
keep that guarantee the panel reads `/system/version` directly and injects
a synthetic notification.

- `notifications.svelte.ts` also fetches `systemApi.getVersion()` →
  `SystemVersion { current, latest, updateAvailable, url }`.
- When `updateAvailable === true`, the store prepends a **synthetic**
  notification item to `recent`:
  - stable id: `"synthetic:update"` (so it dedupes across refreshes and can
    key unread separately from `alert_event` rows).
  - `subject`: `t('notifications.updateAvailable', { version: latest })`
    → e.g. "Mise à jour v2.12.6 disponible".
  - `timestamp`: the version fetch time (client "now" at fetch). Because
    `Date.now()` is fine in the browser (this is frontend, not a workflow
    script), the store stamps it when the fetch resolves.
  - `context.url = url` → clicking opens the GitHub release (same behavior
    the badge had), via the §2.2 `context.url` branch.
  - `severity`: info-level.
- The synthetic item participates in unread counting like any other
  (`timestamp > lastSeen`). Its `timestamp` is set once per "update becomes
  available" transition: if `updateAvailable` stays true across polls, the
  store keeps the FIRST-seen timestamp for `synthetic:update` (don't
  re-stamp on every poll, or it would perpetually re-mark unread). Track
  this with a stored `updateFirstSeen` value.
- If `updateAvailable` flips back to false (operator upgraded), the
  synthetic item disappears from `recent` and `updateFirstSeen` resets.

This means: even a fresh install with **no alerting rules** still shows the
update notification in the panel — the zero-config guarantee is intact,
just relocated from the topbar dot into the sidebar panel.

---

## Data flow

```
     ┌──────────────────────────────────────┐   ┌───────────────────────────┐
     │ GET /observability/alert-events?limit=15 │ │ GET /system/version       │
     │        (existing, admin)             │   │ {updateAvailable,url,...} │
     └───────────────┬──────────────────────┘   └────────────┬──────────────┘
                     │ alertEventsStore.load()                │ systemApi.getVersion()
                     │ .events                                │
                     ▼                                        ▼
        ┌──────────────────────────────────────────────────────┐
        │ notifications.svelte.ts                               │
        │  synthetic update item (if updateAvailable) ───┐     │
        │  recent = [synthetic?, ...events].sort().slice(0,15) │
        │  unreadCount = recent items with ts > lastSeen       │
        │  lastSeen  ← localStorage 'arenet.notifications...'  │
        │  updateFirstSeen ← localStorage (stable synthetic ts)│
        └───────────────┬──────────────────────────────────────┘
                        │
                 NotificationBell.svelte
                 (sidebar entry + popover)
                        │  per-row
                        ▼
                 notificationHref(ev)
                   context.url → GitHub release (new tab)
                   else category/ruleName → /certs | /security | /settings | /
                   fallback → /alerting
```

## Error handling

- Fetch failure → `loadError` set by the store; panel shows inline error,
  bell shows no count (fails closed, never a misleading number).
- No events / no rules configured → empty state with CTA to `/alerting`.
- `context.url` present but malformed → still opens in a new tab; browser
  handles a bad URL. (We don't over-validate; the value is operator-trusted
  since it originates from our own update source.)
- localStorage unavailable (private mode / SSR) → unread bookkeeping
  degrades to "everything read" (count stays 0); panel still lists events.

## Testing (TDD)

Unit tests (vitest + @testing-library/svelte), each written failing-first:

1. **`notifications.svelte.ts`**
   - `unreadCount` counts only items strictly newer than `lastSeen`.
   - First visit (no localStorage key) → `unreadCount === 0` and `lastSeen`
     initialized to newest item's timestamp.
   - `markAllRead()` sets `lastSeen` to newest item timestamp, drops count
     to 0, and persists.
   - `recent` is capped at `PANEL_LIMIT` even when the store holds more.
   - localStorage-absent path does not throw (count 0).
   - **Synthetic update:** when `getVersion()` returns
     `updateAvailable: true`, `recent` includes a `synthetic:update` item
     with `context.url` = the release URL and subject naming `latest`.
   - `updateAvailable: false` → no synthetic item in `recent`.
   - Synthetic timestamp is stable across polls while the update stays
     available (`updateFirstSeen` not re-stamped) → it does not perpetually
     re-mark unread after being read.
   - A failed `getVersion()` does not throw and does not set `loadError`;
     alert events still populate `recent`.

2. **`notificationHref`**
   - `context.url` present → returns that URL, `external: true`.
   - `category`/`ruleName` containing `cert` → `/certs`; `waf` → `/security`;
     `update` (no url) → `/settings`; unknown → `/alerting`.

3. **`NotificationBell.svelte`**
   - Renders label + bell; badge hidden when `unreadCount === 0`, shown with
     the number when > 0, `99+` when > 99.
   - Opening the panel calls `load()` and (on close/markAllRead) resets the
     count.
   - Empty state renders the `/alerting` CTA when there are no events.
   - Escape and click-outside close the panel.

4. **i18n parity guard** (existing test) must stay green — new `notifications.*`
   keys present in both `en.json` and `fr.json`.

## Verification (runtime, per verify skill)

After implementation, build the frontend + run the binary, log in, and:
- Confirm the bell + label appears in the sidebar above the user block, and
  the topbar `UpdateBadge` (next to Gateway Healthy) is gone.
- **Zero-config update path:** with the update checker reporting an update
  but NO alerting rule configured, confirm the panel still shows the
  synthetic "Mise à jour disponible" notification and the count badge.
- With ≥1 alert event present (e.g. seed an alerting rule that fires),
  confirm the count badge appears and the panel lists the event.
- Click an `update_available` notification → new tab to the GitHub release
  URL from `context.url`.
- Click a non-update notification → lands on the mapped internal page (or
  `/alerting` fallback).
- "Tout marquer lu" → count resets; reload page → count stays 0 (localStorage
  persisted).

## Files summary

| Action | File |
| --- | --- |
| Create | `web/frontend/src/lib/stores/notifications.svelte.ts` |
| Create | `web/frontend/src/lib/components/NotificationBell.svelte` |
| Create | `web/frontend/src/lib/stores/notifications.test.ts` |
| Create | `web/frontend/src/lib/components/NotificationBell.test.ts` |
| Modify | `web/frontend/src/lib/components/Sidebar.svelte` (mount bell above foot) |
| Modify | `web/frontend/src/lib/components/Topbar.svelte` (remove `<UpdateBadge />` + import) |
| Delete | `web/frontend/src/lib/components/UpdateBadge.svelte` (only consumer is Topbar — confirmed) |
| Delete | `web/frontend/src/lib/components/UpdateBadge.test.ts` (exists — confirmed) |
| Modify | `web/frontend/src/lib/i18n/locales/en.json` (+`notifications.*`, −`topbar.updateAvailable`) |
| Modify | `web/frontend/src/lib/i18n/locales/fr.json` (+`notifications.*`, −`topbar.updateAvailable`) |

## Global constraints (from CLAUDE.md)

- AGPLv3 `//`-comment header on every new `.ts`/`.svelte` file.
- TypeScript strict mode; PascalCase component filenames; stores in
  `lib/stores/`; API access via the centralized client.
- All interactive elements have ARIA labels; all user-facing text via `t()`.
- No new CSS framework beyond Tailwind.
