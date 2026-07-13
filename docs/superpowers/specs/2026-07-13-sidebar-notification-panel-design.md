# Sidebar Notification Panel — Design

**Date:** 2026-07-13
**Status:** Approved (design sections 1 & 2 validated by operator)
**Milestone target:** v2.12.6

## Goal

Add a dedicated **sidebar notification entry** (bell icon + "Notifications"
label + unread count), placed just above the user/logout footer block.
Clicking it opens a panel listing the most recent alerting events, with
per-notification contextual navigation. The existing topbar `UpdateBadge`
stays (see §2.5) — this is an addition, not a move.

## Motivation

- Notifications currently have no first-class home in the nav. The only
  topbar signal is `UpdateBadge` — a discreet, update-only dot next to the
  "Gateway Healthy" pill — which the operator found easy to miss and too
  narrow (updates only).
- The update-checker work (v2.12.3–v2.12.5) added `update_available` as an
  alerting source. Operators need a visible place where alert events
  (updates, cert expiry, WAF spikes…) surface at a glance, with a jump-off
  to the relevant page.
- The panel is rule-driven (alerting history); `UpdateBadge` remains the
  always-on, zero-config update indicator. The two are complementary — see
  the §2.5 comparison table.

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

Public surface:
- `recent: AlertEvent[]` — `$derived` slice of `alertEventsStore.events`
  capped at `PANEL_LIMIT` (the store may hold more from other views).
- `unreadCount: number` — `$derived`; events with `timestamp > lastSeen`.
- `lastSeen: string` — the persisted RFC-3339 marker (localStorage-backed).
- `load(): Promise<void>` — calls
  `alertEventsStore.load({ limit: PANEL_LIMIT }, true)`.
- `markAllRead(): void` — sets `lastSeen` to the newest event's timestamp
  (or client "now" if list empty), persists to localStorage.
- `loading: boolean`, `loadError: string` — re-exposed from
  `alertEventsStore` state for the panel's loading/error UI.

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
  `en.json` and `fr.json` (parity guard test enforces both exist).

### 2.4 Modified: `Sidebar.svelte`

`web/frontend/src/lib/components/Sidebar.svelte`

- Insert `<NotificationBell />` immediately **before** the `.sidebar-foot`
  block (the avatar/username/logout row, ~line 265).

### 2.5 The topbar `UpdateBadge` — keep, don't delete

The "petite cloche à côté de Gateway Healthy" the operator referred to is
**`UpdateBadge.svelte`** (`Topbar.svelte:105`, shipped v2.12.3). It is NOT
a notification center — it is a discreet, **zero-config** update indicator
that reads `GET /api/v1/system/version` directly and renders only when
`updateAvailable` is true, linking to the GitHub release.

**Decision: keep `UpdateBadge` in the topbar; do not remove it.** Rationale
— the two surfaces have different guarantees and are complementary, not
redundant:

| | `UpdateBadge` (topbar) | Notification panel (sidebar) |
| --- | --- | --- |
| Source | `GET /system/version` (direct) | alerting history (`alert-events`) |
| Config required | **none** — works out of the box | requires an `update_available` **rule** |
| Scope | update availability only | all alert events (updates, certs, WAF…) |

Deleting `UpdateBadge` would regress operators who have the update checker
enabled but **no alerting rule** configured — they'd lose their update
indicator entirely. The sidebar panel does not replace that guarantee
(it's rule-driven). So both coexist: `UpdateBadge` is the always-on "an
update exists" dot; the sidebar panel is the richer, rule-driven event
feed. This also keeps the change surgical (pure addition to the sidebar,
no topbar edit).

> If the operator later wants the topbar badge gone for visual reasons,
> that's a trivial follow-up — but it's a deliberate UX call, not a
> mechanical cleanup, so it's out of scope here.

---

## Data flow

```
                    ┌─────────────────────────────────────────┐
                    │ GET /api/v1/observability/alert-events   │
                    │        ?limit=15   (existing, admin)     │
                    └───────────────────┬──────────────────────┘
                                        │
                        alertingApi.listAlertEvents()
                                        │
                              alertEventsStore.load()
                                        │  .events
                                        ▼
        ┌──────────────────────────────────────────────────────┐
        │ notifications.svelte.ts                               │
        │  recent = events.slice(0, 15)   (derived)            │
        │  unreadCount = events > lastSeen (derived)           │
        │  lastSeen  ← localStorage 'arenet.notifications...'  │
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
   - `unreadCount` counts only events strictly newer than `lastSeen`.
   - First visit (no localStorage key) → `unreadCount === 0` and `lastSeen`
     initialized to newest event's timestamp.
   - `markAllRead()` sets `lastSeen` to newest event timestamp, drops count
     to 0, and persists.
   - `recent` is capped at `PANEL_LIMIT` even when the store holds more.
   - localStorage-absent path does not throw (count 0).

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
  the old topbar bell is gone.
- With ≥1 alert event present (e.g. trigger/seed an `update_available` or
  any rule), confirm the count badge appears and the panel lists it.
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
| Modify | `web/frontend/src/lib/i18n/locales/en.json` (+`notifications.*`) |
| Modify | `web/frontend/src/lib/i18n/locales/fr.json` (+`notifications.*`) |

## Global constraints (from CLAUDE.md)

- AGPLv3 `//`-comment header on every new `.ts`/`.svelte` file.
- TypeScript strict mode; PascalCase component filenames; stores in
  `lib/stores/`; API access via the centralized client.
- All interactive elements have ARIA labels; all user-facing text via `t()`.
- No new CSS framework beyond Tailwind.
