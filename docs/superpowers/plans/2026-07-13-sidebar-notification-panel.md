# Sidebar Notification Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sidebar Notifications entry (bell + label + unread count) opening a panel of the 15 most recent alerting events plus a synthetic "update available" item, and remove the topbar `UpdateBadge`.

**Architecture:** Pure frontend. A new `notifications.svelte.ts` store layers over the existing `alertEventsStore` and also reads `/system/version` to synthesize an update notification; unread state lives in `localStorage`. A new `NotificationBell.svelte` renders the sidebar entry + popover. `Topbar.svelte` drops `UpdateBadge`, which is deleted.

**Tech Stack:** SvelteKit / Svelte 5 runes, TypeScript strict, Tailwind, vitest + @testing-library/svelte, i18n via `t()` with EN/FR bundles.

**Spec:** `docs/superpowers/specs/2026-07-13-sidebar-notification-panel-design.md`

## Global Constraints

- AGPLv3 3-line `//` header on every new `.ts`; HTML-comment AGPL header on every new `.svelte` (match `UpdateBadge.svelte` lines 1-4).
- TypeScript strict mode; PascalCase component filenames; stores in `lib/stores/`; API via the centralized client only.
- All interactive elements have ARIA labels; all user-facing text via `t()`.
- New i18n keys go in BOTH `en.json` and `fr.json` (parity guard test hard-fails otherwise).
- `PANEL_LIMIT = 15`. localStorage keys: `arenet.notifications.lastSeen`, `arenet.notifications.updateFirstSeen`. Synthetic item id: `synthetic:update`.
- Run frontend tests with: `cd web/frontend && npm run test -- <path>` (vitest).

---

### Task 1: i18n keys — add `notifications.*`, remove `topbar.updateAvailable`

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json`
- Modify: `web/frontend/src/lib/i18n/locales/fr.json`
- Test: `web/frontend/src/lib/i18n/parity.test.ts` (existing guard — do not edit, must stay green)

**Interfaces:**
- Produces: i18n keys consumed by Task 4/5 — `notifications.label`, `notifications.title`, `notifications.markAllRead`, `notifications.empty`, `notifications.emptyCta`, `notifications.viewAll`, `notifications.updateAvailable` (param `{version}`), `notifications.ariaOpen`, `notifications.ariaClose`, `notifications.loadError`.

- [ ] **Step 1: Locate the existing `topbar.updateAvailable` key and a good insertion anchor**

Run: `cd web/frontend && grep -n '"topbar"\|updateAvailable\|"notifications"' src/lib/i18n/locales/en.json`
Expected: shows the `topbar` object containing `updateAvailable`, and confirms no `notifications` top-level key exists yet.

- [ ] **Step 2: Add the `notifications` block and remove `topbar.updateAvailable` in `en.json`**

Remove the `"updateAvailable": "..."` line from the `topbar` object. Add a new top-level `notifications` object (alphabetical placement near other top-level keys is fine; match surrounding indentation):

```json
"notifications": {
  "label": "Notifications",
  "title": "Notifications",
  "markAllRead": "Mark all read",
  "empty": "No notifications",
  "emptyCta": "Set up alerts in Alerting →",
  "viewAll": "View all in Alerting →",
  "updateAvailable": "Update {version} available",
  "ariaOpen": "Open notifications",
  "ariaClose": "Close notifications",
  "loadError": "Could not load notifications"
}
```

- [ ] **Step 3: Mirror the exact same changes in `fr.json`**

Remove `topbar.updateAvailable`. Add:

```json
"notifications": {
  "label": "Notifications",
  "title": "Notifications",
  "markAllRead": "Tout marquer lu",
  "empty": "Aucune notification",
  "emptyCta": "Configurer des alertes dans Alerting →",
  "viewAll": "Voir tout dans Alerting →",
  "updateAvailable": "Mise à jour {version} disponible",
  "ariaOpen": "Ouvrir les notifications",
  "ariaClose": "Fermer les notifications",
  "loadError": "Impossible de charger les notifications"
}
```

- [ ] **Step 4: Run the i18n parity guard + JSON validity**

Run: `cd web/frontend && npm run test -- src/lib/i18n/parity.test.ts`
Expected: PASS (both bundles have identical key sets; `topbar.updateAvailable` removed from both, `notifications.*` present in both).

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "i18n(notifications): add notifications.* keys, drop topbar.updateAvailable"
```

---

### Task 2: `notificationHref` — contextual navigation helper

**Files:**
- Create: `web/frontend/src/lib/utils/notification-href.ts`
- Test: `web/frontend/src/lib/utils/notification-href.test.ts`

**Interfaces:**
- Consumes: `AlertEvent` from `$lib/api/alerting`.
- Produces: `notificationHref(ev: AlertEvent): { href: string; external: boolean }` — used by Task 4.

- [ ] **Step 1: Write the failing test**

`web/frontend/src/lib/utils/notification-href.test.ts`:

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect } from 'vitest';
import { notificationHref } from './notification-href';
import type { AlertEvent } from '$lib/api/alerting';

function ev(over: Partial<AlertEvent> = {}): AlertEvent {
	return {
		eventId: 'e1', timestamp: '2026-07-13T10:00:00Z', ruleId: 'r1',
		ruleName: 'rule', severity: 0, category: '', subject: 's',
		channelsFired: [], ...over
	};
}

describe('notificationHref', () => {
	it('uses context.url as an external link when present', () => {
		const r = notificationHref(ev({ context: { url: 'https://github.com/x/releases/v1' } }));
		expect(r).toEqual({ href: 'https://github.com/x/releases/v1', external: true });
	});
	it('routes cert events to /certs', () => {
		expect(notificationHref(ev({ category: 'cert_expiry' })).href).toBe('/certs');
	});
	it('routes waf events to /security', () => {
		expect(notificationHref(ev({ category: 'waf' })).href).toBe('/security');
	});
	it('routes update events (no url) to /settings', () => {
		expect(notificationHref(ev({ ruleName: 'update available' })).href).toBe('/settings');
	});
	it('routes system_health events to /', () => {
		expect(notificationHref(ev({ category: 'system_health' })).href).toBe('/');
	});
	it('falls back to /alerting for unknown categories', () => {
		expect(notificationHref(ev({ category: 'mystery' })).href).toBe('/alerting');
	});
	it('internal links are not external', () => {
		expect(notificationHref(ev({ category: 'cert_expiry' })).external).toBe(false);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web/frontend && npm run test -- src/lib/utils/notification-href.test.ts`
Expected: FAIL — "Cannot find module './notification-href'".

- [ ] **Step 3: Write minimal implementation**

`web/frontend/src/lib/utils/notification-href.ts`:

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { AlertEvent } from '$lib/api/alerting';

// notificationHref derives the click destination for a notification.
// context.url (set by the update source) wins as an external link;
// otherwise a coarse category/ruleName heuristic maps to an internal
// page, with a safe /alerting fallback (never a dead link).
export function notificationHref(ev: AlertEvent): { href: string; external: boolean } {
	const url = ev.context?.url;
	if (typeof url === 'string' && url.length > 0) {
		return { href: url, external: true };
	}
	const hay = `${ev.category ?? ''} ${ev.ruleName ?? ''}`.toLowerCase();
	let href = '/alerting';
	if (hay.includes('cert')) href = '/certs';
	else if (hay.includes('waf') || hay.includes('security')) href = '/security';
	else if (hay.includes('update')) href = '/settings';
	else if (hay.includes('health') || hay.includes('system')) href = '/';
	return { href, external: false };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web/frontend && npm run test -- src/lib/utils/notification-href.test.ts`
Expected: PASS (all 7 assertions).

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/utils/notification-href.ts web/frontend/src/lib/utils/notification-href.test.ts
git commit -m "feat(notifications): add notificationHref contextual nav helper"
```

---

### Task 3: `notifications.svelte.ts` store (unread + synthetic update)

**Files:**
- Create: `web/frontend/src/lib/stores/notifications.svelte.ts`
- Test: `web/frontend/src/lib/stores/notifications.test.ts`

**Interfaces:**
- Consumes: `alertEventsStore` (`.load(filter,reset)`, `.events`, `.loading`, `.loadError`) from `$lib/stores/alerting.svelte`; `systemApi.getVersion()` → `SystemVersion { current, latest, updateAvailable, url }` from `$lib/api/system`; `AlertEvent` type.
- Produces: `notificationsStore` with `recent: AlertEvent[]`, `unreadCount: number`, `lastSeen: string`, `loading: boolean`, `loadError: string`, `load(): Promise<void>`, `markAllRead(): void`. Consumed by Task 4. Constant `PANEL_LIMIT = 15` and synthetic id `SYNTHETIC_UPDATE_ID = 'synthetic:update'` exported for the component + tests.

- [ ] **Step 1: Write the failing test**

`web/frontend/src/lib/stores/notifications.test.ts`. Mock both dependencies (mirror `UpdateBadge.test.ts`'s `vi.hoisted` + `vi.mock` pattern) and a localStorage stub:

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AlertEvent } from '$lib/api/alerting';

const { alertMock, systemMock } = vi.hoisted(() => ({
	alertMock: { load: vi.fn(), state: { events: [] as AlertEvent[], loading: false, loadError: '' } },
	systemMock: { getVersion: vi.fn() }
}));
vi.mock('$lib/stores/alerting.svelte', () => ({
	alertEventsStore: {
		load: (...a: unknown[]) => alertMock.load(...a),
		get events() { return alertMock.state.events; },
		get loading() { return alertMock.state.loading; },
		get loadError() { return alertMock.state.loadError; }
	}
}));
vi.mock('$lib/api/system', () => ({
	systemApi: { getVersion: (...a: unknown[]) => systemMock.getVersion(...a) }
}));

function evt(ts: string, over: Partial<AlertEvent> = {}): AlertEvent {
	return { eventId: ts, timestamp: ts, ruleId: 'r', ruleName: 'n', severity: 0,
		category: 'c', subject: 's', channelsFired: [], ...over };
}
function version(over: Record<string, unknown> = {}) {
	return { current: 'v1', latest: 'v2', updateAvailable: false, url: 'https://x/v2', ...over };
}

beforeEach(() => {
	localStorage.clear();
	alertMock.load.mockReset().mockResolvedValue(undefined);
	alertMock.state = { events: [], loading: false, loadError: '' };
	systemMock.getVersion.mockReset().mockResolvedValue(version());
});

// import fresh each test so store module state resets
async function freshStore() {
	vi.resetModules();
	return (await import('./notifications.svelte')).notificationsStore;
}

describe('notificationsStore', () => {
	it('first visit initializes lastSeen to newest event → unreadCount 0', async () => {
		alertMock.state.events = [evt('2026-07-13T10:00:00Z'), evt('2026-07-13T09:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(0);
	});

	it('counts events strictly newer than a stored lastSeen', async () => {
		localStorage.setItem('arenet.notifications.lastSeen', '2026-07-13T09:30:00Z');
		alertMock.state.events = [evt('2026-07-13T10:00:00Z'), evt('2026-07-13T09:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(1);
	});

	it('markAllRead resets unreadCount to 0 and persists', async () => {
		localStorage.setItem('arenet.notifications.lastSeen', '2026-07-13T00:00:00Z');
		alertMock.state.events = [evt('2026-07-13T10:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.unreadCount).toBe(1);
		s.markAllRead();
		expect(s.unreadCount).toBe(0);
		expect(localStorage.getItem('arenet.notifications.lastSeen')).toBe('2026-07-13T10:00:00Z');
	});

	it('caps recent at PANEL_LIMIT', async () => {
		alertMock.state.events = Array.from({ length: 30 }, (_, i) =>
			evt(`2026-07-13T${String(10 + Math.floor(i / 60)).padStart(2, '0')}:${String(i % 60).padStart(2, '0')}:00Z`));
		const s = await freshStore();
		await s.load();
		expect(s.recent.length).toBe(15);
	});

	it('injects a synthetic update item when updateAvailable', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: true, latest: 'v2.12.6', url: 'https://x/v2.12.6' }));
		const s = await freshStore();
		await s.load();
		const synth = s.recent.find((e) => e.eventId === 'synthetic:update');
		expect(synth).toBeTruthy();
		expect(synth?.context?.url).toBe('https://x/v2.12.6');
	});

	it('no synthetic item when updateAvailable is false', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: false }));
		const s = await freshStore();
		await s.load();
		expect(s.recent.find((e) => e.eventId === 'synthetic:update')).toBeFalsy();
	});

	it('keeps synthetic timestamp stable across polls (no perpetual unread)', async () => {
		systemMock.getVersion.mockResolvedValue(version({ updateAvailable: true }));
		const s = await freshStore();
		await s.load();
		const first = s.recent.find((e) => e.eventId === 'synthetic:update')?.timestamp;
		s.markAllRead();
		await s.load(); // second poll, still available
		const second = s.recent.find((e) => e.eventId === 'synthetic:update')?.timestamp;
		expect(second).toBe(first);
		expect(s.unreadCount).toBe(0);
	});

	it('swallows a failed getVersion without setting loadError', async () => {
		systemMock.getVersion.mockRejectedValue(new Error('boom'));
		alertMock.state.events = [evt('2026-07-13T10:00:00Z')];
		const s = await freshStore();
		await s.load();
		expect(s.loadError).toBe('');
		expect(s.recent.length).toBe(1);
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web/frontend && npm run test -- src/lib/stores/notifications.test.ts`
Expected: FAIL — "Cannot find module './notifications.svelte'".

- [ ] **Step 3: Write minimal implementation**

`web/frontend/src/lib/stores/notifications.svelte.ts`:

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Notification panel state. Layers over alertEventsStore (rule-driven
// alert history) and adds a synthetic "update available" item read
// directly from /system/version so the update signal survives with
// zero alerting config. Unread is tracked in localStorage.

import { alertEventsStore } from '$lib/stores/alerting.svelte';
import type { AlertEvent } from '$lib/api/alerting';
import { systemApi } from '$lib/api/system';

export const PANEL_LIMIT = 15;
export const SYNTHETIC_UPDATE_ID = 'synthetic:update';

const LAST_SEEN_KEY = 'arenet.notifications.lastSeen';
const UPDATE_FIRST_SEEN_KEY = 'arenet.notifications.updateFirstSeen';

function lsGet(key: string): string {
	if (typeof localStorage === 'undefined') return '';
	try { return localStorage.getItem(key) ?? ''; } catch { return ''; }
}
function lsSet(key: string, val: string): void {
	if (typeof localStorage === 'undefined') return;
	try { localStorage.setItem(key, val); } catch { /* ignore */ }
}
function lsDel(key: string): void {
	if (typeof localStorage === 'undefined') return;
	try { localStorage.removeItem(key); } catch { /* ignore */ }
}

interface NotifState {
	lastSeen: string;
	updateItem: AlertEvent | null;
	initialized: boolean;
}

function createNotificationsStore() {
	const state = $state<NotifState>({
		lastSeen: lsGet(LAST_SEEN_KEY),
		updateItem: null,
		initialized: false
	});

	const recent = $derived.by<AlertEvent[]>(() => {
		const events = alertEventsStore.events.slice(0, PANEL_LIMIT);
		const merged = state.updateItem ? [state.updateItem, ...events] : events;
		return merged
			.slice()
			.sort((a, b) => (a.timestamp < b.timestamp ? 1 : a.timestamp > b.timestamp ? -1 : 0))
			.slice(0, PANEL_LIMIT);
	});

	const unreadCount = $derived(
		recent.filter((e) => e.timestamp > state.lastSeen).length
	);

	function newestTimestamp(): string {
		return recent.length > 0 ? recent[0].timestamp : new Date().toISOString();
	}

	async function refreshUpdateItem(): Promise<void> {
		try {
			const v = await systemApi.getVersion();
			if (v.updateAvailable) {
				let firstSeen = lsGet(UPDATE_FIRST_SEEN_KEY);
				if (!firstSeen) {
					firstSeen = new Date().toISOString();
					lsSet(UPDATE_FIRST_SEEN_KEY, firstSeen);
				}
				state.updateItem = {
					eventId: SYNTHETIC_UPDATE_ID,
					timestamp: firstSeen,
					ruleId: '',
					ruleName: 'update available',
					severity: 0,
					category: 'update',
					subject: '', // rendered by the component via i18n with v.latest
					context: { url: v.url, version: v.latest },
					channelsFired: []
				};
			} else {
				state.updateItem = null;
				lsDel(UPDATE_FIRST_SEEN_KEY);
			}
		} catch {
			// Swallow — a version-check failure must not break the panel.
		}
	}

	async function load(): Promise<void> {
		await Promise.all([
			alertEventsStore.load({ limit: PANEL_LIMIT }, true),
			refreshUpdateItem()
		]);
		if (!state.initialized && !lsGet(LAST_SEEN_KEY)) {
			// First-ever visit: treat existing items as read.
			state.lastSeen = newestTimestamp();
			lsSet(LAST_SEEN_KEY, state.lastSeen);
		}
		state.initialized = true;
	}

	function markAllRead(): void {
		state.lastSeen = newestTimestamp();
		lsSet(LAST_SEEN_KEY, state.lastSeen);
	}

	return {
		get recent() { return recent; },
		get unreadCount() { return unreadCount; },
		get lastSeen() { return state.lastSeen; },
		get loading() { return alertEventsStore.loading; },
		get loadError() { return alertEventsStore.loadError; },
		load,
		markAllRead
	};
}

export const notificationsStore = createNotificationsStore();
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web/frontend && npm run test -- src/lib/stores/notifications.test.ts`
Expected: PASS (all 8 tests). If the "first visit" test fails because `lastSeen` is read once at module load, confirm `freshStore()`'s `vi.resetModules()` re-imports — the store reads `lsGet` at construction, so a cleared localStorage yields `''` and the `load()` init path runs.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/stores/notifications.svelte.ts web/frontend/src/lib/stores/notifications.test.ts
git commit -m "feat(notifications): store with unread tracking + synthetic update item"
```

---

### Task 4: `NotificationBell.svelte` component

**Files:**
- Create: `web/frontend/src/lib/components/NotificationBell.svelte`
- Test: `web/frontend/src/lib/components/NotificationBell.test.ts`

**Interfaces:**
- Consumes: `notificationsStore` (Task 3), `notificationHref` (Task 2), `relativeTime` from `$lib/utils/audit-format`, `t` from `$lib/i18n`, `language` from `$lib/stores/language.svelte`.
- Produces: default-exported Svelte component `NotificationBell`, mounted by Task 5.

- [ ] **Step 1: Write the failing test**

`web/frontend/src/lib/components/NotificationBell.test.ts`. Mock the store so tests control `recent`/`unreadCount`:

```ts
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
import type { AlertEvent } from '$lib/api/alerting';

const { store } = vi.hoisted(() => ({
	store: {
		recent: [] as AlertEvent[],
		unreadCount: 0,
		loading: false,
		loadError: '',
		load: vi.fn().mockResolvedValue(undefined),
		markAllRead: vi.fn()
	}
}));
vi.mock('$lib/stores/notifications.svelte', () => ({
	notificationsStore: store,
	PANEL_LIMIT: 15,
	SYNTHETIC_UPDATE_ID: 'synthetic:update'
}));

import NotificationBell from './NotificationBell.svelte';

function evt(over: Partial<AlertEvent> = {}): AlertEvent {
	return { eventId: 'e', timestamp: '2026-07-13T10:00:00Z', ruleId: 'r', ruleName: 'n',
		severity: 0, category: 'c', subject: 'Something happened', channelsFired: [], ...over };
}

beforeEach(() => {
	store.recent = [];
	store.unreadCount = 0;
	store.loading = false;
	store.loadError = '';
	store.load.mockClear();
	store.markAllRead.mockClear();
});

describe('NotificationBell', () => {
	it('renders the label and no badge when unreadCount is 0', () => {
		const { getByText, queryByTestId } = render(NotificationBell);
		expect(getByText('Notifications')).toBeTruthy();
		expect(queryByTestId('notif-count')).toBeNull();
	});

	it('shows the count badge when unreadCount > 0', () => {
		store.unreadCount = 3;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('3');
	});

	it('caps the badge at 99+', () => {
		store.unreadCount = 150;
		const { getByTestId } = render(NotificationBell);
		expect(getByTestId('notif-count').textContent).toContain('99+');
	});

	it('calls load() when the panel opens', async () => {
		const { getByTestId } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		await waitFor(() => expect(store.load).toHaveBeenCalled());
	});

	it('renders the empty-state CTA when there are no items', async () => {
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Set up alerts in Alerting →')).toBeTruthy();
	});

	it('lists items and marks all read on button click', async () => {
		store.recent = [evt({ subject: 'Cert expiring' })];
		store.unreadCount = 1;
		const { getByTestId, getByText } = render(NotificationBell);
		await fireEvent.click(getByTestId('notif-trigger'));
		expect(getByText('Cert expiring')).toBeTruthy();
		await fireEvent.click(getByTestId('notif-markread'));
		expect(store.markAllRead).toHaveBeenCalled();
	});
});
```

Note: the test default locale is **`en`** (`language.svelte.ts:33` — `current = $state<Language>('en')`), so assertions use EN strings. "Notifications" is identical in both bundles; the empty-CTA asserts the EN "Set up alerts in Alerting →".

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web/frontend && npm run test -- src/lib/components/NotificationBell.test.ts`
Expected: FAIL — "Cannot find module './NotificationBell.svelte'".

- [ ] **Step 3: Write minimal implementation**

`web/frontend/src/lib/components/NotificationBell.svelte`:

```svelte
<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sidebar notification entry (bell + label + unread count) with a
  popover listing the most recent alert events plus a synthetic
  update item. Reads notificationsStore; unread via localStorage.
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { notificationsStore, SYNTHETIC_UPDATE_ID } from '$lib/stores/notifications.svelte';
	import { notificationHref } from '$lib/utils/notification-href';
	import { relativeTime } from '$lib/utils/audit-format';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import type { AlertEvent } from '$lib/api/alerting';

	let open = $state(false);
	let triggerEl = $state<HTMLButtonElement | null>(null);
	let panelEl = $state<HTMLDivElement | null>(null);

	const count = $derived(notificationsStore.unreadCount);
	const badge = $derived(count > 99 ? '99+' : String(count));

	function subjectOf(ev: AlertEvent): string {
		if (ev.eventId === SYNTHETIC_UPDATE_ID) {
			const version = (ev.context?.version as string) ?? '';
			return (language.current && t('notifications.updateAvailable', { version })) as string;
		}
		return ev.subject;
	}

	function isUnread(ev: AlertEvent): boolean {
		return ev.timestamp > notificationsStore.lastSeen;
	}

	async function toggle(): Promise<void> {
		open = !open;
		if (open) await notificationsStore.load();
	}
	function close(): void {
		open = false;
		triggerEl?.focus();
	}
	function markRead(): void {
		notificationsStore.markAllRead();
	}

	function onKey(e: KeyboardEvent): void {
		if (e.key === 'Escape' && open) close();
	}
	function onClickOutside(e: MouseEvent): void {
		if (!open) return;
		const target = e.target as Node;
		if (panelEl?.contains(target) || triggerEl?.contains(target)) return;
		open = false;
	}

	onMount(() => {
		notificationsStore.load();
		document.addEventListener('keydown', onKey);
		document.addEventListener('click', onClickOutside, true);
	});
	onDestroy(() => {
		if (typeof document === 'undefined') return;
		document.removeEventListener('keydown', onKey);
		document.removeEventListener('click', onClickOutside, true);
	});
</script>

<div class="notif-wrap">
	<button
		bind:this={triggerEl}
		type="button"
		class="notif-trigger"
		data-testid="notif-trigger"
		aria-haspopup="dialog"
		aria-expanded={open}
		aria-label={language.current && t('notifications.ariaOpen')}
		onclick={toggle}
	>
		<span class="bell" aria-hidden="true">
			<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
				<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" stroke-linecap="round" stroke-linejoin="round" />
				<path d="M13.73 21a2 2 0 0 1-3.46 0" stroke-linecap="round" stroke-linejoin="round" />
			</svg>
		</span>
		<span class="label">{language.current && t('notifications.label')}</span>
		{#if count > 0}
			<span class="count" data-testid="notif-count">{badge}</span>
		{/if}
	</button>

	{#if open}
		<div class="panel" bind:this={panelEl} role="dialog" aria-label={language.current && t('notifications.title')}>
			<div class="panel-head">
				<b>{language.current && t('notifications.title')}</b>
				<button
					type="button"
					class="markread"
					data-testid="notif-markread"
					disabled={count === 0}
					onclick={markRead}
				>{language.current && t('notifications.markAllRead')}</button>
			</div>

			{#if notificationsStore.loadError}
				<div class="panel-msg error">{language.current && t('notifications.loadError')}</div>
			{:else if notificationsStore.recent.length === 0}
				<div class="panel-empty">
					<p>{language.current && t('notifications.empty')}</p>
					<a href="/alerting" onclick={close}>{language.current && t('notifications.emptyCta')}</a>
				</div>
			{:else}
				<ul class="panel-list">
					{#each notificationsStore.recent as ev (ev.eventId)}
						{@const dest = notificationHref(ev)}
						<li class:unread={isUnread(ev)}>
							<a
								href={dest.href}
								target={dest.external ? '_blank' : undefined}
								rel={dest.external ? 'noopener noreferrer' : undefined}
								onclick={close}
							>
								<span class="subject">{subjectOf(ev)}</span>
								<span class="meta">{language.current && relativeTime(ev.timestamp)}</span>
							</a>
						</li>
					{/each}
				</ul>
				<div class="panel-foot">
					<a href="/alerting" onclick={close}>{language.current && t('notifications.viewAll')}</a>
				</div>
			{/if}
		</div>
	{/if}
</div>

<style>
	.notif-wrap { position: relative; }
	.notif-trigger {
		display: flex; align-items: center; gap: 10px; width: 100%;
		padding: 8px 16px; font-size: 13px; color: var(--fg-muted);
		background: none; border: none; cursor: pointer; text-align: left;
	}
	.notif-trigger:hover { color: var(--fg); }
	.bell { position: relative; display: inline-flex; }
	.label { flex: 1; }
	.count {
		background: var(--danger, #d9534f); color: #fff; font-size: 10.5px;
		font-weight: 700; border-radius: 20px; padding: 1px 7px; min-width: 16px;
		text-align: center;
	}
	.panel {
		position: absolute; bottom: 100%; left: 8px; width: 300px;
		background: var(--bg-elevated, #12161d); border: 1px solid var(--border);
		border-radius: 10px; margin-bottom: 8px; z-index: 20; overflow: hidden;
	}
	.panel-head {
		display: flex; align-items: center; justify-content: space-between;
		padding: 10px 14px; border-bottom: 1px solid var(--border);
	}
	.panel-head b { color: var(--fg); font-size: 13.5px; }
	.markread { background: none; border: none; color: var(--accent); font-size: 11px; cursor: pointer; }
	.markread:disabled { color: var(--fg-muted); cursor: default; }
	.panel-list { list-style: none; margin: 0; padding: 0; max-height: 320px; overflow-y: auto; }
	.panel-list li a {
		display: flex; flex-direction: column; gap: 2px; padding: 10px 14px;
		border-bottom: 1px solid var(--border-subtle, #1c222c); text-decoration: none; color: var(--fg-muted);
	}
	.panel-list li.unread a { color: var(--fg); border-left: 2px solid var(--accent); }
	.subject { font-size: 12.5px; color: var(--fg); }
	.meta { font-size: 11px; color: var(--fg-muted); }
	.panel-empty { padding: 18px 14px; text-align: center; font-size: 12.5px; color: var(--fg-muted); }
	.panel-empty a, .panel-foot a { color: var(--accent); font-size: 11.5px; text-decoration: none; }
	.panel-foot { padding: 10px 14px; border-top: 1px solid var(--border); text-align: center; }
	.panel-msg.error { padding: 14px; font-size: 12px; color: var(--danger, #d9534f); }
</style>
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web/frontend && npm run test -- src/lib/components/NotificationBell.test.ts`
Expected: PASS (6 tests). If i18n default locale mismatches the asserted strings, fix the test assertions to the actual default (see the note in Step 1).

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/NotificationBell.svelte web/frontend/src/lib/components/NotificationBell.test.ts
git commit -m "feat(notifications): NotificationBell sidebar entry + popover panel"
```

---

### Task 5: Mount in `Sidebar.svelte`; remove `UpdateBadge` from `Topbar.svelte`

**Files:**
- Modify: `web/frontend/src/lib/components/Sidebar.svelte` (insert `<NotificationBell />` before `.sidebar-foot`, ~line 265)
- Modify: `web/frontend/src/lib/components/Topbar.svelte` (remove `<UpdateBadge />` at line 105 + its import)
- Delete: `web/frontend/src/lib/components/UpdateBadge.svelte`
- Delete: `web/frontend/src/lib/components/UpdateBadge.test.ts`

**Interfaces:**
- Consumes: `NotificationBell` (Task 4).

- [ ] **Step 1: Confirm `UpdateBadge` has no consumer other than Topbar**

Run: `cd web/frontend && grep -rln UpdateBadge src | grep -v 'UpdateBadge.svelte\|UpdateBadge.test'`
Expected: only `src/lib/components/Topbar.svelte`. (If anything else appears, STOP — keep the file and only remove the Topbar usage; adjust this task.)

- [ ] **Step 2: Insert `<NotificationBell />` into `Sidebar.svelte`**

Add the import to the `<script>` block (alongside other component imports):

```ts
import NotificationBell from './NotificationBell.svelte';
```

Insert the component immediately before the `.sidebar-foot` div (currently line 265):

```svelte
	<NotificationBell />

	<div class="sidebar-foot">
```

- [ ] **Step 3: Remove `UpdateBadge` from `Topbar.svelte`**

Delete the import line `import UpdateBadge from './UpdateBadge.svelte';` and the `<UpdateBadge />` line (line 105, inside `.tb-status`). Leave the status dot + `statusHealthy` span intact.

- [ ] **Step 4: Delete the `UpdateBadge` files**

```bash
git rm web/frontend/src/lib/components/UpdateBadge.svelte web/frontend/src/lib/components/UpdateBadge.test.ts
```

- [ ] **Step 5: Typecheck + full frontend test run**

Run: `cd web/frontend && npm run check && npm run test`
Expected: no TypeScript errors (no dangling `UpdateBadge` / `topbar.updateAvailable` references); all tests pass, parity guard green.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/lib/components/Sidebar.svelte web/frontend/src/lib/components/Topbar.svelte
git commit -m "feat(notifications): mount sidebar bell, remove topbar UpdateBadge"
```

---

### Task 6: Runtime verification (verify skill)

**Files:** none (observation only).

- [ ] **Step 1: Build the frontend + binary**

Run: `cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet`
Expected: clean build; `web/build` embedded.

- [ ] **Step 2: Run and drive the UI**

Run `./arenet`, log in, and confirm against the spec's Verification section:
- Sidebar shows the bell + "Notifications" above the user block; topbar `UpdateBadge` (next to Gateway Healthy) is gone.
- Zero-config update path: with the update checker reporting an update and NO alerting rule, the panel shows the synthetic "Mise à jour disponible" item + count badge.
- Click the update item → new tab to the GitHub release (`context.url`).
- Click a non-update item → mapped internal page or `/alerting` fallback.
- "Tout marquer lu" resets the count; reload → count stays 0 (localStorage).

- [ ] **Step 3: Capture evidence + report PASS/FAIL** per the verify skill (screenshot of the sidebar panel open).

---

## Self-Review

**Spec coverage:** §1 data source → Task 3 (store over alertEventsStore). §2.1 store → Task 3. §2.2 notificationHref → Task 2. §2.3 NotificationBell → Task 4. §2.4 Sidebar mount → Task 5. §2.5 remove UpdateBadge → Task 5. §2.6 synthetic update → Task 3. i18n → Task 1. Testing → Tasks 2-4. Verification → Task 6. All covered.

**Placeholder scan:** No TBD/TODO; every code step has full code. The only conditional is Task 4 Step 1's i18n-default note (EN vs FR assertions) — resolved by checking a sibling test at implementation time, not a placeholder.

**Type consistency:** `notificationsStore` surface (`recent`, `unreadCount`, `lastSeen`, `loading`, `loadError`, `load`, `markAllRead`) identical across Tasks 3/4. `notificationHref` signature identical Tasks 2/4. `SYNTHETIC_UPDATE_ID = 'synthetic:update'` consistent Tasks 3/4. `PANEL_LIMIT = 15` consistent. i18n keys defined in Task 1 match those consumed in Task 4.
