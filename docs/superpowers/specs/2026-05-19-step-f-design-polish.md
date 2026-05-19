<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step F — UI Design System Polish + Topology Refonte

## 1.1 Goal

Transform Arenet from a *functional* admin panel (delivered by Steps
A → E) into a **polished product UI** with the visual density,
precision and motion typical of modern technical dashboards (Linear,
Vercel, Resend). Step F is a full-surface design pass: every page
(Login, Setup, Routes, Audit, Topology, Settings) receives a
coordinated refonte against a coherent token system, the topology
view is rebuilt on top of `@xyflow/svelte`, and a server-persisted
light/dark theme toggle lands.

Step F also clears two cosmetic regressions identified during the
v0.3.0-step-e smoke session and pays down the Phase 2 debt on
Svelte component tests.

Predecessors:
- v0.3.0-step-e closed at HEAD `5916045` (smoke doc + tag).
- v0.2.0-step-d closed the auth + audit foundation.

Successors planned:
- Step G — Coraza WAF integration
- Step H — CrowdSec IP reputation
- Step D2 / D3 — multi-user, SSO

## 1.2 Scope

Step F delivers end-to-end:

- **Design system foundation** — a single CSS-variable token system
  for `dark` and `light` modes covering backgrounds, surfaces,
  borders, text levels, accents, status colors, spacing, radii,
  shadows and motion. Tokens are the *only* color / spacing /
  motion values referenced by components; magic numbers in
  component styles are removed.

- **Typography** — Inter (already shipped) for UI; **Geist Mono**
  added for code, route IDs, UUIDs, JSON payloads, timestamps.
  Two new `@font-face` declarations + corresponding Tailwind /
  CSS-var bindings.

- **Light / dark mode** — runtime toggle from a Settings →
  Appearance control. Preference persisted on the server side
  as a column on the existing per-user `User` record (NOT a
  global app-config table), even though Step F is still
  single-admin. The per-user storage shape forward-compats Step
  D2 (multi-user) without a migration — when a second admin
  lands, their preference rides on their own `User` row.
  Loaded by `auth.bootstrap` so the page boots with the right
  theme — no flash of unstyled content (FOUC).

- **Sidebar / topbar refonte** — current `Sidebar.svelte` becomes a
  denser navigation column with icon glyphs, hover affordances,
  collapsed-state pinning, and a footer block carrying user
  identity + connection indicator. A new optional topbar surface
  for page-level actions (filter pills, search, primary action).

- **Atomic component refonte** — Modal, Button, Input, Card, Badge,
  Toast, Checkbox, Spinner, DataTable, StatusDot all receive a
  pass aligned with the new tokens. Public prop surface is
  preserved (variants may be added, none removed); existing
  callers keep working.

- **Topology page** — full rewrite on top of `@xyflow/svelte`
  (Svelte Flow). Custom node types for Clients aggregate, Route
  node, Upstream aggregate. Edges keep particle animation (port
  the Step E spawner) and add a "weighted thickness" mode tied to
  reqPerSec. Zoom / pan / minimap / fit-view controls. Detail
  panel re-styled.

- **Pages refonte** — Login, Setup, Routes, Audit re-skinned with
  the new components and tokens. Behavior unchanged (auth flow,
  CRUD on routes, audit filter / pagination), visuals refreshed.

- **Settings page** — currently a placeholder. Step F ships a real
  Settings page with three sections: **Account** (display name,
  change password trigger, sessions list — last item already
  exists from Step D), **Appearance** (theme toggle), **About**
  (version, links).

- **Two cosmetic fixes from Step E smoke** —
  1. `applyTick` now prunes routes that were in the previous map
     but are absent from the incoming snapshot (orphan-clear).
  2. The topology edge component pauses particle spawning
     whenever the WS connection status is not `connected`,
     regardless of `reqPerSec` (fix applied to legacy
     `TopologyEdge` in Chunk 2, then carried into the new
     `MetricEdge` at Chunk 4b — see §7.2).

- **Animations** — rich, generalized motion (springs, slide-ins,
  fade-throughs, list reorder). Library choice (`motion`, `tween`,
  `svelte/transition`) deferred to Chunk 3; spec §10 lists the
  patterns the choice must support.

- **Svelte component tests** — `@testing-library/svelte` + jsdom
  installed and wired. Tests written for: theme toggle behavior,
  the Step E reactivity regression guards (orphan prune,
  spawn-pause-on-disconnect), Sidebar active-state, Modal close
  paths (Escape / overlay / button), DataTable expand / collapse.
  Pays down the Phase 2 debt accrued at Step D.

## 1.3 Out of scope

Explicitly deferred from Step F:

- **Logo design** — current "Arenet" wordmark in mono stays as
  placeholder. A real logo (SVG mark + wordmark + favicon set)
  will be supplied later; the design system declares a
  `--brand-mark` slot ready to receive it.

- **Mobile / responsive layout** — Arenet is a homelab admin
  desktop tool. Step F keeps the desktop-only assumption.
  Breakpoints below 1024 px are not designed.

- **i18n / l10n** — UI strings stay in English. The current
  copy stays inline; no translation infrastructure.

- **High-contrast / colorblind palettes** — the dark + light pair
  is the only delivery. WCAG AA contrast is verified for both
  modes; further accessibility palettes deferred to Phase 3.

- **Theme follows OS** — the toggle is explicit (`dark` /
  `light`). A `system` option that mirrors `prefers-color-scheme`
  is a small addition deferred to Phase 2; the value of `theme`
  on the user row is restricted to `"dark" | "light"` for now.

- **Component library extraction** — components remain in
  `web/frontend/src/lib/components/`. Publishing them as an npm
  package is not in scope.

- **Backwards-compatibility breakage scan** — Step F preserves
  every public component prop. Adding variants is allowed;
  removing is not. No migration guide required for downstream
  consumers (there are none — single-binary deployment).

- **Animation orchestration library beyond a single lib** — we
  pick one (Chunk 3) and stick to it. No `motion-three` /
  `gsap` / `framer-motion` / et al stack.

- **Multi-user theme inheritance** — Step F is single-admin
  (Step D). When Step D2 lands, `theme` becomes per-user
  naturally because the column is already on `User`. No
  hierarchy / role-based theming.

- **A11y audit beyond the smoke session** — a real audit (axe,
  keyboard nav, screen reader) is Phase 2 Step F+1.

---

## 2. Design tokens system

### 2.1 Token philosophy

One **single source of truth** for every visual constant. Every
component reads CSS custom properties (`var(--token-name)`),
never hard-coded values. The same component renders correctly in
both modes because the underlying tokens swap on `<html data-theme>`.

Tokens live in `web/frontend/src/lib/styles/tokens.css`, imported
once at the top of `app.css`. The current `app.css` `:root` block
is moved there and extended.

### 2.2 Palette

Tokens are grouped by **role**, not by hue. A component that needs
the "elevated surface" color reads `--bg-elevated` — it does NOT
care whether the underlying hex is `#11161f` in dark or `#ffffff`
in light. This decouples component code from theme decisions.

**Backgrounds (5 levels)**

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg-base` | `#0a0e14` | `#fafafa` | page background |
| `--bg-sidebar` | `#060a10` | `#f4f4f5` | sidebar / nav surfaces |
| `--bg-elevated` | `#11161f` | `#ffffff` | cards, panels |
| `--bg-surface` | `#1a212b` | `#f8f8f8` | dropdowns, modals (subtle lift vs `--bg-elevated`) |
| `--bg-hover` | `#1f2733` | `#f4f4f5` | hover state on interactive surfaces |

**Borders (3 levels)**

| Token | Dark | Light | Use |
|---|---|---|---|
| `--border-subtle` | `#1f2733` | `#e4e4e7` | row separators |
| `--border-default` | `#2a3441` | `#d4d4d8` | card / input borders |
| `--border-strong` | `#3a4554` | `#a1a1aa` | focused inputs, primary borders |

**Text (4 levels)**

| Token | Dark | Light | Use |
|---|---|---|---|
| `--text-primary` | `#e6edf3` | `#18181b` | body text, headers |
| `--text-secondary` | `#8b949e` | `#52525b` | labels, subtitles |
| `--text-muted` | `#4a5568` | `#a1a1aa` | placeholders, disabled |
| `--text-inverse` | `#0a0e14` | `#ffffff` | text on accent / button-primary backgrounds |

**Signature (cyan accent)**

| Token | Dark | Light | Use |
|---|---|---|---|
| `--accent-cyan` | `#00d9ff` | `#0891b2` | primary action, active rail, focus ring |
| `--accent-cyan-d` | `#00a8c7` | `#0e7490` | hover variant |

The light-mode cyan is darker (cyan-700 from Tailwind) so it
reads against `--bg-base` (near-white). WCAG AA is not a strict
gate for this homelab admin tool — we eyeball contrast in Chunk
3 and adjust ad hoc if a token reads poorly. If anything fails
visibly (e.g., `--text-muted` invisible on `--bg-elevated` in
light mode), the token gets nudged on the spot and noted in the
chunk commit message.

**Status (4 colors, mode-aware)**

| Token | Dark | Light | Use |
|---|---|---|---|
| `--status-up` | `#00ff88` | `#16a34a` | healthy, connected |
| `--status-warn` | `#ffaa00` | `#d97706` | warning, reconnecting |
| `--status-down` | `#ff4757` | `#dc2626` | error, disconnected, spike |
| `--status-info` | `#a78bfa` | `#7c3aed` | HIBP, info pill |
| `--status-meta` | `#94a3b8` | `#71717a` | meta event badges |

### 2.3 Spacing

Spacing tokens are a 4 px ladder (Tailwind-aligned, exposed as CSS
vars for components that need them outside Tailwind):

| Token | Value |
|---|---|
| `--space-1` | `4px` |
| `--space-2` | `8px` |
| `--space-3` | `12px` |
| `--space-4` | `16px` |
| `--space-5` | `20px` |
| `--space-6` | `24px` |
| `--space-8` | `32px` |
| `--space-10` | `40px` |
| `--space-12` | `48px` |
| `--space-16` | `64px` |

### 2.4 Radii

| Token | Value | Use |
|---|---|---|
| `--radius-sm` | `4px` | badges, pills, small buttons |
| `--radius-md` | `6px` | inputs, default buttons |
| `--radius-lg` | `8px` | cards, panels |
| `--radius-xl` | `12px` | modals, large surfaces |
| `--radius-full` | `9999px` | status dots, avatar circles |

### 2.5 Shadows

| Token | Dark | Light | Use |
|---|---|---|---|
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.4)` | `0 1px 2px rgba(0,0,0,0.06)` | row hover, dropdown |
| `--shadow-md` | `0 4px 8px rgba(0,0,0,0.5)` | `0 4px 8px rgba(0,0,0,0.08)` | floating panel, popover |
| `--shadow-lg` | `0 12px 24px rgba(0,0,0,0.6)` | `0 12px 24px rgba(0,0,0,0.12)` | modal, command palette |
| `--shadow-glow-cyan` | `0 0 16px rgba(0,217,255,0.4)` | `0 0 16px rgba(8,145,178,0.25)` | active item rail, focused button |
| `--shadow-glow-red` | `0 0 16px rgba(255,71,87,0.4)` | `0 0 16px rgba(220,38,38,0.25)` | error spike, danger button |

### 2.6 Motion (transitions / springs)

Two motion families:

**Linear transitions** — for state changes (hover, focus, theme
swap):

| Token | Value | Use |
|---|---|---|
| `--motion-fast` | `100ms cubic-bezier(0.4, 0, 0.2, 1)` | hover, color shifts (Linear-instant feel) |
| `--motion-base` | `200ms cubic-bezier(0.4, 0, 0.2, 1)` | section transitions |
| `--motion-slow` | `400ms cubic-bezier(0.4, 0, 0.2, 1)` | modal in/out, panel slide |

**Springs** — for arrival / departure of UI elements, drag
feedback. Springs are NOT CSS values; they live in a TypeScript
module `web/frontend/src/lib/styles/motion.ts` consumed by
Svelte's `spring()` store (or whatever lib Chunk 3 picks). The
"token" naming is conceptual — they're exported TS constants,
not CSS custom properties. Listed here so the design system
table stays complete. Lib choice deferred to Chunk 3 (§10).

```ts
// motion.ts — tuned at Chunk 3
export const SPRING_SNAPPY = { stiffness: 0.35, damping: 0.5 };
export const SPRING_SOFT   = { stiffness: 0.18, damping: 0.6 };
export const SPRING_BOUNCY = { stiffness: 0.25, damping: 0.35 };
```

| Name | Use |
|---|---|
| `SPRING_SNAPPY` | element entry |
| `SPRING_SOFT` | panel slide-in |
| `SPRING_BOUNCY` | success/celebrate feedback |

Values are placeholders; Chunk 3 tunes them and freezes the
constants. The TS module is the single source of truth.

### 2.7 Typography

```css
--font-sans: 'Inter', system-ui, -apple-system, sans-serif;
--font-mono: 'Geist Mono', ui-monospace, 'JetBrains Mono', monospace;

--text-xs: 11px;   /* badges, metadata captions */
--text-sm: 13px;   /* body, table rows, labels (default UI) */
--text-base: 14px; /* inputs, buttons */
--text-lg: 16px;   /* section headers within a page */
--text-xl: 18px;   /* card titles */
--text-2xl: 22px;  /* page titles */
```

Body text is `--text-sm` (13 px). UI density follows Linear's
14 px-or-below convention. Page titles use `--text-2xl` (22 px)
— not `--text-4xl` like Step C/D did — to align with the
Linear-like density direction.

`--text-3xl` (28 px) and `--text-4xl` (36 px) intentionally
removed: the Linear-like direction has no surface that needs
type that large. If a future hero / marketing-style screen
(unlikely in Phase 1) needs them, they're trivially
re-introduced as a spec amendment.

### 2.8 Geist Mono integration

Geist Mono is added as a self-hosted woff2 alongside the existing
Inter / JetBrains Mono. JetBrains Mono stays as a fallback in the
`--font-mono` stack until every audit/topology consumer migrates
(no big-bang rip-out — risk too high for a polish step).

Three weights are shipped: 400, 500, 600. Subset to Latin to keep
the bundle under 60 kB per weight.

### 2.9 Token apply mechanism

```html
<!-- in src/app.html -->
<html lang="en" data-theme="dark">
```

```css
/* tokens.css */
:root,
[data-theme="dark"] {
  --bg-base: #0a0e14;
  /* ...dark tokens... */
}

[data-theme="light"] {
  --bg-base: #fafafa;
  /* ...light tokens... */
}
```

The theme attribute is set on `<html>` (not `<body>`) so the
background of the very first paint matches.

**Two-phase resolution**:

- **Phase 1 — synchronous bootstrap** (in `<head>`, before any
  Svelte code runs). Priority: cookie `arenet_theme` →
  `localStorage.arenet_theme` → default `'dark'`. This is the
  FOUC-killer (§4.3). Each fallback is local-only; no network
  call.

- **Phase 2 — async reconciliation** (after `/auth/me` resolves
  in the Step D auth bootstrap). If the server's
  `themePreference` differs from the value Phase 1 picked, call
  `theme.applyLocally(me.themePreference)` to swap. Visible as a
  one-time 200 ms transition, only on the first cross-device
  reconcile after a theme change made elsewhere.

Phase 1 NEVER hits the network. Phase 2 reads from the existing
`/me` response (no extra request).

---

## 3. Backend changes

Minimal. One new column, one new endpoint, no migration script (the
BoltDB `User` record decodes legacy rows correctly because Go JSON
unmarshal tolerates missing fields).

### 3.1 User struct

`internal/auth/types.go`:

```go
type User struct {
    // ...existing fields unchanged...
    ThemePreference string `json:"theme_preference,omitempty"` // "dark" | "light" | ""
}
```

Empty string ("") means "no preference yet" — legacy users who
never visited the Settings page. **The frontend treats `""`
identically to `"dark"`** (see §4.2 and §4.3). Valid values
accepted by the API layer are `"dark"` or `"light"` only;
anything else returns 400. `""` is acceptable in storage (it's
the natural zero-value after a user record decodes from a
pre-Step-F BoltDB row) but cannot be written back via the API —
the toggle in Settings always sends either `"dark"` or
`"light"`.

### 3.2 UserStore method

```go
// internal/auth/userstore.go
func (s *UserStore) UpdateThemePreference(ctx context.Context, id, theme string) error
```

Validates `theme ∈ {"dark", "light"}` (rejects anything else, no
silent coercion). Behaves like `UpdateHIBPStatus` — read, mutate,
re-marshal, write. Touches `UpdatedAt`.

### 3.3 API endpoint

```
POST /api/v1/auth/me/theme
Body: {"theme": "dark"|"light"}
Auth: hard-auth (same group as /me/password)
Response: 204 No Content on success
```

`POST` (not `PATCH`) for **verb consistency with Step D** —
Step D uses `POST /me/password` for the analogous "update one
user preference" surface. We align on POST not because PATCH
would be wrong RESTfully but because every existing
preference-update endpoint in the codebase uses POST.

400 on invalid theme value, 401/403 via middleware, 500 on
storage error.

`GET /api/v1/auth/me` (Step D) is extended to include
`themePreference` in the response — front bootstrap reads it.

### 3.4 Audit emission — none

Theme changes are **user-preference configuration**, not security
events. The D7 audit action set (15 entries) stays unchanged.
`POST /auth/me/theme` does NOT emit an audit event. Brainstorm
decision verbatim: "c'est du paramétrage user, pas sécurité".

If a future Step (D2 multi-user with roles) decides to audit
preference changes for compliance, that's a separate spec
amendment.

### 3.5 Tests

`internal/auth/userstore_test.go` gains `TestUpdateThemePreference_*`
covering: valid `dark`, valid `light`, invalid string rejected,
empty user ID error, persistence across re-fetch.

`internal/api/auth_handlers_test.go` gains
`TestPatchTheme_RequiresHardAuth`, `TestPatchTheme_Success`,
`TestPatchTheme_InvalidBody`, `TestPatchTheme_LockedSession_403`.

### 3.6 No new audit actions

`internal/audit/actions.go` is unchanged. The D7 action list stays
at 15 actions.

---

## 4. Frontend foundation

### 4.1 Theme store

New file `web/frontend/src/lib/stores/theme.svelte.ts`:

```ts
class ThemeStore {
  current = $state<'dark' | 'light'>('dark');
  isApplying = $state(false);

  /** Apply a theme to the DOM (data-theme attribute) and persist
   *  optimistically. Calls /auth/me/theme to sync with server. */
  async set(t: 'dark' | 'light'): Promise<void>;

  /** Apply WITHOUT calling the server. Used by bootstrap after /me. */
  applyLocally(t: 'dark' | 'light'): void;
}

export const theme = new ThemeStore();
```

Same singleton class pattern as `auth.svelte.ts` and
`topology.svelte.ts`. `current` mirrors `<html data-theme>`.

### 4.2 Apply mechanism

On change:

```ts
applyLocally(t) {
  this.current = t;
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = t;
  }
}
```

CSS handles the rest via the `[data-theme="light"]` rule (§2.9).
The `<html>` attribute change is animated by a 200 ms transition
on `background-color` and `color` on `body` (and any explicit
component using these — typically none, components use tokens).

**Empty server value handling**: when `/auth/me` returns
`themePreference: ""` (a legacy user), `theme.applyLocally("")`
treats it as `"dark"`. The implementation guards on
`t === 'light' ? 'light' : 'dark'` so any non-`"light"` input
(including `""`, `undefined`, garbage) renders as dark. The
same guard appears in the Phase 1 bootstrap script (§4.3).

### 4.3 FOUC prevention

A small synchronous bootstrap script is placed in `<head>` BEFORE
the SvelteKit app. It MUST execute before the first paint;
priority order: cookie → localStorage → default `'dark'`.

```html
<script>
  (function () {
    var t = document.cookie.match(/arenet_theme=(dark|light)/);
    if (t) {
      document.documentElement.dataset.theme = t[1];
      return;
    }
    try {
      var ls = localStorage.getItem('arenet_theme');
      if (ls === 'dark' || ls === 'light') {
        document.documentElement.dataset.theme = ls;
        return;
      }
    } catch (_) { /* private browsing → ignore */ }
    document.documentElement.dataset.theme = 'dark'; // default
  })();
</script>
```

Default is `'dark'`, matching the current app appearance — a
first-time user (no cookie, no localStorage) sees the same UI
they would have seen pre-Step-F. The script is added to
`src/app.html` (the static HTML shell served by
`adapter-static`).

**Setup wizard** (first user, not yet logged in): the bootstrap
script runs before any Svelte code, so the `/setup` page also
inherits the default `'dark'`. After the admin completes setup
and authenticates, `/auth/me` returns `themePreference: ""` for
the brand-new user; Phase 2 reconciliation (§2.9) sees `""` →
treats as `"dark"` → no swap, no flash. The first explicit
theme choice happens in Settings post-setup.

**Size budget**: < 500 bytes minified. Measured at Chunk 1.
If a future addition pushes it over, refactor (the cookie regex
is already minimal; minifier should produce ~200-300 bytes).

After /auth/me resolves, `theme.applyLocally(me.themePreference)`
updates if the server's value differs from what bootstrap picked
(e.g., user changed theme on another device).

### 4.4 Light/dark toggle component

`Toggle.svelte` — a 2-state segmented control with sun / moon
icons. Lives in `lib/components/`. Used by the Settings page.

```svelte
<Toggle
  options={[{value: 'dark', label: 'Dark'}, {value: 'light', label: 'Light'}]}
  bind:value={theme.current}
  onchange={(v) => theme.set(v)}
/>
```

### 4.5 Cookie set on login

`POST /api/v1/auth/login` sets `arenet_theme=<user_preference>` as
a secondary cookie. Attributes:

- **`HttpOnly=false`** — the bootstrap script in §4.3 must read
  it from JS, so HttpOnly would defeat the purpose. The cookie
  carries NO security-sensitive content (it's a 4-char string
  `"dark"` or `"light"`), so JS-readable is acceptable.
- **`SameSite=Lax`** — NOT Strict. With Strict, the cookie is
  NOT sent on the very first navigation from an external link
  (typical login flow if the admin bookmarks the dashboard),
  which breaks the FOUC bootstrap on first paint. Lax sends the
  cookie on top-level GETs from any origin, which is what the
  bootstrap script needs. The `arenet_session` cookie remains
  Strict because IT carries security context.
- **`Secure`** in prod (dev mode omits, mirroring `arenet_session`).
- **`Path=/`**, **`Max-Age=2592000`** (30 days).

`POST /auth/me/theme` updates this cookie on each successful
call. Lifecycle paths:

- **Explicit logout** (`POST /auth/logout`): sets `Max-Age=0` for
  both `arenet_session` and `arenet_theme`. Clean.
- **Silent expiration** (idle lock window crossed, server
  restart, session pruning, cookie's own `Max-Age` exceeded):
  the cookie is NOT actively cleared. It survives until either
  (a) its own Max-Age expires (30 days), (b) the next successful
  login rewrites it, or (c) the browser session ends (Lax sites
  typically don't survive that). This is **acceptable**: the
  cookie carries only a 4-character preference, no security
  context. Worst case, a freshly-logged-out user sees their
  previously-set theme on the login page itself — exactly the
  desired UX.

The asymmetry (session cleared, theme not) is deliberate; the
session cookie is sensitive, the theme cookie is purely UX.

---

## 5. Components refactor

Every existing component receives a pass. **Public prop surface
preserved** (variants may be added). Internal styles migrate to
tokens only.

### 5.1 Inventory and changes

| Component | Status change | Notes |
|---|---|---|
| `Sidebar.svelte` | Major refonte | Denser, collapsible-state pinned, footer block |
| `Modal.svelte` | Visual refresh | Token migration, animation pass |
| `Button.svelte` | Variants extended | `primary` / `secondary` / `ghost` / `danger` / **`tonal`** (new), sizes unchanged |
| `Input.svelte` | Visual refresh | Focus ring, prefix icon slot |
| `Card.svelte` | Visual refresh + interactive variant | New `interactive` prop for hoverable cards |
| `Badge.svelte` | Variants extended | 5 status variants matching `--status-*` tokens, plus `outline` style |
| `Toast.svelte` | Visual refresh | Token migration |
| `Checkbox.svelte` | Visual refresh | Token migration |
| `Spinner.svelte` | Visual refresh | Token migration |
| `DataTable.svelte` | Visual refresh + sticky header | Header sticks on scroll inside fixed-height container |
| `StatusDot.svelte` | Unchanged behavior | Token migration only |
| `StatCard.svelte` | Visual refresh | Used by future dashboard; minor token pass |
| `Toggle.svelte` | **New** | Segmented 2-state control (§4.4) |
| `Tooltip.svelte` | **New** | Hover-trigger tooltip with 200 ms delay, position-aware |
| `IconButton.svelte` | **New** | Square 32 / 36 / 40 px button for toolbar actions |
| `PageHeader.svelte` | **New** | Page-level title block: title + optional subtitle + action slot for chips / primary button (consumed by Routes / Audit topbars per §5.3) |

### 5.2 Sidebar refonte

Current: 256 px wide, vertical list of 5 items (Routes, Audit,
Topology, Security, Settings), collapsed to 64 px on toggle.

Step F: 240 px (slightly narrower to give more page room), same
items, denser. New visual elements:

- A 48 px header band with the Arenet wordmark: text-only, mono
  font, cyan initial `A`. **Placeholder** — replaced by the real
  logo (SVG mark + wordmark) when supplied (§1.3). The wordmark
  slot is reserved in the Sidebar so the swap is a single-file
  change later.
- Nav items: 32 px tall (down from 40 px), icon + label, hover
  underline.
- A divider after Audit (separating "core" from "config").
- Footer: user identity chip + WS connection dot + collapse
  toggle.

### 5.3 Topbar (optional)

A topbar surface for page-level controls (filter chips, primary
action, search field) is introduced. Not every page uses one.

- Routes page: "Add route" primary button on the right.
- Audit page: filter pills + Clear all on the right.
- Topology page: Zoom controls + Fit-view (handled by Svelte Flow
  built-in panel — see §6).
- Other pages: no topbar.

A `<PageHeader>` component holds: title, optional subtitle, and
a slot for action buttons / chips.

### 5.4 Atomic component contracts (key props)

```ts
// Button
type Variant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'tonal';
type Size = 'sm' | 'md' | 'lg';

// Card
interface Props {
  interactive?: boolean;  // hover lift + cursor
  padding?: 'sm' | 'md' | 'lg';
  variant?: 'default' | 'subtle';
}

// Badge
type Variant = 'cyan' | 'green' | 'amber' | 'red' | 'violet' | 'slate' | 'outline';

// Tooltip (new)
interface Props {
  content: string;
  placement?: 'top' | 'bottom' | 'left' | 'right';
  delayMs?: number; // default 200
}

// Toggle (new)
interface Option<T> { value: T; label: string; icon?: Snippet }
interface Props<T> {
  options: Option<T>[];
  value: T;            // bindable
  onchange?: (v: T) => void;
}
```

### 5.5 No-breakage discipline

Every existing caller keeps working. Callers to verify after
each component edit:

- `+layout.svelte` (consumes `Sidebar` — the refonte in §5.2
  touches this file's wiring)
- All per-page `+page.svelte` (Login, Setup, Routes, Audit,
  Topology, Settings, Security)
- `LockScreen.svelte`
- `ChangePasswordModal.svelte`
- `AuditRow.svelte`
- `AuditExpandedDetails.svelte`
- `TopologyDetailPanel.svelte`

The refactor adds props (defaultable); it never removes or
renames.

`npm run check` must stay at 0 errors throughout.

---

## 6. Topology refonte (Svelte Flow)

### 6.1 Library choice — `@xyflow/svelte`

`@xyflow/svelte` is the Svelte port of `react-flow` from the
xyflow team. It's the most mature Svelte graph library at the
time of writing (2026-05-19). **It is still in alpha**: the
public API can break across minor versions.

**Version pinning**: we pin with `~` (patch-only updates allowed,
minor bumps blocked). The exact version is picked at Chunk 4a
install — likely `~0.1.x` or `~0.2.x` depending on what npm
resolves on that day. Recorded in the Chunk 4a commit message.

Examples of acceptable / rejected pins:
- `"~0.1.20"` ✅ — allows `0.1.21`, `0.1.22`; blocks `0.2.0`.
- `"^0.1.20"` ❌ — would auto-jump to `0.2.x` which alpha
  routinely breaks.
- `"0.1.20"` ✅ but rigid — also acceptable; we use `~` to pick
  up bugfix patches without manual review.

The import surface used in Chunk 4b (every Svelte Flow component
and helper actually consumed) is captured in the Chunk 4b commit
message so future upgrades have an explicit before/after to
diff against.

If `@xyflow/svelte` proves too unstable for a v0.4 ship, the
fallback is **Cytoscape.js** wrapped in a Svelte component —
larger bundle but stable API. Decision point at Chunk 4 day 1
after the first integration spike.

### 6.2 Why a graph library

The Step E hand-rolled SVG worked for one page, but adding
features (drag, zoom, fit-to-view, minimap, edge routing,
collapse / expand sub-graphs in the future) becomes expensive
fast. Svelte Flow gives us:

- Pan / zoom / fit-view (with keyboard shortcuts).
- Smart edge routing (orthogonal, bezier, smoothstep).
- **Topology graph (who-connects-to-who) is read-only via this
  UI** — the route set is managed from `/routes`, mutations on
  this page are NOT supported. **Node POSITIONS are editable
  by drag**, with positions persisted (§6.5). **Connection edge
  creation is disabled** at the Svelte Flow level (deferred —
  potentially Step G for security-policy edges).
- Minimap (toggleable from the topbar).

### 6.3 Node types

Three custom node types registered with the `nodeTypes` prop:

```ts
import ClientsPillar from './topology/nodes/ClientsPillar.svelte';
import RouteNode from './topology/nodes/RouteNode.svelte';
import UpstreamNode from './topology/nodes/UpstreamNode.svelte';

const nodeTypes = { clientsPillar: ClientsPillar, route: RouteNode, upstream: UpstreamNode };
```

The Clients pillar is a single node spanning the visible canvas
height (custom rendering bypasses the Svelte Flow default sizing
— a `data: { height: 'fit' }` is read and the node renders an
absolute-positioned column).

**Use `$state.raw` (NOT `$state`) for the Svelte Flow nodes /
edges stores**:

```ts
let nodes = $state.raw<Node[]>([]);
let edges = $state.raw<Edge[]>([]);
```

The Svelte Flow docs recommend `$state.raw` explicitly.
`$state.raw` skips deep reactivity proxying — Svelte does NOT
track each `node.position.x` or `edge.data.reqPerSec` mutation
individually. Svelte Flow has its own change detection over the
top-level array reference; reassigning the array
(`nodes = [...nodes, newNode]`) is the only signal it needs.
Deep proxies would (a) wreck performance with a few hundred
nodes (every drag fires N proxy notifications) and (b)
re-introduce the cross-module reactivity flakiness Step E
fought (§2.9 + §7).

The page therefore mutates `nodes` / `edges` via array
reassignment, never via `nodes[i].data.reqPerSec = ...`. Every
mutation rebuilds the array; the resulting alloc is dwarfed by
Svelte Flow's diff logic.

### 6.4 Edge types and rendering — full rewrite

Two edge types:

- `metric-edge` — bezier path. Width derived from
  `data.reqPerSec` (linear ramp 1 → 4 px, capped). Color from the
  same logic as Step E (cyan / warn / down). Particle animation
  layer embedded in the edge's custom Svelte Flow component.

**Component fate at Chunk 4b**:

| File | Action |
|---|---|
| `TopologyEdge.svelte` | **deleted wholesale** — replaced by `edges/MetricEdge.svelte` |
| `TopologyParticle.svelte` | **deleted wholesale** — replaced by the particle layer inside MetricEdge |
| `TopologySvg.svelte` | **deleted wholesale** — replaced by `TopologyFlow.svelte` (Svelte Flow root) |
| `TopologyNode.svelte` | **deleted wholesale** — replaced by `nodes/RouteNode.svelte` |
| `TopologyDetailPanel.svelte` | **PRESERVED, restyled only** — functionally OK from Step E (sparklines, close paths, layout). Step F migrates its hex/px to tokens and swaps the URL/timestamp font to Geist Mono. No structural change. |

The particle / spawn / fallback-timer / visibility-pause logic is
**re-written from scratch** inside the new
`edges/MetricEdge.svelte`, not ported file by file. The detail
panel keeps its current implementation aside from the cosmetic
token pass.

**Reused from Step E**: the entire `lib/stores/topology-constants.ts`
module is **preserved unchanged**. Every constant survives the
Chunk 4b rewrite — their values were validated empirically in
the Step E smoke session and have no reason to drift:

- `TICK_INTERVAL_MS = 1000` (server tick cadence mirror)
- `PARTICLE_TRAVEL_MS = 2000`
- `PARTICLE_DENSITY_CAP = 50` per second per edge
- `MAX_PARTICLES_PER_EDGE = 100`
- `COLOR_WARN_THRESHOLD = 0` (any 5xx > 0 ⇒ warn color)
- `COLOR_ERROR_THRESHOLD = 0.05` (≥ 5 % ⇒ down color)
- `ACTIVE_WINDOW_MS = 60_000`
- `SPIKE_WINDOW_TICKS = 10`
- `SPIKE_THRESHOLD = 0.05`
- `HISTORY_CAPACITY = 60`
- `RECONNECT_MIN_MS = 1000`
- `RECONNECT_MAX_MS = 30_000`
- `RECONNECT_DISCONNECTED_THRESHOLD = 5`

**No constant is removed**. `MetricEdge` and the new node
components import them. If a value needs tuning during Chunk 4b
QA, change it in `topology-constants.ts` and update this list.

**Reused conceptual lessons**:

- Spawn timer (setInterval) is paused on `document.hidden`
  (visibility listener).
- Each particle has a fallback `setTimeout` matching
  `PARTICLE_TRAVEL_MS + 500` ms to guarantee cleanup if RAF
  throttles.
- Hard cap `MAX_PARTICLES_PER_EDGE` defends against pathological
  accumulation.

The new system gets to re-architect these without inheriting any
of the Svelte 5 reactivity workarounds (version counter, immutable
replace) that Step E needed — `@xyflow/svelte` has its own
reactivity model around the `nodes` / `edges` Svelte stores, so
the cross-module SvelteMap pattern from Step E is irrelevant to
Chunk 4. The store-level `void topology.version` subscription
stays for `/topology` page consumers (route list, totalReqPerSec),
but particles in MetricEdge read their state directly from the
edge's `data` prop, which is reactive by Svelte Flow's contract.

The particle layer renders inside the edge's SVG `<g>` overlay
provided by Svelte Flow's `<BaseEdge>` slot. Svelte Flow
re-renders the edge whenever the source/target node moves; the
particle stays in sync because the new component re-resolves the
path geometry on each render via `path.getPointAtLength` —
unchanged technique from Step E.

### 6.5 Layout — initial computed + persistence

**Initial positions** computed by a small layout helper
(`computeLayout(routes)`):

- Clients pillar at `x=0, y=0, height=canvas`.
- Route nodes column at `x=400`, distributed Y by index × 80 px
  (taller than Step E's 72 px since the new node is denser).
- Upstream nodes column at `x=800`, Y averaged across incoming
  route Ys (Step E pattern preserved).

**Persistence**. Admin's drag-and-drop adjustments are saved
server-side so a refresh does not reset the layout. Storage:
**one new BoltDB bucket** `topology_layouts`, keyed by user ID,
value JSON-encoded as `map[routeID]{x,y}`. Two new endpoints:

- `GET /api/v1/topology/layout` → `{positions: {[routeID]: {x,y}}}`
- `POST /api/v1/topology/layout` (full upsert) → 204

`POST` (not `PUT`) for **verb consistency with Step F's other
preference-update endpoint** `POST /me/theme` (§3.3). Both
endpoints replace the user's value wholesale — the verb choice
is stylistic, not RESTful semantics.

Both hard-auth gated, same group as `/routes`.

The frontend debounces drag-end events (500 ms) before POST, so a
sustained re-layout produces a single network call. Loading on
mount: GET → merge with `computeLayout(routes)` so unknown
routes still get a default position.

Cosmetic but justified — Step E smoke noted that "admin
frustrated without persistence" would be a likely complaint. The
backend half (1 endpoint pair + storage) lands in **Chunk 4b**
(NOT Chunk 4a spike, NOT Chunk 1), alongside the frontend
integration.

### 6.6 Controls

A `<Controls />` Svelte Flow built-in component in the bottom-left
corner exposes:
- Zoom in / zoom out
- Fit view (reset to default layout)
- Minimap toggle (toggleable; the `<MiniMap />` component lives
  next to it, hidden by default for density)

Plus a keyboard shortcut: `f` = fit-view.

### 6.7 Detail panel

`TopologyDetailPanel.svelte` is **preserved** per the table in
§6.4 — structurally identical, restyled only: hex/px → tokens,
Geist Mono for the upstream URL and timestamps, sparkline colors
swapped to the new accent system. No prop change, no behavior
change. Reused as-is by `TopologyFlow` on node click.

### 6.8 Persistent particle leak fix

The Step E smoke session uncovered that particles continued to
spawn while WS was `disconnected`. Step F: the spawn-restart
effect reads `topology.connectionStatus` and skips starting the
interval when it's not `'connected'`. Implemented in §7.2 — at
Chunk 2 the fix lives in the legacy `TopologyEdge.svelte`; at
Chunk 4b it is carried into the new `MetricEdge.svelte` as part
of the rewrite (same logic, new file).

### 6.9 SvelteFlow CSS scoping

`@xyflow/svelte` ships its own stylesheet (`@xyflow/svelte/dist/style.css`).
We import it once in `app.css` (after our `tokens.css`) so our
tokens win when classes collide. Library default colors are
overridden via the CSS variable shim provided by Svelte Flow
(`--xy-edge-stroke`, `--xy-node-background-color`, etc.).

A doc-comment in the topology page lists every Svelte Flow CSS
variable we override and what token feeds it.

---

## 7. Step E cosmetic bugs — fixes

### 7.1 Orphan route prune in `applyTick`

**Bug**: when a route is deleted via the UI, the WS frame next
tick will not list it. But `applyTick` only ADDS / UPDATES; it
never REMOVES. So the page keeps showing the dead route until
full reload. Step E smoke session §5.f surfaced this.

**Fix**: at the end of `applyTick`, walk the existing `routes`
map and delete any key not present in the snapshot. Behavior is
behind a comment block referencing this section.

```ts
const snapshotIds = new Set(snap.routes.map((r) => r.id));
for (const id of routes.keys()) {
  if (!snapshotIds.has(id)) {
    routes.delete(id);
  }
}
```

The `routes` is a `SvelteMap`, so `.delete()` emits per-key
reactivity. **Critically, `store.apply()` MUST still bump
`this.version++` after the call to `applyTick`** — even when the
only mutation is an orphan prune (no `.set()` happened). Without
the bump, consumers' `$derived(() => { void topology.version;
... })` would not invalidate and the deleted route would stay
visible. The bump pattern from Step E remains unchanged; orphan
prune relies on the existing invalidation path, it does not
introduce a new one.

### 7.2 Pause spawn when WS not connected

**Bug**: even when the WS is `disconnected` and no fresh ticks
arrive, the spawn `setInterval` keeps firing based on the LAST
known `reqPerSec`. Step E smoke session §8 surfaced this
(briefly continued spawning during reconnect window).

Note on naming: in Step F the spawn logic lives in **`MetricEdge`**
(the new Chunk 4b Svelte Flow custom edge), NOT `TopologyEdge`
(which is deleted per §6.4). The fix below is implemented inside
`MetricEdge.svelte` directly. **However**, Chunk 2 (Step E
cosmetic bug fixes) lands BEFORE the Chunk 4 rewrite — so at
Chunk 2 the fix is applied to the still-existing
`TopologyEdge.svelte`, and the same logic is then carried into
`MetricEdge` at Chunk 4b's rewrite. The behavior surface is
identical.

**Fix**: read `topology.connectionStatus` in the spawn-restart
effect. If not `'connected'`, do not start the interval.

```ts
$effect(() => {
  void reqPerSec;
  void reducedMotion;
  void topology.connectionStatus;  // subscribe
  if (topology.connectionStatus !== 'connected') {
    if (spawnTimer !== null) clearInterval(spawnTimer);
    spawnTimer = null;
    return;
  }
  if (typeof document !== 'undefined' && document.hidden) return;
  const rate = Math.max(0, Math.min(reqPerSec, PARTICLE_DENSITY_CAP));
  if (rate <= 0) return;
  spawnTimer = setInterval(spawnOne, 1000 / rate);
});
```

### 7.3 Regression tests

Both fixes get explicit Vitest tests (now possible after Step F
installs `@testing-library/svelte`, see §11):

- `applyTick removes routes absent from snapshot (orphan prune)`
  — lives in `topology.test.ts` (pure helper, no testing-library
  needed).
- `MetricEdge: spawnTimer is null when
  topology.connectionStatus !== 'connected'` — lives in
  `MetricEdge.test.ts` (a Chunk 4b file).

The spawn-pause test cannot live under a `TopologyEdge.test.ts`
filename because that component is deleted at Chunk 4b. It ships
in Chunk 7 targeting the post-rewrite component
(`MetricEdge.svelte`).

---

## 8. Pages refactor

Every page touched. Behavior unchanged.

### 8.1 Login

Visual: centered card on `--bg-base`, 400 px wide, denser fields
(13 px label, 14 px input). New "Sign in to Arenet" header. Below
the form: small footer text "Forgot your admin password? Restart
with `--reset-admin` and follow the prompts" (placeholder for a
future operator runbook link).

`+layout@.svelte` reset still used.

### 8.2 Setup

Same direction as Login: centered card, mono token displayed in
a copy-on-click chip, three input fields, validation feedback
inline.

### 8.3 Routes

Topbar gains the "Add route" primary button (already exists
inline in Step D; just relocated to a `<PageHeader>` slot).
DataTable refresh: sticky header on scroll, hover state on
rows. Row-click expansion is **preserved as-is from Step D**
(`{#snippet expanded(r)}` already in `routes/+page.svelte`) —
only the visual surface gets the token pass; the content
rendered in the expanded block is unchanged.

No new feature in Step F. JSON config preview, route status
indicators, bulk actions etc. are explicit Phase 2 work (§15).

### 8.4 Audit

Filter pills + Clear all in a topbar zone (instead of inline as
in Step D). DataTable with sticky header. Row badges restyled
with the new `Badge` variants. Detail panel keeps its Step D
content; the timestamp column gains a relative-time helper
(`5m ago`) backed by `Intl.RelativeTimeFormat`.

**Render-once semantics**: the relative-time label is computed
on render and NOT refreshed live. If the page sits open for an
hour, the "5m ago" stays "5m ago" until the user refreshes (or
scrolls back to that row, which triggers a re-render of its
content). A live ticking timer would add complexity (one
`setInterval` per visible row + cleanup) for marginal UX gain —
Step F keeps it cosmetic.

### 8.5 Topology

Covered in §6.

### 8.6 Settings (new)

Three sections in a single page (anchor links in the sidebar
optionally — deferred Phase 2):

**Account**
- Display name (read-only for now, edit deferred)
- Username (read-only)
- Change password → opens `ChangePasswordModal` (existing)
- Sessions → DataTable from `/auth/sessions` (existing Step D
  data, was previously buried; surface it here)

**Appearance**
- Theme: `<Toggle>` with dark / light options (§4.4)
- Reduce motion: read-only indicator showing the OS preference
  (`Enabled` / `Disabled`) read via
  `window.matchMedia('(prefers-reduced-motion: reduce)').matches`.
  Respected automatically by the app's CSS (§10.3). **No in-app
  override toggle in Step F** — adding one would require parallel
  server-persisted state and a second cascade rule; deferred to
  Phase 2 if user feedback requests it.

**About**
- **Version** — sourced from `git describe --tags --always` at
  build time and exposed via `import.meta.env.VITE_APP_VERSION`.
  Wiring (Step F adds): `vite.config.ts` has a `define` block
  that runs the git command synchronously during `npm run build`
  (and `npm run dev`) and replaces `VITE_APP_VERSION` accordingly.
  Output examples: `v0.3.0-step-e` (clean tag), `v0.3.0-step-e-3-g7471243` (3 commits past tag), `7471243` (no tag, just SHA).
  Dev fallback for an env without git: `unknown`.
- **License** — AGPL v3 with a link to the LICENSE file on
  GitHub (resolved from `VITE_APP_VERSION` for the right ref).
- **Source** — link to https://github.com/barto95100/arenet.

---

## 9. Settings page detail

Already covered in §8.6. This section drills the storage and
API contract.

### 9.1 Theme preference flow

```
[Toggle click in Settings]
    ↓
theme.set('light')
    ↓
1. theme.applyLocally('light')        // optimistic UI
2. POST /api/v1/auth/me/theme {"theme": "light"}
    ↓
3a. Success → cookie 'arenet_theme=light' set on response
3b. Failure → theme.applyLocally(previous)  // revert
              + toast("Failed to save theme preference")
```

The optimistic update means clicking the toggle feels instant
(< 16 ms). The network call is fire-and-forget from the UX
perspective; only failure path interrupts.

### 9.2 Sessions section

Re-uses Step D's `/auth/sessions` endpoint. Renders a DataTable
with: IssuedAt (relative), LastActivity (relative), IP, UA,
Current?, Revoke action. The revoke uses the existing
`DELETE /sessions/{id}` endpoint. Behavior carried over from Step
D; only the visual surface is reskinned.

### 9.3 No new endpoints beyond §3

`POST /auth/me/theme` is the only new server endpoint Step F
adds.

---

## 10. Animations

### 10.1 Library decision (deferred to Chunk 3)

Two candidates considered:

| Lib | Pros | Cons |
|---|---|---|
| `svelte/motion` + `svelte/transition` (built-in) | Zero deps, Svelte-native, springs included | Bare-bones API, hard to compose complex sequences |
| `motion` (formerly Framer Motion) | Most popular, springs + sequences + layout animations | ~30 kB; Svelte support is community port `svelte-motion`, less polished |

**Bias** : start with the built-in Svelte primitives. Their
spring + tweened stores cover 90% of the listed patterns
(§10.2). If a specific pattern requires layout animations
(FLIP), upgrade to `motion` at Chunk 4 (topology) where the need
is most likely to surface.

### 10.2 Patterns to support

- **Modal in/out**: slide-up + fade with `--motion-slow`
  (400 ms) — heavier surface, longer arc reads as "intentional"
  arrival.
- **Toast queue**: stack-up entry, slide-out on dismiss with
  `--motion-base` (200 ms ease); springy on entry via
  `SPRING_SNAPPY`.
- **Sidebar collapse**: width transition `--motion-base`
  (200 ms).
- **Detail panel slide-in**: `--motion-slow` (400 ms) ease-out
  from the right — same family as modal.
- **Theme swap**: `--motion-base` (200 ms) background-color +
  color transition on `body`; instant on `<html data-theme>`
  swap (the attribute change is not animated, only the
  inherited CSS values are).
- **List reorder (audit/routes)**: FLIP-style — defer to a
  future step if `motion` adds it cleanly.
- **Particle motion (topology)**: technique preserved
  conceptually (RAF + `getPointAtLength`), code rewritten inside
  `MetricEdge.svelte` per §6.4 — the new component re-resolves
  the path geometry via Svelte Flow's `<BaseEdge>` slot and runs
  its own RAF loop with the §6.4 fallback timer + visibility
  pause + cap.
- **Spring on the Theme Toggle**: `svelte/motion.spring` for the
  knob slide between two positions.

### 10.3 Respect `prefers-reduced-motion`

A single CSS rule in `app.css` (already there from Step E,
preserved):

```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0s !important;
    transition-duration: 0s !important;
  }
}
```

For Svelte transitions that aren't CSS-driven, components must
check the media query and skip the transition. A
`useReducedMotion()` helper hook is added at Chunk 3.

---

## 11. Tests Svelte (Phase 2 debt pay-down)

### 11.1 Stack

`@testing-library/svelte` v5 + `@testing-library/jest-dom` (for
matchers) + `@testing-library/user-event` (for user behavior
simulation). All installed at Chunk 7 day 1. Vitest setup
extended with the jsdom-aware testing-library bootstrap.

### 11.2 Scope — user behavior, not implementation

The principle is **render → simulate user interaction → assert
the observable outcome**. Internal Svelte state is not asserted
directly (would be brittle). Specifically excluded:

- Asserting that a `$state` rune holds a specific value.
- Asserting that a component re-rendered N times.
- Snapshot tests of HTML.

### 11.3 Test list

**Theme** (3 tests):
- `Toggle` renders both options; clicking changes the bound value.
- Theme toggle in Settings page calls `theme.set` with the
  expected value when clicked.
- `ThemeStore.applyLocally` sets `<html data-theme>`.

**Sidebar** (4 tests):
- Five nav items render in expected order.
- Clicking an item navigates (mock `goto`).
- Collapsed-state hides labels, keeps icons.
- Active path gets the `--accent-cyan` rail.

**Modal** (4 tests):
- Renders title and children.
- Escape closes (calls `onClose`).
- Overlay click closes.
- `closeOnOverlay={false}` prevents overlay-click close.

**DataTable** (3 tests):
- Headers render.
- Row click toggles expanded view.
- Second click on same row collapses.

**Button** (4 tests):
- Each variant (`primary` / `secondary` / `ghost` / `danger` /
  `tonal`) applies its expected class.
- `loading` prop renders the Spinner and disables click.
- `disabled` prevents `onclick`.
- Keyboard `Enter` triggers `onclick` (focus + Enter user-event).

**Badge** (1 test, parameterized over 7 variants):
- Each of `cyan` / `green` / `amber` / `red` / `violet` /
  `slate` / `outline` renders the expected token color.

**Input** (2 tests):
- Focus ring appears on Tab focus (visible class assertion).
- Prefix icon slot renders when provided.

**Tooltip** (2 tests):
- Hover for ≥ 200 ms shows the tooltip content.
- `placement="bottom"` positions below the trigger (asserted
  via class, not pixel math).

**IconButton** (1 test, parameterized over 3 sizes):
- `size="sm"` / `"md"` / `"lg"` apply the expected square
  dimension class.

**Step E regression guards** — two critical tests, in two
distinct files because they have different mechanics.

### Regression guard A — orphan prune (pure helper test)

Lives in `lib/stores/topology.test.ts` (existing file from
Step E). Pure helper test: NO `@testing-library/svelte`
involved, just Vitest + the Step E test pattern.

```ts
import { describe, it, expect } from 'vitest';
import { topology } from './topology.svelte';

it('removes routes absent from snapshot (orphan prune)', () => {
  topology.clear();
  topology.apply({ t:'2026-05-19T10:00:00Z', routes:[
    { id:'r1', host:'a', upstream:'u', reqs:1, errs:0, reqPerSec:1, errRate5xx:0 },
    { id:'r2', host:'b', upstream:'u', reqs:1, errs:0, reqPerSec:1, errRate5xx:0 }
  ]});
  expect(topology.size).toBe(2);

  topology.apply({ t:'2026-05-19T10:00:01Z', routes:[
    { id:'r1', host:'a', upstream:'u', reqs:1, errs:0, reqPerSec:1, errRate5xx:0 }
    // r2 dropped from snapshot
  ]});
  expect(topology.size).toBe(1);
  expect(topology.get('r2')).toBeUndefined();
});
```

### Regression guard B — MetricEdge spawn pause on disconnect (component mount test)

Lives in a NEW file `routes/topology/+page.test.ts`. Requires
`@testing-library/svelte` because the assertion is on rendered
DOM (`<circle>` elements). Mounts the full topology page,
drives the store, and inspects the rendered tree:

  ```ts
  import { render, screen } from '@testing-library/svelte';
  import { topology } from '$lib/stores/topology.svelte';
  // No SvelteKit alias for /routes — import via relative path
  // from the test file's location at src/routes/topology/+page.test.ts.
  import TopologyPage from './+page.svelte';

  it('renders route nodes when ticks arrive', async () => {
    topology.clear();
    const { container } = render(TopologyPage);
    // tick 1 — route appears
    topology.apply({
      t: '2026-05-19T10:00:00Z',
      routes: [{ id:'r1', host:'smoke.localhost', upstream:'http://10/',
                 reqs:5, errs:0, reqPerSec:5, errRate5xx:0 }]
    });
    // testing-library's findByText awaits microtask + animation
    // frame — perfect for Svelte 5's deferred reactivity.
    expect(await screen.findByText('smoke.localhost')).toBeInTheDocument();
  });
  ```

  This mounts a real component tree (the `/topology` page), drives
  the store via two `topology.apply` calls, and asserts via
  `findByText('smoke.localhost')` — exactly the kind of
  cross-module reactivity check that would have caught the Step E
  regression at unit-test time.

  A second variant covers spawn-pause:

  ```ts
  it('stops spawning particles when WS disconnects', async () => {
    render(TopologyPage);
    topology.apply(/* a snapshot with 50 req/s */);
    topology.setStatus('connected');
    await new Promise(r => setTimeout(r, 100));
    const beforeCount = container.querySelectorAll('circle.particle').length;
    expect(beforeCount).toBeGreaterThan(0);

    topology.setStatus('disconnected');
    await new Promise(r => setTimeout(r, 200));  // spawn interval is ~20ms
    const lateCount = container.querySelectorAll('circle.particle').length;
    // No new particles should be added; existing ones drain.
    expect(lateCount).toBeLessThanOrEqual(beforeCount);
  });
  ```

  **Note on the selector**: `circle.particle` requires
  `MetricEdge.svelte` to set `class="particle"` on every spawned
  `<circle>` element (the Step E TopologyParticle already does
  this — the rewrite must preserve it). The test depends on
  this class being present; if Chunk 4b renames the class, the
  test selector must be updated in the same commit. Documented
  in `MetricEdge.svelte`'s doc-comment.

  Both tests (the "route appears on tick" + spawn-pause) live
  in the new `routes/topology/+page.test.ts`.

**Total**: **26 tests** added in Chunk 7 (3 Theme + 4 Sidebar +
4 Modal + 3 DataTable + 4 Button + 1 Badge + 2 Input + 2 Tooltip
+ 1 IconButton + 2 Step E regression). Coverage target: ≥ 70 %
on `lib/components/` and `lib/stores/` combined (up from the
~86 % already-covered pure modules of Step D — the new tests
push the *component* file coverage from 0 % to substantial).

### 11.4 Tests that stay unit-level (no testing-library)

The Step D / E helper / API client tests stay as they are; they
exercise pure TS and don't need DOM rendering. The new component
tests live alongside them in `*.test.ts` files at the same path.

---

## 12. Implementation plan (chunks)

Step F is implemented in **8 chunks** (Chunk 4 is split into
4a spike + 4b rewrite), ~1-2 weeks at the single-developer pace
observed in Steps D and E.

Each chunk ends on a green test suite + a clean
`npm run check` + a clean `go vet` + Go test suite. Chunks are
committed and pushed separately.

### Chunk 1 — Design system foundation (≈ 1-1.5 day) — pair-live

Files:
- `web/frontend/src/lib/styles/tokens.css` (new)
- `web/frontend/src/app.css` (refactor: imports tokens, removes
  inline `:root` block)
- `web/frontend/src/app.html` (inline FOUC bootstrap script,
  `data-theme="dark"` default)
- `web/frontend/src/lib/stores/theme.svelte.ts` (new)
- `web/frontend/src/lib/components/Toggle.svelte` (new)
- `web/frontend/static/fonts/GeistMono-{400,500,600}.woff2` (new)
- `internal/auth/types.go` (+ `ThemePreference`)
- `internal/auth/userstore.go` (+ `UpdateThemePreference`)
- `internal/auth/userstore_test.go` (5 new tests)
- `internal/api/auth_handlers.go` (+ POST /auth/me/theme handler)
- `internal/api/routes.go` (mount new route in hard-auth subgroup)
- `internal/api/auth_handlers_test.go` (4 new tests)
- `web/frontend/src/lib/api/auth.ts` (typed wrapper for the new
  endpoint + `themePreference` field on `User` type)

**Sanity check — files NOT modified**: `internal/audit/actions.go`
stays untouched (§3.6 — no audit emission on theme change).
`internal/auth/sessionstore.go` stays untouched (no session-side
work needed). If a chunk-1 commit ends up touching either,
that's an unintended scope creep and the diff should be reviewed.

Mode: pair-live because backend changes + token surface choices
+ FOUC bootstrap are all decisions that benefit from explicit
review.

AC: `go test ./internal/auth/... ./internal/api/...` green;
POST /auth/me/theme returns 204 on valid body, 400 on invalid;
`npm run check` 0 errors; the FOUC script applies the cookie
theme on page load before any flash.

### Chunk 2 — Step E cosmetic bug fixes (≈ 0.5 day) — délégable

Files:
- `web/frontend/src/lib/stores/topology.svelte.ts` (orphan prune
  in `applyTick`)
- `web/frontend/src/lib/components/TopologyEdge.svelte` (pause
  spawn when not connected)
- `web/frontend/src/lib/stores/topology.test.ts` (+1 test:
  orphan prune)
- `MetricEdge.test.ts` (DEFERRED to Chunk 7 — targets the
  post-rewrite component, since `TopologyEdge.svelte` is
  deleted at Chunk 4b; the test also needs
  `@testing-library/svelte` which is installed at Chunk 7).

Mode: délégable; recap before commit.

AC: orphan prune regression test green; manual smoke check
(reproduce §5.f / §8 of Step E smoke) — empty state appears
within one tick after `DELETE /routes/{id}`; particles cease
within ~1 s of WS going `disconnected`.

### Chunk 3 — Atomic components refactor + animations lib choice (≈ 1-2 days) — délégable

Files modified (from §5.1 inventory):
- `lib/components/Modal.svelte`
- `lib/components/Button.svelte`
- `lib/components/Input.svelte`
- `lib/components/Card.svelte`
- `lib/components/Badge.svelte`
- `lib/components/Toast.svelte`
- `lib/components/Checkbox.svelte`
- `lib/components/Spinner.svelte`
- `lib/components/DataTable.svelte`
- `lib/components/StatusDot.svelte`
- `lib/components/StatCard.svelte`
- `lib/components/Sidebar.svelte` (refonte per §5.2)

Files new:
- `lib/components/Toggle.svelte` (already created in Chunk 1; not
  re-touched here)
- `lib/components/Tooltip.svelte`
- `lib/components/IconButton.svelte`
- `lib/components/PageHeader.svelte`

Topology components (`TopologyEdge`, `TopologyParticle`,
`TopologySvg`, `TopologyNode`, `TopologyDetailPanel`) are
**explicitly NOT touched here** — they are deleted or
restyled-only at Chunk 4b. Touching them in Chunk 3 would
generate work that the Chunk 4b delete throws away.

Decision point: animations lib choice. Bias is built-in
`svelte/motion`; if Chunk 3 finds it too anemic for the Theme
Toggle knob springs or Toast queue, switch to `motion` and
record the decision in the Chunk 3 commit message.

AC: every existing caller of every component renders identically
to before in dark mode (manual visual diff against a v0.3.0
screenshot — small visual diffs accepted, breaking layout
rejected); `npm run check` green; `npm run build` green;
existing Vitest pure tests still pass.

### Chunk 4a — Svelte Flow spike + go/no-go (≤ 1 day) — pair-live

Before committing to the full topology refonte, a focused spike
validates that `@xyflow/svelte` can deliver the Step F
requirements. Scope:

- Install `@xyflow/svelte` at the pinned alpha version.
- Stand up a minimal page (a sandbox route, not /topology) with
  3 nodes + 2 edges using a custom edge type.
- Implement a barebones particle layer on the custom edge.
- Drive a Svelte Flow `nodes` store with mock data and assert
  particles animate.
- Measure: 50-route synthetic topology pan/zoom — sustained 55+
  FPS on the dev machine.
- Measure: cold bundle size delta vs Step E baseline.

**Decision gate** at end of day 1:

- **GO** (Svelte Flow viable) → proceed to Chunk 4b (rest of the
  rewrite).
- **NO-GO** (custom edges API insufficient, perf below budget, or
  alpha breakage too severe) → fallback to Cytoscape.js wrapped
  in a Svelte component. Spec amendment required before Chunk 4b.

**Spike physical location and lifecycle**:

The spike page lives at
`web/frontend/src/routes/(spike)/flow/+page.svelte`. The
`(spike)` parentheses form a SvelteKit **route group** — the
directory organizes files without contributing a URL segment, so
the spike is reachable at `/flow` during `npm run dev`. The
underscore-prefix form (`_sandbox/`) is avoided because it has
no SvelteKit-native opt-out semantics — it would still ship a
real `/_sandbox/...` URL in the prod build, which we don't want.

Lifecycle:
- The spike directory IS committed at the end of Chunk 4a
  (single commit, message `spike(step-f): @xyflow/svelte
  feasibility — <GO|NO-GO>`) so the experimentation has a
  point-in-time reference in git history.
- The spike directory IS DELETED in the first commit of Chunk
  4b (or by the Chunk 4a commit itself if NO-GO is decided
  same day). The deletion is part of the Chunk 4b PR; no
  half-state left on `main`.
- The route group `(spike)/` is removed entirely once the
  feature work consumes the lessons.

Spike findings reporting: FPS measurements, bundle delta,
breaking-API issues found during the spike, and the GO/NO-GO
decision rationale are all written into the body of the
**Chunk 4b commit message** (or the Chunk 4a commit if NO-GO,
in which case the spec is amended before any Chunk 4b begins).
This is the authoritative record regardless of whether the
spike directory survives in git.

### Chunk 4b — Topology refonte (≈ 2-3 days) — pair-live

Following GO from Chunk 4a. Files (mostly new):

**Frontend**:
- `web/frontend/package.json` (+ `@xyflow/svelte`)
- `web/frontend/src/lib/components/topology/` (new directory):
  - `TopologyFlow.svelte` (replaces `TopologySvg.svelte`)
  - `nodes/ClientsPillar.svelte`
  - `nodes/RouteNode.svelte`
  - `nodes/UpstreamNode.svelte`
  - `edges/MetricEdge.svelte` (carries the particle layer)
  - `layout.ts` (computeLayout helper)
- `web/frontend/src/lib/api/topology-layout.ts` (typed wrapper
  for the new GET/POST `/topology/layout` endpoints — §6.5)
- `web/frontend/src/routes/topology/+page.svelte` (rewires to
  TopologyFlow, loads layout on mount via GET, debounced POST
  on drag-end)

**Backend** (NEW per §6.5):
- `internal/api/topology_handlers.go` (handlers for
  `GET /api/v1/topology/layout` and
  `POST /api/v1/topology/layout`, hard-auth gated)
- `internal/api/topology_handlers_test.go` (4 tests: auth gate,
  GET empty default, POST upsert + GET roundtrip, POST 400 on
  invalid payload)
- `internal/api/routes.go` (mount the two new routes in the
  hard-auth subgroup alongside `/routes` and
  `/ws/topology`)
- `internal/storage/topology_layout.go` (NEW BoltDB helper:
  bucket `topology_layouts`, `Get(userID) → map[routeID]{x,y}`,
  `Put(userID, positions)`)
- `internal/storage/topology_layout_test.go` (3 tests: empty
  bucket returns empty map, roundtrip put+get, unknown user
  returns empty map)
Files **DELETED** (4, per §6.4 table — every spawn/render
responsibility is rewritten inside `MetricEdge.svelte` and the
new node components):
- `web/frontend/src/lib/components/TopologyEdge.svelte`
- `web/frontend/src/lib/components/TopologyParticle.svelte`
- `web/frontend/src/lib/components/TopologySvg.svelte`
- `web/frontend/src/lib/components/TopologyNode.svelte`

Files **KEPT** (1, per §6.4 — preserved, restyled-only):
- `web/frontend/src/lib/components/TopologyDetailPanel.svelte`
  — token migration + Geist Mono for URL/timestamp; no
  structural change.

Mode: pair-live. The lib is alpha; we expect 1-2 dead-ends.

AC: `/topology` renders three columns of nodes; pan/zoom/fit-view
work; minimap toggleable; particles still flow on edges under
load; detail panel opens on node click; Step E smoke session
re-runnable (counter accuracy + 5xx + idle + spike + reconnect)
on the new topology surface.

### Chunk 5 — Pages Login/Setup/Routes/Audit refactor (≈ 1-2 days) — délégable

Files (modified):
- `web/frontend/src/routes/login/+page.svelte`
- `web/frontend/src/routes/setup/+page.svelte`
- `web/frontend/src/routes/routes/+page.svelte` (and components
  it uses)
- `web/frontend/src/routes/audit/+page.svelte` (+ AuditRow,
  AuditExpandedDetails)

Mode: délégable; visual review on each page after the chunk.

AC: **Step D regression check** — manual flow walkthrough
covering: login (valid + invalid creds), setup (only if fresh
binary, idempotent skip otherwise), routes CRUD (create + edit
+ delete each trigger a Caddy reload, verified via `/config`
on :2019), audit filters (by date range, by action) + cursor
pagination (Load more) + detail panel open/close. Plus
`go test ./...` green (unchanged from pre-Step-F). The full
formal `docs/smoke-test-step-d.md` re-run is NOT required at
Chunk 5 — it lives at the Step F post-Chunk-7 smoke
(§12.3); Chunk 5's check is the lighter "did I break Step D
behavior" pass.

Visuals match the Linear-like direction (manual eyeball, no
automated visual diff in scope).

### Chunk 6 — Settings page (≈ 0.5-1 day) — délégable

Files:
- `web/frontend/src/routes/settings/+page.svelte` (replaces
  placeholder)
- Possibly extract `lib/components/SettingsSection.svelte` if
  the section header pattern is reused (≥ 3 occurrences).

Mode: délégable.

AC: theme toggle works end-to-end (click → optimistic UI swap →
POST /auth/me/theme → cookie set → reload preserves theme);
sessions table renders the Step D data; revoke action works.

### Chunk 7 — Svelte component tests (≈ 1-1.5 day) — délégable

Files modified:
- `web/frontend/package.json` (+ `@testing-library/svelte`,
  `@testing-library/jest-dom`, `@testing-library/user-event`)
- `web/frontend/vitest.config.ts` (jsdom-aware setup hooks)
- `web/frontend/src/test/setup.ts` (already exists from Step
  D; extend with testing-library matchers)
- `web/frontend/src/lib/stores/topology.test.ts` (+ orphan
  prune test — Regression Guard A per §11.3)

Files new (10 test files, 26 tests total per §11.3):
- `web/frontend/src/lib/stores/theme.test.ts` (3 Theme tests)
- `web/frontend/src/lib/components/Sidebar.test.ts` (4)
- `web/frontend/src/lib/components/Modal.test.ts` (4)
- `web/frontend/src/lib/components/DataTable.test.ts` (3)
- `web/frontend/src/lib/components/Button.test.ts` (4)
- `web/frontend/src/lib/components/Badge.test.ts` (1
  parameterized over 7 variants)
- `web/frontend/src/lib/components/Input.test.ts` (2)
- `web/frontend/src/lib/components/Tooltip.test.ts` (2)
- `web/frontend/src/lib/components/IconButton.test.ts` (1
  parameterized over 3 sizes)
- `web/frontend/src/routes/topology/+page.test.ts` (2 tests —
  "route appears on tick" + spawn-pause per Regression Guard B)

Mode: délégable.

AC: `npm test` green with the new tests added; coverage on
`lib/components/` ≥ 70 %; the two Step E regression guards
(orphan prune, spawn-pause-on-disconnect) explicitly green.

### 12.1 Sequencing

Strict serial 1 → 2 → 3 → **4a → 4b** → 5 → 6 → 7. Rationale:

- Chunk 1 is a hard prerequisite for every subsequent chunk
  (tokens, theme store).
- Chunk 2 stands alone but lives close to topology code, so
  doing it before Chunk 4 means Chunk 4's rewrite carries the
  fix forward without re-applying.
- Chunk 3 (atomic components) before Chunks 4-5-6 because those
  consume the refactored components.
- Chunk 4 (topology refonte) is the highest-risk chunk; doing it
  before Chunks 5-6 means a setback there doesn't block
  shippable polish on the other pages.
- Chunks 5-6 are independent of each other in principle, but
  serial keeps single-developer focus.
- Chunk 7 (tests) last because it benefits from a stable
  component surface to test against.

### 12.2 Tag plan

**"Spec freeze" definition**: all 5 review passes complete
(messages 1/5 → 5/5 affichés et corrigés), zero outstanding
correction queued, final spec content committed and pushed to
`main`. Once these conditions hold, the tag is created on that
commit.

Tags:
- `v0.4.0-step-f-spec` immediately after spec freeze, on the
  commit that ships the final spec content.
- Each implementation chunk pushed as one or more commits on
  `main`.
- Post-Chunk-7 smoke validation → tag `v0.4.0-step-f` on HEAD
  (the smoke doc commit).

### 12.3 Smoke validation (post-Chunk 7)

A `docs/smoke-test-step-f.md` (new file, mirrors the Step E
pattern) covers:
- Theme toggle end-to-end (cookie + reload preserves).
- Step D smoke (login → setup → routes → audit) still passes
  end-to-end on the new visuals.
- Step E smoke (counter accuracy, WS auth, topology smoke,
  reconnect) still passes on the new TopologyFlow.
- New component tests `npm test` green.
- Visual sanity check on every page in BOTH dark and light
  modes. **Format**: manual eyeball pass by the developer, no
  automated visual-diff tooling in scope. Screenshots of each
  page in each mode are taken and archived under
  `docs/visual-baseline/v0.4.0-step-f/` (PNG, ~10 files: 5
  pages × 2 modes). Filename convention:
  `<page>-<mode>.png` (e.g., `routes-dark.png`). These are
  reference images for future Phase 2 work; they are NOT a
  pass/fail gate at smoke time, just an artifact.

---

## 13. Acceptance criteria

Step F is accepted when all of the following hold:

1. **Token system**: every component file references `--*` CSS
   variables, never hard-coded hex/px values for color, spacing,
   radius, or shadow. `grep -rE '#[0-9a-fA-F]{3,8}' web/frontend/src/lib/components/`
   returns ≤ 5 lines (allowing for SVG `stroke="currentColor"`
   and the literal "Arenet" cyan in the wordmark).

2. **Light/dark toggle**: clicking the Settings → Appearance
   toggle swaps the theme within 200 ms (no flash); refreshing
   the page preserves the choice; logging out + logging back in
   restores the persisted preference from the server.

3. **FOUC**: opening `/login` directly with `arenet_theme=light`
   cookie set produces a light-themed page on FIRST paint, no
   dark flash. (Verified via DevTools → Network → throttle to
   Slow 3G; the inline script in `<head>` runs synchronously.)

4. **No regression on Step D / E**: every section of
   `docs/smoke-test-step-d.md` and `docs/smoke-test-step-e.md`
   still passes against the post-Step-F binary + frontend build.

5. **Topology refonte functional parity**: the §5 of the Step E
   smoke (particles flow under load, idle after 60 s, spike
   under 503, detail panel opens) passes on the new Svelte Flow
   surface. Plus: pan/zoom/fit-view/minimap-toggle work.

6. **Step E cosmetic bugs fixed**: deleting a route from the
   /routes page makes it disappear from /topology within ≤ 2 s
   (next tick); particles cease spawning within ~1 s of the WS
   indicator changing to `reconnecting…` OR `disconnected`
   (both statuses trigger the spawn pause per §7.2 — the check
   is `connectionStatus !== 'connected'`, not a single-status
   guard).

7. **Settings page** delivers: theme toggle, sessions table with
   revoke, About section. Change password reachable via existing
   modal.

8. **Tests**: `npm test` green; coverage on
   `web/frontend/src/lib/components/` ≥ 70 %; the Step E
   reactivity regression guards (orphan prune, spawn-pause)
   are explicitly named tests in the suite.

9. **Type safety**: `npm run check` 0 errors throughout.
   `go vet ./...` clean.

10. **AGPL headers** present on every new file (Go and
    Svelte/TS).

11. **Bundle budget**: production build's main entry chunk ≤
    **500 kB gzipped** (Step E was ~250 kB; Svelte Flow ~80 kB
    minified; Geist Mono ~60 kB total; the rest is room for the
    component refactor + animations lib). Hard upper bound. The
    first authoritative measurement happens at **Chunk 4a
    (spike bundle delta)**; if the spike alone already pushes
    past 500 kB, lazy-load TopologyFlow behind a route-level
    dynamic import in Chunk 4b before the cap is hit.

12. **A11y baseline**: keyboard nav works on Sidebar, primary
    actions reachable via Tab; visible focus rings on every
    interactive element in both themes. **Manual smoke scope**
    = Tab through the Sidebar all 5 items, Tab through each
    page's primary action(s), confirm a visible focus ring in
    dark AND light. **Out of scope for Step F**: screen-reader
    pass, ARIA semantic audit, axe-core run. Those land in
    Phase 2 (Step F+1).

---

## 14. Risks and trade-offs

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `@xyflow/svelte` alpha API breaks across versions | Medium | High | Pin exact version in `package.json`; capture the import surface used in Chunk 4 commit message; fallback to Cytoscape if integration spike day 1 fails |
| Theme tokens force a longer Chunk 3 than planned | Medium | Medium | Cap Chunk 3 at 2 days; if not done, defer non-critical atoms to Chunk 6 |
| Font swap (Inter unchanged, +Geist Mono) causes layout shift | Low | Low | Use `font-display: swap` (already on Inter); test FOUT visible only on first load |
| FOUC bootstrap script blocks first paint | Low | Low | The script is < 500 bytes minified (cap from §4.3), fully synchronous, executes in microseconds — measured at Chunk 1 |
| Particle layer on Svelte Flow edge re-renders mis-aligns | Medium | Medium | Bind path ref on every render; integration test in Chunk 4b alongside the rewrite (NOT Chunk 4a spike — the spike only validates the lib's viability, not particle alignment edge cases) |
| Component prop changes break callers despite the "add-only" rule | Low | High | Run `npm run check` after every component edit; if it errors, that's a discipline violation — rollback the offending change and add the prop additively instead (NEVER rename / NEVER remove). The pre-existing prop must remain backward-compatible across the entire refactor. |
| Bundle exceeds 500 kB | Medium | Medium | Tree-shake `@xyflow/svelte` imports; lazy-load TopologyFlow behind a dynamic import if needed; first measurement at Chunk 4a spike (§13 AC #11) |
| Svelte 5 reactivity gotchas (Step E §11.8) surface again | Medium | Medium | The store keeps the explicit `version` counter pattern; new components consuming the store follow the same `void topology.version` discipline; documented in §7 and tested in §11 |

---

## 15. Out of scope / Phase 3 deferrals

- Logo design (placeholder text only).
- Mobile / responsive layout.
- i18n.
- High-contrast / colorblind palettes.
- "Follow system theme" option.
- Component library extraction.
- A11y full audit.
- Animation orchestration beyond a single lib.
- Edge creation in topology (Phase 3 — potentially Step G for security policies).
- Theme inheritance across multiple users — see §1.2 for the
  forward-compat rationale; Step F is single-admin, the
  per-user column on `User` is already the right shape.

---

## 16. Open questions

None at spec-freeze time. Decisions resolved during the
brainstorm session 2026-05-19:

- Direction: Linear-like dark + light with cyan accent.
- Font: Inter + Geist Mono.
- Persistence: server-side User column (theme) + BoltDB bucket `topology_layouts` (node positions, §6.5) + cookie `arenet_theme` for FOUC bootstrap (§4.5).
- Logo: placeholder text "Arenet".
- Animations: rich, generalized, lib choice at Chunk 3.
- Topology: rewritten on `@xyflow/svelte` (alpha,
  fallback Cytoscape).
- Tests: `@testing-library/svelte` user-behavior + Step E
  regression guards.
- Step E bugs to fix: orphan prune + spawn-pause-on-disconnect.
- Phase 2 carry-over: Svelte component tests.
- Chunks: 8, serial (Chunk 4 split into 4a spike + 4b rewrite).

If an implementation chunk uncovers an ambiguity, **amend the
spec before diverging** (Step D / E rule).

### 16.1 Spec evolution

For audit and process learning: the spec went from **1344
lines** at T0 (initial draft) → **~1920 lines** at freeze
across **5 review passes**:

| Pass | Section coverage | Corrections applied |
|---|---|---|
| Pre-review | §1-§17 initial draft | 10 self-identified + brainstorm-decision integration |
| Review 1 (§1-§4) | foundations | 10 corrections |
| Review 2 (§5-§7) | components + topology + bugs | 12 corrections |
| Review 3 (§8-§11) | pages + animations + tests | 13 corrections |
| Review 4 (§12) | implementation plan | 14 corrections |
| Review 5 (§13-§17) | AC + risks + refs + sanity | 17 corrections |

Total: **76 corrections** across the freeze process (10 pre +
10 + 12 + 13 + 14 + 17). Each pass tightened the spec against
inconsistencies the previous one introduced or surfaced. The
multi-pass discipline caught: 5 path mismatches, 3 verb
inconsistencies (PATCH→POST), 2 numerical alignment errors
(bundle budget, motion timing), and several cross-section
contradictions (e.g., TopologyParticle KEPT vs DELETED).

---

## 17. References

### External

- Svelte Flow (`@xyflow/svelte`): https://svelteflow.dev
- xyflow repo: https://github.com/xyflow/xyflow
- Testing Library Svelte: https://testing-library.com/docs/svelte-testing-library/intro
- Geist Mono: https://vercel.com/font
- Linear's design system writeup: https://linear.app/blog/the-linear-method
- WCAG AA contrast checker: https://webaim.org/resources/contrastchecker/

### Repo-internal

- v0.3.0-step-e tag at SHA `5916045` (Topology + live metrics).
- `docs/smoke-test-step-d.md` (Step D smoke procedure — exists).
- `docs/smoke-test-step-e.md` (Step E smoke procedure — exists).
- `docs/superpowers/specs/2026-05-18-step-e-topology-design.md`
  (Step E spec).
- `docs/superpowers/specs/2026-05-17-step-d-auth-design.md`
  (Step D spec).
- `docs/roadmap.md` (Phase 2 test debt entry).
- `docs/smoke-test-step-f.md` — **TO BE CREATED** at
  post-Chunk-7 smoke validation (§12.3); does not exist at
  spec-freeze time.
