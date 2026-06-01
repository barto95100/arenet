# Step R — OKLCH visual migration + sidebar/topbar refonte + IA reorg

**Status**: FROZEN 2026-05-31 — 8 decisions arbitrated (D1=A, D2=A, D3=A, D4 re-framed, D5=A, D6=A, D7=A, D8=B added + resolved 2026-06-01). Rationale-of-record locked.
**Author**: Ludo + Claude.
**Predecessor**: Step P (auto-classify loop, tagged `v1.3.0-step-p`).
**Map page deferred** to a later step — Step R does NOT introduce the `/map` route; the sidebar nav item is added but the screen ships in a future iteration.

---

## 1. Goal & scope

### 1.1 Goal

Replace the current HEX-cyan visual system (legacy Step E / Step F polish era) with a cohesive **OKLCH-based design system**, drive consistency across all admin pages, and reorganise the IA so that the sidebar matches operator mental groupings (Aperçu / Trafic / Sécurité / Administration) instead of the flat alphabetical-ish list shipped today. The visual reference is the mock at `docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html` (3274 lines, copied from `docs/mocks/pages/index.html` on 2026-05-31). The mock is **source-of-truth** for tokens, dimensions, typography, sidebar/topbar markup, and per-screen layout. Chunks that diverge from it are bugs, not features.

The migration is operator-visible: it touches every page (`/dashboard`, `/topology`, `/routes`, `/waf`, `/security`, `/logs`, `/certs`, `/users`, `/settings`) but does **not** change underlying data flows. Smoke flows from L+M+Q+N+O+P MUST pass unchanged on the new visual — Step R is a presentation layer rewrite, not a functional rework.

### 1.2 Scope (5 sub-tasks — mirror M/Q/N/O/P cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| R.1 | Design tokens + typography foundation | OKLCH CSS custom properties (bg / surface / fg / accent / status) in `app.css`, self-hosted Inter + JetBrains Mono via `@font-face`, `font-variant-numeric: tabular-nums` on body, radii + sidebar/topbar dimension constants. No page-level changes yet — the tokens land first so R.2/R.3/R.4 can consume them. |
| R.2 | Layout chrome refonte | New `Sidebar.svelte` (232px wide, 4 nav-sections, brand block top, sidebar-foot bottom) + new `Topbar.svelte` (56px sticky, backdrop-blur 8px, crumbs + status + search + view-as toggle + notifications + Déployer primary). Replaces today's flat sidebar + light topbar. Active-nav state uses `inset 2px 0 0 var(--accent)` rail. |
| R.3 | IA reorganisation | Sidebar groups: **Aperçu** (Dashboard, Topology, Map-deferred), **Trafic** (Routes, Logs), **Sécurité** (WAF, Security, Certificates), **Administration** (Utilisateurs, Settings). `/certs` promoted out of `/settings/certificates` to a top-level route. `/waf` vs `/security` split confirmed per D4 (WAF = rules config, Security = events + decisions + automation). Map nav item present but routes to a "Coming soon" placeholder. |
| R.4 | Per-page migration | Every existing page rewritten in the new visual: `/dashboard` (KPI cards + traffic chart + recent events), `/topology` (graph in OKLCH palette), `/routes` (table with new row hover + status pills), `/waf` (Coraza paranoia + CRS categories + IP/country lists), `/security` (events + decisions + automation cards from Step P), `/logs`, `/certs`, `/users`, `/settings`. No HEX cyan legacy anywhere. |
| R.5 | Smoke + verdict | Anti-regression matrix: re-run L/M/Q/N/O/P functional smoke flows on the new visual. Bundle delta measurement (gz). Self-hosted-fonts no-internet check. Page-coverage check (grep for legacy HEX cyan returns zero matches). Verdict doc at `docs/smoke-test-step-r.md`. |

### 1.3 What this step DOES NOT do

- **Map page**: deferred to a later step (real feature work — geo-IP DB shipping, map rendering, marker logic). Step R adds only the sidebar entry + placeholder route.
- **Theme switching / light mode**: see D2; default reco is single dark theme, no toggle.
- **D3.js topology animation rework**: the graph keeps its current animation logic; only the palette + node/edge colours migrate to OKLCH tokens.
- **New endpoints / new data models**: zero backend changes outside of trivial settings-shape touch-ups if a new toggle (e.g. view-as) needs persistence. D6 recommends keeping view-as pure visual for v1.4 so no backend touch is needed.
- **Component library extraction**: components stay co-located under `web/frontend/src/lib/components/`. No design-system package, no Storybook.

---

## 2. Decisions (arbitrated)

All 7 decisions arbitrated 2026-05-31. Each entry: outcome → rationale-of-record.

### D1 — Migration cadence: big bang ✓ (Outcome: A)

**Outcome**: big-bang in R.4. All pages migrated within the same step; no `/dashboard` operating in OKLCH while `/topology` still ships legacy HEX cyan.

**Rationale-of-record**: pages share the same chrome (Sidebar + Topbar) and the same token table. Staggering across sub-steps would force users to navigate a half-migrated app for the duration of the rollout, with two visual languages clashing on every page transition. The mock is page-by-page complete; per-page work is mechanical (token swap + markup swap), reviewable as one coherent change against the mock as ground truth. R.4 becomes a large commit but the visual coherence pay-off outweighs the diff size; R.5 smoke verifies functional anti-regression on top.

### D2 — Theme system: single dark theme ✓ (Outcome: A)

**Outcome**: single dark theme. No light-mode toggle. No `:root[data-theme="light"]` overrides shipped in v1.4.

**Rationale-of-record**: zero demonstrated demand for light mode in the homelab operator audience; doubling the QA surface for a feature nobody asked for is unjustified scope. OKLCH tokens make a future light fork cheap (perceptual lightness component lets a future step flip the L-channel scale without re-doing the colour design) — keeping the door architecturally open costs nothing today, so deferring is free.

### D3 — Fonts: self-hosted ✓ (Outcome: A)

**Outcome**: self-hosted Inter + JetBrains Mono via `@font-face`, WOFF2 bundled into the Go binary through SvelteKit static adapter + `embed.FS`. No CDN reference.

**Rationale-of-record**: Arenet's homelab deployment context is explicitly disconnected-friendly. The admin UI MUST boot and render with full typography without internet egress; CDN fonts fail this requirement. Self-hosting also eliminates the privacy leak of every admin-UI page load probing Google Fonts with the homelab IP. Asset cost (~80-120kB WOFF2 per family, Latin + common-punctuation subset) is acceptable under the AC #2 bundle budget.

### D4 — `/waf` vs `/security`: BOTH config, scoped differently ✓ (Re-framed)

**Outcome**: re-framed away from the original "config vs ops" recommendation. Both pages are configuration surfaces, scoped along WAF-specific vs cross-cutting security policy.

- **`/waf` = WAF-specific configuration**. Coraza paranoia level, OWASP CRS category granular toggles (SQLi / XSS / RCE / LFI / Scanners / PHP / Protocol Violations / Bot Detection), per-route rate limits, IP allow/deny manual lists, geo-blocking lists.
- **`/security` = cross-cutting security configuration**. Global TLS config (min version, curves, ciphers, HTTP/3, OCSP stapling, session ticket rotation), security headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy with nonce, Permissions-Policy), authentication providers (OIDC, forward-auth, basic-auth legacy).

**Rationale-of-record**: the mock's eyebrow text on each page (`:2179` "Sécurité · Web Application Firewall" + `:2280` "Sécurité · Configuration TLS et headers") confirms the scoping: both pages are policy/config, just different attack surfaces. The original "ops" interpretation (events + decisions + automation in `/security`) does NOT match the mock — those operational dashboards live elsewhere (the events stream surfaces in the Dashboard's "Événements WAF récents" card; decisions and automation move into a Security Automation card under Settings, where Step P's `/settings/automation` already lives).

**Critical scope implication**: a large share of widgets in both `/waf` and `/security` are mock-promised but NOT backend-implemented today (geo-blocking, manual IP lists, OWASP CRS granular toggle API, global TLS curve/cipher overrides, CSP with nonce injection, security headers controller). These are explicitly out-of-scope for Step R — see §6 "Out-of-scope (exhaustif)" for the full per-page audit and the placeholder strategy.

### D5 — `/certs` promotion: move ✓ (Outcome: A)

**Outcome**: move `/settings/certificates` → top-level `/certs`. The old URL is removed (a SvelteKit redirect from `/settings/certificates` → `/certs` ships as a safety net for in-repo links during the transition; removed in v1.5).

**Rationale-of-record**: Arenet is pre-1.0; no public bookmark surface to preserve. A duplicate route creates canonicalisation drift (two URLs maintaining the same eyebrow + h1 content). The mock places Certificates at top level under Sécurité, signalling that operators view cert state independently of the Settings configuration grid.

### D6 — View-as toggle: cosmetic-only ✓ (Outcome: A)

**Outcome**: view-as toggle (topbar `:731`) ships as a cosmetic UI affordance in v1.4. Clicking toggles a body class that greys out mutation buttons for visual preview; backend session permissions are unchanged. Tooltip: "Aperçu visuel — l'application des permissions arrive dans une étape future".

**Rationale-of-record**: a real viewer mode requires rebuilding the K-era auth gate at every route + scrubbing API responses to honour role + adding a back-channel so the visual state can't be bypassed by URL manipulation. That's a focused security-correctness step in its own right (likely Step T or later). For v1.4, removing the toggle from the mock would leave a gap in the topbar layout; shipping it as cosmetic preserves the visual + signals direction without making security-correctness claims the implementation doesn't back.

### D7 — Animation: CSS transitions only ✓ (Outcome: A)

**Outcome**: hover/active state animations via CSS `transition` only. No motion library (no `motion-one`, no Framer-equivalent). Svelte's built-in `transition:fade` directive may be used sparingly for page-level transitions if needed.

**Rationale-of-record**: the mock's motion vocabulary is hover-on-button + fade-in-on-load + active-row rail indicator — all expressible in `transition: <prop> <duration> <easing>`. No spring physics, no orchestrated sequences. Adding a motion library adds bundle weight + dependency surface for what amounts to hover states. Future motion needs (coordinated dashboard tile reveal etc.) would justify a follow-up step.

### D8 — Sort des sous-routes `/security/decisions` et `/security/[routeId]` ✓ (Outcome: B — Resolved 2026-06-01)

**Question**: la D4 reframing repurpose `/security` (events page) en page de configuration cross-cutting (TLS + headers + auth providers). Mais le code actuel a déjà DEUX sous-routes attachées au namespace `/security/` :

- `/security/decisions` — timeline des decisions CrowdSec + filtres + 4-source attackers union (shipped M.1 + N + Q + P).
- `/security/[routeId]` — drill-down par-route (sécurité par route — quels events, quelles decisions, quel auth-burst).

Le mock prend `/waf` comme surface WAF-spécifique avec une card compacte "IP — listes" (4 entrées visibles) qui ne reproduit ni la timeline complète des decisions, ni les drill-downs per-route. Prendre le mock littéralement = ces deux sous-routes disparaissent (régression fonctionnelle).

**Options**:

- **(a) Consolider dans `/waf` minimal**. La card "IP — listes" du mock remplace la timeline + les drill-downs. Perte fonctionnelle nette. **REJETÉE** au brief : Step R = aesthetic migration PURE, anti-régression fonctionnelle est l'AC #1.
- **(b) Routes préservées, invisibles en sidebar, accessibles via "Voir tout" link**. `/security/decisions` et `/security/[routeId]` restent comme aujourd'hui (re-skinnées en OKLCH dans R.4 mais inchangées fonctionnellement). Pas d'entrée sidebar dédiée. Le `/waf` "IP — listes" card a un footer link "Voir toute la timeline →" qui pointe vers `/security/decisions`. La page `/routes` détail-row a un link "Sécurité de cette route →" qui pointe vers `/security/[routeId]`. Coût: ~zéro re-routing (les routes existent déjà, on rajoute deux links). Pas de perte.
- **(c) Sub-routes sous `/waf` (`/waf/decisions`, `/waf/route/[id]`)** OU restent sous `/security/` avec sub-nav interne (tabs ou breadcrumb-secondaire). Forte préservation IA, "tout ce qui est WAF est sous /waf" comme principe. Coût: re-routing des deux sous-routes (déplacement de `web/frontend/src/routes/security/decisions/` → `web/frontend/src/routes/waf/decisions/` etc.) + breaking changes sur les liens internes.

**Reco**: **(b)**. Zéro régression fonctionnelle (alignement AC #1), zéro re-routing, coût ~deux liens à ajouter. Les sous-routes restent organisées sous `/security/` parce que c'est le namespace que M+N+Q+P utilisent dans leur code (storage layer, audit, REST handlers `/api/v1/security/*` etc.) — re-router le frontend sans toucher le backend force une dissociation namespace-URL qui rend le code plus dur à suivre. L'invisibilité sidebar est OK : les entry points naturels (`/waf` card + `/routes` detail) couvrent l'accès opérationnel.

Si (c) est préféré pour des raisons IA fortes ("tout WAF sous /waf"), version pragmatique : déplacer SEULEMENT la timeline (`/security/decisions` → `/waf/decisions`) mais garder le drill-down per-route sous `/security/[routeId]` parce qu'il aggrège auth-burst + throttle + WAF ensemble (pas un drill-down WAF-only). Moitié-(c) qui évite la dissociation backend/frontend la plus grossière.

**Outcome (2026-06-01)**: option **(b)** — routes préservées, invisibles en sidebar. Reasoning: zéro régression fonctionnelle (AC #1), zéro re-routing, coût ~deux liens à ajouter. (c) aurait été plus IA-propre mais re-routing = surface de risque inutile pour un step aesthetic-only. R.3 implémente cette IA; R.4 ajoute les deux liens "Voir toute la timeline →" (depuis card "IP — listes" du `/waf`) et "Sécurité de cette route →" (depuis row detail de `/routes`).

---

## 3. Acceptance criteria

Smoke harness for R.5 runs each AC against the running binary at `localhost:8080`.

| # | AC | How to verify |
|---|----|---|
| 1 | **Anti-regression fonctionnelle** — every smoke flow shipped in L+M+Q+N+O+P passes UNCHANGED on the new visual. | Re-run each step's smoke harness against the R-branch binary. Each step's existing PASS verdict must hold (no functional behaviour change). |
| 2 | **Bundle delta budget** — gz frontend bundle grows by ≤ +8kB compared to v1.3 baseline (HEX cyan visual), measured at `web/build/_app/immutable/`. Fonts excluded (separate self-hosted asset budget). | `du -sb` on built assets before/after; document the delta in `docs/smoke-test-step-r.md` §B. Budget +5kB is the reco from the user framing; +8kB is the hard ceiling. |
| 3 | **Self-hosted fonts no internet** — Arenet boots and renders all pages with full typography while network egress is blocked. | Smoke harness phase: `iptables` block outbound 443 + 80 → start binary → load every page → confirm Inter + JetBrains Mono rendered (not system-fallback). Visual diff or `getComputedStyle().fontFamily` check. |
| 4 | **All pages migrated** — zero HEX cyan legacy references in any `.svelte` / `.css` / `.ts` file under `web/frontend/src/`. | `grep -riE '#(00d9ff\|0ea5e9\|22d3ee\|legacy-cyan-pattern)' web/frontend/src/` returns no matches. Hard fail otherwise. |
| 5 | OKLCH tokens are the SOLE colour authority — pages reference `var(--accent)` etc., never inline hex/rgb/hsl. | grep for inline `#[0-9a-f]{6}` and `rgb(` in `.svelte` files; allowed only in `app.css` token definitions. |
| 6 | Sidebar matches mock 4-section structure (Aperçu / Trafic / Sécurité / Administration) with the 10 nav items as listed in `docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:655-714`. Map nav item routes to a `<ComingSoon />` placeholder. | DOM inspection on `/dashboard`: 4 `<div class="nav-section">` blocks, each with the expected items. `/map` returns a 200 with the placeholder component. |
| 7 | Topbar is 56px high, sticky, with backdrop-blur 8px, contains crumbs + status + search + view-as + notifications + Déployer button — per mock `:720-741`. | DOM + computed-style inspection. |
| 8 | View-as toggle (D6) — clicking it toggles a body class but issues NO mutation-permission change at the backend. | Click toggle → POST to a route still succeeds with admin session (proof the toggle is cosmetic). |
| 9 | Active-nav rail uses `box-shadow: inset 2px 0 0 var(--accent)` per mock `:701`. | Computed style check on the active nav item. |
| 10 | `font-variant-numeric: tabular-nums` on body (load-bearing for KPI alignment). | Computed style check on `<body>`. |
| 11 | `/certs` exists at top level and `/settings/certificates` does NOT exist (D5 move). | HTTP 200 on `/certs`, HTTP 404 on `/settings/certificates`. |
| 12 | `/waf` and `/security` are distinct pages with distinct purposes per D4. | `/waf` has the Coraza paranoia / CRS / IP-list components; `/security` has the events / decisions / automation cards. |
| 13 | Standard lint/test gates pass: `gofmt -s` clean, `go vet ./...` clean, `staticcheck ./...` clean, `go test ./...` green, `npm run check` green, `npm run build` green. | Run each command. |
| 14 | Accessibility — interactive elements still have proper ARIA labels (CLAUDE.md frontend rule). | axe-core or manual audit on Dashboard + Routes + WAF. |

---

## 4. Architecture

### 4.1 Token foundation (R.1)

`web/frontend/src/app.css` gains the OKLCH token block, sourced verbatim from the mock at `docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:11-44`:

```css
:root {
  --bg:           oklch(15% 0.005 250);
  --surface:      oklch(19% 0.006 250);
  --surface-2:    oklch(22% 0.007 250);
  --surface-hi:   oklch(26% 0.008 250);
  --border:       oklch(28% 0.009 250);
  --border-hi:    oklch(34% 0.011 250);
  --fg:           oklch(96% 0.005 250);
  --fg-muted:     oklch(68% 0.012 250);
  --fg-dim:       oklch(54% 0.011 250);
  --accent:       oklch(68% 0.21 255);
  --accent-soft:  oklch(68% 0.21 255 / 0.14);
  --accent-line:  oklch(68% 0.21 255 / 0.45);
  --ok:    oklch(72% 0.16 150);
  --warn:  oklch(80% 0.14 85);
  --bad:   oklch(66% 0.20 25);
  --info:  oklch(72% 0.12 230);
  --radius: 8px; --radius-sm: 6px; --radius-lg: 12px;
  --sb-width: 232px; --tb-height: 56px;
}
```

Fonts via `@font-face` in the same file, with WOFF2 files placed under `web/frontend/static/fonts/` and embedded by the SvelteKit static adapter → `embed.FS` Go binary. Latin + common-punctuation subset only.

`body { font-family: var(--font-body); font-variant-numeric: tabular-nums; background: var(--bg); color: var(--fg); }`.

### 4.2 Chrome (R.2)

`web/frontend/src/lib/components/Sidebar.svelte` — replaces the current sidebar. Structure mirrors mock `:655-714`:
- `.sb-brand` block: 30px gradient mark + name "Arenet" + env pill (HOMELAB / PROD per backend env detection).
- 4 `.nav-section` blocks with labels Aperçu / Trafic / Sécurité / Administration.
- 10 `.nav-item` links: Dashboard, Topology, Map, Routes, Logs, WAF, Security, Certificates, Utilisateurs, Settings.
- Active state via SvelteKit `$page.url.pathname` matching → applies `.nav-item.active` class with the inset rail per mock `:701`.
- `.sb-foot` block: avatar + who block (current user from K-era auth context).

`web/frontend/src/lib/components/Topbar.svelte` — replaces the current topbar. Structure mirrors mock `:720-741`:
- Sticky, 56px, backdrop-blur 8px, `oklch(17% 0.006 250 / 0.85)` background.
- Crumbs slot (filled by each page via the layout `<svelte:head>` pattern).
- Status dot + text (LAPI connection status, surfaces N's connectivity state).
- Search input with `⌘K` kbd hint (v1.4 wires this to a basic route-filter; full command-palette deferred).
- View-as toggle (D6: cosmetic only).
- Notifications button (badge count from any error-state events; deep-link to `/security`).
- Déployer primary button (current "Apply pending changes" semantics from Step I).

`web/frontend/src/routes/+layout.svelte` is rewritten to use these two components. The existing layout's `<header>` and `<aside>` are removed.

### 4.3 IA reorg (R.3)

Current routes (audited 2026-05-31): `observability`, `observability/[routeId]`, `security`, `security/[routeId]`, `security/decisions`, `routes`, `admin/users`, `settings`, `audit`, `topology`, `login`, `setup`. No `/dashboard`, no `/waf`, no `/logs`, no `/certs`, no `/map`, no top-level `/users`.

Sidebar groupings finalised:

| Section | Items | Target route | Migration action |
|---------|-------|--------------|------------------|
| Aperçu | Dashboard | `/dashboard` | NEW — content sources from existing `/observability` (rename + restructure). |
| Aperçu | Topology | `/topology` | EXISTS — palette migration only. |
| Aperçu | Map | `/map` | NEW placeholder — `<ComingSoon />` component, feature DEFERRED. |
| Trafic | Routes | `/routes` | EXISTS — palette + markup migration. |
| Trafic | Logs | `/logs` | NEW — content sources from observability log tail subset (separate page in mock). |
| Sécurité | WAF | `/waf` | NEW — WAF-specific configuration (D4 reframed). Most widgets out-of-scope (see §6). |
| Sécurité | Security | `/security` | EXISTS as `/security` events page TODAY; in R.3 it's REPURPOSED to cross-cutting security policy config (TLS + headers + auth providers per D4). Events/decisions content moves to Dashboard's "Événements WAF récents" + a Security Automation card under Settings. |
| Sécurité | Certificates | `/certs` | NEW — content sources from existing certs storage backend (`internal/caddymgr/` ACME); no existing UI route, mock provides the visual. |
| Administration | Utilisateurs | `/users` | NEW — content moved from `/admin/users` (sidebar entry collapses the `/admin/` namespace). |
| Administration | Settings | `/settings` | EXISTS — palette + markup migration. |

**Route changes recap**:

- Create: `/dashboard`, `/logs`, `/waf`, `/certs`, `/map`, `/users`.
- Rename or absorb: `/observability` → split into `/dashboard` (KPIs + traffic chart + WAF events card) + `/logs` (live tail + filter); `/admin/users` → `/users`; `/security/decisions` → folded into the Security Automation card under `/settings` (kept the data view as a sub-page accessible via the card, but the standalone route disappears from sidebar).
- Repurpose: `/security` page content swaps from events/decisions display to TLS+headers+auth-providers configuration (D4).
- Keep: `/topology`, `/routes`, `/settings`, `/audit`, `/login`, `/setup`.
- Migration alias: SvelteKit redirect `/settings/certificates` → `/certs` for one release (per D5 safety net); `/admin/users` → `/users`; `/observability` → `/dashboard`; `/security/decisions` → `/settings#security-automation`.

`/map` placeholder: `web/frontend/src/routes/map/+page.svelte` renders a `<ComingSoon />` component with copy explaining the geo-IP feature is scheduled for a later step.

### 4.4 Per-page migration (R.4)

Each page rewritten in the new visual. The mechanical pattern per page:

1. Replace wrapper chrome with new Sidebar + Topbar (handled via `+layout.svelte` rewrite, so per-page no-op for the chrome).
2. Set the page's `screen-head` block (eyebrow + h1 + sub) per the mock's per-screen content.
3. Replace inline colour with token references (`var(--accent)`, `var(--bad)`, etc.).
4. Replace component-local styling that conflicts with the new tokens (button sizing, radius, hover states) — defer to mock `.btn` / `.tb-btn` / `.card` / `.kpi` patterns.
5. For widgets backed by an out-of-scope backend (per §6 audit), ship the placeholder strategy: either inline panel "Coming Soon — feature deferred to Step X" OR omit the section entirely (page shorter than mock but coherent with implemented sections). Decision per widget is taken in §6 audit.
6. Verify with the smoke check (R.5) that all functional paths still work.

Mock anchors per page:

| Page | Route | Mock anchor (file:line) |
|------|-------|------|
| Dashboard | `/dashboard` | `:749-950` |
| Topology | `/topology` | `:952-2014` |
| Routes | `/routes` | `:2015-2174` |
| WAF | `/waf` | `:2176-2274` |
| Security | `/security` | `:2277-2349` |
| Logs | `/logs` | `:2352-2400` |
| Certs | `/certs` | `:2403-2439` |
| Users | `/users` | `:2443-2710` |
| Settings | `/settings` | `:2712-2777` |

Anchors verified during the 2026-05-31 audit (see §6).

### 4.5 Audit + telemetry

No new audit actions. No new metrics. R.4 may add a single audit row `ui_view_as_toggled` if D6 lands as cosmetic and we want a trail of toggle clicks for future RBAC design input — TBD, default OFF.

---

## 5. Risks & mitigations

| Risk | Mitigation |
|------|------|
| **Large mechanical diff in R.4** drowns out a real regression in code review. | R.4 split into per-page commits even though it ships in one step; each commit reviewable against the corresponding mock section. Smoke harness in R.5 verifies functional anti-regression on top of the visual review. |
| **Self-hosted fonts inflate the Go binary** more than budget. | Subset Latin + common punctuation only; gzip via the SvelteKit static adapter. Measure in R.5 AC #2 and AC #3. If over budget, fall back to subsetting to specific glyphs used in the UI. |
| **OKLCH browser support** (older browsers fail to parse the colour function). | OKLCH is supported in all evergreen browsers (Chrome 111+, Firefox 113+, Safari 15.4+). Arenet's operator audience is technical and runs modern browsers; CLAUDE.md does not pin a legacy browser target. Document the minimum in the Step R smoke doc. |
| **D3 topology animations** behave differently in the new palette (contrast, particle visibility). | R.4 dedicates QA time to the topology screen specifically; the mock's accent-line opacity (0.45) is the starting point for edge strokes; tweak in implementation if motion legibility drops. |
| **View-as toggle (D6) confuses operators** who expect it to be functional. | Tooltip explicit: "Aperçu visuel — l'application des permissions arrive dans une étape future". The toggle's cosmetic effect (greying mutation buttons) is opt-in via the toggle itself, not silent. |
| **Map placeholder** feels like a broken nav. | Placeholder copy explains the feature is on the roadmap; consider hiding the nav entry behind a feature flag if friction is high during smoke. |
| **`/certs` URL change** breaks in-repo docs. | R.4 includes a grep across `docs/` for `/settings/certificates` and rewrites all hits. SvelteKit redirect from `/settings/certificates` → `/certs` for one release as a safety net. |

---

## 6. Out of scope (exhaustif — feature gaps audit)

Step R is **aesthetic migration PURE**. Several widgets in the mock represent features that the backend does NOT implement today. They are out-of-scope: R.4 ships either a "Coming Soon — feature deferred" inline panel OR omits the section entirely from the page markup (page shorter than mock, but coherent with what IS backend-implemented).

The PAS 3ème option — implementing the missing backend in passing — is explicitly forbidden: it would explode scope and break the separation between aesthetic migration vs feature work.

Audit performed 2026-05-31 against `internal/` (Go backend) + `web/frontend/src/routes/` (current SvelteKit pages). Per page, mock-promised widgets are classified into three buckets:

- **IMPLÉMENTÉ**: backend + frontend exist. R.4 re-skins.
- **GAP UI**: backend exists, no current UI. R.4 MAY add the UI if mechanical; otherwise defer.
- **GAP BACKEND**: no backend support. **OUT-OF-SCOPE for Step R**, must ship as placeholder or be omitted.

### 6.1 Per-page audit

#### Dashboard (`/dashboard`, mock `:749-950`)

- IMPLÉMENTÉ: KPI tiles (req/s, p95 latency, 5xx error rate, WAF blocks/h) — `internal/metrics/` + `internal/api/metrics_handlers.go`. Traffic chart with metric switcher — observability aggregator. Top routes table — per-route RPS. Upstreams status — caddymgr health state. Live access tail (subset surfaced here as a card) — observability log handlers. Événements WAF récents — `internal/api/security_handlers.go` + M.1 WAF event reader.
- GAP UI: none significant for v1.4.
- GAP BACKEND: none — Dashboard widgets are all backed by existing instrumentation. R.4 strategy: full migration, no placeholder.

#### Topology (`/topology`, mock `:952-2014`)

- IMPLÉMENTÉ: WS live updates — `internal/api/ws_topology.go` + `metrics.Broadcaster`. Graph rendering — current D3 implementation. Per-node hover state.
- GAP UI: time-window selector (5min / 1h / 24h) — observability has windowed aggregates but the topology WS today emits live-only flow rates; surfacing historical windows on the topology view requires a new query path. Vue protocole vs vue service toggle — current frontend has a single view mode; the dual-mode is a UX addition only (no backend gap, but it's a frontend feature). Zoom controls (+, −, 0, fit) — D3 supports zoom but the buttons aren't wired today.
- GAP BACKEND: historical replay of topology flows beyond live state (the mock implies "rewind to 24h ago and replay") — not implemented; live-only. **R.4 strategy**: omit time-window selector + replay controls; keep live view + the zoom buttons can be wired (cheap, pure frontend).

#### Routes (`/routes`, mock `:2015-2174`)

- IMPLÉMENTÉ: route list table (host, matcher, upstream, TLS status, WAF level, health) — `internal/api/` + caddymgr. Route detail (host, matcher, upstreams, LB policy, TLS toggle, HTTP/3 toggle, WAF on/off, rate limit) — caddymgr managed_domain. Upstreams add/remove + weights + drain state — storage + caddymgr. Save/deploy + apply-changes — Step I config-reload mechanism.
- GAP UI: per-route WAF paranoia level granular setting (mock displays a "strict" pill) — Coraza supports per-route paranoia internally but the API does NOT expose per-route override today. **OUT-OF-SCOPE for R.4**; pill shown as static info derived from global paranoia.
- GAP BACKEND: Import Caddyfile button — backup_handlers.go has JSON import but Caddyfile-specific parsing is not implemented. **R.4 strategy**: omit the Import button (the Export already covers the operational need; symmetric Import is a feature gap that lands in its own step).

#### WAF (`/waf`, mock `:2176-2274`) — MOST IMPACTED PAGE

- IMPLÉMENTÉ: WAF events stream (24h aggregates per category) — observability aggregator. Coraza global enable/disable + global paranoia (1-4) — `internal/waf/` + handler config. Mode selector (Blocking) — Coraza configuration.
- GAP UI: per-category event count display — observability aggregator emits per-category stats; presenting them as the OWASP CRS category grid is a frontend reshape (acceptable in R.4).
- GAP BACKEND (out-of-scope, all):
  - **OWASP CRS category granular toggles** (SQLi / XSS / RCE / LFI / Scanners / PHP / Protocol Violations / Bot Detection — each independently on/off per the mock). Coraza's underlying rule registry supports rule-level disable but there is no API + no storage + no UI controller in `internal/waf/` to enable/disable categories. Verified by grep: `grep -rE "Paranoia|CRSCategory|category.*toggle" internal/waf/ internal/api/` returns ZERO hits. **Strategy**: render the category grid as read-only event-count tiles (uses existing aggregator data), omit the toggles. Add inline "Coming Soon — granular category control deferred" banner above the grid.
  - **IP allow/deny manual lists**. CrowdSec auto-decisions exist (Step N), but operator-curated manual allow/deny lists (whitelist friendly IPs, block known-bad CIDR without involving CrowdSec) have no backend storage + no API. **Strategy**: omit the section from the page entirely. The CrowdSec decisions table accessible from `/security/decisions` covers auto-decisions; manual lists land in a future step.
  - **Geo-blocking** (allow/deny country lists, with MaxMind GeoLite2 lookup). Grep for `geoip|maxmind|GeoLite` in `internal/`: zero hits. The `country` strings in observability/storage are CrowdSec decision-scope payloads, NOT IP-to-country lookups. Adding geo-blocking requires: external dep (MaxMind SDK), database file shipping or download, IP-to-country middleware, storage for country lists, new handlers. **Strategy**: omit the geo-blocking section from the page entirely. Document in `docs/backlog-step-r.md` as a candidate feature for a future step (likely needs its own spec given the MaxMind licensing footprint).

#### Security (`/security`, mock `:2277-2349`) — REPURPOSED + MOST IMPACTED

Per D4 reframing, this page becomes the cross-cutting security policy configuration surface (TLS + headers + auth providers). Existing M-era events/decisions content moves to the Dashboard's "Événements WAF récents" card + the Security Automation card under Settings.

- IMPLÉMENTÉ: auth providers list (OIDC, forward-auth, basic-auth) — `internal/auth/` + auth handlers. Audit log "who changed what" — `internal/audit/` (Step P added the 32-action enum).
- GAP UI: none significant.
- GAP BACKEND (out-of-scope, all):
  - **Global TLS config UI** (min version 1.2/1.3, curves x25519/p256/p384, cipher suites, HTTP/3, OCSP stapling, session ticket rotation). Verified by grep `MinVersion|TLSVersion|http3|Curves|CipherSuites` in `internal/caddymgr/`: ZERO hits. Caddy supports these as built-ins but Arenet does not expose them via API or storage today; the binary uses Caddy's defaults. **Strategy**: render an inline read-only "TLS Configuration" card showing Caddy defaults (min version: TLS 1.2, HTTP/3 enabled by default, OCSP stapling on, etc.) with a banner "Configuration en lecture seule — édition deferred to a future step". The defaults are stable enough to show as informational text without backend involvement.
  - **Security headers UI** (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy with nonce injection, Permissions-Policy). Verified by grep `HSTS|strict-transport-security|X-Frame|Content-Security-Policy` in `internal/`: ZERO hits. No header injection middleware in the handler chain. **Strategy**: omit the security headers section from the page entirely. Document in `docs/backlog-step-r.md` — likely a focused future step combining headers + TLS config under one "edge security policy" feature.
  - **CSP with dynamic nonce injection**. Even more substantial than static headers — requires per-request nonce generation, template injection into HTML responses, and CSP middleware coordination. **Strategy**: omit entirely; combined with the security-headers gap above.

#### Logs (`/logs`, mock `:2352-2400`)

- IMPLÉMENTÉ: live access log tail (timestamp, level, status code, request line, duration, source IP) — `internal/api/` log streaming + WS. Filter by level / route / status code range — query filter pipeline. Search box with query syntax (`status:5xx route:/auth/* ip:185.142.*`) — filter parsing in observability. Pause / export buttons — UI controls (export uses backup_handlers).
- GAP UI: GeoIP country display in the log row — current code surfaces CrowdSec country scope on decisions, but per-log-row country annotation is NOT available (would require the same MaxMind dep as the WAF geo-blocking gap). **Strategy**: render the country column as empty / dash for now; populate when the MaxMind dep lands.
- GAP BACKEND: none beyond the GeoIP column.

#### Certs (`/certs`, mock `:2403-2439`)

- IMPLÉMENTÉ: certificate list (domain, issuer, SAN, dates, state) — Caddy certmagic storage. KPI cards (active certs, expiring < 30d, issuer, ACME method) — cert metadata extraction. Force renewal button — ACME trigger.
- GAP UI: per-cert ACME method display (DNS-01 via Cloudflare etc.) — stored in route config but the UI mapping is light frontend work, acceptable in R.4.
- GAP BACKEND: none significant.

#### Users (`/users`, mock `:2443-2710`)

- IMPLÉMENTÉ: users table (id, source, role, MFA, last activity, status, actions) — `internal/auth/userstore.go`. Role toggle (admin/viewer) — `internal/auth/types.go` UserRole. MFA status (TOTP/WebAuthn/API token) — auth backends. SSO sync button — OIDC provisioning. User invite + invited pending list — invitation logic. SSO provider config card (Authentik OIDC etc.) — settings. Role default policy toggles (SSO→viewer, IdP-group→admin, MFA required, free signup) — policy storage.
- GAP UI: none significant.
- GAP BACKEND: none significant.

#### Settings (`/settings`, mock `:2712-2777`)

- IMPLÉMENTÉ: Caddy admin API config (endpoint, port, bind, token rotation) — caddymgr admin API. Telemetry toggles (Prometheus, OpenTelemetry, anonymous usage) — metrics + OTEL. Backup list — backup_handlers. Config export (Caddyfile / JSON) — `internal/api/backup_handlers.go` ExportConfigAsJSON.
- GAP UI: Security Automation card (Step P) needs to land here per the D4 reframing (events/decisions/automation moves out of `/security`). Backend exists since P.3; frontend Card from P.4 just moves location in the sidebar/page navigation.
- GAP BACKEND: none.

### 6.2 Cross-cutting out-of-scope items

- **Map page** (real feature, geo-IP DB shipping, marker logic) — future step. Step R ships only the sidebar entry + `<ComingSoon />` placeholder.
- **Light theme / theme switcher** — D2 outcome.
- **Command palette** (full ⌘K with action search) — v1.4 ships the topbar search input as a basic route-filter only.
- **Real RBAC viewer mode** — D6 outcome; v1.4 ships the toggle as a cosmetic affordance.
- **Notifications panel + bell icon** — v1.4 hides the notifications icon in the topbar entirely. With the alerting step deferred to `docs/superpowers/specs/_deferred/2026-05-31-step-r-alerting.md`, there is no `/alerts` target; deep-linking the bell to `/security/decisions` would be semantically wrong (notifications ≠ enforcement decisions). Re-introduced when the alerting step lands. Tracked in `docs/backlog-step-r.md` #R-3.
- **Déployer button functional action** — v1.4 renders the button visually (per mock) but ships it disabled with a "Bientôt disponible" tooltip. The real action (reload Caddy / apply staged config / commit pending route changes) is feature work outside the aesthetic migration scope. Tracked in `docs/backlog-step-r.md` #R-4.
- **Sidebar collapsed/expanded state** — Step F shipped a localStorage-persisted collapsed mode (64px collapsed / 256px expanded). R.2 removes it: the mock specifies a fixed 232px sidebar with no collapse button by design (focus on content area). The removal IS a UX regression for operators who used the Step F collapse. Tracked in `docs/backlog-step-r.md` #R-2 — if operator demand re-emerges (smaller screens, multi-monitor workflows where the sidebar feels heavy), a future step can re-introduce a collapse toggle with the new visual language. Not in v1.4 because the mock provides no design for the collapsed state.
- **Storybook / component-library extraction** — components stay co-located.
- **D3 topology rework** beyond palette migration + zoom-button wiring — animation logic unchanged.
- **Production deployment artefacts** — that's Step S.

### 6.3 Backlog seeding

Each GAP BACKEND item gets a one-line entry in `docs/backlog-step-r.md` (seeded as part of R.5 verdict commit) so future operators can find the resolution path:

- WAF: OWASP CRS category granular toggles (API + storage + controller).
- WAF: manual IP allow/deny lists (storage + API + handler integration).
- WAF: geo-blocking via MaxMind GeoLite2 (external dep + country lookup middleware + lists storage + handlers).
- Security: global TLS config exposure (min version, curves, ciphers, HTTP/3, OCSP, session tickets) — likely a focused "edge TLS policy" step.
- Security: security headers controller (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) — bundleable with TLS step.
- Security: CSP with dynamic nonce injection — more substantial; may warrant its own step given templating implications.
- Routes: per-route WAF paranoia override (Coraza supports internally, no API exposure).
- Routes: Caddyfile import (mirror of the existing JSON import).
- Topology: time-window selector + historical replay.
- Logs: GeoIP country annotation (depends on WAF geo-blocking MaxMind dep).
- Map: full geo-IP visualisation page.

---

## 7. Appendix — references

- Visual mock (source-of-truth): `docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html` (3274 lines).
  - Tokens: `:11-44`
  - Topbar styles: `:92-116`
  - Sidebar styles + view-as: `:576-714`
  - Sidebar markup: `:655-714`
  - Topbar markup: `:720-741`
  - Screen list (10 sections): `id="dashboard"` `id="topology"` `id="map"` `id="routes"` `id="waf"` `id="security"` `id="logs"` `id="certs"` `id="users"` `id="settings"`
- Predecessor specs (functional surfaces that R MUST not regress):
  - L: `docs/superpowers/specs/2026-05-28-step-l-observability.md`
  - M: `docs/superpowers/specs/2026-05-28-step-m-security.md`
  - Q: `docs/superpowers/specs/2026-05-29-step-q-rate-limit-auth-events.md`
  - N: `docs/superpowers/specs/2026-05-29-step-n-crowdsec.md`
  - O: `docs/superpowers/specs/2026-05-30-step-o-wildcards.md`
  - P: `docs/superpowers/specs/2026-05-31-step-p-auto-classify.md`
- Deferred Step R candidate (alerting Phase 3) — `docs/superpowers/specs/_deferred/2026-05-31-step-r-alerting.md` (kept for future re-activation; not in scope for v1.4).
- CLAUDE.md visual constraints:
  - Frontend stack: SvelteKit 5 + TypeScript strict + Tailwind (no other CSS frameworks).
  - Accessibility: all interactive elements must have ARIA labels.
  - AGPL header required on every new `.ts` / `.svelte` file (component header block).
