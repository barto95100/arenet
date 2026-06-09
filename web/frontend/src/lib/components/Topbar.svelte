<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topbar (Step R.2). Matches the mock at
  docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html:720-741.

  Sticky 56px header with backdrop-blur 8px. Layout:
    crumbs · status · search (⌘K) · view-as toggle · notifications · Déployer

  Crumbs auto-derive from the current pathname (the page label maps
  to the sidebar nav-item label). Pages that want a richer crumb
  (e.g. a route detail showing host name) can override via a slot
  in a future step; v1.4 keeps the simple "Section / pathname" form.

  Status reads the connection state (Caddy admin reachability via
  the existing connection store) — for v1.4 we ship a static
  placeholder showing "12 routes saines" pattern; wiring to real
  data is light frontend work scheduled with R.4 Dashboard work.

  View-as toggle (per D6 — cosmetic-only in v1.4):
    - clicking "Viewer" adds the .viewer class to <body>;
    - the CSS in app.css then greys out .tb-btn.primary, hides
      .admin-only, and shows .ro-banner;
    - the backend session role is UNCHANGED — a click does NOT
      issue any API mutation. Tooltip makes this explicit.

  Search (⌘K hint): v1.4 ships the input as a visual affordance.
  The command-palette wiring is OUT OF SCOPE (spec §6.2).

  Notifications + Déployer (v1.4 status):

  - Notifications: HIDDEN in v1.4. With the alerting step deferred
    (see docs/superpowers/specs/_deferred/2026-05-31-step-r-alerting.md),
    there is no /alerts target; pointing the bell at /security?tab=crowdsec
    would be semantically wrong (notifications ≠ decisions). Re-
    introduced when the alerting step lands. Tracked in
    docs/backlog-step-r.md #R-3.
  - Déployer: present visually but disabled with a "Bientôt
    disponible" tooltip. The real action (reload Caddy / apply
    staged config) is feature work outside the aesthetic migration
    scope. Tracked in docs/backlog-step-r.md #R-4.
-->
<script lang="ts">
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';
	import { onMount } from 'svelte';

	const pathLabels: Record<string, string> = {
		'/dashboard': 'Dashboard',
		'/topology': 'Topology',
		'/map': 'Map',
		'/routes': 'Routes',
		'/logs': 'Logs',
		'/waf': 'WAF',
		'/security': 'Security',
		'/certs': 'Certificates',
		'/users': 'Utilisateurs',
		'/settings': 'Settings',
		'/observability': 'Observability',
		'/audit': 'Audit',
		'/admin/users': 'Utilisateurs'
	};

	const currentPath = $derived(page.url.pathname);
	const crumbLabel = $derived(
		pathLabels[currentPath] ??
			(() => {
				// Sub-route fallback: e.g. /admin/users → "Utilisateurs · users".
				// /security?tab=crowdsec is a query-param tab so falls through to
				// the root /security label, which is the right thing — the parent
				// tab label sits in the topbar; the active sub-tab is visible inline.
				const segs = currentPath.split('/').filter(Boolean);
				if (segs.length === 0) return 'Arenet';
				const root = '/' + segs[0];
				const rootLabel = pathLabels[root] ?? segs[0];
				return segs.length > 1 ? `${rootLabel} · ${segs.slice(1).join('/')}` : rootLabel;
			})()
	);

	// View-as toggle state. The toggle is cosmetic per D6; the actual
	// role is held by the backend. Default to "admin" (which is just
	// "no body class"); clicking "Viewer" adds body.viewer.
	let asRole = $state<'admin' | 'viewer'>('admin');

	function setViewAs(role: 'admin' | 'viewer'): void {
		asRole = role;
		if (typeof document === 'undefined') return;
		if (role === 'viewer') {
			document.body.classList.add('viewer');
		} else {
			document.body.classList.remove('viewer');
		}
	}

	onMount(() => {
		// Ensure the body class is in sync with the initial state on
		// every mount (e.g. after a soft nav that re-mounts the layout).
		setViewAs(asRole);
	});

	// Real role is admin/viewer from the backend; if the backend says
	// the operator is a viewer, the toggle's "Viewer" state should
	// reflect that even though the toggle ITSELF is cosmetic. (When
	// the session role IS viewer, the body.viewer class is set from
	// the start so the same cosmetic restrictions show up.)
	$effect(() => {
		const sessionRole = auth.user?.role;
		if (sessionRole === 'viewer') {
			setViewAs('viewer');
		}
	});
</script>

<div class="topbar" role="banner">
	<div class="crumbs">
		<b>{crumbLabel}</b>
	</div>

	<div class="tb-status" aria-label="État de la passerelle">
		<span class="dot ok" aria-hidden="true"></span>
		<span>Passerelle saine</span>
	</div>

	<div class="search" role="search">
		<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
			<circle cx="7" cy="7" r="5" />
			<path d="M11 11l3 3" />
		</svg>
		<input type="search" placeholder="Rechercher routes, IPs, événements…" aria-label="Rechercher" />
		<kbd>⌘ K</kbd>
	</div>

	<div
		class="view-as"
		role="group"
		aria-label="Aperçu visuel du rôle"
		title="Aperçu visuel — l'application des permissions arrive dans une étape future"
	>
		<button
			type="button"
			class:on={asRole === 'admin'}
			onclick={() => setViewAs('admin')}
			aria-pressed={asRole === 'admin'}
		>Admin</button>
		<button
			type="button"
			class="viewer"
			class:on={asRole === 'viewer'}
			onclick={() => setViewAs('viewer')}
			aria-pressed={asRole === 'viewer'}
		>Viewer</button>
	</div>

	<!-- Notifications icon hidden in v1.4 — no /alerts target while
	     the alerting step is deferred. Will be re-introduced with
	     that step (backlog #R-3). -->

	<button
		type="button"
		class="tb-btn primary write-action"
		disabled
		title="Bientôt disponible — l'action de déploiement arrive dans une étape future"
		aria-label="Déployer la configuration en attente (bientôt disponible)"
	>
		<svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
			<path d="M8 3v10M3 8h10" />
		</svg>
		<span>Déployer</span>
	</button>
</div>

<style>
	.topbar {
		height: var(--tb-height);
		background: oklch(17% 0.006 250 / 0.85);
		backdrop-filter: blur(8px);
		-webkit-backdrop-filter: blur(8px);
		border-bottom: 1px solid var(--border);
		display: flex;
		align-items: center;
		gap: 14px;
		padding: 0 22px;
		position: sticky;
		top: 0;
		z-index: 10;
	}

	.crumbs {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
		color: var(--fg-muted);
	}
	.crumbs b {
		color: var(--fg);
		font-weight: 500;
	}

	.tb-status {
		display: flex;
		align-items: center;
		gap: 8px;
		font-size: 12.5px;
		color: var(--fg-muted);
	}
	.dot {
		width: 8px;
		height: 8px;
		border-radius: 50%;
		flex: none;
	}
	.dot.ok {
		background: var(--status-up);
		box-shadow: 0 0 8px var(--status-up);
	}

	.search {
		margin-left: auto;
		flex: 0 0 320px;
		display: flex;
		align-items: center;
		gap: 8px;
		background: var(--surface);
		border: 1px solid var(--border);
		padding: 5px 10px;
		border-radius: var(--radius);
		color: var(--fg-muted);
		font-size: 12.5px;
	}
	.search input {
		background: none;
		border: none;
		outline: none;
		flex: 1;
		color: var(--fg);
		font-size: 13px;
	}
	.search kbd {
		font-family: var(--font-mono);
		font-size: 10px;
		background: var(--bg);
		border: 1px solid var(--border);
		padding: 1px 5px;
		border-radius: 4px;
		color: var(--fg-dim);
	}

	.view-as {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 3px;
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: 99px;
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.05em;
		text-transform: uppercase;
	}
	.view-as button {
		padding: 4px 10px;
		border-radius: 99px;
		color: var(--fg-dim);
		font-weight: 500;
		background: transparent;
		border: none;
		cursor: pointer;
		transition: background 0.12s, color 0.12s;
	}
	.view-as button.on {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}
	.view-as button.viewer.on {
		color: var(--status-warn);
	}

	.tb-btn {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 5px 10px;
		border-radius: var(--radius-sm);
		font-size: 12.5px;
		color: var(--fg-muted);
		border: 1px solid var(--border);
		background: var(--surface);
		cursor: pointer;
		text-decoration: none;
		transition: background 0.12s, color 0.12s, border-color 0.12s;
	}
	.tb-btn:hover {
		color: var(--fg);
		background: var(--surface-2);
	}
	.tb-btn.primary {
		background: var(--accent);
		color: #fff;
		border-color: transparent;
		font-weight: 500;
	}
	.tb-btn.primary:hover:not(:disabled) {
		background: oklch(62% 0.22 255);
	}
	.tb-btn:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.tb-btn.primary:disabled {
		background: var(--accent);
		filter: saturate(0.6);
	}
</style>
