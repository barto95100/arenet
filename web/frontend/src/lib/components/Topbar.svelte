<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Topbar (Step R.2, slimmed in Phase 5 follow-up).

  Layout: crumbs · status

  Pre-cleanup the topbar carried three additional affordances
  inherited from the original aesthetic mock: a non-functional
  search input + ⌘K hint, a cosmetic Admin/Viewer view-as
  toggle, and a permanently-disabled "Déployer" button. The
  operator called the trio out as zero-value clutter:
    - the search was a visual placeholder with no command
      palette wired behind it (spec §6.2 out of scope)
    - the view-as toggle was advertised as "cosmetic only"
      and could only confuse operators about who they really
      were
    - the Déployer button surfaced a "Bientôt disponible"
      tooltip that pointed at no real feature

  We retain ONE piece of the view-as machinery: the effect
  that auto-applies the `body.viewer` class when the backend
  session is actually role=viewer. The class still drives the
  app-wide read-only affordances in app.css (.viewer
  .admin-only hidden, .viewer .write-action disabled,
  .ro-banner shown). That mechanism is genuine, not cosmetic,
  and removing the explicit toggle does not remove the
  underlying gating.
-->
<script lang="ts">
	import { page } from '$app/state';
	import { auth } from '$lib/stores/auth.svelte';

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

	// Backend-driven viewer gating. When the session role IS
	// viewer, set body.viewer so the app-wide CSS rules in
	// app.css (.admin-only hidden, .write-action disabled,
	// .ro-banner visible) light up. The class is removed when
	// the operator is admin so an admin->viewer->admin user
	// flip (rare but possible across sessions) clears the
	// stale state.
	$effect(() => {
		if (typeof document === 'undefined') return;
		if (auth.user?.role === 'viewer') {
			document.body.classList.add('viewer');
		} else {
			document.body.classList.remove('viewer');
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
</style>
