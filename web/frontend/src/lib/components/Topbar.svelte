<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
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
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import {
		fetchSystemHealth,
		unhealthyComponentNames,
		type SystemHealthResult
	} from '$lib/api/system-health';

	// v2.9.12 i18n Phase 2 — crumb labels resolved from the active
	// bundle. Each entry maps a pathname to a bundle key under
	// sidebar.* (reusing the sidebar nav-item translations so the
	// crumb and the nav stay in sync). The `language.current &&`
	// dependency trigger inside $derived recomputes on every
	// language change.
	const pathToBundleKey: Record<string, string> = {
		'/dashboard': 'sidebar.navDashboard',
		'/topology': 'sidebar.navTopology',
		'/map': 'sidebar.navMap',
		'/routes': 'sidebar.navRoutes',
		'/logs': 'sidebar.navLogs',
		'/waf': 'sidebar.navWAF',
		'/security': 'sidebar.navSecurity',
		'/certs': 'sidebar.navCertificates',
		'/users': 'sidebar.navUsers',
		'/settings': 'sidebar.navSettings',
		'/audit': 'sidebar.navAuditLog',
		'/admin/users': 'sidebar.navUsers'
	};

	const currentPath = $derived(page.url.pathname);
	const crumbLabel = $derived(
		// Touching language.current registers the reactive dependency
		// so the crumb re-resolves on language switch (see
		// $lib/i18n/index.ts docstring for the idiom).
		language.current &&
			(pathToBundleKey[currentPath]
				? t(pathToBundleKey[currentPath])
				: (() => {
						// Sub-route fallback (e.g. /admin/users → "Users · users").
						const segs = currentPath.split('/').filter(Boolean);
						if (segs.length === 0) return 'Arenet';
						const root = '/' + segs[0];
						const rootLabel = pathToBundleKey[root]
							? t(pathToBundleKey[root])
							: segs[0];
						return segs.length > 1
							? `${rootLabel} · ${segs.slice(1).join('/')}`
							: rootLabel;
					})())
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

	// The gateway badge (v2.73).
	//
	// It used to be three lines of static markup: a dot hard-wired
	// to var(--status-up) and the literal topbar.statusHealthy.
	// There was no fetch, no store read and no prop anywhere in this
	// component, so it read "Gateway healthy" in green on every
	// page, in every state, including with Caddy down. The endpoint
	// it should have been reading has existed since Step AL.3a.
	//
	// null is a reading in its own right — "unknown", grey — and not
	// a reason to fall back on the reassuring answer. That fallback
	// is the whole defect.
	let health = $state<SystemHealthResult>(null);
	// Distinguishes "not asked yet" from "asked, no answer". Both
	// render grey, but only the second is worth a tooltip.
	let healthProbed = $state(false);

	const HEALTH_POLL_MS = 30_000;

	const healthStatus = $derived(health?.status ?? 'unknown');
	const healthLabelKey = $derived(
		{
			healthy: 'topbar.statusHealthy',
			degraded: 'topbar.statusDegraded',
			unhealthy: 'topbar.statusUnhealthy',
			unknown: 'topbar.statusUnknown'
		}[healthStatus]
	);
	// Which probes are complaining, for the tooltip. Empty unless
	// something is actually wrong, so a healthy badge carries no
	// title attribute at all.
	const healthDetail = $derived(
		health && health.status !== 'healthy' ? unhealthyComponentNames(health).join(', ') : ''
	);

	$effect(() => {
		if (typeof window === 'undefined') return;

		let cancelled = false;

		async function poll(): Promise<void> {
			// Locked: the LockScreen overlay covers this badge, so the
			// answer is unobservable. Hidden tab: same. Neither is a
			// 403 risk on this path (it needs no session), but a
			// request nobody can see is waste.
			if (auth.state === 'locked') return;
			if (document.visibilityState !== 'visible') return;
			const result = await fetchSystemHealth();
			if (cancelled) return;
			health = result;
			healthProbed = true;
		}

		void poll();
		const id = setInterval(() => void poll(), HEALTH_POLL_MS);
		return () => {
			cancelled = true;
			clearInterval(id);
		};
	});
</script>

<div class="topbar" role="banner">
	<div class="crumbs">
		<b>{crumbLabel}</b>
	</div>

	<!-- role="status" for two reasons. An aria-label on a role-less
	     div is ignored by assistive tech, so the label that was here
	     never reached anyone; and now that the reading changes, a
	     change in the gateway's state is worth announcing. -->
	<div
		class="tb-status"
		role="status"
		data-testid="topbar-health"
		data-status={healthStatus}
		aria-label={language.current && t('topbar.statusAriaLabel')}
		title={healthDetail || undefined}
	>
		<span class="dot" data-status={healthStatus} aria-hidden="true"></span>
		<span>{language.current && t(healthLabelKey)}</span>
	</div>
</div>

<style>
	.topbar {
		height: var(--tb-height);
		background: var(--bg-topbar);
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
	/* Keyed on data-status rather than a class, so a state with no
	   rule here is visibly grey instead of invisibly transparent.
	   The .dot.ok rule this replaces became dead the moment the
	   markup stopped emitting the class, and neither svelte-check
	   nor the build says a word about an unused selector. */
	.dot[data-status='healthy'] {
		background: var(--status-up);
		box-shadow: 0 0 8px var(--status-up);
	}
	.dot[data-status='degraded'] {
		background: var(--status-warn);
		box-shadow: 0 0 8px var(--status-warn);
	}
	.dot[data-status='unhealthy'] {
		background: var(--status-down);
		box-shadow: 0 0 8px var(--status-down);
	}
	.dot[data-status='unknown'] {
		background: var(--fg-muted);
	}
	/* The word already says which state this is, so colour is a
	   second channel rather than the only one. Tinting the text as
	   well is what makes it readable at a glance across a 1440px
	   topbar. */
	.tb-status[data-status='degraded'] {
		color: var(--status-warn);
	}
	.tb-status[data-status='unhealthy'] {
		color: var(--status-down);
	}
</style>
