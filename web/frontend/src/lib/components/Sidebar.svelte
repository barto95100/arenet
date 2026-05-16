<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { page } from '$app/state';
	import StatusDot from './StatusDot.svelte';

	interface Props {
		collapsed?: boolean;
	}

	let { collapsed = $bindable(false) }: Props = $props();

	type IconName = 'routes' | 'topology' | 'security' | 'settings';

	type Item = {
		href: string;
		label: string;
		icon: IconName;
		disabled?: boolean;
		tooltip?: string;
	};

	const items: Item[] = [
		{ href: '/routes', label: 'Routes', icon: 'routes' },
		{ href: '/topology', label: 'Topology', icon: 'topology', disabled: true, tooltip: 'Coming soon' },
		{ href: '/security', label: 'Security', icon: 'security', disabled: true, tooltip: 'Coming soon' },
		{ href: '/settings', label: 'Settings', icon: 'settings', disabled: true, tooltip: 'Coming soon' }
	];

	const currentPath = $derived(page.url.pathname);
	const isActive = (href: string) => currentPath === href;
</script>

<aside
	class="flex flex-col bg-sidebar border-r border-border-subtle h-screen sticky top-0 transition-[width] duration-200"
	style:width={collapsed ? '64px' : '256px'}
	aria-label="Primary"
>
	<div class="px-4 py-5 border-b border-border-subtle">
		<span class="font-mono text-base font-bold tracking-widest">
			<span class="text-cyan">A</span><span class:hidden={collapsed}>RENET</span>
		</span>
	</div>

	<nav class="flex-1 py-3 flex flex-col gap-1">
		{#each items as item (item.href)}
			{@const active = isActive(item.href)}
			<a
				href={item.disabled ? undefined : item.href}
				title={item.tooltip ?? item.label}
				aria-current={active ? 'page' : undefined}
				aria-disabled={item.disabled ? 'true' : undefined}
				tabindex={item.disabled ? -1 : 0}
				class="nav-item mx-2 px-3 py-2 rounded-md text-sm transition-colors flex items-center gap-3"
				class:active
				class:disabled={item.disabled}
				class:collapsed
			>
				<svg
					class="w-[18px] h-[18px] shrink-0"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					aria-hidden="true"
				>
					{#if item.icon === 'routes'}
						<!-- Lucide: share-2 -->
						<circle cx="18" cy="5" r="3" />
						<circle cx="6" cy="12" r="3" />
						<circle cx="18" cy="19" r="3" />
						<line x1="8.59" x2="15.42" y1="13.51" y2="17.49" />
						<line x1="15.41" x2="8.59" y1="6.51" y2="10.49" />
					{:else if item.icon === 'topology'}
						<!-- Lucide: workflow -->
						<rect width="8" height="8" x="3" y="3" rx="2" />
						<path d="M7 11v4a2 2 0 0 0 2 2h4" />
						<rect width="8" height="8" x="13" y="13" rx="2" />
					{:else if item.icon === 'security'}
						<!-- Lucide: shield -->
						<path
							d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
						/>
					{:else if item.icon === 'settings'}
						<!-- Lucide: settings -->
						<path
							d="M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915"
						/>
						<circle cx="12" cy="12" r="3" />
					{/if}
				</svg>
				<span class:hidden={collapsed}>{item.label}</span>
			</a>
		{/each}
	</nav>

	<div class="px-4 py-3 border-t border-border-subtle flex flex-col gap-2">
		<div class="flex items-center gap-2 text-xs" class:justify-center={collapsed}>
			<StatusDot status="up" />
			<span class:hidden={collapsed} class="text-secondary">Connected</span>
		</div>
		<div class="flex items-center gap-2 text-sm" class:justify-center={collapsed}>
			<span
				class="inline-block w-6 h-6 rounded-full bg-elevated border border-border-default text-center leading-6 shrink-0"
			>
				a
			</span>
			<span class:hidden={collapsed} class="text-primary">admin</span>
		</div>
		<button
			class="text-xs text-secondary hover:text-primary self-start"
			class:self-center={collapsed}
			aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
			onclick={() => (collapsed = !collapsed)}
		>
			{collapsed ? '»' : '« Collapse'}
		</button>
	</div>
</aside>

<style>
	.nav-item {
		position: relative;
		color: var(--text-secondary);
	}
	.nav-item:hover:not(.disabled) {
		background-color: var(--bg-hover);
		color: var(--text-primary);
	}
	.nav-item.active {
		color: var(--text-primary);
		background-color: var(--bg-hover);
		box-shadow: 0 0 16px rgba(0, 217, 255, 0.4);
	}
	/* Cyan rail on the left edge of the active item, drawn as a 4px box-shadow
	   inset so it doesn't disrupt layout. */
	.nav-item.active::before {
		content: '';
		position: absolute;
		left: -8px;
		top: 0.4rem;
		bottom: 0.4rem;
		width: 4px;
		border-radius: 2px;
		background-color: var(--accent-cyan);
	}
	.nav-item.disabled {
		color: var(--text-muted);
		cursor: not-allowed;
		pointer-events: none;
	}
	/* When collapsed, the icon centers itself and the label hides cleanly. */
	.nav-item.collapsed {
		justify-content: center;
	}
</style>
