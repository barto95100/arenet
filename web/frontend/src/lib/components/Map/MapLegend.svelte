<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V polish — Map legend.

  Compact panel showing the 5 GeoEvent category colors
  with French labels so new operators can decode the arc
  hues without reading the source. Mounts in the bottom-
  right corner of the map frame; toggleable via a small
  header button so it doesn't obscure the underlying
  geography for operators who don't need it.

  Each entry sources its color from CATEGORY_COLORS in
  categoryColors.ts (single source of truth) — adding a
  new category in the future is a one-file change there
  + a one-line addition to ENTRIES below.

  "Normal" is included for completeness even though the
  backend doesn't emit it today: the 5-category enum is
  locked at spec §5.6, and a future Step V sub-task may
  start emitting normal-traffic events for green-arc
  visibility. Marked with the "à venir" italic suffix so
  the operator isn't surprised by its absence.
-->
<script lang="ts">
	import { CATEGORY_COLORS } from './categoryColors';
	import type { GeoEventCategory } from '$lib/api/types';

	interface LegendEntry {
		category: GeoEventCategory;
		label: string;
		description: string;
		comingSoon?: boolean;
	}

	// Single source of truth for the legend rows. Order is
	// operator-meaningful: rarest-to-most-common left to
	// right when read top-down (normal is rare in practice;
	// auth-failures churn the most).
	const ENTRIES: readonly LegendEntry[] = [
		{
			category: 'normal',
			label: 'Normal',
			description: 'Trafic légitime',
			comingSoon: true
		},
		{
			category: 'throttle',
			label: 'Throttle',
			description: 'Rate-limit (429)'
		},
		{
			category: 'waf',
			label: 'WAF',
			description: 'Bloqué par Coraza (403)'
		},
		{
			category: 'crowdsec',
			label: 'CrowdSec',
			description: 'IP en réputation négative (403)'
		},
		{
			category: 'auth',
			label: 'Auth',
			description: 'Échec d’authentification (401/403)'
		}
	];

	// Operator preference: collapsed by default so the
	// legend doesn't obscure the map's bottom-right corner
	// (where dense LAN attacks land for many homelab
	// topologies). The toggle button stays compact when
	// collapsed.
	let expanded = $state(true);

	function toggle(): void {
		expanded = !expanded;
	}
</script>

<aside
	class="map-legend"
	class:map-legend--collapsed={!expanded}
	data-testid="map-legend"
	aria-label="Légende des catégories d'événements"
>
	<header class="map-legend__header">
		<button
			type="button"
			class="map-legend__toggle"
			onclick={toggle}
			aria-expanded={expanded}
			aria-controls="map-legend-body"
			data-testid="map-legend-toggle"
		>
			<span class="map-legend__title">Légende</span>
			<span class="map-legend__chevron" aria-hidden="true">{expanded ? '▾' : '▴'}</span>
		</button>
	</header>
	{#if expanded}
		<ul id="map-legend-body" class="map-legend__list" data-testid="map-legend-list">
			{#each ENTRIES as entry (entry.category)}
				<li
					class="map-legend__item"
					data-testid={`map-legend-item-${entry.category}`}
					data-category={entry.category}
				>
					<span
						class="map-legend__swatch"
						style="background: {CATEGORY_COLORS[entry.category]};"
						aria-hidden="true"
					></span>
					<span class="map-legend__label">
						<span class="map-legend__label-main">{entry.label}</span>
						<span class="map-legend__label-desc">
							{entry.description}{#if entry.comingSoon}
								<em class="map-legend__coming-soon"> · à venir</em>
							{/if}
						</span>
					</span>
				</li>
			{/each}
		</ul>
	{/if}
</aside>

<style>
	.map-legend {
		position: absolute;
		bottom: 10px;
		right: 12px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		padding: 8px;
		min-width: 180px;
		max-width: 240px;
		font-size: 12px;
		color: var(--text-secondary);
		z-index: 1;
		box-shadow: var(--shadow-sm);
	}
	.map-legend--collapsed {
		min-width: 0;
		padding: 4px;
	}

	.map-legend__header {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}
	.map-legend__toggle {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 2px 6px;
		background: transparent;
		border: 0;
		color: var(--text-secondary);
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		cursor: pointer;
		border-radius: 4px;
	}
	.map-legend__toggle:hover {
		background: var(--bg-hover);
		color: var(--text-primary);
	}
	.map-legend__toggle:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	.map-legend__title {
		font-weight: 600;
	}
	.map-legend__chevron {
		font-size: 10px;
		color: var(--text-muted);
	}

	.map-legend__list {
		list-style: none;
		margin: 6px 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 4px;
	}
	.map-legend__item {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 3px 4px;
	}
	.map-legend__swatch {
		display: inline-block;
		flex: 0 0 auto;
		width: 12px;
		height: 12px;
		border-radius: 50%;
		margin-top: 3px;
		box-shadow: inset 0 0 0 1px rgba(0, 0, 0, 0.15);
	}
	.map-legend__label {
		display: flex;
		flex-direction: column;
		line-height: 1.25;
		min-width: 0;
	}
	.map-legend__label-main {
		color: var(--text-primary);
		font-weight: 600;
		font-size: 12px;
	}
	.map-legend__label-desc {
		color: var(--text-muted);
		font-size: 11px;
	}
	.map-legend__coming-soon {
		font-style: italic;
		color: var(--text-muted);
	}
</style>
