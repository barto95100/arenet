<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import Card from './Card.svelte';

	interface Props {
		label: string;
		value: string | number;
		/**
		 * Positive => up arrow + status-up color, negative => down arrow +
		 * status-down color, zero => muted dot.
		 */
		trend?: number;
		/**
		 * Users-page Phase 1 — optional secondary line rendered
		 * below the value. Used by the /utilisateurs KPI cards to
		 * surface the breakdown sub-label (e.g.
		 * "4 admins · 10 viewers"). Empty → not rendered.
		 */
		hint?: string;
	}

	let { label, value, trend = 0, hint = '' }: Props = $props();

	const trendClass = $derived(
		trend > 0 ? 'text-up' : trend < 0 ? 'text-down' : 'text-muted'
	);
	const trendArrow = $derived(trend > 0 ? '↗' : trend < 0 ? '↘' : '·');
	const trendAbs = $derived(Math.abs(trend));
</script>

<Card padding="p-5">
	<p class="text-xs uppercase tracking-wide text-secondary">{label}</p>
	<div class="mt-2 flex items-baseline gap-2">
		<span class="text-4xl font-bold text-primary tabular-nums">{value}</span>
		{#if trend !== 0}
			<span class="text-sm {trendClass}">{trendArrow} {trendAbs}</span>
		{/if}
	</div>
	{#if hint}
		<p class="mt-1 text-xs text-muted">{hint}</p>
	{/if}
</Card>
