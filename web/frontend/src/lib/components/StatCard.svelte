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
	}

	let { label, value, trend = 0 }: Props = $props();

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
</Card>
