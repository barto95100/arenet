<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	interface Props extends Omit<HTMLInputAttributes, 'class' | 'value'> {
		label?: string;
		error?: string;
		value?: string;
	}

	let {
		label,
		error,
		value = $bindable(''),
		type = 'text',
		id = `input-${Math.random().toString(36).slice(2, 9)}`,
		placeholder = '',
		...rest
	}: Props = $props();
</script>

<div class="flex flex-col gap-1.5">
	{#if label}
		<label for={id} class="text-sm font-medium text-secondary">{label}</label>
	{/if}
	<input
		{id}
		{type}
		{placeholder}
		bind:value
		class="bg-surface border rounded-md px-3 py-2 text-sm text-primary placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-cyan focus:shadow-glow-cyan transition-shadow"
		class:border-down={error}
		class:border-border-default={!error}
		aria-invalid={error ? 'true' : undefined}
		aria-describedby={error ? `${id}-err` : undefined}
		{...rest}
	/>
	{#if error}
		<p id={`${id}-err`} class="text-xs text-down">{error}</p>
	{/if}
</div>
