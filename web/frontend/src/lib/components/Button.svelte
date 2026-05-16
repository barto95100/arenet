<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import Spinner from './Spinner.svelte';

	type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
	type Size = 'sm' | 'md' | 'lg';

	interface Props extends Omit<HTMLButtonAttributes, 'class' | 'children'> {
		variant?: Variant;
		size?: Size;
		loading?: boolean;
		children?: Snippet;
	}

	let {
		variant = 'primary',
		size = 'md',
		loading = false,
		disabled = false,
		type = 'button',
		children,
		...rest
	}: Props = $props();

	const variantClass: Record<Variant, string> = {
		primary:
			'bg-cyan text-inverse hover:shadow-glow-cyan active:scale-[0.98] focus-visible:ring-cyan',
		secondary:
			'bg-elevated text-primary border border-border-default hover:bg-hover focus-visible:ring-cyan',
		ghost:
			'bg-transparent text-secondary hover:text-primary hover:bg-hover focus-visible:ring-cyan',
		danger:
			'bg-down text-inverse hover:shadow-glow-red active:scale-[0.98] focus-visible:ring-down'
	};
	const sizeClass: Record<Size, string> = {
		sm: 'px-2.5 py-1 text-xs',
		md: 'px-3.5 py-1.5 text-sm',
		lg: 'px-5 py-2 text-base'
	};

	const classes = $derived(
		`inline-flex items-center justify-center gap-2 rounded-md font-medium transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-2 disabled:opacity-50 disabled:cursor-not-allowed ${variantClass[variant]} ${sizeClass[size]}`
	);

	// Spinner color follows the variant so the loading indicator stays legible
	// against the button background.
	const spinnerColor = $derived.by(() => {
		if (variant === 'primary' || variant === 'danger') return 'black' as const;
		return 'current' as const;
	});
</script>

<button {type} disabled={disabled || loading} class={classes} {...rest}>
	{#if loading}
		<Spinner size="sm" color={spinnerColor} />
	{/if}
	{@render children?.()}
</button>
