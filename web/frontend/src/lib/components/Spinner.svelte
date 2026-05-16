<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	type Size = 'sm' | 'md' | 'lg';
	let { size = 'md' }: { size?: Size } = $props();
	const sizeMap: Record<Size, number> = { sm: 14, md: 20, lg: 32 };
	const sizePx = $derived(sizeMap[size]);
</script>

<svg
	width={sizePx}
	height={sizePx}
	viewBox="0 0 24 24"
	fill="none"
	role="status"
	aria-label="Loading"
>
	<circle cx="12" cy="12" r="10" stroke="var(--border-default)" stroke-width="3" />
	<path
		d="M22 12a10 10 0 0 1-10 10"
		stroke="var(--accent-cyan)"
		stroke-width="3"
		stroke-linecap="round"
	>
		<animateTransform
			attributeName="transform"
			type="rotate"
			from="0 12 12"
			to="360 12 12"
			dur="0.9s"
			repeatCount="indefinite"
		/>
	</path>
</svg>
