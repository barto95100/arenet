<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Tailwind padding utility (e.g. "p-4", "p-6"). Default p-6. */
		padding?: string;
		/** Extra classes to merge on the wrapper. */
		class?: string;
		children?: Snippet;
	}

	let { padding = 'p-6', class: cls = '', children }: Props = $props();
</script>

<div class="bg-elevated border border-border-subtle rounded-lg {padding} {cls}">
	{@render children?.()}
</div>
