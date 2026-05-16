<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { toasts } from '$lib/stores/toast';
	import Toast from './Toast.svelte';
</script>

<div
	class="pointer-events-none fixed bottom-4 right-4 z-50 flex flex-col gap-2"
	aria-live="polite"
>
	{#each $toasts as entry (entry.id)}
		<Toast {entry} />
	{/each}
</div>
