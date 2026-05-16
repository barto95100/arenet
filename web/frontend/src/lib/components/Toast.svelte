<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { ToastEntry } from '$lib/stores/toast';
	import { dismissToast } from '$lib/stores/toast';

	let { entry }: { entry: ToastEntry } = $props();
</script>

<div
	role="status"
	class="toast pointer-events-auto px-4 py-3 rounded-md border bg-elevated min-w-[16rem] max-w-sm flex items-start gap-3"
	data-variant={entry.variant}
>
	<p class="text-sm flex-1">{entry.message}</p>
	<button
		class="text-secondary hover:text-primary text-xs"
		aria-label="Dismiss notification"
		onclick={() => dismissToast(entry.id)}
	>
		×
	</button>
</div>

<style>
	.toast {
		animation: slide-in 200ms ease-out;
	}
	.toast[data-variant='success'] {
		border-color: rgba(0, 255, 136, 0.4);
		background-color: rgba(0, 255, 136, 0.1);
		box-shadow: 0 0 12px rgba(0, 255, 136, 0.4);
	}
	.toast[data-variant='danger'] {
		border-color: rgba(255, 71, 87, 0.4);
		background-color: rgba(255, 71, 87, 0.1);
		box-shadow: 0 0 12px rgba(255, 71, 87, 0.4);
	}
	.toast[data-variant='info'] {
		border-color: rgba(0, 217, 255, 0.4);
		background-color: rgba(0, 217, 255, 0.1);
		box-shadow: 0 0 16px rgba(0, 217, 255, 0.4);
	}
	@keyframes slide-in {
		from {
			opacity: 0;
			transform: translateX(20px);
		}
		to {
			opacity: 1;
			transform: translateX(0);
		}
	}
</style>
