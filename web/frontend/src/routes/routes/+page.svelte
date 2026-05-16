<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { listRoutes } from '$lib/api/client';
	import type { Route } from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';

	let routes = $state<Route[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	async function loadRoutes() {
		loading = true;
		loadError = null;
		try {
			routes = await listRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			loadError = msg;
			pushToast(msg, 'danger');
		} finally {
			loading = false;
		}
	}

	onMount(loadRoutes);
</script>

<div class="flex items-start justify-between">
	<div>
		<h1 class="text-4xl font-semibold">Routes</h1>
		<p class="text-secondary text-sm mt-1">Manage reverse proxy routes.</p>
	</div>
	<Button onclick={() => alert('form coming in Task 8.3')}>+ Add route</Button>
</div>

{#if loading}
	<div class="flex items-center gap-2 mt-12 text-secondary">
		<Spinner /> Loading routes…
	</div>
{:else if loadError}
	<div class="mt-12 text-down">Failed to load routes: {loadError}</div>
{:else if routes.length === 0}
	<div class="mt-16 flex flex-col items-center text-center gap-4">
		<div class="text-6xl text-muted">◉</div>
		<p class="text-secondary">No routes configured yet.</p>
		<Button onclick={() => alert('form coming in Task 8.3')}>+ Add your first route</Button>
	</div>
{:else}
	<p class="mt-8 text-secondary">{routes.length} routes (stats + table arrive in Task 8.2).</p>
{/if}
