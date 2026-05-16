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
	import StatCard from '$lib/components/StatCard.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import StatusDot from '$lib/components/StatusDot.svelte';
	import Badge from '$lib/components/Badge.svelte';

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

	// Derived stats — recompute when `routes` changes.
	const stats = $derived({
		total: routes.length,
		// `active` shadows `total` until live health checks land in Step E.
		active: routes.length,
		tls: routes.filter((r) => r.tlsEnabled).length,
		waf: routes.filter((r) => r.wafEnabled).length
	});

	function fmtDate(iso: string): string {
		return new Date(iso).toLocaleString();
	}
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
	<div class="mt-12 text-down" role="alert">Failed to load routes: {loadError}</div>
{:else if routes.length === 0}
	<div class="mt-16 flex flex-col items-center text-center gap-4">
		<div class="text-6xl text-muted">◉</div>
		<p class="text-secondary">No routes configured yet.</p>
		<Button onclick={() => alert('form coming in Task 8.3')}>+ Add your first route</Button>
	</div>
{:else}
	<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6">
		<StatCard label="Total Routes" value={stats.total} />
		<StatCard label="Active" value={stats.active} />
		<StatCard label="With TLS" value={stats.tls} />
		<StatCard label="With WAF" value={stats.waf} />
	</div>

	<div class="mt-6">
		<DataTable headers={['Status', 'Host', 'Upstream', 'TLS', 'WAF', 'Actions']} items={routes}>
			{#snippet row(r)}
				<!-- TODO Step E: replace with live health-check status -->
				<td class="px-4 py-3"><StatusDot status="up" /></td>
				<td class="px-4 py-3 font-mono">{r.host}</td>
				<td
					class="px-4 py-3 font-mono text-secondary truncate max-w-[16rem]"
					title={r.upstreamUrl}
				>
					{r.upstreamUrl}
				</td>
				<td class="px-4 py-3">
					{#if r.tlsEnabled}
						<Badge variant="tls">TLS</Badge>
					{:else}
						<span class="text-muted">—</span>
					{/if}
				</td>
				<td class="px-4 py-3">
					{#if r.wafEnabled}
						<Badge variant="waf">WAF</Badge>
					{:else}
						<span class="text-muted">—</span>
					{/if}
				</td>
				<td class="px-4 py-3">
					<div class="flex gap-1">
						<Button variant="ghost" size="sm" onclick={() => alert('edit in 8.3')}>Edit</Button>
						<Button variant="ghost" size="sm" onclick={() => alert('delete in 8.4')}>Delete</Button>
					</div>
				</td>
			{/snippet}
			{#snippet expanded(r)}
				<dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
					<dt class="text-secondary">ID</dt>
					<dd class="font-mono">{r.id}</dd>
					<dt class="text-secondary">Created</dt>
					<dd class="font-mono">{fmtDate(r.createdAt)}</dd>
					<dt class="text-secondary">Updated</dt>
					<dd class="font-mono">{fmtDate(r.updatedAt)}</dd>
					<dt class="text-secondary">Live traffic</dt>
					<dd class="text-muted">— (coming soon)</dd>
				</dl>
			{/snippet}
		</DataTable>
	</div>
{/if}
