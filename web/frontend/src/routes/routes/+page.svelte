<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { listRoutes, createRoute, updateRoute, deleteRoute } from '$lib/api/client';
	import type { Route, RouteRequest } from '$lib/api/types';
	import { ApiError } from '$lib/api/types';
	import { pushToast } from '$lib/stores/toast';
	import Button from '$lib/components/Button.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import StatusDot from '$lib/components/StatusDot.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';

	let routes = $state<Route[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	type FormMode = 'create' | 'edit';
	let formOpen = $state(false);
	let formMode = $state<FormMode>('create');
	let editingId = $state<string | null>(null);
	let submitting = $state(false);
	let formError = $state<string | null>(null);
	let hostError = $state<string | null>(null);
	let upstreamError = $state<string | null>(null);

	let formData = $state<RouteRequest>({
		host: '',
		upstreamUrl: '',
		tlsEnabled: false,
		redirectToHttps: false,
		aliases: [],
		wafEnabled: false
	});

	let confirmTarget = $state<Route | null>(null);
	let deleting = $state(false);

	function resetFormErrors() {
		formError = null;
		hostError = null;
		upstreamError = null;
	}

	function openCreate() {
		formMode = 'create';
		editingId = null;
		// Step I.1: redirectToHttps defaults to true so opting into TLS
		// gives the user the "right thing" (301 from :80 to :443) by
		// default. They can flip the toggle off explicitly if they
		// want plain HTTP to keep serving alongside HTTPS.
		formData = {
			host: '',
			upstreamUrl: '',
			tlsEnabled: false,
			redirectToHttps: true,
			aliases: [],
			wafEnabled: false
		};
		resetFormErrors();
		formOpen = true;
	}

	function openEdit(r: Route) {
		formMode = 'edit';
		editingId = r.id;
		formData = {
			host: r.host,
			upstreamUrl: r.upstreamUrl,
			tlsEnabled: r.tlsEnabled,
			redirectToHttps: r.redirectToHttps,
			// Step I.3: copy aliases by value so editing in the form
			// doesn't mutate the original Route in the table list.
			aliases: [...(r.aliases ?? [])],
			wafEnabled: r.wafEnabled
		};
		resetFormErrors();
		formOpen = true;
	}

	// Step I.3: alias repeater helpers. Empty-string entries are kept
	// in the array while editing (so the user can type) and trimmed
	// out at submit time — that way the backend never sees a payload
	// like aliases: ["a.com", ""] which would 400 on "alias must not
	// be empty" before any meaningful validation happens.
	function addAlias() {
		formData.aliases = [...formData.aliases, ''];
	}
	function removeAlias(i: number) {
		formData.aliases = formData.aliases.filter((_, idx) => idx !== i);
	}

	/**
	 * Map a server validation message to a specific field, or null if the message
	 * is not field-attributable (then it lands in formError as a top-of-form
	 * banner).
	 */
	function fieldFromMessage(msg: string): 'host' | 'upstreamUrl' | null {
		const lower = msg.toLowerCase();
		if (lower.startsWith('host ')) return 'host';
		if (lower.startsWith('upstreamurl ')) return 'upstreamUrl';
		return null;
	}

	async function submitForm() {
		submitting = true;
		resetFormErrors();
		try {
			// Step I.3: drop blank alias rows the user may have added
			// without filling. The backend would 400 on them anyway,
			// but trimming here keeps the round-trip clean for the
			// common "added a row, changed mind" case.
			const payload = {
				...formData,
				aliases: formData.aliases.map((a) => a.trim()).filter((a) => a.length > 0)
			};
			if (formMode === 'create') {
				await createRoute(payload);
				pushToast('Route created', 'success');
			} else if (editingId) {
				await updateRoute(editingId, payload);
				pushToast('Route updated', 'success');
			}
			formOpen = false;
			await loadRoutes();
		} catch (err) {
			if (err instanceof ApiError && err.kind === 'validation') {
				// Validation errors (400, 409) → inline. Form stays open.
				const field = fieldFromMessage(err.message);
				if (field === 'host') hostError = err.message;
				else if (field === 'upstreamUrl') upstreamError = err.message;
				else formError = err.message;
			} else {
				// System errors (500, network, parse, anything else) → toast.
				// Modal stays open so the user can retry without losing input.
				const msg = err instanceof ApiError ? err.message : String(err);
				pushToast(msg, 'danger');
			}
		} finally {
			submitting = false;
		}
	}

	async function confirmDelete() {
		if (!confirmTarget) return;
		deleting = true;
		try {
			await deleteRoute(confirmTarget.id);
			pushToast('Route deleted', 'success');
			confirmTarget = null;
			await loadRoutes();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : String(err);
			pushToast(msg, 'danger');
		} finally {
			deleting = false;
		}
	}

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

<PageHeader title="Routes" subtitle="Manage reverse proxy routes.">
	{#snippet actions()}
		<Button onclick={openCreate}>+ Add route</Button>
	{/snippet}
</PageHeader>

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
		<Button onclick={openCreate}>+ Add your first route</Button>
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
				<td class="px-4 py-3 font-mono">
					{r.host}
					{#if r.aliases && r.aliases.length > 0}
						<!-- Step I.3: compact "+N" badge with a native title
						     tooltip listing every alias. The expanded snippet
						     below has the full readable list; this is the
						     at-a-glance signal in the table row. -->
						<span
							class="ml-1.5 inline-flex items-center px-1.5 py-0.5 rounded text-xs font-sans text-secondary bg-elevated border border-border-subtle cursor-help"
							title={`Aliases:\n${r.aliases.join('\n')}`}
						>+{r.aliases.length}</span>
					{/if}
				</td>
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
						<Button variant="ghost" size="sm" onclick={() => openEdit(r)}>Edit</Button>
						<Button variant="ghost" size="sm" onclick={() => (confirmTarget = r)}>Delete</Button>
					</div>
				</td>
			{/snippet}
			{#snippet expanded(r)}
				<dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
					<dt class="text-secondary">ID</dt>
					<dd class="font-mono">{r.id}</dd>
					<dt class="text-secondary">Hostnames</dt>
					<dd class="font-mono">
						<!-- Step I.3: full hostname list with the primary
						     called out so the reader knows which host is
						     the canonical one (matters for ACME naming +
						     the {http.request.host} placeholder echo). -->
						<div>{r.host} <span class="text-muted">(primary)</span></div>
						{#each r.aliases ?? [] as alias (alias)}
							<div>{alias} <span class="text-muted">(alias)</span></div>
						{/each}
					</dd>
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

<Modal
	open={formOpen}
	title={formMode === 'create' ? 'Add route' : 'Edit route'}
	onClose={() => (formOpen = false)}
>
	<form
		onsubmit={(e) => {
			e.preventDefault();
			submitForm();
		}}
		class="flex flex-col gap-4"
	>
		{#if formError}
			<p
				class="px-3 py-2 rounded bg-down/10 border border-down/40 text-sm text-down"
				role="alert"
			>
				{formError}
			</p>
		{/if}
		<Input
			label="Host"
			bind:value={formData.host}
			placeholder="example.local"
			error={hostError ?? undefined}
		/>
		<!-- Step I.3: alias hostnames. Each row binds to one slot of
		     formData.aliases. The user types a hostname; backend
		     validation rejects malformed entries via the formError
		     banner above. Empty rows are trimmed at submit time. -->
		<div class="flex flex-col gap-2">
			<div class="flex items-center justify-between">
				<span class="text-sm text-secondary">Aliases (optional)</span>
				<Button variant="ghost" size="sm" onclick={addAlias} type="button">+ Add alias</Button>
			</div>
			{#each formData.aliases as _, i (i)}
				<div class="flex items-center gap-2">
					<Input bind:value={formData.aliases[i]} placeholder="alt.example.com" />
					<Button variant="ghost" size="sm" onclick={() => removeAlias(i)} type="button">×</Button>
				</div>
			{/each}
		</div>
		<Input
			label="Upstream URL"
			bind:value={formData.upstreamUrl}
			placeholder="http://127.0.0.1:8080"
			error={upstreamError ?? undefined}
		/>
		<div class="flex flex-col gap-1">
			<Checkbox label="Enable TLS" bind:checked={formData.tlsEnabled} />
			<!-- Step I.1 helper text (Q4 vote C): warn softly that ACME
			     needs a publicly resolvable hostname. localhost / .local
			     fall back to Caddy's internal CA (self-signed). -->
			<p class="text-xs text-muted ml-6">
				Public domain required for Let's Encrypt; localhost / .local
				will fall back to internal CA.
			</p>
		</div>
		<Checkbox
			label="Redirect HTTP → HTTPS"
			bind:checked={formData.redirectToHttps}
			disabled={!formData.tlsEnabled}
			title={formData.tlsEnabled
				? 'Automatically redirects HTTP requests to HTTPS with a 301.'
				: 'Enable TLS to use HTTPS redirect.'}
		/>
		<Checkbox
			label="Enable WAF (coming in Step I.4)"
			bind:checked={formData.wafEnabled}
			disabled
			title="WAF support lands in Step I.4"
		/>
		<!-- Hidden submit button so Enter inside an input still triggers the form. -->
		<button type="submit" class="hidden" aria-hidden="true"></button>
	</form>
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (formOpen = false)}>Cancel</Button>
		<Button onclick={submitForm} loading={submitting}>
			{formMode === 'create' ? 'Create' : 'Save'}
		</Button>
	{/snippet}
</Modal>

<Modal
	open={confirmTarget !== null}
	title="Delete route"
	onClose={() => (confirmTarget = null)}
>
	{#if confirmTarget}
		<p class="text-sm">
			Are you sure you want to delete the route for
			<code class="font-mono text-cyan">{confirmTarget.host}</code>?
		</p>
		<p class="text-xs text-secondary mt-2">
			Caddy will be reloaded immediately. This action cannot be undone.
		</p>
	{/if}
	{#snippet footer()}
		<Button variant="ghost" onclick={() => (confirmTarget = null)}>Cancel</Button>
		<Button variant="danger" loading={deleting} onclick={confirmDelete}>Delete</Button>
	{/snippet}
</Modal>
