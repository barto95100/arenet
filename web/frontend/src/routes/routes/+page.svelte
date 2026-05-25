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

	// Step J.1 → J.3 transitional bridge:
	// The form still has a single Upstream URL input (the pre-J.1
	// shape). The backend now expects an upstreams[] pool + lbPolicy
	// on the wire. To keep the form functional in the J.1→J.3
	// window without shipping any J.3 UI here, we keep `upstreamUrl`
	// as a UI-only field in formData and rebuild a one-element
	// upstreams[] at submit time (see submitForm below). lbPolicy is
	// always sent empty so the backend default (round_robin)
	// applies.
	//
	// FOOTGUN, documented: a route created via the API with multiple
	// upstreams will display only the first one in this form, and
	// EDITING it in the form will overwrite the whole pool with a
	// one-element pool — silently dropping every other upstream.
	// J.3 ships the real repeater + selector; until then, treat the
	// UI as mono-upstream only. The wire types in types.ts already
	// carry the new fields, so this is a UI lag, not a wire lag.
	//
	// J.3 must remove the `upstreamUrl` UI field below, replace the
	// single Input with a repeater, and stop the synthetic mapping
	// in submitForm / openEdit.
	type FormData = Omit<RouteRequest, 'upstreams' | 'lbPolicy'> & { upstreamUrl: string };
	let formData = $state<FormData>({
		host: '',
		upstreamUrl: '',
		tlsEnabled: false,
		redirectToHttps: false,
		aliases: [],
		basicAuthEnabled: false,
		basicAuthUsername: '',
		basicAuthPassword: '',
		requestHeaders: {},
		responseHeaders: {},
		wafMode: 'detect'
	});

	// Step I.5: tracked separately from formData because it reflects
	// the SERVER state (does a hash exist on the route being edited),
	// not the form's write-only password input. Drives the "••• set"
	// placeholder and the empty-password-keeps-hash semantics.
	let basicAuthPasswordSet = $state(false);

	// Step J.1 → J.3 transitional bridge guard: when the route being
	// edited has multiple upstreams (created via API), the single-
	// input UI in this form cannot represent the pool. Saving would
	// silently flatten it (see FOOTGUN comment near formData). We
	// freeze the Upstream URL input in that case and surface a one-
	// line notice so the operator knows to edit via API until J.3
	// ships the real repeater. multiUpstreamReadOnly is set in
	// openEdit / openCreate; the input below binds its `disabled`
	// to it.
	let multiUpstreamReadOnly = $state(false);

	// Step I.6 — header repeater state. We track tuples here (not
	// the final Record) so:
	//   1. an empty row can sit visibly in the form while the user
	//      types the key,
	//   2. two rows with the same key can coexist while editing
	//      (the conversion at submit picks last-wins, matching the
	//      server's JSON-decode behavior),
	//   3. the each-key index stays stable while the user adds /
	//      deletes rows.
	// The conversion to Record<string,string> happens in submitForm.
	let requestHeaderRows = $state<Array<[string, string]>>([]);
	let responseHeaderRows = $state<Array<[string, string]>>([]);

	function addRequestHeader() {
		requestHeaderRows = [...requestHeaderRows, ['', '']];
	}
	function removeRequestHeader(i: number) {
		requestHeaderRows = requestHeaderRows.filter((_, idx) => idx !== i);
	}
	function addResponseHeader() {
		responseHeaderRows = [...responseHeaderRows, ['', '']];
	}
	function removeResponseHeader(i: number) {
		responseHeaderRows = responseHeaderRows.filter((_, idx) => idx !== i);
	}

	// tuplesToRecord drops rows whose KEY is empty (per Step I.6
	// Ajustement 2: empty VALUE is intentionally allowed — some
	// upstreams check header presence, not content — so we only
	// trim on the key side). Last-wins on duplicate keys, matching
	// the server's json.Decode semantics; documented limitation.
	function tuplesToRecord(rows: Array<[string, string]>): Record<string, string> {
		const out: Record<string, string> = {};
		for (const [k, v] of rows) {
			const key = k.trim();
			if (key === '') continue;
			out[key] = v;
		}
		return out;
	}

	function recordToTuples(rec: Record<string, string>): Array<[string, string]> {
		return Object.entries(rec ?? {});
	}

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
		// Step I.7 hotfix (Finding #5): redirectToHttps defaults to
		// FALSE on Create. The earlier "default true" was a
		// well-intentioned UX shortcut (Step I.1) that turned out to
		// silently persist redirect=true on routes the admin never
		// enabled TLS on. The reactive $effect below enforces the
		// same invariant in the form, but starting at false is the
		// cleanest contract: the admin opts INTO the redirect after
		// flipping TLS on.
		formData = {
			host: '',
			upstreamUrl: '',
			tlsEnabled: false,
			redirectToHttps: false,
			aliases: [],
			basicAuthEnabled: false,
			basicAuthUsername: '',
			basicAuthPassword: '',
			requestHeaders: {},
			responseHeaders: {},
			// Step I.4: 'detect' is the FortiWeb-style safe-shadow default
			// (L6). The admin can change to 'off' or 'block' explicitly.
			wafMode: 'detect'
		};
		basicAuthPasswordSet = false;
		// Step J.1: a fresh create starts with a single empty upstream
		// — single-input UI is safe.
		multiUpstreamReadOnly = false;
		requestHeaderRows = [];
		responseHeaderRows = [];
		resetFormErrors();
		formOpen = true;
	}

	function openEdit(r: Route) {
		formMode = 'edit';
		editingId = r.id;
		// Step J.1 → J.3 transitional bridge: show the first
		// upstream's URL in the single-input UI. Multi-upstream
		// routes (created via API) display only Upstreams[0] —
		// editing here will overwrite the whole pool. Documented
		// limitation, see the FormData comment block above.
		formData = {
			host: r.host,
			upstreamUrl: r.upstreams[0]?.url ?? '',
			tlsEnabled: r.tlsEnabled,
			redirectToHttps: r.redirectToHttps,
			// Step I.3: copy aliases by value so editing in the form
			// doesn't mutate the original Route in the table list.
			aliases: [...(r.aliases ?? [])],
			basicAuthEnabled: r.basicAuthEnabled,
			basicAuthUsername: r.basicAuthUsername,
			// Step I.5: password input starts EMPTY on Edit. Empty +
			// hash-already-set → backend preserves the existing hash.
			// User must re-type to rotate.
			basicAuthPassword: '',
			requestHeaders: { ...(r.requestHeaders ?? {}) },
			responseHeaders: { ...(r.responseHeaders ?? {}) },
			wafMode: r.wafMode
		};
		basicAuthPasswordSet = r.basicAuthPasswordSet;
		// Step J.1 → J.3 transitional bridge: freeze the upstream
		// input when the route has more than one upstream so editing
		// can't silently flatten the pool. The operator must use the
		// API (or wait for J.3) to modify the pool itself; other
		// fields (TLS, WAF, headers, …) remain editable normally.
		multiUpstreamReadOnly = r.upstreams.length > 1;
		// Step I.6: seed the repeater tuples from the server's map.
		// We intentionally don't share references — typing in the
		// form should not mutate the table-backing object.
		requestHeaderRows = recordToTuples(r.requestHeaders ?? {});
		responseHeaderRows = recordToTuples(r.responseHeaders ?? {});
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

	// Step I.7 hotfix (Finding #5): redirectToHttps is meaningless
	// without TLS. This reactive effect keeps the form's checkbox
	// state in sync with that invariant — flipping TLS off
	// immediately uncheck the redirect (visually + in formData),
	// so the user can't submit a tls:false + redirect:true payload
	// that would silently activate the redirect later if TLS is
	// flipped back on. The backend mirrors this in createRoute /
	// updateRoute (defense in depth, also covers direct API
	// clients that bypass the form).
	$effect(() => {
		if (!formData.tlsEnabled && formData.redirectToHttps) {
			formData.redirectToHttps = false;
		}
	});

	/**
	 * Map a server validation message to a specific field, or null if the message
	 * is not field-attributable (then it lands in formError as a top-of-form
	 * banner).
	 */
	function fieldFromMessage(msg: string): 'host' | 'upstreamUrl' | null {
		const lower = msg.toLowerCase();
		if (lower.startsWith('host ')) return 'host';
		// Step J.1: backend pool errors are prefixed "upstreams[N]:"
		// or start with "upstreams" (e.g. "upstreams must contain
		// at least one entry"). In the J.1→J.3 transitional UI we
		// only ever send a one-element pool, so any "upstreams[N]"
		// error is N=0 — surface it on the single UI input. J.3
		// must split this back into per-row errors once the
		// repeater lands.
		if (lower.startsWith('upstreams')) return 'upstreamUrl';
		return null;
	}

	async function submitForm() {
		submitting = true;
		resetFormErrors();
		// Step J.1 → J.3 transitional bridge: refuse to submit a
		// multi-upstream route through the single-input UI. The Input
		// is also visually disabled (see the markup), but a clavier-
		// only submit would otherwise still flatten the pool. Belt
		// and suspenders.
		if (multiUpstreamReadOnly) {
			formError = 'Multi-upstream pool — edit via API until J.3 ships the repeater.';
			submitting = false;
			return;
		}
		try {
			// Step I.3: drop blank alias rows the user may have added
			// without filling. The backend would 400 on them anyway,
			// but trimming here keeps the round-trip clean for the
			// common "added a row, changed mind" case.
			//
			// Step I.6: convert the header repeater tuples back to
			// the Record<string,string> the API expects. Empty keys
			// are dropped; empty values are KEPT (Ajustement 2).
			//
			// Step J.1 → J.3 transitional bridge: synthesize the
			// upstreams pool from the single upstreamUrl input and
			// send an empty lbPolicy so the backend default
			// (round_robin) applies. J.3 must replace this with the
			// real pool + selector + and drop the destructured
			// `upstreamUrl` field below.
			const { upstreamUrl, ...rest } = formData;
			const payload: RouteRequest = {
				...rest,
				aliases: formData.aliases.map((a) => a.trim()).filter((a) => a.length > 0),
				requestHeaders: tuplesToRecord(requestHeaderRows),
				responseHeaders: tuplesToRecord(responseHeaderRows),
				upstreams: [{ url: upstreamUrl, weight: 1 }],
				lbPolicy: ''
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
		// Step I.4: count routes where WAF is actively engaged
		// (detect OR block; off means no inspection).
		waf: routes.filter((r) => r.wafMode !== 'off').length
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
					{#if r.basicAuthEnabled}
						<!-- Step I.5: discreet lock icon when Basic Auth is on.
						     Tooltip via the native title attribute names the
						     username so the admin can identify the credential
						     at a glance without opening Edit. -->
						<span
							class="ml-1.5 inline-flex items-center text-muted cursor-help"
							title={`Basic Auth required (user: ${r.basicAuthUsername})`}
							aria-label="Basic Auth required"
						>
							<svg
								xmlns="http://www.w3.org/2000/svg"
								class="w-3.5 h-3.5"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
								stroke-linecap="round"
								stroke-linejoin="round"
								aria-hidden="true"
							>
								<rect width="18" height="11" x="3" y="11" rx="2" />
								<path d="M7 11V7a5 5 0 0 1 10 0v4" />
							</svg>
						</span>
					{/if}
				</td>
				<td
					class="px-4 py-3 font-mono text-secondary truncate max-w-[16rem]"
					title={r.upstreams[0]?.url ?? ''}
				>
					{r.upstreams[0]?.url ?? ''}{r.upstreams.length > 1
						? ` (+${r.upstreams.length - 1})`
						: ''}
				</td>
				<td class="px-4 py-3">
					{#if r.tlsEnabled}
						<Badge variant="tls">TLS</Badge>
					{:else}
						<span class="text-muted">—</span>
					{/if}
				</td>
				<td class="px-4 py-3">
					<!-- Step I.4 — yellow for detect, red for block,
					     em-dash for off (spec L8). Reuses the Badge
					     variants from Step F. -->
					{#if r.wafMode === 'detect'}
						<Badge variant="status-warn">Detect</Badge>
					{:else if r.wafMode === 'block'}
						<Badge variant="status-down">Block</Badge>
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
			disabled={multiUpstreamReadOnly}
		/>
		{#if multiUpstreamReadOnly}
			<p class="text-xs text-muted ml-1">
				Multi-upstream pool — edit via API until J.3 ships the repeater.
			</p>
		{/if}
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
		<!-- Step I.5: per-route Basic Auth. Username + password are
		     only meaningful when the toggle is on. On Edit, the
		     password input stays EMPTY and shows "••• set" as a
		     placeholder when a hash already exists — leaving the
		     input blank tells the backend to keep the existing
		     hash; typing a new value rotates it. -->
		<div class="flex flex-col gap-2">
			<Checkbox label="Require Basic Auth" bind:checked={formData.basicAuthEnabled} />
			{#if formData.basicAuthEnabled}
				<div class="ml-6 flex flex-col gap-2">
					<Input
						label="Username"
						bind:value={formData.basicAuthUsername}
						placeholder="admin"
					/>
					<div>
						<label
							for="basic-auth-password"
							class="text-sm font-medium text-secondary block mb-1"
						>
							Password
						</label>
						<input
							id="basic-auth-password"
							type="password"
							bind:value={formData.basicAuthPassword}
							placeholder={formMode === 'edit' && basicAuthPasswordSet
								? '••• set (leave blank to keep)'
								: ''}
							class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
						/>
					</div>
				</div>
			{/if}
		</div>
		<!-- Step I.4 — WAF mode (Coraza + OWASP CRS). The dropdown
		     pattern matches the /audit page's Action filter. Default
		     'detect' on Create gives the admin a safe-shadow window
		     to spot false positives before flipping to 'block'. -->
		<div>
			<label
				for="route-waf-mode"
				class="text-sm font-medium text-secondary block mb-1"
			>
				WAF (Coraza + OWASP CRS)
			</label>
			<select
				id="route-waf-mode"
				bind:value={formData.wafMode}
				class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
			>
				<option value="off">Off — no inspection</option>
				<option value="detect">Detect — log matches, let traffic through</option>
				<option value="block">Block — return 403 on match</option>
			</select>
			<p class="text-xs text-muted mt-1">
				Start with Detect to spot false positives before enforcing.
			</p>
		</div>
		<!-- Step I.6 — custom request / response headers. Two
		     collapsible sections (closed by default; most routes
		     don't need this). Backend validates RFC 7230 token
		     grammar on names, rejects CR/LF in values, and refuses
		     reserved hop-by-hop / framing-critical header names. -->
		<details class="rounded border border-border-subtle">
			<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
				Request headers
				{#if requestHeaderRows.length > 0}
					<span class="ml-1 text-xs text-muted">({requestHeaderRows.length})</span>
				{/if}
			</summary>
			<div class="p-3 flex flex-col gap-2 border-t border-border-subtle">
				{#each requestHeaderRows as _, i (i)}
					<div class="flex items-center gap-2">
						<Input bind:value={requestHeaderRows[i][0]} placeholder="X-Custom-Header" />
						<Input bind:value={requestHeaderRows[i][1]} placeholder="value" />
						<Button
							variant="ghost"
							size="sm"
							onclick={() => removeRequestHeader(i)}
							type="button">×</Button
						>
					</div>
				{/each}
				<Button variant="ghost" size="sm" onclick={addRequestHeader} type="button"
					>+ Add request header</Button
				>
			</div>
		</details>
		<details class="rounded border border-border-subtle">
			<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
				Response headers
				{#if responseHeaderRows.length > 0}
					<span class="ml-1 text-xs text-muted">({responseHeaderRows.length})</span>
				{/if}
			</summary>
			<div class="p-3 flex flex-col gap-2 border-t border-border-subtle">
				{#each responseHeaderRows as _, i (i)}
					<div class="flex items-center gap-2">
						<Input bind:value={responseHeaderRows[i][0]} placeholder="X-Custom-Header" />
						<Input bind:value={responseHeaderRows[i][1]} placeholder="value" />
						<Button
							variant="ghost"
							size="sm"
							onclick={() => removeResponseHeader(i)}
							type="button">×</Button
						>
					</div>
				{/each}
				<Button variant="ghost" size="sm" onclick={addResponseHeader} type="button"
					>+ Add response header</Button
				>
			</div>
		</details>
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
