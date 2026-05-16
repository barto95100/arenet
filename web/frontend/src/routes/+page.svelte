<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  THROWAWAY SMOKE PAGE — replaced in Chunk 7 with the / -> /routes redirect.
-->
<script lang="ts">
	import { listRoutes } from '$lib/api/client';
	import { ApiError } from '$lib/api/types';
	import Spinner from '$lib/components/Spinner.svelte';
	import StatusDot from '$lib/components/StatusDot.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Card from '$lib/components/Card.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { pushToast } from '$lib/stores/toast';

	let demoModalOpen = $state(false);
	let formModalOpen = $state(false);
	let dangerModalOpen = $state(false);
	let demoModalInput = $state('');

	function spamToasts() {
		pushToast('Route api.local created', 'success');
		setTimeout(() => pushToast('Reload took 142ms', 'info'), 300);
		setTimeout(() => pushToast('Caddy reload failed: bind: address already in use', 'danger'), 600);
		setTimeout(() => pushToast('Route admin.local updated', 'success'), 900);
	}

	type DemoRoute = {
		id: string;
		host: string;
		upstream: string;
		tls: boolean;
		waf: boolean;
		status: 'up' | 'warn' | 'down';
	};
	const demoRoutes: DemoRoute[] = [
		{ id: 'r1', host: 'api.local', upstream: 'http://127.0.0.1:9000', tls: true, waf: false, status: 'up' },
		{ id: 'r2', host: 'admin.local', upstream: 'http://127.0.0.1:9001', tls: true, waf: true, status: 'warn' },
		{ id: 'r3', host: 'legacy.local', upstream: 'http://10.0.0.42:8080', tls: false, waf: false, status: 'down' }
	];

	// Local state for the smoke demo so we can see two-way binding work.
	let hostInput = $state('');
	let portInput = $state('9999');
	let tlsChecked = $state(false);
	let wafChecked = $state(false);

	let apiStatus = $state('loading…');
	listRoutes()
		.then((rs) => (apiStatus = `OK — ${rs.length} route(s)`))
		.catch((e: ApiError | Error) =>
			(apiStatus = `error (${e instanceof ApiError ? e.kind : 'unknown'}): ${e.message}`)
		);
</script>

<div class="p-8 space-y-6">
	<h1 class="text-4xl font-semibold">Arenet design system smoke</h1>
	<p class="text-secondary text-sm">If you can read this, tokens are wired.</p>

	<div>
		<h2 class="text-lg font-semibold mb-2">Backgrounds</h2>
		<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
			<div class="p-4 bg-base border border-border-subtle rounded-lg">bg-base</div>
			<div class="p-4 bg-elevated border border-border-subtle rounded-lg">bg-elevated</div>
			<div class="p-4 bg-surface border border-border-default rounded-lg">bg-surface</div>
			<div class="p-4 bg-hover border border-border-strong rounded-lg">bg-hover</div>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Accent &amp; status</h2>
		<div class="flex flex-wrap gap-2">
			<span class="px-3 py-1 rounded bg-cyan text-inverse">cyan</span>
			<span class="px-3 py-1 rounded bg-up text-inverse">up</span>
			<span class="px-3 py-1 rounded bg-warn text-inverse">warn</span>
			<span class="px-3 py-1 rounded bg-down text-inverse">down</span>
			<span class="px-3 py-1 rounded bg-info text-inverse">info</span>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Glow</h2>
		<div class="shadow-glow-cyan p-4 bg-elevated border border-cyan rounded-lg w-fit">
			shadow-glow-cyan
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Mono</h2>
		<p class="font-mono text-sm text-secondary">192.0.2.1:443 — 503 Service Unavailable</p>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Spinner — sizes (cyan default)</h2>
		<div class="flex items-center gap-4">
			<Spinner size="sm" />
			<Spinner size="md" />
			<Spinner size="lg" />
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Spinner — colors</h2>
		<div class="flex items-center gap-4 flex-wrap">
			<span class="flex items-center gap-2"><Spinner color="cyan" /> cyan (default)</span>
			<span class="flex items-center gap-2 bg-cyan p-2 rounded">
				<Spinner color="black" /> <span class="text-inverse">black on cyan</span>
			</span>
			<span class="flex items-center gap-2 bg-down p-2 rounded">
				<Spinner color="black" /> <span class="text-inverse">black on danger</span>
			</span>
			<span class="flex items-center gap-2 text-up">
				<Spinner color="current" /> current (inherits text color)
			</span>
			<span class="flex items-center gap-2 text-warn">
				<Spinner color="current" /> current on warn
			</span>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">StatusDot (up, warn, down, info, idle)</h2>
		<div class="flex items-center gap-4">
			<span class="flex items-center gap-1"><StatusDot status="up" /> up</span>
			<span class="flex items-center gap-1"><StatusDot status="warn" /> warn</span>
			<span class="flex items-center gap-1"><StatusDot status="down" /> down</span>
			<span class="flex items-center gap-1"><StatusDot status="info" /> info</span>
			<span class="flex items-center gap-1"><StatusDot status="idle" /> idle</span>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Button — variants</h2>
		<div class="flex flex-wrap gap-3 items-center">
			<Button>Primary</Button>
			<Button variant="secondary">Secondary</Button>
			<Button variant="ghost">Ghost</Button>
			<Button variant="danger">Danger</Button>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Button — sizes</h2>
		<div class="flex flex-wrap gap-3 items-center">
			<Button size="sm">Small</Button>
			<Button size="md">Medium</Button>
			<Button size="lg">Large</Button>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Button — states</h2>
		<div class="flex flex-wrap gap-3 items-center">
			<Button loading>Loading</Button>
			<Button disabled>Disabled</Button>
			<Button variant="danger" loading>Danger loading</Button>
			<Button variant="secondary" disabled>Secondary disabled</Button>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Input — states</h2>
		<div class="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-2xl">
			<Input label="Host" placeholder="example.com" bind:value={hostInput} />
			<Input
				label="Upstream port (with error)"
				placeholder="port"
				bind:value={portInput}
				error="port must be between 1 and 65535"
			/>
			<Input label="No label below" placeholder="bare input, no label" />
		</div>
		<p class="text-xs text-secondary mt-2">
			Bound values: host=<code class="font-mono text-cyan">{hostInput || '(empty)'}</code>,
			port=<code class="font-mono text-cyan">{portInput}</code>
		</p>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Checkbox — states</h2>
		<div class="flex flex-col gap-2 max-w-md">
			<Checkbox label="Enable TLS" bind:checked={tlsChecked} />
			<Checkbox label="Enable WAF" bind:checked={wafChecked} />
			<Checkbox label="Disabled, no tooltip" disabled />
			<Checkbox
				label="Disabled with tooltip (hover me)"
				disabled
				title="Available in Step F"
			/>
			<Checkbox label="Pre-checked" checked />
		</div>
		<p class="text-xs text-secondary mt-2">
			Bound values: tls=<code class="font-mono text-cyan">{tlsChecked}</code>, waf=<code
				class="font-mono text-cyan">{wafChecked}</code
			>
		</p>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Badge — variants</h2>
		<div class="flex flex-wrap gap-2 items-center">
			<Badge variant="tls">TLS</Badge>
			<Badge variant="waf">WAF</Badge>
			<Badge variant="status-up">UP</Badge>
			<Badge variant="status-warn">WARN</Badge>
			<Badge variant="status-down">DOWN</Badge>
			<Badge>neutral</Badge>
			<Badge variant="tls">Badge with longer text</Badge>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Card — wrapper</h2>
		<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
			<Card>
				<h3 class="text-lg font-semibold mb-2">Default padding</h3>
				<p class="text-sm text-secondary">
					Card with the default <code class="font-mono text-cyan">p-6</code> padding.
				</p>
			</Card>
			<Card padding="p-4">
				<h3 class="text-lg font-semibold mb-2">Tight padding</h3>
				<p class="text-sm text-secondary">
					Same wrapper, <code class="font-mono text-cyan">padding="p-4"</code>.
				</p>
			</Card>
			<Card padding="p-8" class="border-cyan">
				<h3 class="text-lg font-semibold mb-2">Custom class</h3>
				<p class="text-sm text-secondary">
					Border overridden via <code class="font-mono text-cyan">class="border-cyan"</code>.
				</p>
			</Card>
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">StatCard — composed</h2>
		<div class="grid grid-cols-2 md:grid-cols-4 gap-3">
			<StatCard label="Total routes" value={12} />
			<StatCard label="Active" value={9} trend={2} />
			<StatCard label="With TLS" value={4} trend={-1} />
			<StatCard label="With WAF" value={0} />
		</div>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">DataTable — composed</h2>
		<DataTable
			headers={['Status', 'Host', 'Upstream', 'TLS', 'WAF']}
			items={demoRoutes}
		>
			{#snippet row(r)}
				<td class="px-4 py-3"><StatusDot status={r.status} /></td>
				<td class="px-4 py-3 font-mono">{r.host}</td>
				<td class="px-4 py-3 font-mono text-secondary truncate max-w-[16rem]" title={r.upstream}>
					{r.upstream}
				</td>
				<td class="px-4 py-3">
					{#if r.tls}<Badge variant="tls">TLS</Badge>{:else}<span class="text-muted">—</span>{/if}
				</td>
				<td class="px-4 py-3">
					{#if r.waf}<Badge variant="waf">WAF</Badge>{:else}<span class="text-muted">—</span>{/if}
				</td>
			{/snippet}
			{#snippet expanded(r)}
				<dl class="grid grid-cols-2 gap-x-6 gap-y-1 text-xs">
					<dt class="text-secondary">ID</dt>
					<dd class="font-mono">{r.id}</dd>
					<dt class="text-secondary">Upstream (full)</dt>
					<dd class="font-mono">{r.upstream}</dd>
					<dt class="text-secondary">Live traffic</dt>
					<dd class="text-muted">— (coming soon)</dd>
				</dl>
			{/snippet}
		</DataTable>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">Modal — composed</h2>
		<div class="flex flex-wrap gap-3">
			<Button onclick={() => (demoModalOpen = true)}>Open simple modal</Button>
			<Button variant="secondary" onclick={() => (formModalOpen = true)}>
				Open form modal (focus trap demo)
			</Button>
			<Button variant="danger" onclick={() => (dangerModalOpen = true)}>
				Open delete-style modal
			</Button>
		</div>
	</div>

	<Modal open={demoModalOpen} title="Demo modal" onClose={() => (demoModalOpen = false)}>
		<p class="text-sm">
			Hello from a modal. Press <kbd class="font-mono text-cyan">Escape</kbd> or click outside
			to close. Tab should NOT escape the dialog.
		</p>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (demoModalOpen = false)}>Cancel</Button>
			<Button onclick={() => (demoModalOpen = false)}>Confirm</Button>
		{/snippet}
	</Modal>

	<Modal open={formModalOpen} title="Form modal" onClose={() => (formModalOpen = false)}>
		<div class="flex flex-col gap-4">
			<Input label="Host" placeholder="example.com" bind:value={demoModalInput} />
			<Input label="Upstream URL" placeholder="http://127.0.0.1:9000" />
			<Checkbox label="Enable TLS" />
		</div>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (formModalOpen = false)}>Cancel</Button>
			<Button onclick={() => (formModalOpen = false)}>Save</Button>
		{/snippet}
	</Modal>

	<Modal
		open={dangerModalOpen}
		title="Delete route"
		onClose={() => (dangerModalOpen = false)}
	>
		<p class="text-sm">
			Are you sure you want to delete
			<code class="font-mono text-cyan">test.local</code>?
		</p>
		<p class="text-xs text-secondary mt-2">
			Caddy will be reloaded immediately. This action cannot be undone.
		</p>
		{#snippet footer()}
			<Button variant="ghost" onclick={() => (dangerModalOpen = false)}>Cancel</Button>
			<Button variant="danger" onclick={() => (dangerModalOpen = false)}>Delete</Button>
		{/snippet}
	</Modal>

	<div>
		<h2 class="text-lg font-semibold mb-2">Toast — composed</h2>
		<div class="flex flex-wrap gap-3">
			<Button
				variant="secondary"
				onclick={() => pushToast('Route created successfully', 'success')}
			>
				Push success
			</Button>
			<Button
				variant="secondary"
				onclick={() => pushToast('Network error: Failed to fetch', 'danger')}
			>
				Push danger
			</Button>
			<Button
				variant="secondary"
				onclick={() => pushToast('Heads up: Caddy was reloaded', 'info')}
			>
				Push info
			</Button>
			<Button variant="ghost" onclick={spamToasts}>Spam 4 toasts (queue test)</Button>
		</div>
		<p class="text-xs text-secondary mt-2">
			Toasts appear bottom-right, auto-dismiss after 4 s, manual × dismiss available.
		</p>
	</div>

	<div>
		<h2 class="text-lg font-semibold mb-2">API client smoke</h2>
		<p class="text-sm">
			GET <code class="font-mono text-cyan">/api/v1/routes</code>:
			<span class="font-mono">{apiStatus}</span>
		</p>
	</div>
</div>
