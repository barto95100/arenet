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
		<h2 class="text-lg font-semibold mb-2">API client smoke</h2>
		<p class="text-sm">
			GET <code class="font-mono text-cyan">/api/v1/routes</code>:
			<span class="font-mono">{apiStatus}</span>
		</p>
	</div>
</div>
