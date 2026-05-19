<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  AuditExpandedDetails (spec §9.5). Rendered inside the expanded row
  of DataTable when the user clicks an AuditRow.

  Shows: full timestamp (UTC), actor (display + UUID), target (type +
  full UUID), IP, User-Agent (wrapped), Message, and side-by-side
  Before/After JSON blocks with 50-line folding (spec §9.8).
-->
<script lang="ts">
	import type { AuditEvent } from '$lib/api/audit';
	import { formatJsonWithFold } from '$lib/utils/audit-format';

	interface Props {
		event: AuditEvent;
	}

	let { event }: Props = $props();

	// Per-block fold state (spec §9.8). Each AuditExpandedDetails
	// instance owns its own UI state; persists while the row is open
	// and discards when the row collapses (component unmounts).
	let beforeFoldedOpen = $state(false);
	let afterFoldedOpen = $state(false);

	const beforeJson = $derived(formatJsonWithFold(event.beforeJson));
	const afterJson = $derived(formatJsonWithFold(event.afterJson));

	const actorLine = $derived.by(() => {
		if (event.actorUserId) {
			const label = event.actorUsernameSnapshot || event.actorUserId;
			return `${label} (${event.actorUserId})`;
		}
		const attempted = event.actorUsernameSnapshot || '';
		return attempted
			? `(unauthenticated) — attempted: ${attempted}`
			: '(unauthenticated)';
	});

	const targetLine = $derived(
		event.targetType || event.targetId
			? `${event.targetType || '?'} (${event.targetId || '?'})`
			: '(none)'
	);

	const messageLine = $derived(event.message || '(none)');
</script>

<dl class="grid grid-cols-[8rem_1fr] gap-y-2 text-sm">
	<dt class="text-secondary">Full timestamp:</dt>
	<dd class="font-mono text-primary">{event.timestamp} UTC</dd>

	<dt class="text-secondary">Actor:</dt>
	<dd class="text-primary">{actorLine}</dd>

	<dt class="text-secondary">Target:</dt>
	<dd class="text-primary font-mono">{targetLine}</dd>

	<dt class="text-secondary">IP:</dt>
	<dd class="font-mono text-primary">{event.ip || '—'}</dd>

	<dt class="text-secondary">User-Agent:</dt>
	<dd class="font-mono text-primary text-xs ua-line">
		{event.userAgent || '—'}
	</dd>

	<dt class="text-secondary">Message:</dt>
	<dd class="text-primary">
		{#if event.message}
			{messageLine}
		{:else}
			<span class="text-muted">{messageLine}</span>
		{/if}
	</dd>
</dl>

<div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
	<div>
		<h4 class="text-xs uppercase tracking-wide text-secondary mb-1.5">Before</h4>
		<pre class="json-block">{beforeFoldedOpen ? beforeJson.full : beforeJson.display}</pre>
		{#if beforeJson.foldable && !beforeFoldedOpen}
			<button
				type="button"
				class="text-xs text-cyan hover:underline mt-1"
				onclick={() => (beforeFoldedOpen = true)}
			>
				Show more
			</button>
		{/if}
	</div>
	<div>
		<h4 class="text-xs uppercase tracking-wide text-secondary mb-1.5">After</h4>
		<pre class="json-block">{afterFoldedOpen ? afterJson.full : afterJson.display}</pre>
		{#if afterJson.foldable && !afterFoldedOpen}
			<button
				type="button"
				class="text-xs text-cyan hover:underline mt-1"
				onclick={() => (afterFoldedOpen = true)}
			>
				Show more
			</button>
		{/if}
	</div>
</div>

<style>
	.json-block {
		font-family: var(--font-mono);
		font-size: var(--text-xs);
		line-height: 1.5;
		color: var(--text-primary);
		background: var(--bg-base);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		max-height: 24rem;
		overflow: auto;
		white-space: pre-wrap;
		word-break: break-word;
		margin: 0;
	}
	.ua-line {
		word-break: break-all;
	}
</style>
