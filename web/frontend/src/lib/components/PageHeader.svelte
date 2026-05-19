<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PageHeader (Step F §5.3 — new in Chunk 3.2).

  Surface for page-level controls. Holds a title, an optional
  subtitle, and a right-aligned actions slot. Used by:

    - Routes page → "Add route" primary button
    - Audit page → filter chips + "Clear all"
    - Settings page → (no actions for now)

  Topology and Setup/Login pages stay headerless — they have their
  own UX patterns (canvas, centered card).

  Public API (add-only per §1.3):

    title    — string (required)
    subtitle — string (optional)
    actions  — Snippet (optional, right-aligned)
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		title: string;
		subtitle?: string;
		actions?: Snippet;
	}

	let { title, subtitle, actions }: Props = $props();
</script>

<header class="page-header">
	<div class="page-header__text">
		<h1 class="page-header__title">{title}</h1>
		{#if subtitle}
			<p class="page-header__subtitle">{subtitle}</p>
		{/if}
	</div>
	{#if actions}
		<div class="page-header__actions">
			{@render actions()}
		</div>
	{/if}
</header>

<style>
	.page-header {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
		padding-bottom: var(--space-6);
		margin-bottom: var(--space-6);
		border-bottom: 1px solid var(--border-subtle);
	}
	.page-header__title {
		font-size: var(--text-2xl);
		font-weight: 600;
		color: var(--text-primary);
		line-height: 1.2;
		margin: 0;
	}
	.page-header__subtitle {
		margin-top: var(--space-1);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		line-height: 1.5;
	}
	.page-header__actions {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		flex-shrink: 0;
	}
</style>
