<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PageHeader — page-level header surface.

  Step R.4.2 visual refonte: mirrors the mock's .screen-head
  pattern at docs/superpowers/mocks/2026-05-31-step-r-aesthetic.html
  :749-760 — optional eyebrow (mono caps over the title) + title +
  subtitle, plus a right-aligned actions slot. The component is the
  single point of truth for page-head visual so all 10 existing
  call sites pick up the new style without per-page changes.

  Public API (add-only — `eyebrow` is the new prop):

    eyebrow  — string (optional, mono caps small-text breadcrumb-ish
               header — e.g. "Vue d'ensemble", "Sécurité · WAF")
    title    — string (required)
    subtitle — string (optional)
    actions  — Snippet (optional, right-aligned)

  Used by: Routes, Audit, Settings, Topology, Observability,
  Security, Security/[id], Security/decisions, Admin/users.
  R.4.1 Dashboard ships its own inline .screen-head; future
  cleanup can switch it to this component.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		eyebrow?: string;
		title: string;
		subtitle?: string;
		actions?: Snippet;
	}

	let { eyebrow, title, subtitle, actions }: Props = $props();
</script>

<header class="page-header">
	<div class="page-header__text">
		{#if eyebrow}
			<div class="page-header__eyebrow">{eyebrow}</div>
		{/if}
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
		gap: 16px;
		margin-bottom: 18px;
	}
	.page-header__text {
		min-width: 0;
	}
	.page-header__eyebrow {
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-muted);
		margin-bottom: 6px;
	}
	.page-header__title {
		font-size: 22px;
		font-weight: 600;
		color: var(--fg);
		line-height: 1.2;
		letter-spacing: -0.01em;
		margin: 0;
	}
	.page-header__subtitle {
		margin-top: 6px;
		font-size: 13px;
		color: var(--fg-muted);
		line-height: 1.5;
		max-width: 640px;
	}
	.page-header__actions {
		display: flex;
		align-items: center;
		gap: 8px;
		flex-shrink: 0;
	}
</style>
