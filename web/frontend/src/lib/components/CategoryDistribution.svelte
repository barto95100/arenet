<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

<!--
Step M.3 — Per-OWASP-category distribution strip for the
/security dashboard.

Renders a horizontal bar (or set of segments) showing the
relative counts of WAF events by category over the
summary window. Empty state: when every category is 0,
shows a single muted "no WAF events" message rather than
a flat bar.

Colour mapping is fixed (not per-tenant) so an operator
re-reads the dashboard with consistent semantics:
  - SQLi / RCE → status-down (red — critical attack surface)
  - XSS / LFI  → status-warn (amber — common but less severe)
  - PROTOCOL   → status-info (purple — protocol-layer)
  - OTHER      → text-muted

Step F design tokens — no OKLCH, no per-category accents
beyond the Step F palette.
-->

<script lang="ts">
	import { ALL_OWASP_CATEGORIES, type OwaspCategory } from '$lib/api/types';

	interface Props {
		/**
		 * Map of OwaspCategory → count over the window.
		 * Missing keys are treated as 0.
		 */
		counts: Record<string, number>;
	}
	let { counts }: Props = $props();

	// Map each category to a CSS var for its bar fill. Hard-
	// coded mapping; if a future category lands in
	// ALL_OWASP_CATEGORIES, the fallback colour for unknown
	// keys is `--text-muted`.
	const CATEGORY_COLOR: Record<OwaspCategory, string> = {
		SQLi: 'var(--status-down)',
		XSS: 'var(--status-warn)',
		RCE: 'var(--status-down)',
		LFI: 'var(--status-warn)',
		PROTOCOL: 'var(--status-info)',
		OTHER: 'var(--text-muted)'
	};

	// Total across all categories for the strip's width
	// computation. Derived so any prop change reflows
	// without manual invalidation.
	const total = $derived(
		ALL_OWASP_CATEGORIES.reduce((sum, c) => sum + (counts[c] ?? 0), 0)
	);

	// Each row gets a width ratio of its share of total +
	// the raw count for the right-aligned numeric label.
	const rows = $derived(
		ALL_OWASP_CATEGORIES.map((c) => ({
			category: c,
			count: counts[c] ?? 0,
			ratio: total > 0 ? (counts[c] ?? 0) / total : 0,
			color: CATEGORY_COLOR[c]
		}))
	);
</script>

<div class="strip">
	{#if total === 0}
		<div class="empty">no WAF events in window</div>
	{:else}
		{#each rows as row (row.category)}
			<div class="row">
				<div class="label">{row.category}</div>
				<div class="bar-track">
					<div
						class="bar-fill"
						style:width="{(row.ratio * 100).toFixed(1)}%"
						style:background={row.color}
					></div>
				</div>
				<div class="count">{row.count}</div>
			</div>
		{/each}
	{/if}
</div>

<style>
	.strip {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.row {
		display: grid;
		grid-template-columns: 4.5rem 1fr 3rem;
		align-items: center;
		gap: 0.5rem;
		font-size: var(--text-xs, 11px);
	}
	.label {
		color: var(--text-secondary);
		font-family: var(--font-mono, monospace);
		text-transform: uppercase;
		letter-spacing: 0.05em;
	}
	.bar-track {
		height: 8px;
		background: var(--bg-surface);
		border-radius: 4px;
		overflow: hidden;
		min-width: 24px;
	}
	.bar-fill {
		height: 100%;
		border-radius: 4px;
		min-width: 1px;
		transition: width 200ms ease-out;
	}
	@media (prefers-reduced-motion: reduce) {
		.bar-fill {
			transition: none;
		}
	}
	.count {
		font-family: var(--font-mono, monospace);
		text-align: right;
		color: var(--text-primary);
		font-variant-numeric: tabular-nums;
	}
	.empty {
		padding: 0.75rem;
		text-align: center;
		font-style: italic;
		color: var(--text-muted);
		font-size: var(--text-sm, 13px);
	}
</style>
