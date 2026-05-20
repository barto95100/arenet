// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Badge component tests (Step F Chunk 7.1, spec §11.3 — 1 test
// parametrized over the 6 variants). Behavior-based per §11.2:
// each variant must render with the correct data-variant attribute,
// which is the contract Badge.svelte uses to switch its CSS.
//
// Spec §5.4 declared 7 variants (cyan/green/amber/red/violet/slate/
// outline) — the actual implementation in Step F shipped 6
// (tls/waf/status-up/status-warn/status-down/neutral). The Chunk 1
// add-only discipline froze the existing API; this test asserts on
// what really ships rather than the abstract spec.

import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import Badge from './Badge.svelte';

function textSnippet(text: string) {
	return createRawSnippet(() => ({
		render: () => `<span>${text}</span>`
	}));
}

type BadgeVariant =
	| 'tls'
	| 'waf'
	| 'status-up'
	| 'status-warn'
	| 'status-down'
	| 'neutral';

describe('Badge', () => {
	it.each<BadgeVariant>([
		'tls',
		'waf',
		'status-up',
		'status-warn',
		'status-down',
		'neutral'
	])('renders with data-variant="%s"', (variant) => {
		const { container } = render(Badge, {
			variant,
			children: textSnippet('Active')
		});

		// Badge uses `<span class="badge" data-variant={variant}>` —
		// the data-variant attribute is the styling contract picked up
		// by the per-variant CSS rules. Asserting on it (rather than on
		// CSS class names) keeps the test resilient to internal CSS
		// refactors of Badge.svelte.
		const el = container.querySelector('.badge');
		expect(el).not.toBeNull();
		expect(el).toHaveAttribute('data-variant', variant);
		// Badge content survives the variant change.
		expect(screen.getByText('Active')).toBeInTheDocument();
	});
});
