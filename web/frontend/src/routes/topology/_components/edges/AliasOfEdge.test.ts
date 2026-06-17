// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.a — AliasOfEdge visual contract pin.
//
// Tests the rendered SVG produced by BaseEdge:
//   - emits a <path> element (BaseEdge's standard surface)
//   - the path's style attribute carries the dashed-stroke
//     contract (dasharray + muted color + opacity)
//   - NO <animateMotion> element is rendered (the structural
//     contract that distinguishes AliasOfEdge from
//     AnimatedFlowEdge — adding particles to alias edges would
//     visually double-count traffic).
//
// Props pass through `{props: {…}}` because EdgeProps carries
// `id` / `source` / `target` fields that collide with Svelte
// component option names; the wrapping disambiguates per
// testing-library/svelte's validation.

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import { Position } from '@xyflow/svelte';
import AliasOfEdge from './AliasOfEdge.svelte';

// Cast to `any` at the test boundary — EdgeProps' generic
// arithmetic (Edge<Record<string, unknown>> intersected with
// EdgePosition + the marker types) is wider than what we need
// for visible-DOM assertions, and TypeScript's union-distribution
// rejects perfectly-valid runtime shapes that happen to omit
// one of the optional fields the generic union requires.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const COMMON_PROPS: any = {
	id: 'e-alias-r-1-alt',
	source: 'alias-r-1-alt',
	target: 'fqdn-r-1',
	type: 'alias-of',
	sourceX: 100,
	sourceY: 200,
	targetX: 400,
	targetY: 0,
	sourcePosition: Position.Right,
	targetPosition: Position.Left,
	style: '',
	markerEnd: '',
	selected: false,
	animated: false,
	interactionWidth: 0,
	data: { kind: 'alias-of', aliasOf: 'r-1' }
};

describe('AliasOfEdge', () => {
	it('renders an SVG <path> element', () => {
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		const path = container.querySelector('path');
		expect(path).not.toBeNull();
	});

	it('applies a dashed stroke (stroke-dasharray) to the path', () => {
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		const path = container.querySelector('path');
		const style = path?.getAttribute('style') ?? '';
		expect(style).toContain('stroke-dasharray');
		expect(style).toContain('3 4');
	});

	it('uses a muted accent color (--fg-dim)', () => {
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		const path = container.querySelector('path');
		const style = path?.getAttribute('style') ?? '';
		expect(style).toContain('--fg-dim');
	});

	it('uses a thin stroke-width (1) so the edge reads as a hint, not a primary connection', () => {
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		const path = container.querySelector('path');
		const style = path?.getAttribute('style') ?? '';
		expect(style).toContain('stroke-width: 1');
	});

	it('does NOT emit any <animateMotion> element (no particles)', () => {
		// Structural contract that distinguishes AliasOfEdge from
		// AnimatedFlowEdge. Adding particles to alias edges would
		// double-count traffic visually — the real flow already
		// animates on the Caddy→Backend edges shared by every
		// alias of the same route.
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		expect(container.querySelector('animateMotion')).toBeNull();
		expect(container.querySelector('circle')).toBeNull();
	});

	it('does NOT include flow-edge accent palette (--accent / oklch high-chroma) on the stroke', () => {
		// The flow-edge palette uses oklch(68% 0.21 255) for live
		// traffic. AliasOfEdge must NOT borrow that hue — its
		// muted palette is what reads as "semantic relationship"
		// instead of "traffic line". If a future refactor accidentally
		// swaps the constants this test catches it.
		const { container } = render(AliasOfEdge, { props: COMMON_PROPS });
		const path = container.querySelector('path');
		const style = path?.getAttribute('style') ?? '';
		expect(style).not.toContain('0.21');
		expect(style).not.toContain('--accent');
	});
});
