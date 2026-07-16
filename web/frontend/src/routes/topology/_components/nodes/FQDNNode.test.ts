// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.e — FQDNNode chevron toggle contract pin.
//
// Tests the operator-visible contract added in Phase 3.e :
//   - chevron appears ONLY when the route has at least one alias
//     (data.aliasCount > 0) — routes without aliases stay
//     visually unchanged.
//   - chevron rotation : default (no .expanded class) when the
//     route is collapsed, rotated 90° (.expanded class) when
//     expanded — both rendered from the same chevron-right SVG.
//   - chevron click toggles the page-local collapsedRoutes store
//     for the right route ID, propagation stopped so SvelteFlow
//     doesn't also select the node.
//   - collapsed routes render the aggregate meta "N aliases · X
//     r/s" instead of the per-route req/s line, expanded routes
//     render the layout's data.meta verbatim. The compact "r/s"
//     suffix (vs the verbose "req/s total") is the HOTFIX from
//     the post-Phase-3.e ship — see the format comment block in
//     FQDNNode.svelte for the overflow rationale.
//
// The collapsedRoutes store import is the real module — the test
// resets it between cases via the store's own reset() helper.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import type { FQDNNodeData } from '../../_types';
import { collapsedRoutes } from '../../_collapsed.svelte';

vi.mock('@xyflow/svelte', async () => {
	const actual = await vi.importActual<typeof import('@xyflow/svelte')>('@xyflow/svelte');
	const HandleStub = (await import('./HandleStub.test.svelte')).default;
	return {
		...actual,
		Handle: HandleStub
	};
});

const FQDNNode = (await import('./FQDNNode.svelte')).default;

function makeData(overrides: Partial<FQDNNodeData> = {}): FQDNNodeData {
	return {
		kind: 'fqdn',
		host: 'primary.example.com',
		protocols: 'HTTPS',
		meta: '5 req/s',
		aliases: [],
		wafLevel: 'off',
		routeId: 'r-1',
		aliasCount: 0,
		aliasTotalRps: 0,
		collapsed: false,
		disabled: false,
		...overrides
	};
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function nodeProps(data: FQDNNodeData): any {
	return {
		id: 'fqdn-r-1',
		type: 'fqdn',
		data,
		dragging: false,
		selected: false,
		isConnectable: false,
		positionAbsoluteX: 0,
		positionAbsoluteY: 0,
		width: 200,
		height: 70,
		zIndex: 0
	};
}

describe('FQDNNode chevron toggle', () => {
	beforeEach(() => {
		collapsedRoutes.reset();
	});

	it('no chevron when the route has zero aliases', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 0 }))
		});
		expect(container.querySelector('.chevron')).toBeNull();
	});

	it('renders chevron when the route has at least one alias', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 3 }))
		});
		expect(container.querySelector('.chevron')).not.toBeNull();
	});

	it('chevron carries .expanded class when the route is expanded', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 3, collapsed: false }))
		});
		const chevron = container.querySelector('.chevron');
		expect(chevron?.classList.contains('expanded')).toBe(true);
	});

	it('chevron drops .expanded class when the route is collapsed', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 3, collapsed: true }))
		});
		const chevron = container.querySelector('.chevron');
		expect(chevron?.classList.contains('expanded')).toBe(false);
	});

	it('click on chevron toggles the collapsedRoutes store for the right route ID', async () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ routeId: 'r-1', aliasCount: 3, collapsed: false }))
		});
		const chevron = container.querySelector('.chevron') as HTMLButtonElement;
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
		await fireEvent.click(chevron);
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(true);
		await fireEvent.click(chevron);
		expect(collapsedRoutes.isCollapsed('r-1')).toBe(false);
	});

	it('chevron click invokes stopPropagation so SvelteFlow does not also select the node', async () => {
		// Pin the call to stopPropagation on the synthesised
		// click event. Without this the chevron's click would
		// bubble up to SvelteFlow's node-selection handler and
		// the operator would see the FQDN node get a selection
		// outline on every toggle — visually distracting.
		//
		// Spying on the event itself is the cleanest signal
		// because Svelte 5's event delegation makes the actual
		// bubbling path harder to assert from outside.
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 3 }))
		});
		const chevron = container.querySelector('.chevron') as HTMLButtonElement;
		const ev = new MouseEvent('click', { bubbles: true, cancelable: true });
		const stopSpy = vi.spyOn(ev, 'stopPropagation');
		chevron.dispatchEvent(ev);
		expect(stopSpy).toHaveBeenCalledTimes(1);
	});

	it('collapsed routes render aggregate meta "N aliases · X r/s" (compact, single-line)', () => {
		render(FQDNNode, {
			props: nodeProps(
				makeData({
					aliasCount: 21,
					aliasTotalRps: 5.34,
					collapsed: true,
					meta: 'should-not-appear-when-collapsed'
				})
			)
		});
		// HOTFIX (2026-06-17) — the format is "N aliases · X r/s"
		// (no " total" suffix, "r/s" not "req/s"). Verbose
		// "21 aliases · 5.34 req/s total" wrapped to 3 lines in
		// the 176 px content budget and pushed the FQDN past its
		// RouteGroupNode container.
		expect(screen.getByText('21 aliases · 5.34 r/s')).toBeInTheDocument();
		expect(screen.queryByText('should-not-appear-when-collapsed')).toBeNull();
		// Defensive : the literal string "total" must not appear
		// anywhere in the rendered meta.
		expect(screen.queryByText(/total/)).toBeNull();
	});

	it('expanded routes render layout-provided data.meta verbatim', () => {
		render(FQDNNode, {
			props: nodeProps(
				makeData({
					aliasCount: 3,
					aliasTotalRps: 2,
					collapsed: false,
					meta: '8 req/s · 3 aliases'
				})
			)
		});
		expect(screen.getByText('8 req/s · 3 aliases')).toBeInTheDocument();
	});

	it('singular "alias" vs plural "aliases" in the collapsed meta', () => {
		const { unmount } = render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 1, aliasTotalRps: 0.5, collapsed: true }))
		});
		expect(screen.getByText('1 alias · 0.50 r/s')).toBeInTheDocument();
		unmount();
		render(FQDNNode, {
			props: nodeProps(makeData({ aliasCount: 2, aliasTotalRps: 0, collapsed: true }))
		});
		expect(screen.getByText('2 aliases · 0 r/s')).toBeInTheDocument();
	});

	it('collapsed meta string stays under the FQDN content-width budget at pathological counts', () => {
		// Empirical bound : the FQDN card is 200 px wide with
		// 12 px lateral padding, leaving 176 px of content width.
		// The meta uses a 10.5 px mono font (≈6.3 px / char in
		// most mono faces), so ~28 chars is the practical wrap
		// threshold. The format change cuts the meta to ~21
		// chars at 21 aliases; this test pins the upper bound
		// for the worst plausible homelab scale (1000 aliases,
		// 1 r/s aggregate = "1000 aliases · 1 r/s" = 20 chars).
		const MAX_CHARS = 26; // headroom over the 28-char wrap line
		const cases = [
			{ aliasCount: 1, aliasTotalRps: 0 },
			{ aliasCount: 21, aliasTotalRps: 0.1 },
			{ aliasCount: 21, aliasTotalRps: 5.34 },
			{ aliasCount: 21, aliasTotalRps: 999 },
			{ aliasCount: 1000, aliasTotalRps: 0.1 },
			{ aliasCount: 1000, aliasTotalRps: 999 }
		];
		for (const c of cases) {
			const { container, unmount } = render(FQDNNode, {
				props: nodeProps(makeData({ ...c, collapsed: true }))
			});
			const meta = container.querySelector('.meta') as HTMLElement;
			const text = (meta.textContent ?? '').trim();
			if (text.length > MAX_CHARS) {
				throw new Error(
					`collapsed meta too long for aliasCount=${c.aliasCount} ` +
						`aliasTotalRps=${c.aliasTotalRps}: ` +
						`"${text}" (${text.length} chars, max ${MAX_CHARS})`
				);
			}
			unmount();
		}
	});
});

// v2.14.3 route disable/enable — a disabled route still appears in the
// topology (Caddy config generation just skips it), so the FQDN node
// must read as "deliberately off" rather than a mysterious zero-traffic
// phantom. See internal/api/topology/types.go Route.Disabled docstring.
describe('FQDNNode disabled route dimming', () => {
	it('applies the dim/disabled state when data.disabled is true', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ disabled: true }))
		});
		const node = container.querySelector('.fqdn-node');
		expect(node?.classList.contains('disabled')).toBe(true);
		expect(node?.getAttribute('data-disabled')).toBe('true');
	});

	it('sets the tooltip to the disabled i18n string when disabled', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ disabled: true }))
		});
		const node = container.querySelector('.fqdn-node');
		expect(node?.getAttribute('title')).toBe('Disabled — not serving traffic');
	});

	it('does not apply the dim state or tooltip when disabled is false', () => {
		const { container } = render(FQDNNode, {
			props: nodeProps(makeData({ disabled: false }))
		});
		const node = container.querySelector('.fqdn-node');
		expect(node?.classList.contains('disabled')).toBe(false);
		expect(node?.getAttribute('data-disabled')).toBe('false');
		expect(node?.getAttribute('title')).toBeNull();
	});
});
