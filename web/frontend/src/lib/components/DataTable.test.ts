// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// DataTable component tests (Step F Chunk 7.2, spec §11.3 — 3 tests).
// Behavior-based per §11.2.
//
// DataTable is `generics="T extends { id: string }"`. The row + expanded
// snippets receive the item as parameter, so createRawSnippet's render
// callback takes the typed parameter and returns the markup string.
// testing-library handles the HTML strings; we read the rendered <td>
// content as the assertion surface.

import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { createRawSnippet, type Snippet } from 'svelte';
import DataTable from './DataTable.svelte';

interface Item {
	id: string;
	label: string;
}

const items: Item[] = [
	{ id: 'r1', label: 'route one' },
	{ id: 'r2', label: 'route two' }
];

// Snippets that read the row item parameter. The double cast widens
// the snippet's parameter type from Item to the generic `{id: string}`
// that svelte-check infers from the DataTable's generic signature in
// a non-TSX context. The runtime contract is intact (Svelte calls
// the snippet with the actual Item at render time).
function rowSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<td class="px-4 py-3">${item.label}</td>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

function expandedSnippet(): Snippet<[{ id: string }]> {
	return createRawSnippet((getItem: () => Item) => ({
		render: () => {
			const item = getItem();
			return `<div data-testid="expanded-${item.id}">expanded: ${item.label}</div>`;
		}
	})) as unknown as Snippet<[{ id: string }]>;
}

describe('DataTable', () => {
	it('renders all headers + a row per item', () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet()
		});

		// Headers in <th>.
		expect(screen.getByRole('columnheader', { name: 'Label' })).toBeInTheDocument();
		// One <td> per item via the row snippet.
		expect(screen.getByText('route one')).toBeInTheDocument();
		expect(screen.getByText('route two')).toBeInTheDocument();
	});

	it('reveals the expanded snippet when a row is clicked, then collapses on second click', async () => {
		const user = userEvent.setup();
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		// Pre-click: expanded panel is not rendered (activeId === null,
		// the `{#if expanded && activeId === item.id}` branch is false).
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();

		// Click on the first row's <tr> (role="button" via DataTable's
		// markup). We target by accessible name composed of the inner
		// <td> text, since each <tr> is role="button".
		const rows = screen.getAllByRole('button');
		const firstRow = rows[0];
		await user.click(firstRow);
		expect(screen.getByTestId('expanded-r1')).toBeInTheDocument();

		// Second click on the same row collapses it (activeId returns
		// to null per the toggle() logic).
		await user.click(firstRow);
		expect(screen.queryByTestId('expanded-r1')).not.toBeInTheDocument();
	});

	it('shows a fallback empty-state message when items is empty', () => {
		render(DataTable, {
			headers: ['Label'],
			items: [] as Item[],
			row: rowSnippet()
		});

		// DataTable renders a single fallback row with "No items." text
		// inside a colspan'd <td>. Asserting on the text is enough; the
		// surrounding markup is a defensive scaffold.
		expect(screen.getByText('No items.')).toBeInTheDocument();
	});

	it('drops row interactivity when interactive=false (Step G G.3)', () => {
		// Sessions table use case: caller passes no expanded snippet and
		// wants read-only rows. The pre-G.3 component left cursor-pointer
		// + role=button + tabindex + hover-rail on every row regardless,
		// causing the parasite-cursor cosmetic bug documented in smoke
		// doc Step F §5 dette #1.
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			interactive: false
		});

		// No role=button on rows → screen.queryAllByRole returns 0 for
		// the row layer (the columnheader role is still there for <th>).
		expect(screen.queryAllByRole('button')).toHaveLength(0);

		// Rows render but without tabindex and without the .interactive
		// class that drives cursor + hover-rail + focus-ring in CSS.
		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.getAttribute('tabindex')).toBeNull();
			expect(r.getAttribute('role')).toBeNull();
			expect(r.classList.contains('interactive')).toBe(false);
		}
	});

	it('defaults to interactive=true, and the row stays a row', () => {
		// v2.72 — this test used to require role="button" and
		// tabindex="0" on the <tr>, which was the defect itself:
		// role="button" overrides the implicit `row` role and takes the
		// cells out of the table's accessibility tree, so a screen
		// reader announced one control named by every column
		// concatenated. The interactive AFFORDANCE is what callers
		// depend on, and that is what this now pins — the visual class
		// and the click — without the lie about what the row is.
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		const rows = container.querySelectorAll('tr.data-row');
		expect(rows).toHaveLength(items.length);
		for (const r of rows) {
			expect(r.getAttribute('role')).toBeNull();
			expect(r.getAttribute('tabindex')).toBeNull();
			expect(r.classList.contains('interactive')).toBe(true);
		}
	});
});

// v2.72 — an expandable row gets a real disclosure button.
//
// The row carried role="button" + tabindex="0". role="button"
// overrides the implicit `row` role, which takes the <td> children out
// of the table's accessibility tree: a screen reader announced ONE
// control whose name was all the cells concatenated, with no column
// headers to anchor them. And the audit row contains two real filter
// buttons, so that was a button inside a button — the nested controls
// stayed Tab-focusable but were flattened out of the tree, so focus
// could land on something that announced nothing.
describe('DataTable — the disclosure button', () => {
	it('renders one per row, with aria-expanded', async () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		const first = screen.getByTestId(`data-row-toggle-${items[0].id}`);
		expect(first.tagName).toBe('BUTTON');
		expect(first.getAttribute('aria-expanded')).toBe('false');

		await fireEvent.click(first);

		expect(first.getAttribute('aria-expanded')).toBe('true');
	});

	it('points aria-controls at the details row once open', async () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		const first = screen.getByTestId(`data-row-toggle-${items[0].id}`);
		// Closed: there is no details row to control, so the attribute
		// must be absent rather than dangling.
		expect(first.getAttribute('aria-controls')).toBeNull();

		await fireEvent.click(first);

		const controls = first.getAttribute('aria-controls');
		expect(controls).toBeTruthy();
		expect(document.getElementById(controls!)).not.toBeNull();
	});

	it('names each button from rowLabel', async () => {
		// A screen-reader user tabbing a list of fifty rows needs them
		// told apart; "Details, button" fifty times is not a name.
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet(),
			rowLabel: (item: { id: string }) => `Details for ${item.id}`
		});

		expect(
			screen.getByRole('button', { name: `Details for ${items[0].id}` })
		).toBeInTheDocument();
	});

	it('gives the disclosure column a named header cell', () => {
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet(),
			rowLabelHeader: 'Row details'
		});

		const headerCells = container.querySelectorAll('thead th');
		// One more than the caller's headers: the column association
		// only means something if every column has a header.
		expect(headerCells).toHaveLength(2);
		expect(headerCells[0].textContent).toContain('Row details');
	});

	it('spans the extra column in the details row and the empty row', async () => {
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		await fireEvent.click(screen.getByTestId(`data-row-toggle-${items[0].id}`));

		const detailsCell = container.querySelector('tr.bg-surface td');
		expect(detailsCell?.getAttribute('colspan')).toBe('2');
	});

	it('adds no button to a read-only table', () => {
		render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			interactive: false
		});

		expect(screen.queryByTestId(`data-row-toggle-${items[0].id}`)).toBeNull();
	});

	it('adds no button when there is nothing to expand', () => {
		// interactive defaults to true, but with no `expanded` snippet
		// there is no disclosure to offer — the alerting tabs render
		// that shape.
		render(DataTable, { headers: ['Label'], items, row: rowSnippet() });

		expect(screen.queryByTestId(`data-row-toggle-${items[0].id}`)).toBeNull();
	});
});

// The mouse affordance is years old and operators use it, so it stays
// — but it must not fire for a click that started on a control inside
// the row. The audit row has two filter buttons of its own.
describe('DataTable — the row click', () => {
	it('still toggles when the row itself is clicked', async () => {
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: rowSnippet(),
			expanded: expandedSnippet()
		});

		await fireEvent.click(container.querySelector('tr.data-row')!);

		expect(container.querySelector('tr.bg-surface')).not.toBeNull();
	});

	it('does not toggle when a control inside the row is clicked', async () => {
		const { container } = render(DataTable, {
			headers: ['Label'],
			items,
			row: createRawSnippet(() => ({
				render: () => `<td><button type="button" data-testid="inner">Filter</button></td>`
			})),
			expanded: expandedSnippet()
		});

		await fireEvent.click(screen.getAllByTestId('inner')[0]);

		expect(container.querySelector('tr.bg-surface')).toBeNull();
	});
});
