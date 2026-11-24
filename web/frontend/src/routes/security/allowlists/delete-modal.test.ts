// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Allowlists page — delete-confirmation guards (#377).
//
// Dogfood v2.86.0 caught an orphan confirm dialog: after a successful
// DELETE, confirmDelete() reset deleteTarget to null but never closed
// the dialog (confirmDeleteOpen stayed true), so the ConfirmDialog
// lingered showing an empty name ("Delete the allowlist ""?") and its
// confirm button silently did nothing. These guards assert on what the
// admin SEES (§guard: assert the output), not on component internals.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { auth } from '$lib/stores/auth.svelte';
import type { User } from '$lib/api/auth';

vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));
vi.mock('$lib/api/allowlists', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/api/allowlists')>();
	return { ...actual, listAllowlists: vi.fn(), deleteAllowlist: vi.fn() };
});

import Page from './+page.svelte';
import { listAllowlists, deleteAllowlist, type Allowlist } from '$lib/api/allowlists';

const adminUser: User = {
	id: 'u1',
	username: 'admin',
	displayName: 'Admin',
	locked: false,
	passwordCompromised: false,
	hibpCheckStatus: 'clean',
	themePreference: 'dark',
	languagePreference: 'en',
	role: 'admin',
	authSource: 'local'
};

const sample: Allowlist = {
	slug: 'test',
	name: 'test',
	description: '',
	enabled: true,
	scopeBlock: true,
	scopeThrottle: true,
	scopeAudit: true,
	entries: [{ cidr: '10.0.0.1/32', note: '' }],
	createdAt: '2026-11-24T10:00:00Z',
	updatedAt: '2026-11-24T10:00:00Z'
};

describe('allowlists page — delete confirmation', () => {
	beforeEach(() => {
		auth.user = adminUser;
		vi.mocked(deleteAllowlist).mockResolvedValue();
	});
	afterEach(() => {
		auth.user = null;
		vi.clearAllMocks();
	});

	it('G_delete_modal_closes_after_success: the full open→confirm→success sequence closes the dialog and clears the target', async () => {
		vi.mocked(listAllowlists).mockResolvedValueOnce([sample]).mockResolvedValue([]);
		const user = userEvent.setup();
		render(Page);

		// 1. a row is listed (after onMount(load)).
		await screen.findByText('test');
		// 2. open the confirm dialog from the row's Delete action (the only
		//    "Delete" button before the dialog mounts).
		await user.click(screen.getByRole('button', { name: 'Delete' }));
		// dialog is open and names the real target — we walk the sequence,
		// not a hand-set final state.
		const dialog = await screen.findByRole('dialog', { name: 'Delete allowlist' });
		expect(within(dialog).getByText(/Delete the allowlist "test"\?/)).toBeInTheDocument();

		// 3. confirm inside the dialog; the mocked DELETE resolves success.
		await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
		expect(deleteAllowlist).toHaveBeenCalledWith('test');

		// 4. assert BOTH state transitions through what the admin sees
		//    (§guard: assert the output, never the private $state):
		//      confirmDeleteOpen → false  ⇒  no dialog left in the DOM
		//      deleteTarget      → null   ⇒  no lingering empty-name body
		await waitFor(() => {
			expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
			expect(screen.queryByText(/Delete the allowlist ""\?/)).not.toBeInTheDocument();
		});
	});

	it('G_delete_modal_shows_correct_name: dialog interpolates the name and never lingers with an empty one', async () => {
		vi.mocked(listAllowlists).mockResolvedValueOnce([sample]).mockResolvedValue([]);
		const user = userEvent.setup();
		render(Page);

		await screen.findByText('test');
		await user.click(screen.getByRole('button', { name: 'Delete' }));

		// The open dialog interpolates the real name, not an empty string.
		expect(await screen.findByText(/Delete the allowlist "test"\?/)).toBeInTheDocument();

		const dialog = screen.getByRole('dialog');
		await user.click(within(dialog).getByRole('button', { name: 'Delete' }));

		// After the delete succeeds, no orphan dialog with an empty name.
		await waitFor(() =>
			expect(screen.queryByText(/Delete the allowlist ""\?/)).not.toBeInTheDocument()
		);
	});
});
