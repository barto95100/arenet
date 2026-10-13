// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { BackupSchedule } from '$lib/api/settings';

const baseView: BackupSchedule = {
	enabled: false,
	frequency: 'daily',
	time: '03:00',
	weekday: 0,
	keep: 14,
	dir: '',
	effectiveDir: '/var/lib/arenet/backups',
	passphraseSet: false,
	emailMode: 'never',
	emailChannelId: '',
	alertChannelIds: [],
	timeZone: 'UTC+02:00 (CEST)',
	status: {}
};

const api = {
	getBackupSchedule: vi.fn(),
	putBackupSchedule: vi.fn(),
	runBackupNow: vi.fn(),
	listBackups: vi.fn(),
	deleteBackup: vi.fn(),
	restoreBackupFile: vi.fn(),
	backupDownloadURL: (n: string) => `/api/v1/admin/backups/${n}`
};
const listChannels = vi.fn();
const pushToast = vi.fn();

vi.mock('$lib/api/settings', () => ({ settingsApi: api, MIN_BACKUP_PASSPHRASE_LEN: 12 }));
vi.mock('$lib/api/alerting', () => ({ alertingApi: { listChannels: () => listChannels() } }));
vi.mock('$lib/stores/toast', () => ({ pushToast: (m: string, v?: string) => pushToast(m, v) }));

import {
	hasUnsaved,
	unsavedIds,
	resetUnsavedRegistry
} from '$lib/stores/unsaved.svelte';

const { default: Section } = await import('./ScheduledBackupsSection.svelte');

beforeEach(() => {
	for (const f of Object.values(api)) if (typeof f === 'function' && 'mockReset' in f) f.mockReset();
	listChannels.mockReset();
	pushToast.mockReset();
	api.getBackupSchedule.mockResolvedValue({ ...baseView });
	api.listBackups.mockResolvedValue({ dir: baseView.effectiveDir, files: [] });
	listChannels.mockResolvedValue([
		{ id: 'mail1', name: 'ops-mail', kind: 'email', enabled: true, minSeverity: 0, config: {} },
		{ id: 'hook1', name: 'discord', kind: 'webhook', enabled: true, minSeverity: 0, config: {} }
	]);
});

async function renderLoaded() {
	render(Section);
	await screen.findByText('Scheduled backups');
	await screen.findByTestId('sched-enabled');
}

describe('ScheduledBackupsSection', () => {
	it('is hidden when the backend does not offer the feature', async () => {
		api.getBackupSchedule.mockRejectedValue(new ApiError('unavailable', 409, 'validation'));
		render(Section);
		await waitFor(() => expect(api.getBackupSchedule).toHaveBeenCalled());
		expect(screen.queryByText('Scheduled backups')).not.toBeInTheDocument();
	});

	it('requires a passphrase to enable, and checks length and confirmation', async () => {
		await renderLoaded();
		await userEvent.click(screen.getByTestId('sched-enabled'));
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('Set a passphrase to enable scheduled backups.')).toBeInTheDocument();

		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
		await userEvent.type(pass, 'short');
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('At least 12 characters.')).toBeInTheDocument();

		await userEvent.clear(pass);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'something different here');
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByText('The passphrases do not match.')).toBeInTheDocument();
		expect(api.putBackupSchedule).not.toHaveBeenCalled();
	});

	it('saves the schedule with an email channel chosen among email channels only', async () => {
		api.putBackupSchedule.mockImplementation(async (r) => ({ ...baseView, ...r, passphraseSet: true }));
		await renderLoaded();
		await userEvent.click(screen.getByTestId('sched-enabled'));
		const [pass, confirm] = screen.getAllByLabelText(/passphrase/i);
		await userEvent.type(pass, 'a long enough passphrase');
		await userEvent.type(confirm, 'a long enough passphrase');
		await userEvent.selectOptions(screen.getByTestId('sched-email-mode'), 'weekly');
		const channelSelect = screen.getByTestId('sched-email-channel');
		expect(within(channelSelect).queryByText('discord')).not.toBeInTheDocument();
		await userEvent.selectOptions(channelSelect, 'mail1');
		await userEvent.click(screen.getByLabelText(/discord/));
		await userEvent.click(screen.getByRole('button', { name: 'Save' }));

		await waitFor(() => expect(api.putBackupSchedule).toHaveBeenCalled());
		expect(api.putBackupSchedule.mock.calls[0][0]).toMatchObject({
			enabled: true,
			passphrase: 'a long enough passphrase',
			emailMode: 'weekly',
			emailChannelId: 'mail1',
			alertChannelIds: ['hook1']
		});
		expect(pushToast).toHaveBeenCalledWith('Scheduled backups saved.', 'success');
	});

	it('runs a backup now and restores one from the list after confirmation', async () => {
		api.getBackupSchedule.mockResolvedValue({ ...baseView, passphraseSet: true });
		api.listBackups.mockResolvedValue({
			dir: baseView.effectiveDir,
			files: [{ name: 'arenet-backup-auto-20260921-030000.json', size: 2048, modTime: '2026-09-21T03:00:00Z' }]
		});
		api.runBackupNow.mockResolvedValue({ file: 'arenet-backup-auto-20260921-221500.json', size: 10, pruned: 0, emailed: false });
		api.restoreBackupFile.mockResolvedValue({ routesImported: 3, usersImported: 1 });
		await renderLoaded();

		await userEvent.click(screen.getByRole('button', { name: 'Back up now' }));
		await waitFor(() =>
			expect(pushToast).toHaveBeenCalledWith('Backup arenet-backup-auto-20260921-221500.json written.', 'success')
		);

		const row = await screen.findByTestId('sched-file-row');
		expect(within(row).getByText('Download').closest('a')).toHaveAttribute(
			'href',
			'/api/v1/admin/backups/arenet-backup-auto-20260921-030000.json'
		);
		await userEvent.click(within(row).getByRole('button', { name: /Restore/ }));
		expect(await screen.findByText('Restore this backup?')).toBeInTheDocument();
		const dialogRestore = screen.getAllByRole('button', { name: 'Restore' }).at(-1)!;
		await userEvent.click(dialogRestore);
		await waitFor(() => expect(api.restoreBackupFile).toHaveBeenCalledWith('arenet-backup-auto-20260921-030000.json'));
	});
});

// v2.72 — the section tells the settings page when leaving would
// discard input (spec 2026-10-13). Its onMount is async, so the
// registration goes through an $effect; the destroy case below is what
// proves that teardown actually runs.
describe('ScheduledBackupsSection — unsaved input', () => {
	beforeEach(() => {
		resetUnsavedRegistry();
	});

	it('reports nothing on a freshly loaded form', async () => {
		await renderLoaded();

		expect(hasUnsaved()).toBe(false);
	});

	it('reports a toggled schedule and forgets it once toggled back', async () => {
		await renderLoaded();

		await userEvent.click(screen.getByTestId('sched-enabled'));
		expect(unsavedIds()).toEqual(['scheduled-backups']);

		await userEvent.click(screen.getByTestId('sched-enabled'));
		expect(hasUnsaved()).toBe(false);
	});

	it('reports a typed passphrase, which has nothing to compare against', async () => {
		await renderLoaded();

		await userEvent.type(
			screen.getByLabelText(/Passphrase \(at least/i),
			'correct-horse-battery'
		);

		expect(hasUnsaved()).toBe(true);
	});

	it('is clean after a successful save', async () => {
		await renderLoaded();
		api.putBackupSchedule.mockResolvedValue({ ...baseView, keep: 30 });

		const keep = screen.getByTestId('sched-keep');
		await userEvent.clear(keep);
		await userEvent.type(keep, '30');
		expect(hasUnsaved()).toBe(true);

		await userEvent.click(screen.getByRole('button', { name: /Save/i }));
		await waitFor(() => expect(api.putBackupSchedule).toHaveBeenCalled());

		await waitFor(() => expect(hasUnsaved()).toBe(false));
	});

	it('unregisters when the section is destroyed', async () => {
		const { unmount } = render(Section);
		await screen.findByTestId('sched-enabled');
		await userEvent.click(screen.getByTestId('sched-enabled'));
		expect(hasUnsaved()).toBe(true);

		unmount();

		expect(hasUnsaved()).toBe(false);
	});
});
