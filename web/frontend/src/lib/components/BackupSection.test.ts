// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// BackupSection tests — pin the user-facing contracts of the
// /settings Backup & Restore section :
//
//   - Export (redacted) triggers a direct download — no confirmation
//   - Export (with secrets) gates the download behind a danger
//     ConfirmDialog ; only the post-confirm action triggers the
//     download URL
//   - Restore parses the selected JSON file before POST + surfaces
//     the typed RestoreReport in a verbose breakdown
//   - Restore error from ApiError is surfaced verbatim — the
//     backend's "two paths forward" wording must reach the operator
//     without rewording
//   - Malformed JSON in the picked file surfaces an inline parse
//     error WITHOUT calling the network
//
// Pure CI hygiene : mirrors the v2.9.1 OIDCConcurrent test pattern.
// Zero production code touched ; only the test file added.
//
// window.location.href stubbing — we don't redefine
// window.location (jsdom resists, and the contract we want to pin
// is "the right URL builder is called with the right flag", not
// "the href setter received exactly this string"). We spy on
// settingsApi.exportBackupURL instead — that returns the URL
// string the component assigns to location.href. The assignment
// itself is a one-liner ; the contract we care about lives in
// the URL-builder call.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { ApiError } from '$lib/api/types';
import type { RestoreReport } from '$lib/api/settings';

const exportURLMock = vi.fn<(includeSecrets: boolean) => string>();
const postRestoreMock = vi.fn<
	(
		body: unknown,
		opts: { allowIncompleteRestore?: boolean; allowEmptyUsers?: boolean }
	) => Promise<RestoreReport>
>();

vi.mock('$lib/api/settings', () => ({
	settingsApi: {
		exportBackupURL: (includeSecrets: boolean) => exportURLMock(includeSecrets),
		postRestore: (
			body: unknown,
			opts: { allowIncompleteRestore?: boolean; allowEmptyUsers?: boolean }
		) => postRestoreMock(body, opts)
	}
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (msg: string, variant?: string) => pushToastMock(msg, variant)
}));

// Stub window.location.href assignment so the download trigger
// doesn't navigate the jsdom window away mid-test. Captures the
// assigned value so a complementary assertion can verify the URL.
//
// Approach : redefine window.location with a setter on `href` that
// records the assignment rather than actually navigating. Restored
// in afterEach via the property descriptor.
let assignedHref: string | null = null;
const originalLocation = window.location;
beforeEach(() => {
	exportURLMock.mockReset();
	postRestoreMock.mockReset();
	pushToastMock.mockReset();
	assignedHref = null;

	// jsdom's window.location is read-only at the property level
	// but we can replace it wholesale via defineProperty. The
	// minimal shape we need is a `href` setter ; nothing else in
	// BackupSection touches window.location.
	Object.defineProperty(window, 'location', {
		configurable: true,
		writable: true,
		value: {
			set href(v: string) {
				assignedHref = v;
			},
			get href() {
				return assignedHref ?? '';
			}
		}
	});
});

// Defensive — restore the real window.location after each test so
// any subsequent test in the same vitest worker isn't affected.
afterEach(() => {
	Object.defineProperty(window, 'location', {
		configurable: true,
		writable: true,
		value: originalLocation
	});
});

// Dynamic import AFTER the mocks are in place so the component
// captures the mocked settingsApi.
const { default: BackupSection } = await import('./BackupSection.svelte');

const happyReport: RestoreReport = {
	routesImported: 3,
	usersImported: 1,
	dnsProvidersImported: 1,
	forwardAuthProvidersImported: 0,
	oidcConfigImported: true,
	sentinelsInheritedTotal: 2,
	sentinelsUnresolvedTotal: 0,
	incompleteRows: 0
};

describe('BackupSection — export', () => {
	it('exports redacted without any confirmation', async () => {
		exportURLMock.mockReturnValue('/api/v1/admin/backup');
		render(BackupSection);

		const btn = screen.getByRole('button', { name: 'Export (redacted)' });
		await userEvent.click(btn);

		expect(exportURLMock).toHaveBeenCalledTimes(1);
		expect(exportURLMock).toHaveBeenCalledWith(false);
		expect(assignedHref).toBe('/api/v1/admin/backup');
	});

	it('export-with-secrets gates the download behind a ConfirmDialog', async () => {
		exportURLMock.mockReturnValue('/api/v1/admin/backup?include-secrets=true');
		render(BackupSection);

		const btn = screen.getByRole('button', { name: 'Export with secrets…' });
		await userEvent.click(btn);

		// At this point the dialog is open but no URL has been
		// requested yet — the operator must confirm first.
		expect(exportURLMock).not.toHaveBeenCalled();
		expect(assignedHref).toBeNull();
		expect(
			screen.getByText(/Export with cleartext secrets/i)
		).toBeInTheDocument();
	});

	it('confirming the danger dialog triggers the include-secrets download', async () => {
		exportURLMock.mockReturnValue('/api/v1/admin/backup?include-secrets=true');
		render(BackupSection);

		await userEvent.click(
			screen.getByRole('button', { name: 'Export with secrets…' })
		);
		// Confirm by clicking the danger-variant action in the
		// dialog — labelled "Download with secrets" by the
		// component (line 211 BackupSection.svelte).
		const confirmBtn = await screen.findByRole('button', {
			name: 'Download with secrets'
		});
		await userEvent.click(confirmBtn);

		expect(exportURLMock).toHaveBeenCalledTimes(1);
		expect(exportURLMock).toHaveBeenCalledWith(true);
		expect(assignedHref).toBe(
			'/api/v1/admin/backup?include-secrets=true'
		);
	});
});

describe('BackupSection — restore', () => {
	function pickFile(content: string): File {
		return new File([content], 'arenet-backup.json', {
			type: 'application/json'
		});
	}

	it('parses the picked file JSON + POSTs with default opts (both flags off)', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		const snapshot = JSON.stringify({
			schema_version: '1.0.0',
			routes: [],
			users: []
		});
		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, { target: { files: [pickFile(snapshot)] } });

		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		expect(postRestoreMock).toHaveBeenCalledTimes(1);
		const [body, opts] = postRestoreMock.mock.calls[0];
		expect((body as Record<string, unknown>).schema_version).toBe('1.0.0');
		// Both flags default to false.
		expect(opts).toEqual({
			allowIncompleteRestore: false,
			allowEmptyUsers: false
		});
	});

	it('propagates the opt-in flags from the checkboxes to the POST', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		// Tick both opt-in checkboxes.
		const incomplete = screen.getByRole('checkbox', {
			name: /Allow incomplete restore/i
		}) as HTMLInputElement;
		const emptyUsers = screen.getByRole('checkbox', {
			name: /Allow empty users/i
		}) as HTMLInputElement;
		await fireEvent.click(incomplete);
		await fireEvent.click(emptyUsers);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});

		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		const [, opts] = postRestoreMock.mock.calls[0];
		expect(opts).toEqual({
			allowIncompleteRestore: true,
			allowEmptyUsers: true
		});
	});

	it('renders the verbose report on a successful restore', async () => {
		postRestoreMock.mockResolvedValue(happyReport);
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"1.0.0"}')] }
		});
		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		// Counts from happyReport must surface in the <dl>.
		await waitFor(() => {
			expect(screen.getByText('3')).toBeInTheDocument(); // routes
		});
		// Boolean field rendered as "yes" / "no" per the
		// component's template.
		expect(screen.getByText('yes')).toBeInTheDocument();
		// Sentinels inherited count.
		expect(screen.getByText('2')).toBeInTheDocument();
	});

	it('surfaces the ApiError message verbatim on restore rejection', async () => {
		// The backend's "two paths forward" reject wording reaches
		// the operator unchanged — the component must NOT reword.
		const verbatim =
			'Restore rejected: schema_version 2.0.0 is MAJOR-incompatible with this binary (1.0.0). Two paths forward: (1) downgrade ... ; (2) export current config and re-import.';
		postRestoreMock.mockRejectedValue(new ApiError(verbatim, 400));
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{"schema_version":"2.0.0"}')] }
		});
		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		await waitFor(() => expect(postRestoreMock).toHaveBeenCalled());

		// The error <pre> carries role=alert ; assert the verbatim
		// substring lands without rewording.
		const alert = await screen.findByRole('alert');
		expect(alert.textContent).toContain('Two paths forward');
		expect(alert.textContent).toContain('schema_version 2.0.0');
	});

	it('surfaces an inline parse error WITHOUT calling postRestore on malformed JSON', async () => {
		// Operator picked a non-JSON file (e.g. a binary dump or a
		// truncated archive). The component catches JSON.parse
		// SyntaxError before any network call.
		render(BackupSection);

		const fileInput = document.querySelector(
			'input[type="file"]'
		) as HTMLInputElement;
		await fireEvent.change(fileInput, {
			target: { files: [pickFile('{not-json,')] }
		});
		await userEvent.click(screen.getByRole('button', { name: 'Restore' }));
		await waitFor(() => {
			expect(screen.getByRole('alert')).toBeInTheDocument();
		});

		expect(postRestoreMock).not.toHaveBeenCalled();
		const alert = screen.getByRole('alert');
		expect(alert.textContent).toContain('Invalid JSON');
	});
});
