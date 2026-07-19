// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE (Task 7) — component tests for
// ExternalCertsPanel. Pins:
//   1. The list renders one row per cert in the backend-given order
//      (soonest-first / notAfter ascending) — NO client re-sort.
//   2. Each row carries an expiry badge whose severity tracks the
//      days-to-notAfter thresholds (< 7d red, < 30d amber, else green).
//   3. The delete confirm dialog surfaces the "does NOT revoke with the
//      issuing CA" copy (i18n key referenced here; Task 9 fills the
//      value, so this test keys on the notice element + its i18n key).
//   4. On upload, warnings from the response render as an inline notice.
//   5. A 409 delete opens the blocked dialog with the blocking routes.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { ExternalCertificate } from '$lib/api/external-certs';

const { toastMock, apiMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		externalCertsApi: {
			list: vi.fn(),
			get: vi.fn(),
			upload: vi.fn(),
			remove: vi.fn()
		}
	}
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/external-certs', () => apiMock);

import Panel from './ExternalCertsPanel.svelte';

const NOW = new Date('2026-06-05T12:00:00Z');

function daysFromNow(days: number): string {
	return new Date(NOW.getTime() + days * 86_400_000).toISOString();
}

function extCert(over: Partial<ExternalCertificate>): ExternalCertificate {
	return {
		id: 'id-' + (over.name ?? 'x'),
		name: 'cert',
		description: '',
		certPEM: 'CERT',
		chainPEM: '',
		keyPEM: '',
		issuer: 'DigiCert Inc',
		subject: 'CN=example.com',
		serialNumber: '0A',
		keyAlgorithm: 'RSA',
		signatureAlgorithm: 'SHA256-RSA',
		notBefore: daysFromNow(-30),
		notAfter: daysFromNow(60),
		dnsNames: ['example.com'],
		createdAt: daysFromNow(-30),
		updatedAt: daysFromNow(-30),
		warnings: [],
		...over
	};
}

beforeEach(() => {
	vi.useFakeTimers({ toFake: ['Date'] });
	vi.setSystemTime(NOW);
	toastMock.pushToast.mockReset();
	apiMock.externalCertsApi.list.mockReset();
	apiMock.externalCertsApi.upload.mockReset();
	apiMock.externalCertsApi.remove.mockReset();
	apiMock.externalCertsApi.list.mockResolvedValue([]);
});

afterEach(() => {
	vi.useRealTimers();
});

describe('ExternalCertsPanel — list', () => {
	it('renders one row per cert, preserving the backend soonest-first order', async () => {
		// Backend returns already sorted by notAfter ascending. We pass
		// them in that order and assert the DOM preserves it verbatim.
		const soonest = extCert({ name: 'soonest', notAfter: daysFromNow(3) });
		const middle = extCert({ name: 'middle', notAfter: daysFromNow(20) });
		const latest = extCert({ name: 'latest', notAfter: daysFromNow(200) });
		apiMock.externalCertsApi.list.mockResolvedValue([soonest, middle, latest]);

		render(Panel);
		await screen.findByTestId('external-certs-table');
		const rows = screen.getAllByTestId('external-cert-row');
		expect(rows).toHaveLength(3);
		expect(rows.map((r) => r.dataset.id)).toEqual([soonest.id, middle.id, latest.id]);
	});

	it('renders an expiry badge whose severity tracks the thresholds', async () => {
		const danger = extCert({ name: 'danger', notAfter: daysFromNow(3) }); // < 7d
		const warn = extCert({ name: 'warn', notAfter: daysFromNow(20) }); // < 30d
		const ok = extCert({ name: 'ok', notAfter: daysFromNow(200) }); // healthy
		apiMock.externalCertsApi.list.mockResolvedValue([danger, warn, ok]);

		render(Panel);
		await screen.findByTestId('external-certs-table');
		const rows = screen.getAllByTestId('external-cert-row');

		const badgeVariant = (row: HTMLElement) =>
			row.querySelector('.badge')?.getAttribute('data-variant');

		const byId = (id: string) => rows.find((r) => r.dataset.id === id)!;
		expect(badgeVariant(byId(danger.id))).toBe('status-down');
		expect(badgeVariant(byId(warn.id))).toBe('status-warn');
		expect(badgeVariant(byId(ok.id))).toBe('status-up');
	});

	it('shows the empty state when there are no external certs', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		render(Panel);
		expect(await screen.findByTestId('external-certs-empty')).toBeInTheDocument();
	});
});

describe('ExternalCertsPanel — delete dialog', () => {
	it('opens a confirm dialog carrying the "does NOT revoke" notice', async () => {
		const cert = extCert({ name: 'to-delete' });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));

		// The revoke notice element is present and carries the "does NOT
		// revoke with the issuing CA" copy owned by the i18n key
		// certificates.external.delete.confirm.revokeNotice (Task 9).
		const notice = await screen.findByTestId('external-cert-revoke-notice');
		expect(notice).toBeInTheDocument();
		expect(notice.textContent ?? '').toContain('does NOT revoke');
		// The confirm button is wired.
		expect(screen.getByTestId('external-cert-delete-confirm')).toBeInTheDocument();
	});

	it('calls remove() and refreshes the list on confirm', async () => {
		const cert = extCert({ name: 'gone' });
		apiMock.externalCertsApi.list.mockResolvedValueOnce([cert]).mockResolvedValueOnce([]);
		apiMock.externalCertsApi.remove.mockResolvedValue(undefined);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));
		await userEvent.click(await screen.findByTestId('external-cert-delete-confirm'));

		expect(apiMock.externalCertsApi.remove).toHaveBeenCalledWith(cert.id);
		await tick();
		expect(screen.queryByTestId(`external-cert-delete-${cert.id}`)).not.toBeInTheDocument();
	});

	it('opens the blocked dialog listing routes on a 409', async () => {
		const cert = extCert({ name: 'used' });
		apiMock.externalCertsApi.list.mockResolvedValue([cert]);
		apiMock.externalCertsApi.remove.mockRejectedValue(
			Object.assign(new Error('in use'), {
				status: 409,
				blockingRoutes: ['app.example.com']
			})
		);

		render(Panel);
		await userEvent.click(await screen.findByTestId(`external-cert-delete-${cert.id}`));
		await userEvent.click(await screen.findByTestId('external-cert-delete-confirm'));

		// The blocked dialog mounts (its body copy + the {routes}
		// interpolation are owned by the i18n key
		// certificates.external.delete.blocked.text, which Task 9 fills;
		// until then t() returns the raw key without interpolating, so we
		// assert the dialog element is present rather than the route text).
		const blocked = await screen.findByTestId('external-cert-blocked-text');
		expect(blocked).toBeInTheDocument();
		// The blocked path must NOT emit a success toast.
		expect(toastMock.pushToast).not.toHaveBeenCalledWith(expect.anything(), 'success');
		// The delete row is still present — nothing was removed.
		expect(screen.getByTestId(`external-cert-delete-${cert.id}`)).toBeInTheDocument();
	});
});

describe('ExternalCertsPanel — upload', () => {
	it('renders response warnings as an inline notice after a successful upload', async () => {
		apiMock.externalCertsApi.list.mockResolvedValue([]);
		apiMock.externalCertsApi.upload.mockResolvedValue(
			extCert({
				name: 'uploaded',
				warnings: [{ code: 'expires_soon', message: 'This certificate expires soon.' }]
			})
		);

		render(Panel);
		await screen.findByTestId('external-cert-upload-form');

		await userEvent.type(screen.getByTestId('external-cert-name'), 'uploaded');
		await userEvent.type(screen.getByTestId('external-cert-cert-pem'), 'CERTPEM');
		await userEvent.type(screen.getByTestId('external-cert-key-pem'), 'KEYPEM');
		await userEvent.click(screen.getByTestId('external-cert-upload-btn'));

		const notice = await screen.findByTestId('external-cert-warnings');
		expect(notice.textContent ?? '').toContain('This certificate expires soon.');
		expect(apiMock.externalCertsApi.upload).toHaveBeenCalledWith(
			expect.objectContaining({ name: 'uploaded', certPEM: 'CERTPEM', keyPEM: 'KEYPEM' })
		);
	});
});
