// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.2 — ChannelModal behaviour tests. Focus on the
// operator-visible invariants:
//   - kind selector swaps webhook / email field groups
//   - kind selector is disabled in edit mode (can't
//     migrate webhook → email post-create)
//   - password preserve-on-omit UX: edit mode shows the
//     [défini] placeholder until "Modifier le mot de
//     passe" is checked
//   - validation errors block submit
//   - successful submit calls the API + emits onSaved

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type { AlertChannel, AlertChannelRequest } from '$lib/api/alerting';

const createMock = vi.fn();
const updateMock = vi.fn();
const testMock = vi.fn();

vi.mock('$lib/api/alerting', async () => {
	const real = await vi.importActual<typeof import('$lib/api/alerting')>('$lib/api/alerting');
	return {
		...real,
		alertingApi: {
			...real.alertingApi,
			createChannel: (r: AlertChannelRequest) => createMock(r),
			updateChannel: (id: string, r: AlertChannelRequest) => updateMock(id, r),
			testChannel: (id: string) => testMock(id)
		}
	};
});

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (m: string, v?: string) => pushToastMock(m, v)
}));

beforeEach(() => {
	createMock.mockReset();
	updateMock.mockReset();
	testMock.mockReset();
	pushToastMock.mockReset();
});

function webhookFixture(): AlertChannel {
	return {
		id: 'ch-1',
		name: 'ops-webhook',
		kind: 'webhook',
		enabled: true,
		minSeverity: 1,
		config: {
			url: 'https://hooks.example.com/x',
			method: 'POST',
			timeoutSeconds: 10,
			headers: { Authorization: '[redacted]' }
		},
		createdAt: '2026-06-15T12:00:00Z',
		updatedAt: '2026-06-15T12:00:00Z'
	};
}

function emailFixture(): AlertChannel {
	return {
		id: 'ch-2',
		name: 'ops-email',
		kind: 'email',
		enabled: true,
		minSeverity: 1,
		config: {
			smtpHost: 'smtp.example.com',
			smtpPort: 587,
			smtpUsername: 'alerts',
			smtpPassword: '', // backend redacts on GET
			from: 'alerts@example.com',
			to: ['ops@example.com'],
			useTLS: false,
			useStartTLS: true
		},
		createdAt: '2026-06-15T12:00:00Z',
		updatedAt: '2026-06-15T12:00:00Z'
	};
}

describe('ChannelModal', () => {
	it('shows webhook fields when kind=webhook (create mode default)', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		expect(screen.getByLabelText(/URL/i)).toBeTruthy();
		// Email-specific labels should NOT be present.
		expect(screen.queryByLabelText(/SMTP host/i)).toBeNull();
		expect(screen.queryByLabelText(/^From$/i)).toBeNull();
	});

	it('swaps to email fields when kind=email is selected', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		const kindSelect = screen.getByLabelText(/^Type$/i) as HTMLSelectElement;
		await fireEvent.change(kindSelect, { target: { value: 'email' } });

		expect(screen.getByLabelText(/SMTP host/i)).toBeTruthy();
		expect(screen.getByLabelText(/^From$/i)).toBeTruthy();
		// Webhook fields should be hidden.
		expect(screen.queryByLabelText(/^URL$/i)).toBeNull();
	});

	it('disables the kind selector in edit mode', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: webhookFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const kindSelect = screen.getByLabelText(/^Type$/i) as HTMLSelectElement;
		expect(kindSelect.disabled).toBe(true);
	});

	it('shows [set] placeholder for SMTP password in email edit mode', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const pwd = screen.getByLabelText(/SMTP password/i) as HTMLInputElement;
		expect(pwd.value).toBe('[set]');
		expect(pwd.disabled).toBe(true);
		// The "Change password" checkbox should be present.
		expect(screen.getByLabelText(/Change password/i)).toBeTruthy();
	});

	it('enables the password input after toggling "Change password"', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});
		const toggle = screen.getByLabelText(/Change password/i) as HTMLInputElement;
		await fireEvent.click(toggle);
		const pwd = screen.getByLabelText(/SMTP password/i) as HTMLInputElement;
		// After toggling the readonly [set] input is replaced
		// with a fresh editable password input.
		expect(pwd.disabled).toBe(false);
		expect(pwd.value).toBe('');
	});

	it('blocks submit when the webhook URL is empty', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved }
		});

		const nameInput = screen.getByLabelText(/^Name$/i) as HTMLInputElement;
		await fireEvent.input(nameInput, { target: { value: 'test-wh' } });
		// URL intentionally left empty.
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/webhook URL is required/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
		expect(onSaved).not.toHaveBeenCalled();
	});

	it('blocks submit when URL has invalid scheme', async () => {
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.input(screen.getByLabelText(/^Name$/i), {
			target: { value: 'test-wh' }
		});
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'ftp://bad.example.com' }
		});
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(screen.getByText(/http:\/\/ or https:\/\//i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('calls createChannel + onSaved on a valid webhook submit', async () => {
		createMock.mockResolvedValue(webhookFixture());
		const Modal = (await import('./ChannelModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, channel: null, onClose: () => {}, onSaved }
		});

		await fireEvent.input(screen.getByLabelText(/^Name$/i), {
			target: { value: 'ops-webhook' }
		});
		await fireEvent.input(screen.getByLabelText(/^URL$/i), {
			target: { value: 'https://hooks.example.com/x' }
		});
		await fireEvent.click(screen.getByText('Create'));

		await waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const [req] = createMock.mock.calls[0];
		expect(req.kind).toBe('webhook');
		expect(req.name).toBe('ops-webhook');
		expect(onSaved).toHaveBeenCalledTimes(1);
	});

	it('sends smtpPassword="" on edit when "Change password" stays unchecked (preserve)', async () => {
		updateMock.mockResolvedValue(emailFixture());
		const Modal = (await import('./ChannelModal.svelte')).default;
		render(Modal, {
			props: {
				open: true,
				channel: emailFixture(),
				onClose: () => {},
				onSaved: () => {}
			}
		});

		// Submit without touching the password toggle.
		await fireEvent.click(screen.getByText('Save'));

		await waitFor(() => {
			expect(updateMock).toHaveBeenCalledTimes(1);
		});
		const [id, req] = updateMock.mock.calls[0];
		expect(id).toBe('ch-2');
		expect(req.config.smtpPassword).toBe('');
	});
});
