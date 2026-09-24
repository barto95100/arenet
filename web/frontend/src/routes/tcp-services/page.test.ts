// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.42 — TCP / UDP services page.
//
// What is pinned is what the operator relies on: the list says what
// guards each relay, a preset fills what you would otherwise have to
// know by heart (including whether the thing should be exposed at
// all), the two pairings the API refuses are surfaced before Save,
// and the PROXY-protocol block says what to configure on the far
// side — the silent failure mode of this feature.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { tick } from 'svelte';

const { api } = vi.hoisted(() => ({
	api: {
		listTCPServices: vi.fn(),
		createTCPService: vi.fn(),
		updateTCPService: vi.fn(),
		deleteTCPService: vi.fn(),
		testTCPService: vi.fn()
	}
}));

vi.mock('$lib/api/tcp-services', async (importOriginal) => ({
	...((await importOriginal()) as Record<string, unknown>),
	listTCPServices: (...a: unknown[]) => api.listTCPServices(...a),
	createTCPService: (...a: unknown[]) => api.createTCPService(...a),
	updateTCPService: (...a: unknown[]) => api.updateTCPService(...a),
	deleteTCPService: (...a: unknown[]) => api.deleteTCPService(...a),
	testTCPService: (...a: unknown[]) => api.testTCPService(...a)
}));
vi.mock('$lib/stores/toast', () => ({ pushToast: vi.fn() }));

import Page from './+page.svelte';

function service(over: Record<string, unknown> = {}) {
	return {
		id: 'svc1',
		name: 'stalwart-imaps',
		listenPort: 993,
		protocol: 'tcp',
		upstreams: [{ host: '10.20.0.5', port: 993 }],
		proxyProtocol: 'v2',
		crowdSecEnabled: true,
		createdAt: '2026-09-24T10:00:00Z',
		updatedAt: '2026-09-24T10:00:00Z',
		...over
	};
}

beforeEach(() => {
	Object.values(api).forEach((fn) => fn.mockReset());
	api.listTCPServices.mockResolvedValue([]);
});

describe('/tcp-services — list', () => {
	it('explains what a relay is when there is none', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		const text = screen.getByTestId('tcp-empty').textContent ?? '';
		expect(text).toMatch(/WAF/);
		expect(text).toMatch(/end to end/i);
	});

	it('shows what guards each relay', async () => {
		api.listTCPServices.mockResolvedValue([
			service(),
			service({
				id: 'svc2',
				name: 'wireguard',
				protocol: 'udp',
				listenPort: 51820,
				crowdSecEnabled: false,
				ipFilter: { mode: 'allow', cidrs: ['192.168.1.0/24'] }
			})
		]);
		render(Page);

		const row = await screen.findByTestId('tcp-row-svc1');
		expect(row.textContent).toContain('tcp/0.0.0.0:993');
		expect(row.textContent).toContain('proxy v2');
		expect(row.textContent).toContain('crowdsec');

		const udp = screen.getByTestId('tcp-row-svc2');
		expect(udp.textContent).toContain('udp/0.0.0.0:51820');
		expect(udp.textContent).toMatch(/ip\s*:\s*1/);
	});
});

describe('/tcp-services — presets', () => {
	it('fills the port, the protocol and the exposure decision', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		// PostgreSQL: TCP 5432, and restricted by default — a database
		// open to the internet is the mistake the presets exist to
		// prevent.
		await userEvent.click(screen.getByTestId('tcp-preset-postgresql'));
		await tick();
		expect((document.getElementById('tcp-listen-port') as HTMLInputElement).value).toBe('5432');
		expect((screen.getByTestId('tcp-restrict') as HTMLInputElement).checked).toBe(true);
		expect(screen.getByTestId('tcp-protocol-tcp').getAttribute('aria-checked')).toBe('true');

		// Inbound mail: the opposite — the world must reach it.
		await userEvent.click(screen.getByTestId('tcp-preset-smtp'));
		await tick();
		expect((document.getElementById('tcp-listen-port') as HTMLInputElement).value).toBe('25');
		expect((screen.getByTestId('tcp-restrict') as HTMLInputElement).checked).toBe(false);

		// WireGuard: UDP.
		await userEvent.click(screen.getByTestId('tcp-preset-wireguard'));
		await tick();
		expect(screen.getByTestId('tcp-protocol-udp').getAttribute('aria-checked')).toBe('true');
	});
});

describe('/tcp-services — the two refusals, before Save', () => {
	it('warns about PROXY v1 over UDP and about an active check over UDP', async () => {
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.click(screen.getByTestId('tcp-protocol-udp'));
		await userEvent.click(screen.getByTestId('tcp-proxy-v1'));
		await tick();
		expect(screen.getByTestId('tcp-udp-v1-warning').textContent).toMatch(/v2/);

		// The health-check switch is disabled over UDP rather than
		// letting the operator arm something the API will refuse.
		expect((screen.getByTestId('tcp-healthcheck') as HTMLInputElement).disabled).toBe(true);
	});
});

describe('/tcp-services — the PROXY protocol pairing', () => {
	it('says what to configure on the backend, and tests it', async () => {
		api.listTCPServices.mockResolvedValue([service()]);
		api.testTCPService.mockResolvedValue({
			backends: [{ backend: '10.20.0.5:993', ok: true, elapsedMs: 3 }],
			proxyProtocolNote: 'On Stalwart, that is proxyTrustedNetworks.'
		});
		render(Page);

		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();

		const callout = screen.getByTestId('tcp-proxy-callout').textContent ?? '';
		expect(callout).toMatch(/proxyTrustedNetworks/);
		expect(callout).toMatch(/silently/i);

		await userEvent.click(screen.getByText('Test the backends'));
		await waitFor(() => expect(screen.getByTestId('tcp-test-result')).toBeInTheDocument());
		expect(screen.getByTestId('tcp-test-result').textContent).toContain('10.20.0.5:993');
	});

	it('disappears when no header is sent', async () => {
		api.listTCPServices.mockResolvedValue([service({ proxyProtocol: '' })]);
		render(Page);
		await userEvent.click(await screen.findByTestId('tcp-row-svc1'));
		await tick();
		expect(screen.queryByTestId('tcp-proxy-callout')).toBeNull();
	});
});

describe('/tcp-services — saving', () => {
	it('ships what the form holds', async () => {
		api.createTCPService.mockResolvedValue(service());
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();

		await userEvent.click(screen.getByTestId('tcp-preset-imaps'));
		await userEvent.type(document.getElementById('tcp-backend-host') as HTMLInputElement, '10.20.0.5');
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(api.createTCPService).toHaveBeenCalledTimes(1));
		const payload = api.createTCPService.mock.calls[0][0];
		expect(payload).toMatchObject({
			name: 'imaps',
			protocol: 'tcp',
			listenPort: 993,
			proxyProtocol: 'v2',
			crowdSecEnabled: true
		});
		expect(payload.upstreams[0]).toMatchObject({ host: '10.20.0.5', port: 993 });
	});

	it('surfaces what the server refused', async () => {
		api.createTCPService.mockRejectedValue(new Error('port 443 is used by Arenet HTTPS routes'));
		render(Page);
		await waitFor(() => expect(screen.getByTestId('tcp-empty')).toBeInTheDocument());
		await userEvent.click(screen.getAllByText('+ New service')[0]);
		await tick();
		await userEvent.click(screen.getByText('Save'));

		await waitFor(() => expect(screen.getByTestId('tcp-form-error')).toBeInTheDocument());
		expect(screen.getByTestId('tcp-form-error').textContent).toContain('Arenet HTTPS routes');
	});
});
