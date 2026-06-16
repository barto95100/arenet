// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// AL.4.b.3 — RuleModal behaviour tests. Mirrors the
// AL.4.b.2 ChannelModal test layout. Focus on the dynamic
// source/eval form switching + the channel multi-select +
// validation rejects + valid submit payload shape.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import type {
	AlertChannel,
	AlertRule,
	AlertRuleRequest,
	AlertRuleTestResponse
} from '$lib/api/alerting';

const createMock = vi.fn();
const updateMock = vi.fn();
const testMock = vi.fn();
const listChannelsMock = vi.fn();
const listRulesMock = vi.fn();

vi.mock('$lib/api/alerting', async () => {
	const real = await vi.importActual<typeof import('$lib/api/alerting')>('$lib/api/alerting');
	return {
		...real,
		alertingApi: {
			...real.alertingApi,
			createRule: (r: AlertRuleRequest) => createMock(r),
			updateRule: (id: string, r: AlertRuleRequest) => updateMock(id, r),
			testRule: (id: string): Promise<AlertRuleTestResponse> => testMock(id),
			listChannels: (): Promise<AlertChannel[]> => listChannelsMock(),
			listRules: (): Promise<AlertRule[]> => listRulesMock()
		}
	};
});

const listRoutesMock = vi.fn();
vi.mock('$lib/api/client', async () => {
	const real = await vi.importActual<typeof import('$lib/api/client')>('$lib/api/client');
	return {
		...real,
		listRoutes: () => listRoutesMock()
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
	listChannelsMock.mockReset();
	listRulesMock.mockReset();
	listRoutesMock.mockReset();
	pushToastMock.mockReset();
	// Default seeds: 2 enabled channels, no routes (cert
	// path is fine without), no rules.
	listChannelsMock.mockResolvedValue([
		{
			id: 'ch-1',
			name: 'ops-webhook',
			kind: 'webhook',
			enabled: true,
			minSeverity: 0,
			config: { url: 'http://x', method: 'POST', timeoutSeconds: 5 },
			createdAt: '',
			updatedAt: ''
		},
		{
			id: 'ch-2',
			name: 'ops-email',
			kind: 'email',
			enabled: true,
			minSeverity: 0,
			config: {
				smtpHost: 'x',
				smtpPort: 587,
				smtpUsername: '',
				smtpPassword: '',
				from: 'a@b',
				to: ['c@d'],
				useTLS: false,
				useStartTLS: true
			},
			createdAt: '',
			updatedAt: ''
		}
	] satisfies AlertChannel[]);
	listRulesMock.mockResolvedValue([]);
	listRoutesMock.mockResolvedValue([]);
});

function thresholdRule(): AlertRule {
	return {
		id: 'rule-1',
		name: 'block-rate',
		enabled: true,
		kind: 'threshold',
		severity: 1,
		category: 'waf',
		source: 'waf_event_rate',
		sourceParams: { windowSecs: 300, action: 'BLOCK' },
		evalParams: { operator: '>', value: 50 },
		channels: ['ch-1'],
		cooldownSecs: 300,
		createdAt: '2026-06-16T10:00:00Z',
		updatedAt: '2026-06-16T10:00:00Z'
	};
}

describe('RuleModal', () => {
	it('shows the waf_event_rate sub-form by default (create mode)', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		// waf_event_rate exposes a window/action/route trio.
		expect(screen.getByLabelText(/Fenêtre/i)).toBeTruthy();
		expect(screen.getByLabelText(/Action/i)).toBeTruthy();
		// cert_expiry-only label must NOT be present.
		expect(screen.queryByLabelText(/Hôte/i)).toBeNull();
	});

	it('swaps to cert_expiry sub-form when source = cert_expiry', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'cert_expiry' } });

		expect(screen.getByLabelText(/Hôte/i)).toBeTruthy();
		// waf_event_rate fields gone.
		expect(screen.queryByLabelText(/Fenêtre/i)).toBeNull();
	});

	it('swaps to system_health sub-form when source = system_health', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		await fireEvent.change(sourceSelect, { target: { value: 'system_health' } });

		expect(screen.getByLabelText(/Composant/i)).toBeTruthy();
		expect(screen.queryByLabelText(/Fenêtre/i)).toBeNull();
		expect(screen.queryByLabelText(/Hôte/i)).toBeNull();
	});

	it('swaps to State eval form when kind=state', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		const stateRadio = screen.getByLabelText(/État \(chaîne\)/i) as HTMLInputElement;
		await fireEvent.click(stateRadio);

		expect(screen.getByLabelText(/Valeur attendue/i)).toBeTruthy();
		expect(screen.queryByLabelText(/Opérateur/i)).toBeNull();
	});

	it('disables the kind selector in edit mode', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: thresholdRule(), onClose: () => {}, onSaved: () => {} }
		});

		const threshRadio = screen.getByLabelText(/Seuil \(numérique\)/i) as HTMLInputElement;
		const stateRadio = screen.getByLabelText(/État \(chaîne\)/i) as HTMLInputElement;
		expect(threshRadio.disabled).toBe(true);
		expect(stateRadio.disabled).toBe(true);
	});

	it('blocks submit when no channels are selected', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		// Wait for channels to load so the multi-select is rendered.
		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});

		// Fill required scalar fields.
		await fireEvent.input(screen.getByLabelText(/^Nom \(slug\)$/i), {
			target: { value: 'no-channels' }
		});
		// Don't tick any channel checkbox.
		await fireEvent.click(screen.getByText('Créer'));

		await waitFor(() => {
			expect(screen.getByText(/au moins un canal/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('blocks submit when name does not match the slug regex', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved: () => {} }
		});

		await fireEvent.input(screen.getByLabelText(/^Nom \(slug\)$/i), {
			target: { value: 'Block Rate High!' } // spaces + caps + bang
		});
		// Tick a channel so the only invariant left is the name.
		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Créer'));

		await waitFor(() => {
			expect(screen.getByText(/minuscules.*alphanumérique.*tirets/i)).toBeTruthy();
		});
		expect(createMock).not.toHaveBeenCalled();
	});

	it('submits a valid threshold rule with the expected payload', async () => {
		createMock.mockResolvedValue(thresholdRule());
		const Modal = (await import('./RuleModal.svelte')).default;
		const onSaved = vi.fn();
		render(Modal, {
			props: { open: true, rule: null, onClose: () => {}, onSaved }
		});

		await waitFor(() => {
			expect(screen.getByText('ops-webhook')).toBeTruthy();
		});

		await fireEvent.input(screen.getByLabelText(/^Nom \(slug\)$/i), {
			target: { value: 'block-rate' }
		});
		const opsWh = screen.getByText('ops-webhook').previousElementSibling as HTMLInputElement;
		await fireEvent.click(opsWh);
		await fireEvent.click(screen.getByText('Créer'));

		await waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const [req] = createMock.mock.calls[0];
		expect(req.name).toBe('block-rate');
		expect(req.kind).toBe('threshold');
		expect(req.source).toBe('waf_event_rate');
		expect(req.channels).toEqual(['ch-1']);
		// Eval params shape: threshold ⇒ {operator, value}.
		expect(req.evalParams.operator).toBe('>');
		expect(typeof req.evalParams.value).toBe('number');
		// Source params shape: waf_event_rate ⇒ at least
		// windowSecs (defaults to 300).
		expect(req.sourceParams.windowSecs).toBeGreaterThanOrEqual(60);
		expect(onSaved).toHaveBeenCalledTimes(1);
	});

	it('pre-populates the edit form from an existing rule', async () => {
		const Modal = (await import('./RuleModal.svelte')).default;
		render(Modal, {
			props: { open: true, rule: thresholdRule(), onClose: () => {}, onSaved: () => {} }
		});

		const nameInput = screen.getByLabelText(/^Nom \(slug\)$/i) as HTMLInputElement;
		expect(nameInput.value).toBe('block-rate');

		const sourceSelect = screen.getByLabelText(/^Source$/i) as HTMLSelectElement;
		expect(sourceSelect.value).toBe('waf_event_rate');

		const opSelect = screen.getByLabelText(/Opérateur/i) as HTMLSelectElement;
		expect(opSelect.value).toBe('>');

		const valueInput = screen.getByLabelText(/Valeur seuil/i) as HTMLInputElement;
		expect(Number(valueInput.value)).toBe(50);

		// The pre-populated channel checkbox is ticked.
		await waitFor(() => {
			const opsWhText = screen.getByText('ops-webhook');
			const checkbox = opsWhText.previousElementSibling as HTMLInputElement;
			expect(checkbox.checked).toBe(true);
		});
	});
});
