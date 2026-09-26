// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';

const { securityMock } = vi.hoisted(() => ({
	securityMock: { searchASN: vi.fn(), namesASN: vi.fn() }
}));
vi.mock('$lib/api/security', () => securityMock);

import ASNPicker from './ASNPicker.svelte';

const loaded = (results: { asn: number; name: string }[]) => ({ loaded: true, indexReady: true, results });

beforeEach(() => {
	securityMock.searchASN.mockReset();
	securityMock.namesASN.mockReset();
	securityMock.namesASN.mockResolvedValue(loaded([]));
});

describe('ASNPicker', () => {
	it('searches by name and adds the picked AS as a labelled chip', async () => {
		securityMock.searchASN.mockResolvedValue(loaded([{ asn: 16276, name: 'OVH SAS' }]));
		render(ASNPicker, { props: { value: [], label: 'ASN', testid: 'p' } });
		await userEvent.type(screen.getByTestId('p-input'), 'ovh');
		await waitFor(() => expect(screen.getByTestId('p-suggestion')).toHaveTextContent('OVH SAS'));
		expect(securityMock.searchASN).toHaveBeenCalledWith('ovh', 20);
		await userEvent.keyboard('{Enter}');
		expect(screen.getByTestId('p-chip')).toHaveTextContent('AS16276 OVH SAS');
	});

	it('accepts a bare typed number even without a database hit', async () => {
		securityMock.searchASN.mockResolvedValue({ loaded: false, indexReady: false, results: [] });
		render(ASNPicker, { props: { value: [], label: 'ASN', testid: 'p' } });
		await userEvent.type(screen.getByTestId('p-input'), 'AS14061');
		await waitFor(() => expect(screen.getByTestId('p-no-db')).toBeInTheDocument());
		await userEvent.keyboard('{Enter}');
		expect(screen.getByTestId('p-chip')).toHaveTextContent('AS14061');
	});

	it('labels saved numbers on mount and hides excluded ones from suggestions', async () => {
		securityMock.namesASN.mockResolvedValue(loaded([{ asn: 14061, name: 'DigitalOcean' }]));
		securityMock.searchASN.mockResolvedValue(
			loaded([
				{ asn: 14061, name: 'DigitalOcean' },
				{ asn: 16276, name: 'OVH SAS' },
				{ asn: 15169, name: 'Google' }
			])
		);
		render(ASNPicker, { props: { value: [14061], exclude: [15169], label: 'ASN', testid: 'p' } });
		await waitFor(() => expect(screen.getByTestId('p-chip')).toHaveTextContent('AS14061 DigitalOcean'));
		expect(securityMock.namesASN).toHaveBeenCalledWith([14061]);
		await userEvent.type(screen.getByTestId('p-input'), 'o');
		await waitFor(() => expect(screen.getAllByTestId('p-suggestion')).toHaveLength(1));
		expect(screen.getByTestId('p-suggestion')).toHaveTextContent('OVH SAS');
	});

	it('removes a chip', async () => {
		render(ASNPicker, { props: { value: [3215], label: 'ASN', testid: 'p' } });
		await userEvent.click(screen.getByRole('button', { name: /Remove AS3215/ }));
		expect(screen.queryByTestId('p-chip')).not.toBeInTheDocument();
	});
});
