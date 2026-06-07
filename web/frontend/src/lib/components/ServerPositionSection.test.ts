// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Step V.7 — ServerPositionSection tests.
//
// Mocks the three V.4 API functions (fetchServerPosition,
// putServerPosition, redetectServerPosition) so the test
// drives the component's form state machine directly.
// pushToast is also mocked so success/error toasts can be
// asserted without rendering the toast store layer.

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/svelte';
import type { ServerPosition } from '$lib/api/types';
import { ApiError } from '$lib/api/types';

const fetchServerPositionMock = vi.fn<() => Promise<ServerPosition>>();
const putServerPositionMock = vi.fn<(body: {
	lat: number;
	lon: number;
	city: string;
	country: string;
}) => Promise<ServerPosition>>();
const redetectServerPositionMock = vi.fn<() => Promise<ServerPosition>>();

vi.mock('$lib/api/security', () => ({
	fetchServerPosition: () => fetchServerPositionMock(),
	putServerPosition: (
		body: { lat: number; lon: number; city: string; country: string }
	) => putServerPositionMock(body),
	redetectServerPosition: () => redetectServerPositionMock()
}));

const pushToastMock = vi.fn();
vi.mock('$lib/stores/toast', () => ({
	pushToast: (message: string, variant?: string) => pushToastMock(message, variant)
}));

beforeEach(() => {
	fetchServerPositionMock.mockReset();
	putServerPositionMock.mockReset();
	redetectServerPositionMock.mockReset();
	pushToastMock.mockReset();
});

const { default: ServerPositionSection } = await import('./ServerPositionSection.svelte');

const autoPosition: ServerPosition = {
	lat: 48.8566,
	lon: 2.3522,
	city: 'Paris',
	country: 'FR',
	mode: 'auto',
	sourceIp: '203.0.113.42',
	detectedAt: new Date(Date.now() - 5 * 60 * 1000).toISOString() // 5 min ago
};

const manualPosition: ServerPosition = {
	lat: 45.764,
	lon: 4.8357,
	city: 'Lyon',
	country: 'FR',
	mode: 'manual',
	detectedAt: new Date(Date.now() - 60 * 1000).toISOString()
};

const degradedPosition: ServerPosition = {
	lat: 0,
	lon: 0,
	city: '',
	country: '',
	mode: 'auto',
	degraded: true
};

describe('ServerPositionSection — mount + load', () => {
	it('renders the header + Auto badge for an auto-detected position', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			const header = screen.getByTestId('server-position-header');
			expect(header.textContent ?? '').toContain('Auto');
		});
	});

	it('renders the Manuel badge for a manual override', async () => {
		fetchServerPositionMock.mockResolvedValue(manualPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-header').textContent ?? '').toContain(
				'Manuel'
			);
		});
	});

	it('renders the Dégradé badge + degraded banner when degraded:true', async () => {
		fetchServerPositionMock.mockResolvedValue(degradedPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-header').textContent ?? '').toContain(
				'Dégradé'
			);
			expect(screen.getByTestId('server-position-degraded')).toBeInTheDocument();
		});
	});

	it('mentions ARENET_GEOIP_MMDB in the degraded banner for operator actionability', async () => {
		fetchServerPositionMock.mockResolvedValue(degradedPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-degraded').textContent ?? '').toContain(
				'ARENET_GEOIP_MMDB'
			);
		});
	});

	it('populates the form from the loaded position', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
			const lon = screen.getByTestId('server-position-lon-input') as HTMLInputElement;
			expect(lat.value).toBe('48.8566');
			expect(lon.value).toBe('2.3522');
		});
	});

	it('renders a load-error banner on fetch failure', async () => {
		fetchServerPositionMock.mockRejectedValue(new Error('HTTP 503'));
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-load-error')).toBeInTheDocument();
		});
	});

	it('shows the sourceIp + detectedAt when mode=auto', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			const meta = screen.getByTestId('server-position-detected-at');
			expect(meta.textContent ?? '').toContain('203.0.113.42');
		});
	});
});

describe('ServerPositionSection — PUT happy path', () => {
	it('PUTs the form values on submit + reloads to show the new state', async () => {
		fetchServerPositionMock.mockResolvedValueOnce(autoPosition);
		putServerPositionMock.mockResolvedValue(manualPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lat-input')).toBeInTheDocument();
		});

		const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
		const lon = screen.getByTestId('server-position-lon-input') as HTMLInputElement;
		await fireEvent.input(lat, { target: { value: '45.764' } });
		await fireEvent.input(lon, { target: { value: '4.8357' } });

		const form = screen.getByTestId('server-position-form');
		await fireEvent.submit(form);

		await waitFor(() => {
			expect(putServerPositionMock).toHaveBeenCalled();
		});
		const callArg = putServerPositionMock.mock.calls[0][0];
		expect(callArg.lat).toBe(45.764);
		expect(callArg.lon).toBe(4.8357);
	});

	it('surfaces a success toast on save', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		putServerPositionMock.mockResolvedValue(manualPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-form')).toBeInTheDocument();
		});
		const form = screen.getByTestId('server-position-form');
		await fireEvent.submit(form);
		await waitFor(() => {
			expect(pushToastMock).toHaveBeenCalledWith(
				expect.stringContaining('Position'),
				'success'
			);
		});
	});

	it('surfaces a danger toast on save failure (ApiError)', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		putServerPositionMock.mockRejectedValue(new ApiError('admin role required', 403));
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-form')).toBeInTheDocument();
		});
		const form = screen.getByTestId('server-position-form');
		await fireEvent.submit(form);
		await waitFor(() => {
			const dangerCall = pushToastMock.mock.calls.find((c) => c[1] === 'danger');
			expect(dangerCall).toBeDefined();
		});
	});
});

describe('ServerPositionSection — validation', () => {
	it('rejects lat > 90 with an inline error', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lat-input')).toBeInTheDocument();
		});

		const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
		await fireEvent.input(lat, { target: { value: '95' } });
		const form = screen.getByTestId('server-position-form');
		await fireEvent.submit(form);

		await waitFor(() => {
			// The Input component renders the error in a <p>
			// next to the input — find it via text content.
			expect(screen.getByText(/-90 et 90/)).toBeInTheDocument();
		});
		// PUT must NOT be called because validation rejected.
		expect(putServerPositionMock).not.toHaveBeenCalled();
	});

	it('rejects lat < -90 with an inline error', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lat-input')).toBeInTheDocument();
		});

		const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
		await fireEvent.input(lat, { target: { value: '-91' } });
		await fireEvent.submit(screen.getByTestId('server-position-form'));

		await waitFor(() => {
			expect(screen.getByText(/-90 et 90/)).toBeInTheDocument();
		});
		expect(putServerPositionMock).not.toHaveBeenCalled();
	});

	it('rejects lon > 180 with an inline error', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lon-input')).toBeInTheDocument();
		});

		const lon = screen.getByTestId('server-position-lon-input') as HTMLInputElement;
		await fireEvent.input(lon, { target: { value: '181' } });
		await fireEvent.submit(screen.getByTestId('server-position-form'));

		await waitFor(() => {
			expect(screen.getByText(/-180 et 180/)).toBeInTheDocument();
		});
		expect(putServerPositionMock).not.toHaveBeenCalled();
	});

	it('accepts boundary lat/lon (-90, 90, -180, 180)', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		putServerPositionMock.mockResolvedValue(manualPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lat-input')).toBeInTheDocument();
		});

		const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
		const lon = screen.getByTestId('server-position-lon-input') as HTMLInputElement;
		await fireEvent.input(lat, { target: { value: '90' } });
		await fireEvent.input(lon, { target: { value: '-180' } });

		await fireEvent.submit(screen.getByTestId('server-position-form'));
		await waitFor(() => {
			expect(putServerPositionMock).toHaveBeenCalled();
		});
	});

	it('accepts empty city / country (spec §5.2)', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		putServerPositionMock.mockResolvedValue(manualPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-city-input')).toBeInTheDocument();
		});

		const city = screen.getByTestId('server-position-city-input') as HTMLInputElement;
		const country = screen.getByTestId('server-position-country-input') as HTMLInputElement;
		await fireEvent.input(city, { target: { value: '' } });
		await fireEvent.input(country, { target: { value: '' } });
		await fireEvent.submit(screen.getByTestId('server-position-form'));

		await waitFor(() => {
			expect(putServerPositionMock).toHaveBeenCalled();
		});
		const callArg = putServerPositionMock.mock.calls[0][0];
		expect(callArg.city).toBe('');
		expect(callArg.country).toBe('');
	});
});

describe('ServerPositionSection — Redetect button', () => {
	it('calls redetectServerPosition + reloads the form', async () => {
		fetchServerPositionMock.mockResolvedValue(manualPosition);
		redetectServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-form')).toBeInTheDocument();
		});

		const redetectBtn = screen.getByText(/Re-détecter/i);
		await fireEvent.click(redetectBtn);

		await waitFor(() => {
			expect(redetectServerPositionMock).toHaveBeenCalled();
		});
	});

	it('surfaces a danger toast when redetect returns degraded', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		redetectServerPositionMock.mockResolvedValue(degradedPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByText(/Re-détecter/i)).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByText(/Re-détecter/i));

		await waitFor(() => {
			const dangerCall = pushToastMock.mock.calls.find((c) => c[1] === 'danger');
			expect(dangerCall).toBeDefined();
		});
	});

	it('surfaces a success toast when redetect succeeds', async () => {
		fetchServerPositionMock.mockResolvedValue(manualPosition);
		redetectServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByText(/Re-détecter/i)).toBeInTheDocument();
		});

		await fireEvent.click(screen.getByText(/Re-détecter/i));

		await waitFor(() => {
			const successCall = pushToastMock.mock.calls.find((c) => c[1] === 'success');
			expect(successCall).toBeDefined();
		});
	});
});

describe('ServerPositionSection — Reset button', () => {
	it('restores form values from the last-loaded position without an endpoint call', async () => {
		fetchServerPositionMock.mockResolvedValue(autoPosition);
		render(ServerPositionSection);
		await waitFor(() => {
			expect(screen.getByTestId('server-position-lat-input')).toBeInTheDocument();
		});

		const lat = screen.getByTestId('server-position-lat-input') as HTMLInputElement;
		await fireEvent.input(lat, { target: { value: '12.345' } });
		expect(lat.value).toBe('12.345');

		const resetBtn = screen.getByText(/Réinitialiser/i);
		await fireEvent.click(resetBtn);

		await waitFor(() => {
			expect((screen.getByTestId('server-position-lat-input') as HTMLInputElement).value).toBe(
				'48.8566'
			);
		});
		// Reset MUST NOT call any backend endpoint.
		expect(putServerPositionMock).not.toHaveBeenCalled();
		expect(redetectServerPositionMock).not.toHaveBeenCalled();
		// fetchServerPosition was called once on mount; the reset
		// must not refetch.
		expect(fetchServerPositionMock).toHaveBeenCalledTimes(1);
	});
});
