// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// /certs page tests — pin the contract of:
//   - #R-6 Pack A migration: editor mounted on /certs,
//     auto-renewal info card rendered, /settings no longer
//     carries the managed-domains UI.
//   - Step T T.4: unified Domaines table fed by GET
//     /api/certificates, runtime KPI cards, Tous/Wildcard/
//     Expirent bientôt tab filter, status badges per AC #10,
//     OBTAIN_FAILED tooltip, empty + error states. Pack A
//     editor must remain functional even when /api/certificates
//     fails (AC #13 degraded mode mirrored on the frontend).

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { tick } from 'svelte';
import { render, screen, fireEvent } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import type { Certificate } from '$lib/api/types';

// Mocks. Same vi.hoisted pattern as the Routes page tests so the
// module imports happen after the mock factories are in place.
const { toastMock, apiMock, settingsMock, certsMock } = vi.hoisted(() => ({
	toastMock: { pushToast: vi.fn() },
	apiMock: {
		listRoutes: vi.fn(),
	},
	settingsMock: {
		settingsApi: {
			listManagedDomains: vi.fn(),
			createManagedDomain: vi.fn(),
			deleteManagedDomain: vi.fn(),
			getDNSProviderOVH: vi.fn(),
		},
	},
	certsMock: {
		certificatesApi: {
			list: vi.fn(),
		},
	},
}));

vi.mock('$lib/stores/toast', () => toastMock);
vi.mock('$lib/api/client', () => apiMock);
vi.mock('$lib/api/settings', () => settingsMock);
vi.mock('$lib/api/certificates', () => certsMock);

import Page from './+page.svelte';

// Anchor "now" for the fixture so daysUntilExpiry calculations
// land at deterministic values regardless of when CI runs. We
// stub Date in tests that depend on the precise day count;
// fixture timestamps are computed relative to this anchor.
const NOW = new Date('2026-06-05T12:00:00Z');

function daysFromNow(days: number): string {
	return new Date(NOW.getTime() + days * 86400000).toISOString();
}

// Step T T.4 — fixture covering every status the AC #10 badge
// table maps. Tests that don't need the full set reach into this
// list by domain.
const fixtureCerts: Certificate[] = [
	{
		domain: 'valid.example.com',
		sanList: ['valid.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-60),
		notAfter: daysFromNow(60),
		status: 'VALID',
		source: 'specific',
	},
	{
		domain: 'soon.example.com',
		sanList: ['soon.example.com', 'www.soon.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-70),
		notAfter: daysFromNow(15),
		status: 'RENEWAL_PENDING',
		source: 'specific',
	},
	{
		domain: '*.wild.example.com',
		sanList: ['*.wild.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-30),
		notAfter: daysFromNow(60),
		status: 'VALID',
		source: 'wildcard',
	},
	{
		domain: 'expired.example.com',
		sanList: ['expired.example.com'],
		issuer: "Let's Encrypt",
		notBefore: daysFromNow(-120),
		notAfter: daysFromNow(-3),
		status: 'EXPIRED',
		source: 'specific',
	},
	{
		// OBTAIN_FAILED fixtures mirror the empirically-captured
		// wire shape against AreNET-test on 2026-06-05: the
		// backend emits sanList=null for entries that never
		// reached cert_obtained (no on-disk leaf to parse). The
		// snapshot()-level hotfix in tracker.go now coerces nil
		// to [], but the test keeps the null shape so the
		// frontend null-coalescing read (cert.sanList ?? []) is
		// exercised on every page test that loads fixtureCerts —
		// regression check survives if the backend ever
		// reintroduces the nil-slice gotcha.
		domain: 'broken.example.com',
		sanList: null,
		issuer: '',
		notBefore: daysFromNow(-30),
		notAfter: daysFromNow(60),
		status: 'OBTAIN_FAILED',
		source: 'specific',
		lastError: "subject 'broken.example.com' does not qualify for a public certificate",
		lastErrorAt: daysFromNow(-0.01),
	},
];

beforeEach(() => {
	toastMock.pushToast.mockReset();
	apiMock.listRoutes.mockReset();
	settingsMock.settingsApi.listManagedDomains.mockReset();
	settingsMock.settingsApi.createManagedDomain.mockReset();
	settingsMock.settingsApi.deleteManagedDomain.mockReset();
	settingsMock.settingsApi.getDNSProviderOVH.mockReset();
	certsMock.certificatesApi.list.mockReset();

	// Sensible defaults: no routes, no domains, DNS provider
	// configured, no certs. Individual tests override these.
	apiMock.listRoutes.mockResolvedValue([]);
	settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
		domains: [],
	});
	settingsMock.settingsApi.getDNSProviderOVH.mockResolvedValue({
		endpoint: 'ovh-eu',
		applicationKey: '',
		applicationSecret: '',
		consumerKey: '',
		configured: true,
	});
	certsMock.certificatesApi.list.mockResolvedValue([]);
});

describe('/certs — auto-renewal info card', () => {
	it('renders the auto-renewal info card post-load', async () => {
		render(Page);

		// The card is keyed on its data-testid so any future
		// copy edit doesn't break the test. The localized title
		// is also asserted so a regression that removes the
		// French copy still fails loudly.
		const card = await screen.findByTestId('auto-renewal-card');
		expect(card).toBeInTheDocument();
		expect(screen.getByText('Renouvellement automatique')).toBeInTheDocument();
		expect(card.textContent ?? '').toMatch(/certmagic/i);
		expect(card.textContent ?? '').toMatch(/30 jours/);
	});
});

describe('/certs — managed-domains editor (migrated from /settings in #R-6 Pack A; reframed by T.5)', () => {
	it('inline form is gone — only the wizard trigger remains in the policies section', async () => {
		render(Page);
		// Post-T.5 regression check: the legacy inline "Declare
		// managed domain" submit must NOT be in the DOM. The
		// wizard trigger replaces it.
		await screen.findByTestId('open-wildcard-wizard');
		expect(
			screen.queryByRole('button', { name: /declare managed domain/i }),
		).not.toBeInTheDocument();
		// The wizard modal isn't mounted until the trigger fires
		// (Modal is gated by open=false).
		expect(screen.queryByTestId('wildcard-wizard-form')).not.toBeInTheDocument();
	});

	it('clicking "+ Wildcard apex" opens the wizard with the three form controls', async () => {
		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		// Wizard fields — same controls the pre-T.5 inline form
		// exposed, just relocated. Labels stay identical so the
		// vocabulary is preserved.
		expect(await screen.findByLabelText('Apex domain')).toBeInTheDocument();
		expect(screen.getByLabelText('DNS provider')).toBeInTheDocument();
		expect(
			screen.getByLabelText('Include bare apex in cert SAN'),
		).toBeInTheDocument();
		// Footer Declare button.
		expect(
			screen.getByRole('button', { name: /^déclarer$/i }),
		).toBeInTheDocument();
	});

	it('renders existing managed domains with inline Delete buttons', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					provider: 'ovh',
				},
				{
					apex: 'other.example',
					includeApex: false,
					provider: 'ovh',
				},
			],
		});

		render(Page);

		// Each domain renders as `*.<apex>` (with optional bare
		// apex suffix when includeApex). The Delete button has a
		// per-domain aria-label so we can target both. Use
		// findByRole on the Delete button as the wait anchor
		// because it's only mounted post-load; matching on the
		// apex text can be ambiguous when includeApex doubles
		// the text occurrences in the same row.
		expect(
			await screen.findByRole('button', {
				name: 'Delete managed domain example.com',
			}),
		).toBeInTheDocument();
		expect(
			screen.getByRole('button', { name: 'Delete managed domain other.example' }),
		).toBeInTheDocument();
	});

	it('submitting the wizard calls settingsApi.createManagedDomain with trimmed apex', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			provider: 'ovh',
		});

		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		const apexInput = (await screen.findByTestId(
			'wizard-apex-input',
		)) as HTMLInputElement;
		await userEvent.type(apexInput, '  new.example  ');

		// fireEvent.submit on the form so the test exercises the
		// same code path Enter-in-input would (hidden submit button
		// inside the form catches it; the footer Déclarer button
		// has its own onclick wired to the same handler).
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);
		await tick();

		expect(settingsMock.settingsApi.createManagedDomain).toHaveBeenCalledWith({
			apex: 'new.example',
			includeApex: true,
			provider: 'ovh',
		});
	});

	// Wizard close/submit/error contracts are unit-tested in
	// WildcardApexWizard.test.ts. The page tests below stay narrow:
	// trigger → wizard mounts → submission reaches the same API
	// the pre-T.5 inline form did, and onCreated refreshes the list.
	// We don't assert the wizard UNMOUNTS post-close at the page
	// level because JSDOM doesn't drive svelte/transition out-
	// animations the way browsers do, leaving the dialog node in
	// the DOM after `open` flips to false. The behavioural
	// contract (onClose fired, list refreshed) is verified at the
	// component level.

	it('successful submit through the page refreshes the policies list', async () => {
		settingsMock.settingsApi.createManagedDomain.mockResolvedValue({
			apex: 'new.example',
			includeApex: true,
			provider: 'ovh',
		});
		// First call (page load): empty. Second call (after
		// wizard onCreated): the new policy. Reflects the
		// loadManagedDomains-as-onCreated wiring.
		settingsMock.settingsApi.listManagedDomains
			.mockResolvedValueOnce({ domains: [] })
			.mockResolvedValueOnce({
				domains: [
					{ apex: 'new.example', includeApex: true, provider: 'ovh' },
				],
			});

		render(Page);
		const trigger = await screen.findByTestId('open-wildcard-wizard');
		await userEvent.click(trigger);
		await tick();

		const apexInput = (await screen.findByTestId(
			'wizard-apex-input',
		)) as HTMLInputElement;
		await userEvent.type(apexInput, 'new.example');
		const form = screen.getByTestId('wildcard-wizard-form');
		await fireEvent.submit(form);

		// Newly-declared policy appears in the list (refreshed
		// via the onCreated callback the page passes to the
		// wizard). findByRole waits for the refresh tick.
		expect(
			await screen.findByRole('button', {
				name: 'Delete managed domain new.example',
			}),
		).toBeInTheDocument();
	});

	it('section header carries the T.5-reframed title "Politiques wildcard par apex"', async () => {
		render(Page);
		await screen.findByTestId('open-wildcard-wizard');
		expect(
			screen.getByText('Politiques wildcard par apex'),
		).toBeInTheDocument();
	});

	it('clicking Delete on a domain opens the revertTo modal', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [
				{
					apex: 'example.com',
					includeApex: true,
					provider: 'ovh',
				},
			],
		});

		render(Page);
		// Wait via the per-domain Delete button — unique
		// anchor, only mounted post-load.
		const deleteBtn = await screen.findByRole('button', {
			name: 'Delete managed domain example.com',
		});

		// Modal not mounted before the delete click.
		expect(
			screen.queryByLabelText('Revert covered routes to'),
		).not.toBeInTheDocument();

		await userEvent.click(deleteBtn);
		await tick();

		// The dialog mounts with the revertTo select + the
		// per-modal Cancel/Delete buttons. The title carries the
		// apex so the operator sees what they're about to delete.
		expect(
			screen.getByLabelText('Revert covered routes to'),
		).toBeInTheDocument();
		expect(
			screen.getByText(/delete managed domain example\.com/i),
		).toBeInTheDocument();
	});
});

describe('/certs — DNS-provider-unconfigured warning', () => {
	it('renders the warning when configured=false', async () => {
		settingsMock.settingsApi.getDNSProviderOVH.mockResolvedValue({
			endpoint: '',
			applicationKey: '',
			applicationSecret: '',
			consumerKey: '',
			configured: false,
		});

		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByTestId('open-wildcard-wizard');

		// The warning text is a sentence the test pins partially
		// so a future copy edit doesn't break the contract.
		expect(
			screen.getByText(/DNS provider unconfigured/i),
		).toBeInTheDocument();
	});

	it('hides the warning when configured=true', async () => {
		// Default beforeEach sets configured=true; this test
		// pins the negative-path explicitly.
		render(Page);
		// Wait until the editor is mounted (post-load) — the
		// submit button is the most stable signal because it's
		// only in the DOM inside the `{:else}` branch after
		// loading flips to false. Plain text like "Managed
		// domains" also appears in the PageHeader subtitle, so
		// using it as a wait-anchor would resolve too early.
		await screen.findByTestId('open-wildcard-wizard');

		expect(
			screen.queryByText(/DNS provider unconfigured/i),
		).not.toBeInTheDocument();
	});
});

// Step T T.4 — unified Domaines table tests. The fixture covers
// every status the AC #10 badge mapping handles; per-test mocks
// reach into `fixtureCerts` by domain name to keep each test's
// scope narrow.

describe('/certs — runtime KPI cards (T.4)', () => {
	it('Certificats actifs counts total + breaks down wildcard / spécifique', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-certs-actifs');
		// 5 fixture certs, 1 wildcard, 4 specific.
		expect(card.textContent ?? '').toMatch(/5/);
		expect(card.textContent ?? '').toMatch(/1 wildcard/);
		expect(card.textContent ?? '').toMatch(/4 spécifiques/);
	});

	it('Expirent < 30 jours surfaces the renewal-window count', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-expirent-bientot');
		// fixtureCerts: soon (15d), expired (-3d), broken (60d but
		// status fresh-failed doesn't affect daysUntilExpiry). The
		// "expiring soon" predicate is days <= 30, so soon + expired
		// = 2.
		expect(card.textContent ?? '').toMatch(/2/);
		expect(card.textContent ?? '').toMatch(/renouvellement auto programmé/);
	});

	it('Émetteur principal surfaces the dominant issuer', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-emetteur');
		expect(card.textContent ?? '').toMatch(/Let's Encrypt/);
	});

	it('Méthode ACME shows Auto when no managed domain declared', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-methode');
		expect(card.textContent ?? '').toMatch(/Auto/);
	});

	it('Méthode ACME flips to DNS-01 when at least one managed domain is declared', async () => {
		settingsMock.settingsApi.listManagedDomains.mockResolvedValue({
			domains: [{ apex: 'example.com', includeApex: true, provider: 'ovh' }],
		});
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const card = await screen.findByTestId('kpi-methode');
		expect(card.textContent ?? '').toMatch(/DNS-01/);
		expect(card.textContent ?? '').toMatch(/via OVH/);
	});
});

describe('/certs — Domaines table (T.4)', () => {
	it('renders one row per certificate with domain + issuer + SAN cells', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		expect(rows).toHaveLength(fixtureCerts.length);
		// Wildcard row carries 1 SAN; broken carries 1 SAN; soon
		// carries 2 (verifies sanList.length flows through).
		const soonRow = rows.find((r) => r.dataset.domain === 'soon.example.com')!;
		expect(soonRow.textContent ?? '').toMatch(/2 SAN/);
	});

	it('status badge label matches AC #10 vocabulary for each status', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		// VALID → VALIDE, RENEWAL_PENDING → RENOUV. AUTO,
		// EXPIRED → EXPIRÉ, OBTAIN_FAILED → ÉCHEC.
		expect(screen.getAllByText('VALIDE').length).toBeGreaterThan(0);
		expect(screen.getByText('RENOUV. AUTO')).toBeInTheDocument();
		expect(screen.getByText('EXPIRÉ')).toBeInTheDocument();
		expect(screen.getByText('ÉCHEC')).toBeInTheDocument();
	});

	it('renders an OBTAIN_FAILED row with null sanList as "0 SAN" without crashing (hotfix regression)', async () => {
		// Pre-hotfix the backend marshaled sanList as JSON null
		// for OBTAIN_FAILED entries that never reached
		// cert_obtained (Go nil-slice gotcha — see
		// internal/certinfo/tracker.go snapshot). The frontend's
		// cert.sanList.length read crashed on null. Both sides
		// fixed; the broken.example.com fixture above carries
		// sanList=null to ensure this regression is caught if
		// either side reverts.
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const broken = rows.find((r) => r.dataset.domain === 'broken.example.com')!;
		expect(broken).toBeDefined();
		expect(broken.textContent ?? '').toMatch(/0 SAN/);
	});

	it('OBTAIN_FAILED row carries the lastError tooltip', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const echec = screen.getByText('ÉCHEC');
		// Tooltip wraps the badge; the bubble mounts on hover/focus.
		// We assert the wrapper's aria-describedby contract by
		// simulating focus and reading the bubble text.
		const wrapper = echec.closest('.tt-wrapper') as HTMLElement | null;
		expect(wrapper).not.toBeNull();
		await fireEvent.focusIn(wrapper!);
		await tick();
		expect(
			screen.getByText(/does not qualify for a public certificate/),
		).toBeInTheDocument();
	});

	it('expired row labels the EXPIRE DANS cell as "expiré"', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');
		const rows = screen.getAllByTestId('cert-row');
		const expired = rows.find((r) => r.dataset.domain === 'expired.example.com')!;
		expect(expired.textContent ?? '').toMatch(/expiré/);
	});

	it('shows the page-level empty state when no certs exist', async () => {
		// Default mock already returns []; explicit for clarity.
		certsMock.certificatesApi.list.mockResolvedValue([]);
		render(Page);
		const empty = await screen.findByTestId('certs-empty');
		expect(empty.textContent ?? '').toMatch(/Aucun certificat actif/);
	});

	it('shows the error banner when /api/certificates rejects', async () => {
		certsMock.certificatesApi.list.mockRejectedValue(new Error('boom'));
		render(Page);
		const err = await screen.findByTestId('certs-error');
		expect(err.textContent ?? '').toMatch(/Impossible de récupérer/);
		// Pack A editor MUST still mount even when certs failed
		// (AC #13 degraded mode mirrored on the frontend). Post-
		// T.5 the wizard trigger is the new declaration affordance.
		expect(screen.getByTestId('open-wildcard-wizard')).toBeInTheDocument();
	});
});

describe('/certs — Domaines tabs (T.4)', () => {
	it('Wildcard tab filters to source=wildcard rows only', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-wildcard');
		await userEvent.click(tab);
		await tick();

		const rows = screen.getAllByTestId('cert-row');
		expect(rows).toHaveLength(1);
		expect(rows[0].dataset.domain).toBe('*.wild.example.com');
	});

	it('Expirent bientôt tab filters to certs within the renewal window OR already expired', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-expiring');
		await userEvent.click(tab);
		await tick();

		const rows = screen.getAllByTestId('cert-row');
		// soon (15d) + expired (-3d) qualify; valid/wild/broken
		// have notAfter beyond the 30d window.
		expect(rows.map((r) => r.dataset.domain).sort()).toEqual(
			['expired.example.com', 'soon.example.com'].sort(),
		);
	});

	it('per-tab empty state surfaces when the active filter yields zero rows', async () => {
		// All-VALID fixture, no wildcards — the Wildcard tab MUST
		// render the per-tab empty branch, NOT the page-level
		// "Aucun certificat actif" copy.
		certsMock.certificatesApi.list.mockResolvedValue([
			{
				domain: 'one.example.com',
				sanList: ['one.example.com'],
				issuer: "Let's Encrypt",
				notBefore: daysFromNow(-30),
				notAfter: daysFromNow(60),
				status: 'VALID',
				source: 'specific',
			},
		]);
		render(Page);
		await screen.findByTestId('certs-table');

		const tab = screen.getByTestId('tab-wildcard');
		await userEvent.click(tab);
		await tick();

		expect(screen.getByTestId('certs-tab-empty')).toBeInTheDocument();
		// And the page-level empty state must NOT be shown — the
		// dataset isn't empty, just the filter.
		expect(screen.queryByTestId('certs-empty')).not.toBeInTheDocument();
	});

	it('Tous tab is the default selection on first render', async () => {
		certsMock.certificatesApi.list.mockResolvedValue(fixtureCerts);
		render(Page);
		const tab = await screen.findByTestId('tab-all');
		expect(tab.getAttribute('aria-selected')).toBe('true');
	});
});
