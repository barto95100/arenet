// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.19.0 external-certs SOCLE (Task 8) — parity tests for the
// hostMatchesSAN helper. Cases mirror the Go reference test
// TestHostMatchesSAN (internal/storage/routes_external_cert_test.go)
// case-for-case so any drift between the two implementations trips
// one of these.

import { describe, it, expect } from 'vitest';
import { hostMatchesSAN } from './san-match';

describe('hostMatchesSAN — RFC 6125 host↔SAN matching', () => {
	it('matches an exact SAN', () => {
		expect(hostMatchesSAN('app.example.com', ['app.example.com'])).toBe(true);
	});

	it('matches a single-label wildcard SAN', () => {
		expect(hostMatchesSAN('app.example.com', ['*.example.com'])).toBe(true);
	});

	it('does NOT match a wildcard across two labels', () => {
		expect(hostMatchesSAN('sub.app.example.com', ['*.example.com'])).toBe(false);
	});

	it('does NOT match the bare apex against a *. wildcard', () => {
		expect(hostMatchesSAN('example.com', ['*.example.com'])).toBe(false);
	});

	it('is case-insensitive', () => {
		expect(hostMatchesSAN('APP.example.com', ['app.example.com'])).toBe(true);
		expect(hostMatchesSAN('app.example.com', ['*.EXAMPLE.com'])).toBe(true);
	});

	it('does NOT match an unrelated host', () => {
		expect(hostMatchesSAN('other.com', ['app.example.com'])).toBe(false);
	});

	it('tolerates a trailing FQDN dot on either side', () => {
		expect(hostMatchesSAN('app.example.com.', ['app.example.com'])).toBe(true);
		expect(hostMatchesSAN('app.example.com', ['*.example.com.'])).toBe(true);
	});

	it('returns false against an empty SAN list', () => {
		expect(hostMatchesSAN('app.example.com', [])).toBe(false);
	});

	it('matches when any one SAN in the list covers the host', () => {
		expect(hostMatchesSAN('app.example.com', ['other.com', '*.example.com'])).toBe(true);
	});
});
