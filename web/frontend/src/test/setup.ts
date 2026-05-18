// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Vitest global setup. Stubs $app/navigation (provided by SvelteKit at
// runtime but absent from the test resolver) and provides a minimal
// fetch mock helper the API client tests rely on.

import { vi } from 'vitest';

// Stub $app/navigation: goto is a no-op spy that tests can read to
// verify redirect behavior of the 401 interceptor (spec §6.4).
vi.mock('$app/navigation', () => ({
	goto: vi.fn(() => Promise.resolve())
}));
