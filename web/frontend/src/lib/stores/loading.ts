// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { writable, derived } from 'svelte/store';

const counter = writable(0);

export const loading = derived(counter, ($c) => $c > 0);

export function beginRequest(): void {
	counter.update((c) => c + 1);
}
export function endRequest(): void {
	counter.update((c) => Math.max(0, c - 1));
}
