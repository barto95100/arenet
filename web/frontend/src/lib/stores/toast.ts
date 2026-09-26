// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import { writable } from 'svelte/store';

export type ToastVariant = 'success' | 'danger' | 'info';

export interface ToastEntry {
	id: number;
	message: string;
	variant: ToastVariant;
}

const TOAST_TTL_MS = 4000;
let nextId = 1;

export const toasts = writable<ToastEntry[]>([]);

/**
 * Push a toast onto the queue. Auto-dismisses after ttlMs (default
 * TOAST_TTL_MS); longer for messages the operator must read.
 */
export function pushToast(message: string, variant: ToastVariant = 'info', ttlMs: number = TOAST_TTL_MS): void {
	const id = nextId++;
	toasts.update((list) => [...list, { id, message, variant }]);
	setTimeout(() => dismissToast(id), ttlMs);
}

/** Remove a toast from the queue immediately. Safe to call on unknown ids. */
export function dismissToast(id: number): void {
	toasts.update((list) => list.filter((t) => t.id !== id));
}
