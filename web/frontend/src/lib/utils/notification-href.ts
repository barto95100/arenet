// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { AlertEvent } from '$lib/api/alerting';

// notificationHref derives the click destination for a notification.
// context.url (set by the update source) wins as an external link;
// otherwise a coarse category/ruleName heuristic maps to an internal
// page, with a safe /alerting fallback (never a dead link).
export function notificationHref(ev: AlertEvent): { href: string; external: boolean } {
	const url = ev.context?.url;
	if (typeof url === 'string' && url.length > 0) {
		return { href: url, external: true };
	}
	const hay = `${ev.category ?? ''} ${ev.ruleName ?? ''}`.toLowerCase();
	let href = '/alerting';
	if (hay.includes('cert')) href = '/certs';
	else if (hay.includes('waf') || hay.includes('security')) href = '/security';
	else if (hay.includes('update')) href = '/settings';
	else if (hay.includes('health') || hay.includes('system')) href = '/';
	return { href, external: false };
}
