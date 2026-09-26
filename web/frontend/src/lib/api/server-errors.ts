// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.46 — server refusals, in the operator's language.
//
// Arenet used to return refusals as English sentences and the frontend
// printed them verbatim, so an operator working in French met English
// at exactly the moments that matter: the redirect loop guard, the
// uppercase path, the UDP probe. The project's own rule says UI
// strings go through i18n; these bypassed it.
//
// The server now sends a stable `code` and `params` alongside the
// sentence (internal/apierr). This resolves the code against
// `errors.server.<code>` and falls back to the server's own sentence
// when no translation exists — which is what lets the catalogue grow
// one message at a time instead of in one risky sweep, and what keeps
// an unrecognised code readable instead of showing a bare key.

import { ApiError } from './types';
import { t } from '$lib/i18n';

/**
 * The message to show for a failed request: translated when the code
 * is known, the server's sentence otherwise.
 */
export function serverErrorMessage(err: unknown): string {
	if (err instanceof ApiError && err.code) {
		const key = `errors.server.${err.code}`;
		// t() returns the key itself when it is missing from both
		// bundles, which is the signal to fall back rather than print
		// "errors.server.some_code" at the operator.
		const translated = t(key, (err.params ?? {}) as Record<string, string | number>);
		if (translated !== key) return translated;
	}
	if (err instanceof Error) return err.message;
	return String(err);
}
