// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// i18n module (v2.9.11 Phase 1). Pure runtime resolver — no
// dependency on any external i18n library. Bundles are imported
// statically so they ship in the initial JS chunk (~50 KiB total
// for en + fr at Phase 2 sizing; trivial today with 30 keys).
//
// Usage in components (Svelte 5):
//
//   <script>
//     import { t } from '$lib/i18n';
//     import { language } from '$lib/stores/language.svelte';
//     // The `language.current &&` is the dependency trigger.
//     // Without reading language.current inside the $derived, the
//     // value would not recompute on language change.
//     let label = $derived(language.current && t('common.save'));
//   </script>
//   <button>{label}</button>
//
// Why a regular function (not a Svelte store): keeping `t()` as a
// plain function lets non-component code (toasts, error formatters,
// utils) call it without dancing around the store-subscription API.
// Reactivity is opt-in at the call site via $derived as shown above.

import { language } from '$lib/stores/language.svelte';
import en from './locales/en.json';
import fr from './locales/fr.json';

type Bundle = Record<string, unknown>;
const bundles: Record<string, Bundle> = { en, fr };

/** Resolve a dotted key path against a bundle. Returns the string
 *  value if found, undefined otherwise. */
function resolve(bundle: Bundle, key: string): string | undefined {
	const parts = key.split('.');
	let node: unknown = bundle;
	for (const part of parts) {
		if (typeof node !== 'object' || node === null) return undefined;
		node = (node as Record<string, unknown>)[part];
	}
	return typeof node === 'string' ? node : undefined;
}

/** Replace {placeholder} tokens in a template with the corresponding
 *  values from `params`. Missing placeholders are left untouched —
 *  useful for spotting missing-param bugs visually instead of silent
 *  empty substitutions. */
function interpolate(
	template: string,
	params?: Record<string, string | number>
): string {
	if (!params) return template;
	return template.replace(/\{(\w+)\}/g, (whole, name) => {
		const value = params[name];
		return value === undefined || value === null ? whole : String(value);
	});
}

/** Resolve a translation key against the active language bundle.
 *
 *  Fallback chain (spec §Edge cases):
 *    1. Active language bundle (language.current)
 *    2. English bundle (source of truth)
 *    3. Raw key — signals a missing translation visually so devs
 *       see it during smoke testing
 *
 *  Optional `params` interpolates {placeholder} tokens. */
export function t(
	key: string,
	params?: Record<string, string | number>
): string {
	const active = bundles[language.current] ?? bundles.en;
	let hit = resolve(active, key);
	if (hit === undefined && active !== bundles.en) {
		hit = resolve(bundles.en, key);
	}
	if (hit === undefined) {
		// Log once-per-key in dev so the missing-key set is discoverable
		// without flooding the console. Production builds optimise the
		// branch out via dead-code elimination on import.meta.env.DEV.
		if (typeof import.meta !== 'undefined' && import.meta.env?.DEV) {
			// eslint-disable-next-line no-console
			console.warn(`[i18n] missing key: ${key}`);
		}
		return key;
	}
	return interpolate(hit, params);
}
