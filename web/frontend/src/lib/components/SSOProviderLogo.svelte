<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  SSO provider logo — small square asset rendered on the login
  page's "Continuer avec SSO" button, and reusable wherever a
  provider needs visual identification (future: Settings page
  preview, audit log icon column).

  Asset source: the SvelteKit static directory at
  web/frontend/static/sso-providers/. Files served verbatim by
  the adapter-static build (no bundling, no Vite import
  resolution) — the operator can replace assets without
  rebuilding the binary.

  Expected files (deposit the official brand SVG at each path):
    static/sso-providers/authentik.svg
    static/sso-providers/keycloak.svg
    static/sso-providers/authelia.svg

  Fallback: when `kind` is empty, unknown, OR the asset 404s,
  we render an inline Lucide log-in glyph on a neutral gradient.
  This keeps the button functional even before assets are
  deposited (or if an operator typos the kind in storage by
  hand).
-->
<script lang="ts">
	import type { OIDCProviderKind } from '$lib/api/types';
	import { oidcProviderColors } from '$lib/utils/oidc-labels';

	interface Props {
		/**
		 * Provider kind from /auth/oidc/status or from settings.
		 * Empty / undefined / unknown enum value → generic fallback.
		 */
		kind?: OIDCProviderKind | string | undefined;
		/** Box size in pixels — default matches the login button. */
		size?: number;
	}

	let { kind = '', size = 22 }: Props = $props();

	const KNOWN_KINDS = new Set(['authentik', 'keycloak', 'authelia']);

	// Resolve to a static asset only for known kinds; fall back
	// to the inline glyph otherwise. The browser will 404
	// silently if the operator deposited the wrong filename —
	// in that case the <img> alt text shows but no glyph; we
	// could probe with onerror handlers but for v1.0 we keep
	// the path simple and rely on the operator to put the right
	// files in static/sso-providers/.
	const useAsset = $derived(KNOWN_KINDS.has(String(kind)));
	const assetUrl = $derived(useAsset ? `/sso-providers/${kind}.svg` : '');
	const altText = $derived(useAsset ? `Logo ${kind}` : '');

	// Phase 2 follow-up — kind-specific gradient pulled from
	// the shared oidc-labels mapping, so the sidebar tile and
	// the /utilisateurs SOURCE badge stay in sync.
	const colors = $derived(oidcProviderColors(kind));
	const gradient = $derived(`linear-gradient(140deg, ${colors.gradFrom} 0%, ${colors.gradTo} 100%)`);
</script>

<span
	class="sso-provider-logo"
	style:width="{size}px"
	style:height="{size}px"
	style:background={gradient}
	aria-hidden="true"
>
	{#if useAsset}
		<img src={assetUrl} alt={altText} width={size} height={size} />
	{:else}
		<!-- Inline Lucide log-in fallback on a neutral gradient. -->
		<svg
			viewBox="0 0 24 24"
			width={Math.round(size * 0.64)}
			height={Math.round(size * 0.64)}
			fill="none"
			stroke="currentColor"
			stroke-width="2"
			stroke-linecap="round"
			stroke-linejoin="round"
		>
			<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
			<polyline points="10 17 15 12 10 7" />
			<line x1="15" y1="12" x2="3" y2="12" />
		</svg>
	{/if}
</span>

<style>
	.sso-provider-logo {
		display: grid;
		place-items: center;
		border-radius: 5px;
		color: #fff;
		box-shadow: inset 0 1px 0 oklch(82% 0.12 250 / 0.35);
		overflow: hidden;
	}
	.sso-provider-logo img {
		width: 100%;
		height: 100%;
		object-fit: contain;
		padding: 3px;
	}
</style>
