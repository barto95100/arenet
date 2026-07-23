<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Country flag (SVG via flag-icons). Renders the flag for an ISO 3166-1
  alpha-2 code as an accessible inline image. SVG (not emoji) so the flag
  renders identically on every OS — emoji regional-indicators show "FR"
  boxes on Windows. The flag-icons CSS is imported once globally
  (+layout.svelte). Single source of truth for flag rendering, reused by
  the country-block chips and the search dropdown.

  Fallback: an empty/unknown code renders a neutral placeholder (no broken
  flag), mirroring the fallback discipline in $lib/data/countries.ts.
-->
<script lang="ts">
	import { countryName } from '$lib/data/countries';

	interface Props {
		/** ISO 3166-1 alpha-2 country code (e.g. "FR"). Case-insensitive. */
		code: string;
	}

	let { code }: Props = $props();

	// flag-icons uses lowercase class suffixes (fi fi-fr). Guard against a
	// non-2-letter input so we don't emit a broken `fi fi-` class.
	let normalized = $derived((code ?? '').trim().toLowerCase());
	let valid = $derived(/^[a-z]{2}$/.test(normalized));
	let label = $derived(countryName(code) || code || '');
</script>

{#if valid}
	<span class="flag fi fi-{normalized}" role="img" aria-label={label} data-testid="country-flag"
	></span>
{:else}
	<!-- Neutral placeholder for an unknown/empty code — no broken flag. -->
	<span class="flag flag--unknown" role="img" aria-label={label} data-testid="country-flag"></span>
{/if}

<style>
	.flag {
		display: inline-block;
		width: 1.25rem;
		/* flag-icons is 4:3; keep that ratio so flags don't distort. */
		height: 0.9375rem;
		border-radius: 2px;
		/* A hairline keeps light flags (e.g. Japan) visible on light bg. */
		box-shadow: inset 0 0 0 1px rgb(0 0 0 / 0.08);
		vertical-align: -0.15em;
		flex: none;
	}
	.flag--unknown {
		background: var(--surface-hi, #2a2a2a);
	}
</style>
