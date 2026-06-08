<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  W.7 follow-up — operator-friendly host display for
  per-route log rows. The /logs page renders rows from 5
  event sources (waf, throttle, auth, cert, country_block);
  three of them (waf + country_block events) carry a raw
  routeId UUID rather than the human hostname. This
  component resolves the UUID via a Map<routeId, host>
  built once on page mount + falls back gracefully when
  the route was deleted between block time and page load.

  Render contract:
    - routeMap.get(routeId) defined → render host as the
      visible text + the full UUID as a title tooltip
      (forensic ops can still grep the UUID without
      bloating the column).
    - routeMap.get(routeId) undefined → render a
      truncated UUID (first 8 chars + "…") with the full
      UUID as the title tooltip. The route was either
      deleted OR the routeMap fetch failed; either way
      the operator gets enough to grep manually.
    - routeId empty / undefined → render "(unknown)" so
      a row with no route association doesn't look broken.

  Mounted in /logs +page.svelte once per row that carries
  a routeId. No props beyond {routeId, routeMap} — the
  parent owns the fetch lifecycle.
-->
<script lang="ts">
	interface Props {
		routeId: string | undefined;
		routeMap: Map<string, string>;
	}
	let { routeId, routeMap }: Props = $props();

	// Resolved label: host when known, truncated UUID
	// otherwise. The fallback truncation matches the
	// "first 8 chars of a UUID is operationally
	// recognisable" convention git uses for SHAs.
	const display = $derived.by(() => {
		if (!routeId) return '(unknown)';
		const host = routeMap.get(routeId);
		if (host) return host;
		return routeId.length > 8 ? routeId.slice(0, 8) + '…' : routeId;
	});

	// Full UUID always available via the title tooltip so
	// operators investigating an incident can grep
	// journalctl / SQLite by the canonical identifier
	// even when the route is gone.
	const tooltip = $derived(routeId ?? '');

	// CSS hook the parent can target — fallback rows get
	// a muted style to signal "this route is gone".
	const isFallback = $derived(!routeId || !routeMap.get(routeId));
</script>

<span
	class="route-host"
	class:route-host--fallback={isFallback}
	data-testid="route-host"
	data-route-id={routeId ?? ''}
	title={tooltip}
>
	{display}
</span>

<style>
	.route-host {
		font-family: inherit;
		color: inherit;
	}
	.route-host--fallback {
		font-family: var(--font-mono);
		color: var(--text-muted);
		font-size: 11px;
	}
</style>
