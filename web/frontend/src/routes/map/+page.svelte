<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.5 — Threat map (scaffold).

  Replaces the R.2 stub (commit 4691eb2) with the actual
  Mercator world + Arenet position marker. V.5 ships the
  static foundation; V.6 will overlay the live geo-event
  WS stream + arc animation, V.7 the manual-override
  settings UI.

  Data flow:
    onMount → GET /api/v1/observability/server-position
            → bind result into <WorldMap arenetLat=... />
            → degraded mode renders a banner + a world-
              centered map without a marker (lat/lon=0
              would otherwise place the pin off the coast
              of Ghana, which is the canonical "broken"
              GeoIP fallback the operator MUST recognize).

  V.5 does NOT subscribe to the WS yet — the WorldMap
  component's arc layer is V.6 scope.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import WorldMap from '$lib/components/Map/WorldMap.svelte';
	import LicenseFooter from '$lib/components/Map/LicenseFooter.svelte';
	import { fetchServerPosition } from '$lib/api/security';
	import type { ServerPosition } from '$lib/api/types';

	let position: ServerPosition | null = $state(null);
	let loadError: string | null = $state(null);
	let loading = $state(true);

	onMount(async () => {
		try {
			position = await fetchServerPosition();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	});
</script>

<svelte:head>
	<title>Map · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Trafic · Map"
	title="Threat map"
	subtitle="Visualisation géographique des sources de trafic et des décisions sécurité. WAF, throttle, CrowdSec et auth-failures sont affichés depuis leur source jusqu'à l'instance Arenet (animation des arcs en V.6)."
/>

{#if loading}
	<div class="map-state map-state--loading" data-testid="map-loading">
		Chargement de la position serveur…
	</div>
{:else if loadError}
	<div class="map-state map-state--error" role="alert" data-testid="map-error">
		<strong>Erreur de chargement.</strong>
		<span>{loadError}</span>
	</div>
{:else if position}
	{@const degraded = position.degraded === true}
	{#if degraded}
		<div class="map-state map-state--degraded" role="status" data-testid="map-degraded">
			<strong>GeoIP indisponible.</strong>
			<span>
				La position du serveur n'a pas pu être détectée automatiquement. Vérifiez que la base
				GeoLite2-City est présente à <code>/var/lib/arenet/GeoLite2-City.mmdb</code> (ou
				configurez <code>ARENET_GEOIP_MMDB</code>), puis redémarrez. Une position manuelle peut
				aussi être enregistrée via l'API
				<code>PUT /api/v1/observability/server-position</code> (UI de Paramètres en V.7).
			</span>
		</div>
	{/if}
	<div class="map-frame" data-testid="map-frame">
		<WorldMap
			arenetLat={degraded ? null : position.lat}
			arenetLon={degraded ? null : position.lon}
			city={position.city}
			country={position.country}
			mode={position.mode}
		/>
	</div>
{/if}

<LicenseFooter />

<style>
	.map-state {
		padding: 18px 20px;
		margin-bottom: 16px;
		border-radius: 8px;
		border: 1px solid var(--border-subtle);
		background: var(--bg-surface);
		color: var(--text-secondary);
		font-size: 14px;
		line-height: 1.5;
	}
	.map-state strong {
		display: block;
		color: var(--text-primary);
		margin-bottom: 4px;
	}
	.map-state code {
		font-family: var(--font-mono);
		font-size: 12px;
		background: var(--bg-base);
		padding: 1px 5px;
		border-radius: 4px;
		color: var(--text-secondary);
	}
	.map-state--error {
		border-color: var(--status-down);
	}
	.map-state--degraded {
		border-color: var(--status-warn);
	}
	.map-frame {
		margin-top: 8px;
	}
</style>
