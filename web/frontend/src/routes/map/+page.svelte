<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.6 — Threat map (live).

  V.5 (commit a95e35d) shipped the static foundation: world
  TopoJSON + Arenet position marker. V.6 wires the live
  data pipeline:

    1. GET /api/v1/observability/server-position (V.4)
       → centers the map, places the Arenet marker.
    2. GET /api/v1/observability/geo-events?limit=500 (V.3)
       → seeds the WorldMap's `events` prop with replay
         data so the page paints SOMETHING immediately,
         not blank-until-first-WS-frame.
    3. WS /api/v1/ws/geo-events (V.3)
       → appends each frame to `events`; WorldMap spawns
         a new arc per non-LAN event with a category-
         colored stroke.

  The page caps `events` at MAX_EVENTS so a long-running
  tab doesn't accumulate forever; the arc lifecycle inside
  WorldMap is self-pruning so the in-DOM SVG arc count
  stays bounded independently.

  WS lifecycle: connect on mount, auto-reconnect with the
  exponential backoff schedule in geo-events-stream.ts,
  close cleanly on unmount. The connection-state pill in
  the top-right shows the operator the wire health at a
  glance — "Live" green when arcs are flowing,
  "Reconnexion…" amber when the WS dropped and the page is
  catching up.

  V.7 will land the operator-facing settings UI for the
  manual position override (the V.4 PUT endpoint).
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import WorldMap from '$lib/components/Map/WorldMap.svelte';
	import LicenseFooter from '$lib/components/Map/LicenseFooter.svelte';
	import { fetchServerPosition, fetchGeoEventsReplay } from '$lib/api/security';
	import type { ServerPosition, GeoEvent } from '$lib/api/types';
	import {
		openGeoEventStream,
		type GeoEventStreamHandle,
		type GeoEventStreamState
	} from '$lib/ws/geo-events-stream';

	// In-memory cap so a long-running tab doesn't accumulate
	// without bound. Replay seeds at most 500; the live
	// stream can append on top up to MAX_EVENTS, after
	// which the oldest entries are dropped from the front.
	// WorldMap's arc lifecycle (ARC_TOTAL_MS ~3.5 s) keeps
	// the SVG cost independent of this cap — the cap only
	// matters for the prop array's identity churn.
	const MAX_EVENTS = 1000;
	const REPLAY_LIMIT = 500;

	let position: ServerPosition | null = $state(null);
	let loadError: string | null = $state(null);
	let loading = $state(true);
	let events: GeoEvent[] = $state([]);
	let wsState: GeoEventStreamState = $state('connecting');
	let wsHandle: GeoEventStreamHandle | null = null;
	// Step V.7 — LAN counter. WorldMap.svelte skips LAN
	// events from the arc spawn per spec §3.8 because they
	// would all originate at the Arenet position and clutter
	// the world view. To keep that internal traffic visible
	// to the operator (a sudden LAN spike still means
	// something), we count it here and surface a small chip
	// next to the WS status pill. Resets per page mount —
	// the operator can clear it by reloading the page.
	let lanCount = $state(0);

	onMount(async () => {
		// Step 1 — load position. A failure here is fatal:
		// without the Arenet pixel position, the WorldMap
		// can't draw arcs. The error banner kicks in and
		// the WS isn't even attempted (no point streaming
		// events into a degraded UI).
		try {
			position = await fetchServerPosition();
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
			loading = false;
			return;
		}
		loading = false;

		// Step 2 — load replay. A replay failure is NON-fatal
		// per spec §5.4 (the GET endpoint returns a degraded
		// 200 envelope rather than 5xx). We log + continue;
		// the WS still opens so live events flow.
		try {
			const replay = await fetchGeoEventsReplay(REPLAY_LIMIT);
			events = replay.events;
			// V.7 — seed the LAN counter from the replay so a
			// page reload doesn't reset it to zero when LAN
			// traffic was already in the ring buffer.
			for (const ev of replay.events) {
				if (ev.isLan) lanCount++;
			}
		} catch (err) {
			// eslint-disable-next-line no-console
			console.warn('[map] geo events replay failed; live stream still attempted', err);
		}

		// Step 3 — open WS. The handle auto-reconnects with
		// the geo-events-stream.ts backoff schedule. The
		// state-change callback feeds the status pill.
		wsHandle = openGeoEventStream(
			(event) => {
				// V.7 — bump the LAN counter alongside the
				// events append. The counter increments for
				// every LAN event regardless of whether the
				// downstream arc layer renders it (it does
				// not, per spec §3.8) so the operator's
				// internal-traffic signal is preserved.
				if (event.isLan) lanCount++;
				// Append + cap. Identity churn matters: the
				// WorldMap $effect watches events.length so
				// a new tail entry triggers an arc spawn
				// without re-spawning the prefix.
				const next = events.length >= MAX_EVENTS ? events.slice(1) : events.slice();
				next.push(event);
				events = next;
			},
			(state) => {
				wsState = state;
			}
		);
	});

	onDestroy(() => {
		wsHandle?.close();
		wsHandle = null;
	});
</script>

<svelte:head>
	<title>Map · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Trafic · Map"
	title="Threat map"
	subtitle="Visualisation géographique en temps réel des sources de trafic et des décisions sécurité. WAF, throttle, CrowdSec et auth-failures sont rendus sous forme d'arcs colorés depuis la source jusqu'à l'instance Arenet."
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
		<div class="map-overlay-pills">
		{#if lanCount > 0}
			<div
				class="lan-pill"
				data-testid="map-lan-pill"
				data-lan-count={lanCount}
				role="status"
				title="Trafic interne (LAN/RFC1918) reçu depuis l'ouverture de la page. Ces événements ne sont pas affichés sur la carte mondiale car leur origine est l'instance Arenet elle-même."
			>
				<span class="lan-pill__icon" aria-hidden="true">⌂</span>
				<span data-testid="map-lan-pill-count">{lanCount}</span>
				<span class="lan-pill__label">interne{lanCount > 1 ? 's' : ''} (LAN)</span>
			</div>
		{/if}
		<div
			class="ws-pill ws-pill--{wsState}"
			data-testid="map-ws-pill"
			data-ws-state={wsState}
			role="status"
		>
			<span class="ws-pill__dot" aria-hidden="true"></span>
			{#if wsState === 'open'}
				Live
			{:else if wsState === 'connecting'}
				Connexion…
			{:else if wsState === 'reconnecting'}
				Reconnexion…
			{:else}
				Hors ligne
			{/if}
		</div>
		</div>
		<WorldMap
			arenetLat={degraded ? null : position.lat}
			arenetLon={degraded ? null : position.lon}
			city={position.city}
			country={position.country}
			mode={position.mode}
			{events}
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
		position: relative;
		margin-top: 8px;
	}

	/* V.7 — top-right pill stack. The WS pill (V.6) and
	   the LAN counter pill (V.7) share an absolute-
	   positioned flex row so they line up without each
	   pill needing its own top/right offset. */
	.map-overlay-pills {
		position: absolute;
		top: 10px;
		right: 12px;
		display: inline-flex;
		align-items: center;
		gap: 8px;
		z-index: 1;
	}

	/* WebSocket status pill — top-right of the map frame.
	   Mirrors the connection-status surface from the
	   topology page (the operator's mental model for live
	   data is already established there). */
	.ws-pill {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 4px 10px;
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--text-secondary);
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 999px;
		pointer-events: none;
	}

	/* LAN events counter — same pill shape as the WS pill
	   so they sit next to each other visually. The tooltip
	   on hover (title attr on the markup) explains why
	   these events don't render as arcs. Pointer-events
	   on so the title attr triggers. */
	.lan-pill {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 4px 10px;
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--text-secondary);
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: 999px;
		cursor: help;
	}
	.lan-pill__icon {
		font-size: 13px;
		line-height: 1;
		color: var(--status-meta);
	}
	.lan-pill__label {
		color: var(--text-muted);
		text-transform: none;
		letter-spacing: 0;
	}
	.ws-pill__dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: currentColor;
		opacity: 0.85;
	}
	.ws-pill--open {
		color: var(--status-up);
	}
	.ws-pill--connecting,
	.ws-pill--reconnecting {
		color: var(--status-warn);
	}
	.ws-pill--connecting .ws-pill__dot,
	.ws-pill--reconnecting .ws-pill__dot {
		animation: ws-pill-pulse 1.2s ease-in-out infinite;
	}
	.ws-pill--closed {
		color: var(--text-muted);
	}

	@keyframes ws-pill-pulse {
		0%,
		100% {
			opacity: 0.3;
		}
		50% {
			opacity: 1;
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.ws-pill--connecting .ws-pill__dot,
		.ws-pill--reconnecting .ws-pill__dot {
			animation: none;
			opacity: 0.7;
		}
	}
</style>
