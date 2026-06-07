<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step V.5 — Mercator world map + Arenet position marker.

  Renders the world-atlas TopoJSON via D3's geoMercator
  projection, centered on the Arenet server's position
  (props arenetLat / arenetLon). The marker is INLINED into
  this component rather than split out so it shares the
  projection scope — projecting (lat, lon) → (x, y) requires
  the same d3.geoMercator instance the country paths use, and
  passing the projection as a prop between sibling
  components is more friction than the encapsulation buys.

  Architecture:
    - svg is bound from Svelte; D3 only mutates the
      <g class="countries"> + <g class="marker"> children.
      The marker uses a Svelte-managed <g> instead of D3-
      mutated SVG so reactive props (city, country, mode)
      update cleanly without re-running render().
    - The projection is recomputed whenever width / height /
      arenetLat / arenetLon change, then countries re-paint
      and the projected marker pixel position recomputes via
      a $derived expression.
    - viewBox + preserveAspectRatio="xMidYMid meet" make the
      SVG responsive within its container while keeping the
      Mercator aspect ratio honest.

  V.6 will mount an arc layer inside this same <svg> (one
  per geo event) so the arcs share the projection. The
  current API is forward-compatible: V.6 just adds a
  <Snippet /> children prop receiving the projection
  function.

  V.5 category colors (locked here for V.6 reuse):
    - normal:   --status-up    (oklch ~72% 0.16 150 — green)
    - throttle: --status-warn  (oklch ~80% 0.14 85  — amber)
    - waf:      --status-down  (oklch ~66% 0.20 25  — red)
    - crowdsec: --status-down  (oklch ~66% 0.20 25  — red)
    - auth:     --status-info  (oklch ~72% 0.12 230 — cyan)
  Crowdsec and waf share the same hue intentionally — both
  are block-class decisions; the tooltip disambiguates the
  source. V.6 may split them via opacity or pattern if the
  visual ambiguity proves confusing in smoke.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import * as d3 from 'd3';
	import { feature } from 'topojson-client';
	import type { GeoProjection, GeoPath } from 'd3-geo';
	import type { Topology } from 'topojson-specification';
	import type { Feature, FeatureCollection, Geometry } from 'geojson';

	interface Props {
		/** Width of the SVG viewBox in pixels (default 1200). */
		width?: number;
		/** Height of the SVG viewBox in pixels (default 600). */
		height?: number;
		/**
		 * Arenet latitude — when null the map centers on the
		 * world (lat=20° for a balanced Mercator) and no
		 * marker is rendered. V.5 callers pass nullable to
		 * cover the degraded-mode case (no MMDB) gracefully.
		 */
		arenetLat?: number | null;
		/** Arenet longitude — see arenetLat. */
		arenetLon?: number | null;
		/** Operator-facing city label rendered next to the marker. */
		city?: string;
		/** Operator-facing country label rendered next to the marker. */
		country?: string;
		/**
		 * "auto" (V.1 ipify-then-GeoIP) or "manual" (V.4 PUT
		 * override). When "manual", a small badge appears
		 * next to the city label so the operator can tell at
		 * a glance whether they're looking at their own
		 * choice or the auto-detected default.
		 */
		mode?: 'auto' | 'manual';
		/**
		 * Optional path to the TopoJSON asset. Default points
		 * at the V.5-bundled /world-50m.topo.json (CC0
		 * world-atlas). Tests override to a fixture or mock.
		 */
		topojsonUrl?: string;
	}

	let {
		width = 1200,
		height = 600,
		arenetLat = null,
		arenetLon = null,
		city = '',
		country = '',
		mode = 'auto',
		topojsonUrl = '/world-50m.topo.json'
	}: Props = $props();

	let svg: SVGSVGElement | undefined = $state();
	let countries: FeatureCollection<Geometry> | null = $state(null);
	let loadError: string | null = $state(null);

	// Projection recomputes whenever its inputs change. A
	// scale of 140 gives a comfortable world view at 1200×600;
	// larger scales zoom in. The center falls back to
	// (lon=0, lat=20) when Arenet position is unknown — places
	// the equator slightly below center for a balanced view.
	const projection: GeoProjection = $derived(
		d3
			.geoMercator()
			.center([arenetLon ?? 0, arenetLat ?? 20])
			.scale(140)
			.translate([width / 2, height / 2])
	);
	const path: GeoPath = $derived(d3.geoPath(projection));

	// Projected marker pixel position. null when Arenet
	// coordinates are unknown OR when the projection clips
	// the point (off-screen). The marker <g> is skipped in
	// that case.
	const markerXY: [number, number] | null = $derived.by(() => {
		if (arenetLat === null || arenetLon === null) return null;
		const xy = projection([arenetLon, arenetLat]);
		return xy ?? null;
	});

	onMount(async () => {
		try {
			const resp = await fetch(topojsonUrl);
			if (!resp.ok) {
				throw new Error(`HTTP ${resp.status} loading ${topojsonUrl}`);
			}
			const topo = (await resp.json()) as Topology;
			// world-atlas ships `countries` as the polygon
			// feature set; `land` is a single merged outline
			// (V.5 uses countries for per-border rendering;
			// future steps can switch to `land` for a cleaner
			// silhouette).
			countries = feature(topo, topo.objects.countries) as FeatureCollection<Geometry>;
		} catch (err) {
			loadError = String(err);
			// eslint-disable-next-line no-console
			console.error('[WorldMap] failed to load TopoJSON', err);
		}
	});

	// Paint countries whenever the data or projection changes.
	// D3 handles the join + path d-attribute; Svelte just
	// hosts the <g class="countries"> root.
	$effect(() => {
		if (!svg || !countries) return;
		d3.select(svg)
			.select<SVGGElement>('g.countries')
			.selectAll<SVGPathElement, Feature<Geometry>>('path')
			.data(countries.features)
			.join('path')
			.attr('d', (d) => path(d))
			.attr('fill', 'var(--map-land, var(--bg-surface))')
			.attr('stroke', 'var(--map-border, var(--border-subtle))')
			.attr('stroke-width', 0.5);
	});
</script>

<div class="worldmap" data-testid="worldmap-container">
	{#if loadError}
		<div class="worldmap__error" role="alert">
			Carte indisponible: {loadError}
		</div>
	{/if}
	<svg
		bind:this={svg}
		viewBox="0 0 {width} {height}"
		preserveAspectRatio="xMidYMid meet"
		class="worldmap__svg"
		role="img"
		aria-label={city || country
			? `Carte du monde centrée sur ${city || country}`
			: 'Carte du monde'}
	>
		<!-- Ocean background — a single rect under the land. -->
		<rect
			x="0"
			y="0"
			width={width}
			height={height}
			fill="var(--map-ocean, var(--bg-base))"
		/>
		<g class="countries" data-testid="worldmap-countries"></g>
		{#if markerXY}
			<g class="marker" transform="translate({markerXY[0]}, {markerXY[1]})" data-testid="worldmap-marker">
				<!-- Pulsing halo — pure CSS animation, no JS. -->
				<circle r="10" class="marker__pulse" />
				<circle r="5" class="marker__core" />
				{#if city || country}
					<text x="12" y="-10" class="marker__label">
						{city}{#if city && country}, {/if}{country}
						{#if mode === 'manual'}
							<tspan dx="4" class="marker__badge">(manuel)</tspan>
						{/if}
					</text>
				{/if}
			</g>
		{/if}
	</svg>
</div>

<style>
	.worldmap {
		position: relative;
		width: 100%;
		background: var(--map-ocean, var(--bg-base));
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		overflow: hidden;
	}
	.worldmap__svg {
		display: block;
		width: 100%;
		height: auto;
	}
	.worldmap__error {
		position: absolute;
		top: 12px;
		left: 12px;
		right: 12px;
		padding: 10px 14px;
		background: var(--bg-surface);
		border: 1px solid var(--status-warn);
		border-radius: 6px;
		color: var(--text-primary);
		font-size: 13px;
		z-index: 1;
	}

	/* Marker — pulsing halo + solid core. */
	.marker__pulse {
		fill: var(--status-info);
		opacity: 0.25;
		transform-origin: center;
		transform-box: fill-box;
		animation: marker-pulse 2.2s ease-in-out infinite;
	}
	.marker__core {
		fill: var(--status-info);
		stroke: var(--bg-base);
		stroke-width: 1.5;
	}
	.marker__label {
		fill: var(--text-primary);
		font-size: 13px;
		font-weight: 600;
		paint-order: stroke fill;
		stroke: var(--bg-base);
		stroke-width: 3;
	}
	.marker__badge {
		fill: var(--text-muted);
		font-size: 11px;
		font-weight: 400;
	}

	@keyframes marker-pulse {
		0%,
		100% {
			transform: scale(0.85);
			opacity: 0.4;
		}
		50% {
			transform: scale(1.8);
			opacity: 0.1;
		}
	}

	/* Respect operator preference — reduced motion stops the
	   pulse animation but keeps the halo visible at its base
	   size so the marker is still distinguishable from a
	   plain dot. */
	@media (prefers-reduced-motion: reduce) {
		.marker__pulse {
			animation: none;
			opacity: 0.3;
		}
	}
</style>
