<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TEST FIXTURE — only used by TopologyEdge.test.ts.

  TopologyEdge renders an SVG <g> element, which requires an <svg>
  parent in the SVG namespace. Rendering it directly via
  @testing-library/svelte attaches the <g> to a plain <div>, where
  HTML-namespace rules make the children silently malformed (jsdom
  doesn't enforce SVG, but Svelte's reactive bindings interact
  oddly with the wrong namespace).

  This fixture provides the <svg> wrapper. The .test.svelte naming
  keeps it co-located with the test file but makes its purpose
  explicit in code search.
-->
<script lang="ts">
	import TopologyEdge from './TopologyEdge.svelte';

	interface Props {
		reqPerSec: number;
		errRate5xx?: number;
		reducedMotion?: boolean;
	}

	let { reqPerSec, errRate5xx = 0, reducedMotion = false }: Props = $props();
</script>

<svg width="800" height="200" viewBox="0 0 800 200" data-testid="edge-svg">
	<TopologyEdge
		x1={100}
		y1={100}
		x2={700}
		y2={100}
		{reqPerSec}
		{errRate5xx}
		{reducedMotion}
	/>
</svg>
