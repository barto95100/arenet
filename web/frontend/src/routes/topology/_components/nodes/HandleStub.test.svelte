<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Test-only stub for SvelteFlow's <Handle>. Used by
  AliasNode.test.ts to side-step the SvelteFlow per-node
  context requirement (Handle calls getNodeIdContext which
  is only populated when SvelteFlow itself mounts a custom
  node type — impossible to reproduce in jsdom without
  reproducing half the SvelteFlow runtime).

  The stub renders nothing; the test surface is the rendered
  card body around the Handle. We deliberately don't declare
  `$props()` because the Handle's prop surface is wide and
  we ignore all of it — Svelte 5 tolerates this in a stub
  component used purely as a test mock substitute.
-->
<!-- Render nothing. -->
