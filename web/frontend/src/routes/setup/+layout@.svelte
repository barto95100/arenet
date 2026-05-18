<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Layout reset for /setup (spec §6.10). See /login/+layout@.svelte
  for rationale.
-->
<script lang="ts">
	import '../../app.css';
	import favicon from '$lib/assets/favicon.svg';
	import ToastContainer from '$lib/components/ToastContainer.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Initial setup — Arenet</title>
</svelte:head>

{@render children?.()}
<ToastContainer />
