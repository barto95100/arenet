<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import '../app.css';
	import { onMount } from 'svelte';
	import favicon from '$lib/assets/favicon.svg';
	import Sidebar from '$lib/components/Sidebar.svelte';
	import ToastContainer from '$lib/components/ToastContainer.svelte';

	let { children } = $props();

	let collapsed = $state(false);

	const STORAGE_KEY = 'arenet.sidebar.collapsed';

	onMount(() => {
		try {
			const stored = localStorage.getItem(STORAGE_KEY);
			if (stored === 'true') collapsed = true;
		} catch {
			/* localStorage unavailable (private mode, etc.) — ignore */
		}
	});

	$effect(() => {
		try {
			localStorage.setItem(STORAGE_KEY, String(collapsed));
		} catch {
			/* ignore */
		}
	});
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>Arenet</title>
</svelte:head>

<div class="flex min-h-screen">
	<Sidebar bind:collapsed />
	<main class="flex-1 p-6">
		{@render children?.()}
	</main>
</div>
<ToastContainer />
