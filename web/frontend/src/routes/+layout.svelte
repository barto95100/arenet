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
	import { loading } from '$lib/stores/loading';

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
	<main class="flex-1 p-6 relative" aria-busy={$loading} aria-live="polite">
		{#if $loading}
			<div class="absolute left-0 right-0 top-0 h-0.5 overflow-hidden">
				<div class="h-full w-1/3 bg-cyan loading-shimmer"></div>
			</div>
		{/if}
		{@render children?.()}
	</main>
</div>
<ToastContainer />

<style>
	.loading-shimmer {
		animation: shimmer 1.5s ease-in-out infinite;
	}
	@keyframes shimmer {
		0% {
			transform: translateX(-100%);
		}
		100% {
			transform: translateX(400%);
		}
	}
</style>
