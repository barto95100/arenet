<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Phase 2 follow-up — colored rounded-square user avatar with
  initials, used in the /utilisateurs table rows. The bg colour
  is derived deterministically from the seed (typically the
  username) via avatarColorKey(); the same seed always lands in
  the same bucket so operators can rely on the visual cue for
  recognition across sessions.

  The previous inline `.avatar` class on the users page
  rendered a flat cyan circle for every user — visually
  monotonous and not what the mockup shows.
-->
<script lang="ts">
	import { avatarColorKey, AVATAR_COLOR_STYLES } from '$lib/utils/avatar-color';

	interface Props {
		seed: string;
		initials: string;
		size?: number;
		/**
		 * Phase 4 — when true, render a machine glyph
		 * (terminal/bot) instead of initials. Background stays
		 * deterministic per seed so service accounts get the
		 * same per-name colour family as humans — visual
		 * grouping affordance.
		 */
		service?: boolean;
	}

	let { seed, initials, size = 32, service = false }: Props = $props();

	const colorKey = $derived(avatarColorKey(seed));
	const palette = $derived(AVATAR_COLOR_STYLES[colorKey]);
	const glyphSize = $derived(Math.round(size * 0.52));
</script>

<span
	class="user-avatar"
	data-color={colorKey}
	data-service={service ? 'true' : 'false'}
	style:width="{size}px"
	style:height="{size}px"
	style:background-color={palette.bg}
	style:color={palette.fg}
	style:font-size="{Math.round(size * 0.4)}px"
	aria-hidden="true"
>
	{#if service}
		<!-- Lucide-style terminal glyph — recognised "machine
		     account" affordance, matches the "$_" prompt look. -->
		<svg
			width={glyphSize}
			height={glyphSize}
			viewBox="0 0 24 24"
			fill="none"
			stroke="currentColor"
			stroke-width="2"
			stroke-linecap="round"
			stroke-linejoin="round"
		>
			<polyline points="4 17 10 11 4 5" />
			<line x1="12" y1="19" x2="20" y2="19" />
		</svg>
	{:else}
		{initials}
	{/if}
</span>

<style>
	.user-avatar {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border-radius: 6px;
		font-weight: 600;
		letter-spacing: 0.02em;
		flex: none;
		font-family: var(--font-mono);
		user-select: none;
	}
</style>
