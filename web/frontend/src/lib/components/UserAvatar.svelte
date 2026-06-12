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
	}

	let { seed, initials, size = 32 }: Props = $props();

	const colorKey = $derived(avatarColorKey(seed));
	const palette = $derived(AVATAR_COLOR_STYLES[colorKey]);
</script>

<span
	class="user-avatar"
	data-color={colorKey}
	style:width="{size}px"
	style:height="{size}px"
	style:background-color={palette.bg}
	style:color={palette.fg}
	style:font-size="{Math.round(size * 0.4)}px"
	aria-hidden="true"
>
	{initials}
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
