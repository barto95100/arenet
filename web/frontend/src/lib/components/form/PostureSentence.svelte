<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  The Arenet Authors
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PostureSentence (v2.41) — one live sentence stating what a setting
  does to traffic, framed by the same coloured rail as the section it
  sits in (allow green, block red, watch amber).

  It generalises GeoRuleSentence's treatment, which the operator
  already reads as "this is what the rule does", to the other
  decision-making settings of the route form. GeoRuleSentence keeps
  its own markup: its sentence is built from three lists with an
  explicit OR between them, which is more than a wrapper can carry.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		posture: 'allow' | 'block' | 'watch';
		testid?: string;
		children: Snippet;
	}

	let { posture, testid, children }: Props = $props();
</script>

<p class="sentence" data-posture={posture} data-testid={testid} aria-live="polite">
	{@render children()}
</p>

<style>
	.sentence {
		margin: 0;
		padding: 8px 10px;
		border-radius: 6px;
		font-size: 13px;
		line-height: 1.5;
		color: var(--text-secondary);
		border: 1px solid var(--border-subtle);
		background: var(--bg-surface);
	}
	.sentence[data-posture='block'] {
		border-left: 3px solid var(--status-down);
	}
	.sentence[data-posture='allow'] {
		border-left: 3px solid var(--status-up);
	}
	.sentence[data-posture='watch'] {
		border-left: 3px solid var(--status-warn);
	}
	.sentence :global(strong) {
		color: var(--text-primary);
		font-weight: 600;
	}
</style>
