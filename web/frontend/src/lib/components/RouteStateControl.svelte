<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  RouteStateControl (Task 8). A 3-state segmented control for a
  route's lifecycle: Active / Maintenance / Disabled. Each segment
  has a fixed semantic color + icon (play triangle / wrench / power)
  and the active segment is filled with its semantic color.

  This is a NEW standalone component — it deliberately does NOT
  extend or import Toggle.svelte (which is hardcoded to 2 generic
  slots and used by Theme/Language; touching it risks regressing
  those). It instead copies Toggle's proven patterns:

    - controlled `value` + `onchange` contract (NOT bindable — the
      caller re-renders after onchange, same reasoning as Toggle's
      theme-store integration: a single writer for the value)
    - role="radiogroup" on the container, role="radio" + aria-checked
      per segment
    - keyboard navigation via ArrowLeft/ArrowRight/Home/End, roving
      focus follows the checked segment (WAI-ARIA radiogroup pattern)

  Public API (add-only; do not rename/remove props):

    value    — current state: 'active' | 'maintenance' | 'disabled'
    onchange — fired with the new state on user interaction
    disabled — disables interaction entirely (e.g. while isApplying)
    ariaLabel — labels the group for screen readers
-->
<script lang="ts">
	type RouteState = 'active' | 'maintenance' | 'disabled';

	interface Props {
		value: RouteState;
		onchange?: (v: RouteState) => void;
		disabled?: boolean;
		ariaLabel?: string;
	}

	let { value, onchange, disabled = false, ariaLabel }: Props = $props();

	const STATES: RouteState[] = ['active', 'maintenance', 'disabled'];

	const LABELS: Record<RouteState, string> = {
		active: 'Active',
		maintenance: 'Maintenance',
		disabled: 'Disabled'
	};

	function pick(v: RouteState): void {
		if (disabled || v === value) return;
		onchange?.(v);
	}

	// WAI-ARIA radiogroup pattern: arrow keys move the checked state
	// (not just focus) — mirrors Toggle's click-to-select semantics
	// extended to 3 segments with wraparound.
	function onKeydown(e: KeyboardEvent): void {
		if (disabled) return;
		const idx = STATES.indexOf(value);
		let next: number | null = null;
		switch (e.key) {
			case 'ArrowLeft':
			case 'ArrowUp':
				next = (idx - 1 + STATES.length) % STATES.length;
				break;
			case 'ArrowRight':
			case 'ArrowDown':
				next = (idx + 1) % STATES.length;
				break;
			case 'Home':
				next = 0;
				break;
			case 'End':
				next = STATES.length - 1;
				break;
			default:
				return;
		}
		e.preventDefault();
		pick(STATES[next]);
	}
</script>

<!-- svelte-ignore a11y_interactive_supports_focus -->
<div
	class="route-state-control"
	role="radiogroup"
	aria-label={ariaLabel}
	aria-disabled={disabled || undefined}
	onkeydown={onKeydown}
>
	{#each STATES as state (state)}
		<button
			type="button"
			role="radio"
			class="segment"
			data-state={state}
			class:active={state === value}
			aria-checked={state === value}
			tabindex={state === value ? 0 : -1}
			{disabled}
			onclick={() => pick(state)}
		>
			<span class="icon" aria-hidden="true">
				{#if state === 'active'}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
						<path d="M4 2.5v11l10-5.5-10-5.5z" />
					</svg>
				{:else if state === 'maintenance'}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor">
						<path
							d="M13.7 2.3a3.5 3.5 0 0 1-4.6 4.6l-5.4 5.4a1.2 1.2 0 0 1-1.7-1.7l5.4-5.4a3.5 3.5 0 0 1 4.6-4.6l-2 2 .9 1.8 1.8.9 2-2z"
						/>
					</svg>
				{:else}
					<svg viewBox="0 0 16 16" width="14" height="14" fill="none">
						<path
							d="M8 1.5v6"
							stroke="currentColor"
							stroke-width="1.6"
							stroke-linecap="round"
						/>
						<path
							d="M4.5 3.5a5 5 0 1 0 7 0"
							stroke="currentColor"
							stroke-width="1.6"
							stroke-linecap="round"
							fill="none"
						/>
					</svg>
				{/if}
			</span>
			<span class="lbl">{LABELS[state]}</span>
		</button>
	{/each}
</div>

<style>
	.route-state-control {
		display: inline-grid;
		grid-template-columns: repeat(3, 1fr);
		gap: var(--space-1);
		padding: 2px;
		background: var(--bg-surface);
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius-full);
		user-select: none;
	}
	.segment {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-3);
		min-width: 64px;
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-secondary);
		background: transparent;
		border: 0;
		border-radius: var(--radius-full);
		cursor: pointer;
		transition:
			color var(--motion-fast),
			background-color var(--motion-fast);
	}
	.segment[data-state='active'].active {
		background: var(--status-up);
		color: var(--text-on-color, #fff);
	}
	.segment[data-state='maintenance'].active {
		background: var(--status-warn);
		color: var(--text-on-color, #fff);
	}
	.segment[data-state='disabled'].active {
		background: var(--status-down);
		color: var(--text-on-color, #fff);
	}
	.segment:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.segment:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	.icon {
		display: inline-flex;
		line-height: 0;
	}
	.lbl {
		line-height: 1;
	}
</style>
