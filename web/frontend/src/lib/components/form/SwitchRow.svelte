<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  SwitchRow (v2.41) — one on/off setting of the route form: a switch,
  its label, and the helper line that says what it actually does. The
  control is a real `<input type="checkbox">` (so the testids, the
  keyboard and the form semantics stay exactly what they were) painted
  as a switch through `appearance: none`.

  `danger` marks a setting that removes a protection. The red frame
  only paints once the setting is actually ON — a red box around an
  untouched switch reads as an error the operator has to fix, which
  is exactly what it is not. Off, the row is ordinary; on, the frame
  is the warning, so the helper text does not have to shout.

  Controlled on purpose (`checked` + `onchange`, no bind): the CRS row
  has to intercept the false → true direction behind a confirm dialog
  and leave the box unchecked if the operator cancels. A caller that
  just wants the value assigns it in `onchange`.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		checked: boolean;
		label: string;
		helper?: string;
		danger?: boolean;
		disabled?: boolean;
		/** testid of the checkbox itself. */
		testid?: string;
		/** id of the checkbox, when something else labels it. */
		inputId?: string;
		/** testid of the wrapping <label>. */
		labelTestid?: string;
		onchange?: (next: boolean, event: Event) => void;
		/** Extra content under the helper (warnings, links). */
		children?: Snippet;
	}

	let {
		checked,
		label,
		helper = '',
		danger = false,
		disabled = false,
		testid,
		inputId,
		labelTestid,
		onchange,
		children
	}: Props = $props();
</script>

<div class="row" class:danger={danger && checked}>
	<label class="head" data-testid={labelTestid}>
		<input
			type="checkbox"
			class="switch"
			id={inputId}
			{checked}
			{disabled}
			data-testid={testid}
			onchange={(e) => onchange?.(e.currentTarget.checked, e)}
		/>
		<span class="lbl">{label}</span>
	</label>
	{#if helper}
		<p class="helper">{helper}</p>
	{/if}
	{#if children}
		<div class="extra">{@render children()}</div>
	{/if}
</div>

<style>
	.row {
		display: flex;
		flex-direction: column;
		gap: 4px;
		padding: 10px 12px;
		border: 1px solid var(--border-subtle);
		border-radius: 8px;
		background: var(--bg-surface);
	}
	.row.danger {
		border-color: var(--badge-danger-border);
		background: var(--badge-danger-bg);
	}
	.row.danger .lbl {
		color: var(--status-down);
	}
	.head {
		display: flex;
		align-items: center;
		gap: 10px;
		cursor: pointer;
	}
	.lbl {
		font-size: var(--text-sm);
		font-weight: 500;
		color: var(--text-primary);
	}
	.helper,
	.extra {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-muted);
		max-width: 65ch;
		padding-left: 44px;
	}
	@media (max-width: 640px) {
		.helper,
		.extra {
			padding-left: 0;
		}
	}

	/* The switch: a real checkbox, repainted. */
	.switch {
		appearance: none;
		-webkit-appearance: none;
		flex: none;
		position: relative;
		width: 34px;
		height: 20px;
		margin: 0;
		border-radius: var(--radius-full);
		background: var(--bg-elevated);
		box-shadow: inset 0 0 0 1px var(--border-default);
		cursor: pointer;
		transition:
			background-color var(--motion-fast),
			box-shadow var(--motion-fast);
	}
	.switch::after {
		content: '';
		position: absolute;
		top: 2px;
		left: 2px;
		width: 16px;
		height: 16px;
		border-radius: 50%;
		background: var(--text-muted);
		transition:
			transform var(--motion-fast),
			background-color var(--motion-fast);
	}
	.switch:checked {
		background: var(--accent-cyan);
		box-shadow: inset 0 0 0 1px var(--accent-cyan);
	}
	.switch:checked::after {
		transform: translateX(14px);
		background: var(--bg-base, #fff);
	}
	.row.danger .switch:checked {
		background: var(--status-down);
		box-shadow: inset 0 0 0 1px var(--status-down);
	}
	.switch:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.switch:focus-visible {
		outline: 2px solid var(--accent-cyan);
		outline-offset: 2px;
	}
	@media (prefers-reduced-motion: reduce) {
		.switch,
		.switch::after {
			transition: none;
		}
	}
</style>
