<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.
-->
<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		open?: boolean;
		title: string;
		onClose: () => void;
		children?: Snippet;
		footer?: Snippet;
	}

	let { open = false, title, onClose, children, footer }: Props = $props();

	let dialog: HTMLDivElement | undefined = $state(undefined);
	const titleId = `modal-title-${Math.random().toString(36).slice(2, 9)}`;

	/**
	 * Returns the focusable descendants of the dialog, in tab order.
	 * Used by the trap logic to wrap Tab/Shift+Tab inside the modal.
	 */
	function focusable(): HTMLElement[] {
		if (!dialog) return [];
		const selector =
			'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
		return Array.from(dialog.querySelectorAll<HTMLElement>(selector));
	}

	function onKeydown(event: KeyboardEvent) {
		if (event.key === 'Escape') {
			event.preventDefault();
			onClose();
			return;
		}
		if (event.key !== 'Tab') return;
		const items = focusable();
		if (items.length === 0) {
			event.preventDefault();
			return;
		}
		const first = items[0];
		const last = items[items.length - 1];
		const active = document.activeElement as HTMLElement | null;
		if (event.shiftKey && active === first) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && active === last) {
			event.preventDefault();
			first.focus();
		}
	}

	$effect(() => {
		if (!open) return;
		document.addEventListener('keydown', onKeydown);
		const previouslyFocused = document.activeElement as HTMLElement | null;
		// Move focus into the dialog after Svelte mounts the markup.
		queueMicrotask(() => {
			const items = focusable();
			(items[0] ?? dialog)?.focus();
		});
		return () => {
			document.removeEventListener('keydown', onKeydown);
			previouslyFocused?.focus();
		};
	});
</script>

{#if open}
	<div
		role="presentation"
		class="fixed inset-0 z-50 flex items-center justify-center p-4 modal-fade"
		style:background-color="rgba(10, 14, 20, 0.8)"
		style:backdrop-filter="blur(4px)"
		onclick={(e) => {
			if (e.target === e.currentTarget) onClose();
		}}
		onkeydown={(e) => {
			/* keydown is handled at document level via $effect; this stub keeps
			   svelte/a11y happy on the click handler. */
		}}
	>
		<div
			bind:this={dialog}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
			class="bg-elevated border border-border-default rounded-lg shadow-2xl w-full max-w-md modal-slide-up focus:outline-none"
		>
			<header class="px-5 py-4 border-b border-border-subtle">
				<h2 id={titleId} class="text-lg font-semibold">{title}</h2>
			</header>
			<div class="px-5 py-4">{@render children?.()}</div>
			{#if footer}
				<footer class="px-5 py-3 border-t border-border-subtle flex justify-end gap-2">
					{@render footer()}
				</footer>
			{/if}
		</div>
	</div>
{/if}

<style>
	.modal-fade {
		animation: fade-in 200ms ease-out;
	}
	.modal-slide-up {
		animation: slide-up 200ms ease-out;
	}
	@keyframes fade-in {
		from {
			opacity: 0;
		}
		to {
			opacity: 1;
		}
	}
	@keyframes slide-up {
		from {
			opacity: 0;
			transform: translateY(20px);
		}
		to {
			opacity: 1;
			transform: translateY(0);
		}
	}
</style>
