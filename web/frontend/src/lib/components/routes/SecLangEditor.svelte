<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  SecLangEditor (v2.38) — CodeMirror 6 editor for a route's SecLang:
  highlighting, completion (directives, variables, @operators,
  actions, ctl / t values) and the server's per-line problems shown
  as diagnostics. Same lifecycle pattern as HtmlEditor (bind:value,
  no feedback loop, insertAtCursor for templates).
-->
<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { EditorState } from '@codemirror/state';
	import { EditorView, keymap, lineNumbers, drawSelection } from '@codemirror/view';
	import { defaultKeymap, history, historyKeymap, indentWithTab } from '@codemirror/commands';
	import { syntaxHighlighting } from '@codemirror/language';
	import { autocompletion, completionKeymap } from '@codemirror/autocomplete';
	import { lintGutter, setDiagnostics, type Diagnostic } from '@codemirror/lint';
	import type { SecLangError } from '$lib/api/types';
	import { secLang, secLangCompletions, secLangHighlight } from '$lib/utils/seclang-language';

	interface Props {
		value: string;
		label: string;
		/** Problems reported by the server (1-based lines). */
		errors?: SecLangError[];
		minHeight?: number;
	}

	let { value = $bindable(''), label, errors = [], minHeight = 220 }: Props = $props();

	let containerEl: HTMLDivElement | undefined = $state();
	let view: EditorView | undefined = $state();
	let updatingFromEditor = false;

	onMount(() => {
		if (!containerEl) return;
		view = new EditorView({
			parent: containerEl,
			state: EditorState.create({
				doc: value,
				extensions: [
					lineNumbers(),
					history(),
					drawSelection(),
					secLang,
					syntaxHighlighting(secLangHighlight),
					autocompletion({ override: [secLangCompletions] }),
					lintGutter(),
					keymap.of([...completionKeymap, ...defaultKeymap, ...historyKeymap, indentWithTab]),
					EditorView.lineWrapping,
					EditorView.theme({
						'&': { minHeight: `${minHeight}px` },
						'.cm-scroller': { fontFamily: 'var(--font-mono)', fontSize: '13px' },
						'.cm-content': { padding: '8px 0' },
						'.cm-gutters': {
							backgroundColor: 'var(--bg-base)',
							borderRight: '1px solid var(--border-subtle)',
							color: 'var(--text-secondary)'
						}
					}),
					EditorView.updateListener.of((u) => {
						if (!u.docChanged) return;
						updatingFromEditor = true;
						value = u.state.doc.toString();
						queueMicrotask(() => {
							updatingFromEditor = false;
						});
					})
				]
			})
		});
	});

	onDestroy(() => {
		view?.destroy();
		view = undefined;
	});

	$effect(() => {
		if (!view || updatingFromEditor) return;
		const current = view.state.doc.toString();
		if (current === value) return;
		view.dispatch({ changes: { from: 0, to: current.length, insert: value } });
	});

	// Server problems → diagnostics on their line.
	$effect(() => {
		if (!view) return;
		const doc = view.state.doc;
		const diagnostics: Diagnostic[] = errors
			.filter((e) => e.line >= 1 && e.line <= doc.lines)
			.map((e) => {
				const line = doc.line(e.line);
				return { from: line.from, to: line.to, severity: 'error', message: e.message };
			});
		view.dispatch(setDiagnostics(view.state, diagnostics));
	});

	/** Inserts text at the cursor (end of document when never focused). */
	export function insertAtCursor(text: string): void {
		if (!view) {
			value = value + text;
			return;
		}
		const { from, to } = view.state.selection.main;
		view.dispatch({ changes: { from, to, insert: text }, selection: { anchor: from + text.length } });
		view.focus();
	}
</script>

<div
	class="seclang-editor"
	bind:this={containerEl}
	role="textbox"
	aria-label={label}
	aria-multiline="true"
	data-testid="seclang-editor"
></div>

<style>
	.seclang-editor {
		border: 1px solid var(--border-subtle);
		border-radius: var(--radius);
		background: var(--bg-base);
		overflow: hidden;
	}
	.seclang-editor :global(.cm-editor) {
		background: var(--bg-base);
		color: var(--text-primary);
	}
	.seclang-editor :global(.cm-editor.cm-focused) {
		outline: 2px solid var(--accent-cyan);
		outline-offset: -1px;
	}
</style>
