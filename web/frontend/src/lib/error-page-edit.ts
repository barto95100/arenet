// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #384 — pure switch logic for the error-page template editor.
//
// The editor shows one status code's HTML body at a time (activeBuffer,
// two-way bound to CodeMirror). Switching tabs must (a) persist what the
// operator typed for the code being LEFT, and (b) load the code being
// OPENED — without ever overwriting the target code's stored content.
//
// The pre-#384 implementation did this with two competing $effect blocks
// (one loading on activeCode change, one writing editPages[activeCode] =
// activeBuffer). Their ordering raced: the write-back could fire with the
// NEW activeCode but the OLD activeBuffer, clobbering the target code's
// body with the previous code's text — silent data loss. This function
// makes the save-then-load a single, ordered, race-free step.

export interface CodeSwitchResult {
	/** editPages with the left code's buffer persisted. */
	editPages: Record<number, string>;
	/** The buffer to show for the newly-opened code. */
	buffer: string;
}

export function applyCodeSwitch(
	editPages: Record<number, string>,
	fromCode: number,
	fromBuffer: string,
	toCode: number
): CodeSwitchResult {
	// Persist the buffer of the code being left into a NEW map (never
	// mutate the caller's object). Writing fromCode cannot touch toCode
	// when they differ; when they are the same, the live buffer wins —
	// re-selecting the current tab is a no-op.
	const next = { ...editPages, [fromCode]: fromBuffer };
	return { editPages: next, buffer: next[toCode] ?? '' };
}
