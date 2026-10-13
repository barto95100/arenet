// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

// Who still has unsaved input (spec 2026-10-13, D1 / D2).
//
// A settings tab's content sits behind {#if activeTab === '…'}, so
// leaving the tab unmounts the section and destroys its $state. That
// is the discard the operator needs to be asked about first.
//
// Each section registers a predicate while it is mounted and drops it
// on destroy. Because the inactive tabs are unmounted, the registry
// only ever holds the sections of the tab currently on screen — the
// guard needs no per-tab bookkeeping, and a section that forgets to
// unregister cannot leak a stale "dirty" into another tab, because
// unregistration is the component's own teardown.
//
// The predicate is owned by the section on purpose (D1). A generic diff
// over the panel's DOM cannot tell input that was typed from values a
// save reloaded, and a dialog that fires after a successful save is
// worse than no dialog at all.

type DirtyPredicate = () => boolean;

const predicates = new Map<string, DirtyPredicate>();

/**
 * Registers `isDirty` under `id` for as long as the caller is mounted.
 * Returns the unregister function, which is what a component returns
 * from onMount or calls in its $effect teardown.
 *
 * Registering the same id twice replaces the predicate: a remount
 * after a tab switch must not leave the previous instance's closure
 * behind.
 */
export function registerUnsaved(id: string, isDirty: DirtyPredicate): () => void {
	predicates.set(id, isDirty);
	return () => {
		// Only drop the entry if it is still ours. A remount can run
		// before the previous instance's teardown, and clearing then
		// would unregister the live section.
		if (predicates.get(id) === isDirty) {
			predicates.delete(id);
		}
	};
}

/**
 * Runs one predicate, treating a throw as "not dirty".
 *
 * This fails open on purpose. The guard sits in front of the tab
 * strip, so a predicate that throws — reading a field the API left
 * undefined, say — would otherwise cancel every switch out of that
 * tab with no dialog and no message, and the operator would have no
 * way out but a reload. A missed warning is the lesser failure.
 */
function isDirtySafe(id: string, isDirty: DirtyPredicate): boolean {
	try {
		return isDirty();
	} catch (err) {
		console.error(`unsaved: predicate for ${id} threw`, err);
		return false;
	}
}

/** True when any mounted section reports unsaved input. */
export function hasUnsaved(): boolean {
	for (const [id, isDirty] of predicates) {
		if (isDirtySafe(id, isDirty)) return true;
	}
	return false;
}

/** The ids currently reporting unsaved input. For tests and debugging. */
export function unsavedIds(): string[] {
	const ids: string[] = [];
	for (const [id, isDirty] of predicates) {
		if (isDirtySafe(id, isDirty)) ids.push(id);
	}
	return ids;
}

/** Drops every registration. Tests only — components unregister on destroy. */
export function resetUnsavedRegistry(): void {
	predicates.clear();
}
