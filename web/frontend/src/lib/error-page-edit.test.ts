// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// #384 guards: switching error-code tabs must preserve each code's body.
// The bug was silent data loss — switching from an edited 404 to 403
// clobbered 403's stored body with the 404 text, and the editor then
// showed the 404 content under the 403 tab.

import { describe, it, expect } from 'vitest';
import { applyCodeSwitch } from './error-page-edit';

describe('applyCodeSwitch (#384)', () => {
	it('G_switch_loads_target_code_body: opening another code shows THAT code body, not the one left', () => {
		const editPages = { 404: 'orig-404', 403: 'orig-403' };
		// Operator edited 404, then clicks the 403 tab.
		const res = applyCodeSwitch(editPages, 404, 'edited-404', 403);
		expect(res.buffer).toBe('orig-403');
		// The editor must NOT keep showing the code being left.
		expect(res.buffer).not.toBe('edited-404');
	});

	it('G_switch_persists_left_code_edits: the code being left keeps the operator edits', () => {
		const editPages = { 404: 'orig-404', 403: 'orig-403' };
		const res = applyCodeSwitch(editPages, 404, 'edited-404', 403);
		expect(res.editPages[404]).toBe('edited-404');
	});

	it('G_switch_never_clobbers_target: the target code body is untouched by the switch', () => {
		const editPages = { 404: 'orig-404', 403: 'orig-403' };
		const res = applyCodeSwitch(editPages, 404, 'edited-404', 403);
		// The whole point: 403 must still read orig-403 after the switch.
		expect(res.editPages[403]).toBe('orig-403');
	});

	it('G_switch_loads_empty_for_absent_code: opening a code with no stored body yields an empty buffer', () => {
		const editPages = { 404: 'orig-404' };
		const res = applyCodeSwitch(editPages, 404, 'edited-404', 500);
		expect(res.buffer).toBe('');
		expect(res.editPages[404]).toBe('edited-404');
	});

	it('G_switch_same_code_is_idempotent: re-selecting the current code preserves its live buffer', () => {
		const editPages = { 404: 'orig-404' };
		const res = applyCodeSwitch(editPages, 404, 'edited-404', 404);
		expect(res.buffer).toBe('edited-404');
		expect(res.editPages[404]).toBe('edited-404');
	});

	it('does not mutate the input editPages object (no aliasing surprises)', () => {
		const editPages = { 404: 'orig-404', 403: 'orig-403' };
		const snapshot = { ...editPages };
		applyCodeSwitch(editPages, 404, 'edited-404', 403);
		expect(editPages).toEqual(snapshot);
	});
});
