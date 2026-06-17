// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Sujet 1 Phase 3.e (2026-06-17) — per-route collapse/expand
// state for the col-0 alias stack.
//
// Page-local store: lives alongside the topology view (not in
// $lib/stores) because it's a UX concern that doesn't bleed
// across pages and shouldn't exist on routes that never mount
// /topology.
//
// Persistence: in-memory only (V1). State resets on page
// reload. A V2 candidate is localStorage keyed by routeID so
// the operator's preferred collapsed set survives a refresh —
// see `#R-TOPO-collapse-persistence` in the backlog when it
// gets logged.
//
// Default: every route is EXPANDED (not present in the set).
// Operator collapses individual routes on demand via the
// chevron toggle on FQDNNode. Trading verbosity for discovery
// — a freshly-arrived operator should see everything once;
// repeat visitors can fold the stacks they don't care about.

class CollapsedRoutes {
	// Set of routeIDs that are currently COLLAPSED. Absence ==
	// expanded (the default). Encoded as a tagged $state so
	// Svelte 5 reactivity picks up Set mutations — we replace
	// the whole Set on every toggle rather than mutating in
	// place because Set mutation doesn't trigger Svelte
	// reactivity by itself.
	collapsed = $state<Set<string>>(new Set());

	isCollapsed(routeID: string): boolean {
		return this.collapsed.has(routeID);
	}

	toggle(routeID: string): void {
		// Replace the Set so Svelte $state picks up the change.
		// new Set(existing) clones in O(N); cheap at homelab
		// route cardinality (<100 routes typical).
		const next = new Set(this.collapsed);
		if (next.has(routeID)) {
			next.delete(routeID);
		} else {
			next.add(routeID);
		}
		this.collapsed = next;
	}

	// Test helper — explicit setters so test cases can put the
	// store into a known shape without relying on toggle
	// semantics.
	expand(routeID: string): void {
		if (!this.collapsed.has(routeID)) return;
		const next = new Set(this.collapsed);
		next.delete(routeID);
		this.collapsed = next;
	}

	collapse(routeID: string): void {
		if (this.collapsed.has(routeID)) return;
		const next = new Set(this.collapsed);
		next.add(routeID);
		this.collapsed = next;
	}

	// Test helper — wipe state between cases.
	reset(): void {
		this.collapsed = new Set();
	}
}

export const collapsedRoutes = new CollapsedRoutes();
