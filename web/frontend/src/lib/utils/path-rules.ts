// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { PathRule } from '$lib/api/types';

// fix/path-rule-empty-500 — dogfooding bug: an operator edited a route,
// removed a path-rule's protection (left ipFilter.mode "off" with a
// residual CIDR, no basic auth), clicked Save, and got a 500. The
// backend correctly rejects a path-rule with zero active protection
// (`path_rule "...": must declare at least one protection (basic auth
// or IP filter)`) — that's a storage.Route.validate() invariant, not a
// bug. The bug was twofold: (1) the backend surfaced that rejection as
// a 500 instead of a 400 (fixed separately in updateRoute), and (2) the
// frontend had no business sending a rule with no active protection in
// the first place — "remove a rule's protection" reads to an operator
// as "remove the rule", not "send an invalid rule and hope the server
// tells me why".
//
// Product decision: a path-rule with no ACTIVE protection is silently
// dropped at submit time. "Active" means:
//   - basicAuth is configured with a non-empty username, OR
//   - ipFilter.mode is 'allow' or 'deny' (i.e. not 'off'/'').
// A kept rule whose ipFilter.mode is 'off' has its cidrs cleared on
// the wire — a residual CIDR list under mode "off" is meaningless and
// is exactly what triggered the operator's 500 (the log showed
// `mode:"off", cidrs:["8.8.8.8"]`).

/** Returns true when `rule.basicAuth` represents a configured (non-empty
 *  username) basic-auth override. */
function hasActiveBasicAuth(rule: PathRule): boolean {
	return !!rule.basicAuth && rule.basicAuth.username.trim().length > 0;
}

/** Returns true when `rule.ipFilter` is an active allow/deny gate
 *  (mode 'off' or '' is not active, regardless of any residual cidrs). */
function hasActiveIPFilter(rule: PathRule): boolean {
	const mode = rule.ipFilter?.mode;
	return mode === 'allow' || mode === 'deny';
}

/** Returns true when `rule.upstreams` is a non-empty pool (pure routing
 *  counts as active content — v2.23.0). */
function hasActiveUpstream(rule: PathRule): boolean {
	return !!rule.upstreams && rule.upstreams.length > 0;
}

/**
 * sanitizePathRules filters `rules` down to those that carry at least
 * one active protection (basic auth with a non-empty username, or an
 * ipFilter in allow/deny mode), or a non-empty upstream pool — a pure
 * routing rule with no auth/IP-filter is legitimate content and must
 * survive (v2.23.0). Also clears `cidrs` on any kept rule whose
 * ipFilter mode is 'off' (a residual CIDR list under mode "off" is
 * dead weight and confusing on the wire).
 *
 * Pure and side-effect-free — does not mutate the input array or its
 * elements — so it's callable directly from the submit payload
 * assembler and from unit tests.
 */
export function sanitizePathRules(rules: PathRule[]): PathRule[] {
	return rules
		.filter((rule) => hasActiveBasicAuth(rule) || hasActiveIPFilter(rule) || hasActiveUpstream(rule))
		.map((rule) => {
			if (rule.ipFilter && rule.ipFilter.mode === 'off') {
				return { ...rule, ipFilter: { ...rule.ipFilter, cidrs: [] } };
			}
			return rule;
		});
}
