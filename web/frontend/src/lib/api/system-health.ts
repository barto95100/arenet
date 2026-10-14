// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Client for GET /system/health (v2.73).
//
// This endpoint cannot go through lib/api/client.ts's request(),
// which hardcodes the /api/v1 prefix (client.ts:175). /system/health
// is mounted at the root, deliberately outside the auth subtree, so
// an external monitor without cookies can scrape it
// (internal/api/routes.go:82-90).
//
// That placement is also why polling it from the topbar does not
// reintroduce the 403 flood documented in client.ts: the 233 forbidden
// responses that got an operator's own address banned by
// crowdsecurity/http-admin-interface-probing were on /api/v1 paths,
// which refuse background traffic while the session is locked. This
// path needs no session and answers 200 either way. The topbar still
// skips the poll while locked and while the tab is hidden, because a
// request nobody can see is waste.
//
// Status mapping, read in internal/api/system_health.go:66-68 rather
// than assumed: healthy and degraded both answer 200, unhealthy
// answers 503 WITH THE SAME JSON BODY. So a non-ok response is data
// here, not an error, and the body is parsed either way.

/** Overall and per-component verdicts — internal/systemhealth.Status. */
export type SystemHealthStatus = 'healthy' | 'degraded' | 'unhealthy';

/** One probe's verdict. Mirrors systemhealth.NamedReport. */
export interface SystemHealthComponent {
	name: string;
	status: SystemHealthStatus;
	message: string;
	latency_ms?: number;
}

/** Mirrors systemhealth.Report. */
export interface SystemHealthReport {
	status: SystemHealthStatus;
	timestamp: string;
	version?: string;
	components: SystemHealthComponent[];
}

/**
 * What the caller gets. `null` means the question could not be
 * answered — the request failed, timed out, or came back in a shape
 * this build does not recognise.
 *
 * Deliberately distinct from "unhealthy": the topbar badge must be
 * able to say "I do not know" rather than pick a reassuring or an
 * alarming answer. Reading a static "healthy" in this case is the
 * defect this module exists to fix.
 */
export type SystemHealthResult = SystemHealthReport | null;

/** Request budget. Short: this is a badge, not a diagnostic. */
const HEALTH_TIMEOUT_MS = 5000;

const VALID_STATUSES: readonly string[] = ['healthy', 'degraded', 'unhealthy'];

/**
 * Narrows an unknown parsed body to a report.
 *
 * Only `status` is required, because that is all the badge needs and
 * a future field addition must not turn the badge grey. `components`
 * is defaulted rather than demanded for the same reason.
 */
function asReport(raw: unknown): SystemHealthReport | null {
	if (typeof raw !== 'object' || raw === null) return null;
	const o = raw as Record<string, unknown>;
	if (typeof o.status !== 'string' || !VALID_STATUSES.includes(o.status)) return null;
	const components = Array.isArray(o.components)
		? (o.components.filter(
				(c) => typeof c === 'object' && c !== null
			) as SystemHealthComponent[])
		: [];
	return {
		status: o.status as SystemHealthStatus,
		timestamp: typeof o.timestamp === 'string' ? o.timestamp : '',
		version: typeof o.version === 'string' ? o.version : undefined,
		components
	};
}

/**
 * Reads the gateway's health once.
 *
 * Never throws and never toasts: the caller is a badge that polls, and
 * a toast per failed tick would be worse than the silence it replaces.
 * A null return is the honest answer, and the badge renders it.
 */
export async function fetchSystemHealth(): Promise<SystemHealthResult> {
	const controller = new AbortController();
	const timeoutId = setTimeout(() => controller.abort(), HEALTH_TIMEOUT_MS);
	try {
		const res = await fetch('/system/health', {
			credentials: 'include',
			signal: controller.signal
		});
		// 503 carries a full report — see the note at the top.
		if (res.status !== 200 && res.status !== 503) return null;
		return asReport(await res.json());
	} catch {
		return null;
	} finally {
		clearTimeout(timeoutId);
	}
}

/**
 * Names the components that are not healthy, for the badge's tooltip.
 *
 * Returns an empty array for a healthy report, so the caller can leave
 * the title attribute off entirely rather than set an empty one.
 */
export function unhealthyComponentNames(report: SystemHealthReport): string[] {
	return report.components.filter((c) => c.status !== 'healthy').map((c) => c.name);
}
