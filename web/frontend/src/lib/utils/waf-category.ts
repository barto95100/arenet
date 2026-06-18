// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase Y (2026-06-18) — single source of truth for the
// operator-facing presentation of every OwaspCategory : the
// human label, the longer description, the colour token used
// across charts / tiles / event tables, and the family
// grouping used by the /waf page tiles.
//
// Why centralise : pre-Y every consumer (CategoryDistribution,
// WafEventList, MixedEventList, /waf, /security/[routeId])
// carried its own switch over the 6-category enum. With the
// Phase Y expansion to 25 categories, that pattern would
// duplicate the same 25-arm switch in 5+ files. Centralising
// here lets the consumers read CATEGORY_META[c].label etc.
// without each one needing to know about the full taxonomy.
//
// Source of truth for the ranges + purpose : the empirical
// audit pinned in internal/waf/category.go's switch and
// internal/waf/category_test.go's per-file mapping table.
// Updating the Go side without updating CATEGORY_META here
// will leave the dashboard rendering raw enum strings — the
// `unknown` fallback at the bottom catches that silently
// but the operator sees less friendly labels.

import type { OwaspCategory } from '$lib/api/types';

/** The family bucket the /waf page renders together. */
export type CategoryFamily =
	| 'request-attack'
	| 'protocol-behaviour'
	| 'aggregator'
	| 'data-leak'
	| 'infrastructure';

export interface CategoryMeta {
	label: string;
	description: string;
	/** CSS var name (without `var()`) for the chart / pill colour. */
	color: string;
	family: CategoryFamily;
}

/** Fallback for unknown categories (post-Y rows referencing a
 *  category the frontend hasn't been taught yet — keeps the
 *  UI rendering instead of crashing). */
const UNKNOWN_META: CategoryMeta = {
	label: 'Inconnu',
	description: 'Catégorie non reconnue par le frontend.',
	color: 'var(--text-muted)',
	family: 'infrastructure'
};

export const CATEGORY_META: Record<OwaspCategory, CategoryMeta> = {
	// --- Request attacks (red / orange family) ---
	SQLi: {
		label: 'SQL Injection',
		description: 'CRS 942xxx — UNION SELECT, blind SQLi, malicious comments.',
		color: 'var(--status-down)',
		family: 'request-attack'
	},
	XSS: {
		label: 'Cross-site scripting',
		description: 'CRS 941xxx — payloads JS, vecteurs HTML, évasion par encodage.',
		color: 'var(--status-warn)',
		family: 'request-attack'
	},
	RCE: {
		label: 'Remote Code Execution (shell)',
		description: 'CRS 932xxx — injection de commandes shell, eval.',
		color: 'var(--status-down)',
		family: 'request-attack'
	},
	PHP: {
		label: 'PHP injection',
		description: 'CRS 933xxx — code PHP, fonctions dangereuses, variables superglobales.',
		color: 'var(--status-down)',
		family: 'request-attack'
	},
	JAVA: {
		label: 'Java exploit',
		description:
			"CRS 944xxx — désérialisation Java, JNDI (Log4Shell), classes dangereuses.",
		color: 'var(--status-down)',
		family: 'request-attack'
	},
	GENERIC: {
		label: 'Generic app attack (Node / SSRF / template)',
		description: 'CRS 934xxx — SSRF, injection de template, Node.js patterns.',
		color: 'var(--status-warn)',
		family: 'request-attack'
	},
	LFI: {
		label: 'Local File Inclusion',
		description: 'CRS 930xxx — path traversal, /etc/passwd, exfil de config.',
		color: 'var(--status-warn)',
		family: 'request-attack'
	},
	RFI: {
		label: 'Remote File Inclusion',
		description: 'CRS 931xxx — inclusion de fichier distant via http://, ftp://, etc.',
		color: 'var(--status-warn)',
		family: 'request-attack'
	},

	// --- Protocol / behaviour ---
	METHOD: {
		label: 'Method enforcement',
		description: 'CRS 911xxx — verbes HTTP non autorisés (TRACE, CONNECT, etc.).',
		color: 'var(--status-info)',
		family: 'protocol-behaviour'
	},
	PROTOCOL: {
		label: 'Protocol enforcement',
		description:
			"CRS 920xxx — requêtes mal formées, headers absents, charset invalide.",
		color: 'var(--status-info)',
		family: 'protocol-behaviour'
	},
	PROTOCOL_ATK: {
		label: 'Protocol attack',
		description: 'CRS 921xxx — HTTP smuggling, request splitting.',
		color: 'var(--status-warn)',
		family: 'protocol-behaviour'
	},
	MULTIPART: {
		label: 'Multipart attack',
		description: 'CRS 922xxx — exploitation du parseur multipart.',
		color: 'var(--status-warn)',
		family: 'protocol-behaviour'
	},
	SCANNER: {
		label: 'Scanner detection',
		description:
			"CRS 913xxx — détection d'outils de scan (sqlmap, nikto, nmap, etc.) via User-Agent.",
		color: 'var(--status-info)',
		family: 'protocol-behaviour'
	},
	SESSION: {
		label: 'Session fixation',
		description: 'CRS 943xxx — patterns d\'attaque sur les sessions et cookies.',
		color: 'var(--status-warn)',
		family: 'protocol-behaviour'
	},

	// --- Aggregators ---
	ANOMALY_REQ: {
		label: 'Anomaly score (request)',
		description:
			"CRS 949xxx — l'agrégateur de score d'anomalie inbound, déclenche le block quand le seuil global est atteint.",
		color: 'var(--text-muted)',
		family: 'aggregator'
	},
	ANOMALY_RESP: {
		label: 'Anomaly score (response)',
		description: 'CRS 959xxx — agrégateur de score sur la réponse upstream.',
		color: 'var(--text-muted)',
		family: 'aggregator'
	},
	CORRELATION: {
		label: 'Correlation',
		description: 'CRS 980xxx — corrélation inbound / outbound, méta-règles.',
		color: 'var(--text-muted)',
		family: 'aggregator'
	},

	// --- Response-side / data leak ---
	DATA_LEAK: {
		label: 'Data leak (generic)',
		description:
			"CRS 950xxx — fuite d'information générique dans la réponse (debug, headers serveur, etc.).",
		color: 'var(--status-warn)',
		family: 'data-leak'
	},
	DATA_LEAK_SQL: {
		label: 'Data leak (SQL errors)',
		description: 'CRS 951xxx — messages d\'erreur SQL fuités (MySQL, PostgreSQL, MSSQL).',
		color: 'var(--status-warn)',
		family: 'data-leak'
	},
	DATA_LEAK_JAVA: {
		label: 'Data leak (Java stack)',
		description: 'CRS 952xxx — stack traces Java fuitées dans la réponse.',
		color: 'var(--status-warn)',
		family: 'data-leak'
	},
	DATA_LEAK_PHP: {
		label: 'Data leak (PHP errors)',
		description: 'CRS 953xxx — warnings / fatal errors PHP fuités.',
		color: 'var(--status-warn)',
		family: 'data-leak'
	},
	DATA_LEAK_IIS: {
		label: 'Data leak (IIS info)',
		description: 'CRS 954xxx — fuite d\'info IIS (.NET, version, paths internes).',
		color: 'var(--status-warn)',
		family: 'data-leak'
	},
	WEBSHELL: {
		label: 'Web shell signature',
		description:
			'CRS 955xxx — signatures de webshells dans la réponse (c99, r57, b374k, etc.).',
		color: 'var(--status-down)',
		family: 'data-leak'
	},

	// --- Infrastructure / catch-all ---
	INIT: {
		label: 'CRS init',
		description: 'CRS 901xxx — initialisation des variables tx.*, paranoia level.',
		color: 'var(--text-muted)',
		family: 'infrastructure'
	},
	COMMON_EXCEPT: {
		label: 'False-positive bypass',
		description: 'CRS 905xxx — exceptions communes pour éviter les false-positives.',
		color: 'var(--text-muted)',
		family: 'infrastructure'
	},
	OTHER: {
		label: 'Autres règles Coraza',
		description:
			"Règles hors taxonomie CRS standard (extensions opérateur, plugins custom).",
		color: 'var(--text-muted)',
		family: 'infrastructure'
	}
};

/** Safe accessor — returns the fallback meta for unknown
 *  categories so the UI never crashes on a category string
 *  the frontend hasn't been taught yet. */
export function categoryMeta(c: OwaspCategory | string): CategoryMeta {
	return (CATEGORY_META as Record<string, CategoryMeta>)[c] ?? UNKNOWN_META;
}

/** Operator-facing family labels for the /waf page section
 *  headers. Order matches the visual flow : focal attacks
 *  first, then behaviour, then aggregators, response-side,
 *  infrastructure. */
export const FAMILY_LABEL: Record<CategoryFamily, string> = {
	'request-attack': 'Attaques sur la requête',
	'protocol-behaviour': 'Protocole / comportement',
	aggregator: 'Agrégateurs de score',
	'data-leak': 'Fuite de données (réponse)',
	infrastructure: 'Infrastructure CRS'
};

/** Categories grouped by family in dashboard-display order.
 *  Computed from CATEGORY_META + ALL_OWASP_CATEGORIES so the
 *  /waf page can iterate families → categories without
 *  reasoning about the flat enum order. */
export function categoriesByFamily(
	all: readonly OwaspCategory[]
): Array<{ family: CategoryFamily; categories: OwaspCategory[] }> {
	const groups = new Map<CategoryFamily, OwaspCategory[]>();
	for (const c of all) {
		const fam = categoryMeta(c).family;
		const arr = groups.get(fam) ?? [];
		arr.push(c);
		groups.set(fam, arr);
	}
	// Stable order per FAMILY_LABEL keys.
	return (Object.keys(FAMILY_LABEL) as CategoryFamily[])
		.filter((fam) => groups.has(fam))
		.map((family) => ({ family, categories: groups.get(family)! }));
}
