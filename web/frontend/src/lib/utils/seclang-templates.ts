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

// v2.38 — commented SecLang templates for the route editor. Each one
// is explained line by line (in the UI language) and uses only what
// the allowlist accepts. `{ID}` placeholders become free rule IDs.

export type SecLangTemplateKey =
	| 'jsonOnly'
	| 'allowedMethods'
	| 'adminFromLan'
	| 'requireApiKey'
	| 'badBots'
	| 'argLength'
	| 'fieldException';

export const SECLANG_TEMPLATE_KEYS: SecLangTemplateKey[] = [
	'jsonOnly',
	'allowedMethods',
	'adminFromLan',
	'requireApiKey',
	'badBots',
	'argLength',
	'fieldException'
];

type Lang = 'fr' | 'en';

const TEMPLATES: Record<SecLangTemplateKey, Record<Lang, string>> = {
	jsonOnly: {
		fr: `# API en JSON uniquement : sous /api/, une requête qui envoie un corps
# (POST, PUT, PATCH) doit déclarer Content-Type: application/json.
# 1) le chemin commence par /api/ …
SecRule REQUEST_FILENAME "@beginsWith /api/" \\
    "id:{ID},phase:1,deny,status:415,log,msg:'API : JSON uniquement',chain"
    # 2) … la méthode envoie un corps …
    SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH)$" "chain"
    # 3) … et le Content-Type n'est pas JSON (t:lowercase : insensible à la casse).
    SecRule REQUEST_HEADERS:Content-Type "!@beginsWith application/json" "t:none,t:lowercase"
`,
		en: `# JSON-only API: under /api/, a request with a body (POST, PUT,
# PATCH) must declare Content-Type: application/json.
# 1) the path begins with /api/ …
SecRule REQUEST_FILENAME "@beginsWith /api/" \\
    "id:{ID},phase:1,deny,status:415,log,msg:'API: JSON only',chain"
    # 2) … the method sends a body …
    SecRule REQUEST_METHOD "@rx ^(?:POST|PUT|PATCH)$" "chain"
    # 3) … and the Content-Type is not JSON (t:lowercase: case-insensitive).
    SecRule REQUEST_HEADERS:Content-Type "!@beginsWith application/json" "t:none,t:lowercase"
`
	},
	allowedMethods: {
		fr: `# Méthodes autorisées : tout ce qui n'est pas GET, HEAD, POST ou OPTIONS
# est refusé avec 405. "!@rx" = « ne correspond pas à ».
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|OPTIONS)$" \\
    "id:{ID},phase:1,deny,status:405,log,msg:'Méthode non autorisée'"
`,
		en: `# Allowed methods: anything but GET, HEAD, POST or OPTIONS is
# refused with 405. "!@rx" = "does not match".
SecRule REQUEST_METHOD "!@rx ^(?:GET|HEAD|POST|OPTIONS)$" \\
    "id:{ID},phase:1,deny,status:405,log,msg:'Method not allowed'"
`
	},
	adminFromLan: {
		fr: `# /admin seulement depuis le réseau local.
# 1) l'IP source n'est PAS dans les réseaux listés (remplace par les tiens) …
SecRule REMOTE_ADDR "!@ipMatch 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12" \\
    "id:{ID},phase:1,deny,status:403,log,msg:'Admin : réseau local uniquement',chain"
    # 2) … et le chemin commence par /admin.
    SecRule REQUEST_FILENAME "@beginsWith /admin" "t:none"
`,
		en: `# /admin from the local network only.
# 1) the source IP is NOT in the listed networks (use your own) …
SecRule REMOTE_ADDR "!@ipMatch 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12" \\
    "id:{ID},phase:1,deny,status:403,log,msg:'Admin: LAN only',chain"
    # 2) … and the path begins with /admin.
    SecRule REQUEST_FILENAME "@beginsWith /admin" "t:none"
`
	},
	requireApiKey: {
		fr: `# Exiger un en-tête X-Api-Key sur /api/.
# "&REQUEST_HEADERS:X-Api-Key" compte les en-têtes de ce nom ; "@eq 0" = absent.
SecRule REQUEST_FILENAME "@beginsWith /api/" \\
    "id:{ID},phase:1,deny,status:401,log,msg:'Clé API manquante',chain"
    SecRule &REQUEST_HEADERS:X-Api-Key "@eq 0" "t:none"
`,
		en: `# Require an X-Api-Key header on /api/.
# "&REQUEST_HEADERS:X-Api-Key" counts headers with that name; "@eq 0" = absent.
SecRule REQUEST_FILENAME "@beginsWith /api/" \\
    "id:{ID},phase:1,deny,status:401,log,msg:'Missing API key',chain"
    SecRule &REQUEST_HEADERS:X-Api-Key "@eq 0" "t:none"
`
	},
	badBots: {
		fr: `# Bloquer des robots par leur User-Agent.
# "@pm" cherche n'importe lequel des mots (plus rapide qu'une regex),
# t:lowercase rend la recherche insensible à la casse.
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto masscan zgrab nuclei ahrefsbot semrushbot" \\
    "id:{ID},phase:1,deny,status:403,log,msg:'Robot bloqué',t:none,t:lowercase"
`,
		en: `# Block bots by User-Agent.
# "@pm" looks for any of the words (faster than a regex);
# t:lowercase makes it case-insensitive.
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto masscan zgrab nuclei ahrefsbot semrushbot" \\
    "id:{ID},phase:1,deny,status:403,log,msg:'Bot blocked',t:none,t:lowercase"
`
	},
	argLength: {
		fr: `# Refuser un paramètre de plus de 2000 caractères (hors corps de fichier).
# t:length remplace la valeur par sa longueur ; "@gt 2000" = plus grande que.
# phase:2 : les paramètres du corps (formulaires) sont connus.
SecRule ARGS "@gt 2000" \\
    "id:{ID},phase:2,deny,status:413,log,msg:'Paramètre trop long',t:none,t:length"
`,
		en: `# Refuse a parameter longer than 2000 characters (file bodies excluded).
# t:length replaces the value with its length; "@gt 2000" = greater than.
# phase:2: body parameters (forms) are known.
SecRule ARGS "@gt 2000" \\
    "id:{ID},phase:2,deny,status:413,log,msg:'Parameter too long',t:none,t:length"
`
	},
	fieldException: {
		fr: `# Exception ciblée : sur /api/save, la règle CRS 942100 (SQLi) n'inspecte
# plus le paramètre « content » (éditeur de texte riche). Elle continue
# d'inspecter tous les autres paramètres. Doit tourner en phase 1.
SecRule REQUEST_FILENAME "@streq /api/save" \\
    "id:{ID},phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:content"
`,
		en: `# Targeted exception: on /api/save, CRS rule 942100 (SQLi) no longer
# inspects the "content" parameter (rich-text editor). It keeps
# inspecting every other parameter. Must run in phase 1.
SecRule REQUEST_FILENAME "@streq /api/save" \\
    "id:{ID},phase:1,pass,nolog,t:none,ctl:ruleRemoveTargetById=942100;ARGS:content"
`
	}
};

/** The template text with `{ID}` replaced by `id`, in `lang`. */
export function secLangTemplate(key: SecLangTemplateKey, lang: string, id: number): string {
	const l: Lang = lang === 'fr' ? 'fr' : 'en';
	return TEMPLATES[key][l].replaceAll('{ID}', String(id));
}
