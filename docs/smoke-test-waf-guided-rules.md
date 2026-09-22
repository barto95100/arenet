<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — guided WAF rules (v2.37.0)

Date: 2026-09-22. Real binary (macOS, `--dev`, HTTP :8080), Python
HTTP server on 127.0.0.1:9912 as the backend (404 on unknown paths,
501 on POST — both prove the request reached it). Route
`rules.localhost`, WAF **block**, full CRS, three rules created in the
`POST /routes` body:

- 120000 « Fichiers sensibles » — path contains `/.env`, `/.git`
- 120001 « Login sans navigateur » — method is POST **and** path begins with `/login` **and** User-Agent absent or empty
- 120002 « Admin sans jeton » — path begins with `/admin` **and** header `X-Admin-Token` absent

| Time | Request | Expected | Observed |
|---|---|---|---|
| 17:25:23 | GET `/app/.env` | 403 (120000) | 403 |
| 17:25:23 | GET `/` | 200 | 200 |
| 17:25:23 | POST `/login`, no User-Agent | 403 (120001) | 403 |
| 17:25:23 | POST `/login`, browser UA | passes | 501 (backend) |
| 17:25:23 | GET `/login`, no UA | passes (method differs) | 404 (backend) |
| 17:25:23 | GET `/admin/x`, no token | 403 (120002) | 403 |
| 17:25:23 | GET `/admin/x` + `X-Admin-Token` | passes | 404 (backend) |
| — | `/security/events` | CUSTOM + names | `120000 CUSTOM 'Fichiers sensibles' BLOCK 403`, same for 120001 / 120002 |
| — | PUT: mode **detect**, 120002 disabled | IDs kept | `[(120000,F),(120001,F),(120002,T)]` |
| 17:26:37 | GET `/app/.env` (detect) | passes + logged | 404 (backend); event `120000 'Fichiers sensibles' DETECT` (CRS 930130 / 949110 also logged — in block mode the custom rule denies at phase 1, before them) |
| 17:26:37 | GET `/admin/x`, no token (rule disabled) | passes | 404 (backend) |
| — | restart | rules kept | kept, mode detect, 120002 disabled |
| — | `GET /admin/backup` | rules exported | `waf_custom_rules` with the 3 rules and their IDs |
| — | PUT with a value `x" "id:1,…,ctl:ruleEngine=Off` | 400 | 400 (double quote refused) |

Unit / E2E coverage: every operator (match and non-match), AND
between conditions, detect vs block, disabled rule, CRS-disabled
emission (`TestCustomRules_E2E*`, real Coraza + CRS); chained
directives validated by `caddy.Validate` in
`TestBuildConfigJSON_LoadsCleanly`; API ID allocation / stability /
validation; UI editor, presets, sentence, route payload.

Verdict: **pass**.
