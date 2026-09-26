<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — per-route SecLang editor (v2.38.0)

Date: 2026-09-22. Real binary (macOS, `--dev`, HTTP :8080), Python HTTP
server on 127.0.0.1:9912 as the backend (404 on unknown paths). Route
`sl.localhost`, WAF **block**, full CRS.

## Allowlist (PUT /routes/{id} with `wafSecLang`)

| Attempt | Expected | Observed |
|---|---|---|
| `Include /etc/passwd` | 400, line 1 | 400 `directive "include" is not allowed` |
| `@inspectFile /bin/sh` | 400 | 400 `operator @inspectFile is not allowed` |
| `setenv:X=1` | 400 | 400 `action "setenv" is not allowed` |
| `ctl:ruleEngine=Off` | 400 | 400 `ctl:ruleEngine is not allowed` |
| `ENV:HOME` | 400 | 400 `the ENV collection is not allowed` |
| `@pmFromFile /etc/hosts` | 400 | 400 `operator @pmFromFile is not allowed` |
| `id:942100` | 400 | 400 `id 942100 is outside 130000..139999` |
| every template (7 × FR/EN) via `/waf/seclang/validate` | valid | 14 / 14 valid |
| templates "allowed methods" (FR) + "API key" (FR) + "bots" (EN) | 200 | 200 |

## Traffic (17:58:07)

| Request | Expected | Observed |
|---|---|---|
| `DELETE /` | 405 (130000) | 405 |
| `GET /api/x`, no `X-Api-Key` | 401 (130001) | 401 |
| `GET /api/x` + key | passes | 404 (backend) |
| `GET /`, UA `Nikto/2.5` | 403 (130002) | 403 |
| `GET /`, browser | 200 | 200 |
| `/security/events` | CUSTOM + msg as name | `130002 'Bot blocked'`, `130001 'Clé API manquante'`, `130000 'Méthode non autorisée'` |

## Tester, bridge, persistence

- `POST /routes/{id}/waf-test` `PATCH /` (stored SecLang) → blocked 405 by 130000, mode block; SQLi sample with draft `""` → blocked 403 by 949110 with 942100 listed (CRS only). No event recorded, no reload.
- `POST /waf/seclang/from-guided` (path begins with /admin + header absent, id 130010) → commented chained SecLang with `msg:'Admin sans jeton'`.
- Restart: `DELETE /` still 405. `GET /admin/backup` carries `waf_seclang` (16 lines).

Unit / E2E coverage: allowlist refusals and error lines (`TestCheckSecLang_*`), dry run (`TestDryRun_*`), bridge equivalence + draft override + order (`TestGuidedRuleSecLang_*`, `TestWAFDirectivesForRoute_*`, `TestBuildWAFHandler_SecLang_*`), `caddy.Validate` fixture, API (`waf_seclang_test.go`), UI (section, tester, templates, completion, page bridge + refused save).

Verdict: **pass**.
