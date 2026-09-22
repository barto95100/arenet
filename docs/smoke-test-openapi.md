<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — OpenAPI documentation (v2.39.0)

Date: 2026-09-22. Real binary built with `-X main.version=v2.39.0-smoke`
(macOS, `--dev`, admin API :8001).

| Step | Expected | Observed |
|---|---|---|
| `GET /api/v1/openapi.json` anonymous | 401 | 401 |
| same with the admin session | 200, version injected | 200, `info.version = v2.39.0-smoke`, 109 paths / 146 operations, 243 KB |
| service-account create op found in the document, with its example | present | `POST /admin/users/service-accounts` "Create a service account", example `{name: backup-bot, role: viewer, expiresAt}` |
| create a service account as documented | token returned once | `{token, tokenId, user}` |
| `GET /routes` with `Authorization: Bearer <token>` | 200 | 200 |
| `GET /openapi.json` with the bearer token | 200 | 200 |
| `POST /routes` with the bearer token (admin SA) | 201 | 201 |
| independent lint: `npx @redocly/cli lint openapi.json` | valid | **valid**, 8 warnings (WebSocket 101 / OIDC 302 without a 2xx, one path ambiguity that exists in the API) |

**Finding (fixed before the PR):** the first lint reported 9 structural
errors: plain YAML scalars in flow mappings (`{ description: a, b }`)
were split at the comma / colon into stray keys. Quoted, and
`TestOpenAPI_NoSplitText` now rejects any key with a space or a trailing
dot. The lint also asked for `operationId`s: derived automatically when
missing (`getRoutesById`…), uniqueness tested.

**Probe finding (fixed before the PR):** the role probe first classified
`/auth/me/password`, `/me/theme`, `/me/language`, `/unlock` as public — the
`/auth` rate limiter answered 429 after a burst from one IP. Each probe
call now uses its own client IP, and a 429 fails the test.

Guards in CI: `TestOpenAPI_CoversEveryRoute` (router ⇄ document, both
ways), `TestOpenAPI_RolesMatchTheRouter` (each operation called
anonymously then as a viewer), `TestOpenAPI_OperationsWellFormed`,
`TestOpenAPI_RefsResolve`, `TestOpenAPI_NoSplitText`,
`TestOpenAPI_OperationIDsUnique`, `TestOpenAPI_Endpoint`,
`TestBuildOpenAPI_RefusesDuplicates`. UI: `/api-docs` page tests (list,
search, detail, try it with confirmation).

Verdict: **pass**.
