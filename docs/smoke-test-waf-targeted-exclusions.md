<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — targeted WAF exclusions (v2.36.0)

Date: 2026-09-22. Real binary (macOS, `--dev`, HTTP listener :8080),
Python HTTP server on 127.0.0.1:9912 as the backend (404 on unknown
paths, 501 on POST — both prove the request reached it). Route
`waf.localhost`, WAF **block**, full CRS. Payload `content=1' OR '1'='1`.

| Time | Step | Expected | Observed |
|---|---|---|---|
| 16:28:42 | GET `/api/save?content=<sqli>` | 403, event names the field | 403; events `942100` `matchedVar=ARGS:content`, `949110` `matchedVar=TX:blocking_inbound_anomaly_score` |
| 16:28:55 | `POST /routes/{id}/waf-exclusions` `{942100, ARGS:content, /api/save}` | 200, stored, reload | 200; `wafTargetedExclusions` echoed; audit `route_updated` |
| 16:29:00 | same GET | reaches backend | 404 (backend) |
| 16:29:00 | POST form `content=<sqli>` on `/api/save` | reaches backend | 501 (backend) |
| 16:29:00 | `?other=<sqli>` on `/api/save` | still blocked | 403 |
| 16:29:00 | `/login?content=<sqli>` | still blocked | 403 |
| 16:29:00 | `/api/save/sub?content=<sqli>` (exact path) | still blocked | 403 |
| — | same exclusion again (`args:content`) | 409 | 409 "already exists" |
| — | exclude `949110` | 400 | 400 "blocking-evaluation rule … exclude the rule that matched instead" |
| — | target `ARGS:x",ctl:ruleEngine=Off` | 400 | 400 (quote / comma refused) |
| 16:30:30 | `?other=<sqli>` after the 60 s dedup window | event with the other field | `942100` `matchedVar=ARGS:other` |
| — | PUT route with `{…, path:/api, pathPrefix:true}` | prefix | 200 |
| 16:31:27 | `/api?content=`, `/api/save/sub?content=` | pass | 404, 404 (backend) |
| 16:31:27 | `/apix?content=` | still blocked | **403** (after fix, see below) |
| 16:31:27 | `/login?content=` | still blocked | 403 |
| — | restart the binary | exclusions kept | kept (the 16:31:27 run is after a restart) |
| — | `GET /admin/backup` | field exported | `waf_targeted_exclusions: [{rule_id:942100, target:ARGS:content, path:/api, path_prefix:true}]` |

**Finding (fixed before the PR):** the first prefix run let
`/apix?content=` through: `@beginsWith /api` is a raw string prefix.
"And everything below it" now emits `@streq /api` + `@beginsWith /api/`
(a path ending in `/` keeps a single `@beginsWith`). Pinned by
`TestTargetedExclusionDirectives_Shapes` and the `/api` / `/apix` cases of
`TestTargetedExclusion_E2E` (real CRS).

**Note (existing behaviour):** repeats of the same route + source IP +
rule within 60 s are persisted once (`waf.Sink` LRU); the 16:29:00
blocks therefore did not add rows. Documented in the WAF wiki page.

## Upgrade / downgrade

- Metrics DB created by **v2.35.1** (schema 12, 2 WAF events) → v2.36:
  migrated to **13**, old rows read back with `matched_var = ''` (the
  dialog then offers the whole-route exclusion, as designed).
- Back to **v2.35.1** on that data: the proxy keeps serving (200), but
  the metrics / WAF history is disabled ("unsupported schema version
  13", the existing downgrade policy) and targeted exclusions are
  ignored (unknown field). Restore the pre-upgrade backup of
  `metrics.db` to downgrade cleanly.

## UI

Covered by component tests (dialog: targeted / prefix / no path /
no-field fallback / 409 / 400; event list button: admin-only, hidden on
949110 and Arenet rules; route-form editor: add / remove / validation;
route page: exclusions loaded on edit and shipped on save). Visual
check on the test host after upgrade: **Logs** → a WAF row →
**Exclude…**.

Verdict: **pass** (after the prefix fix).
