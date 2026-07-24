# Smoke test — Per-path upstream routing (v2.23.0)

Live checklist for the per-path upstream routing feature (path-rule may now
carry its own `upstreams` pool + `lbPolicy` + `healthCheck`, independent of
the route's own pool). Mirrors `docs/smoke-test-path-rules.md`'s structure and
setup. **Results column intentionally left blank — fill in during the live
run**, PASS/FAIL + one-line evidence per gate.

## Setup

```bash
BIN=./arenet ; DATA=/tmp/pu-data ; rm -rf "$DATA"; mkdir -p "$DATA"
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  "$BIN" --dev --admin-port 127.0.0.1:8009 --data-dir "$DATA" >arenet.log 2>&1 &
TOKEN=$(grep "Setup token:" arenet.log | tail -1 | sed 's/.*Setup token: //' | tr -d '"')
curl -s -c ck -X POST http://127.0.0.1:8009/api/v1/auth/setup -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"SmokeTestPass123!\",\"email\":\"a@b.co\"}"
A=http://127.0.0.1:8009/api/v1 ; B=http://127.0.0.1:8080 ; BS=https://127.0.0.1:8443
```

Three trivial test upstreams are needed:
- `:9099` (route's own pool) — returns 200 `route-pool path=<path>`
- `:9199` (http, /v1's own pool) — returns 200 `v1-pool path=<path>`
- `:9299` (https, self-signed, /legacy's own pool) — returns 200
  `legacy-pool path=<path>` over TLS
- one of the two above can double as a deliberately-broken pool (stopped
  process / closed port) to exercise the 502 gates.

Route created (`POST /api/v1/routes`) — host `api-bff.local`, wire is
camelCase:

```json
{ "host":"api-bff.local",
  "upstreams":[{"url":"http://127.0.0.1:9099","weight":1}],
  "pathRules":[
    {"pathPrefix":"/v1",
     "upstreams":[{"url":"http://127.0.0.1:9199","weight":1}],
     "lbPolicy":"round_robin"},
    {"pathPrefix":"/legacy",
     "upstreams":[{"url":"https://127.0.0.1:9299","weight":1}],
     "lbPolicy":"round_robin",
     "insecureSkipVerify":true},
    {"pathPrefix":"/docs",
     "basicAuth":{"username":"doc","password":"docpass"}}
  ]}
```

> `/docs` intentionally carries NO `upstreams` — it must inherit the route's
> own pool (`:9099`) while still enforcing its basic-auth, proving
> auth-only and upstream-routing compose independently.

## Gates

| # | Gate | Expected | Result |
|---|------|----------|--------|
| 1 | Route's own pool (no matching path rule) | `GET $B/api/v1/other` with `Host: api-bff.local` → **200** `route-pool path=/api/v1/other` | |
| 2 | `/v1` → own http pool | `GET $B/v1/x` → **200** `v1-pool path=/v1/x` (NOT `route-pool`) | |
| 3 | `/legacy` → own https pool (transport) | `GET $B/legacy/x` → **200** `legacy-pool path=/legacy/x`; confirm via logs/response that Arenet dialed `https://127.0.0.1:9299` (independent transport from the route's http pool) | |
| 4 | `/docs` → inherits route pool + basic-auth | No creds → **401**. With `-u doc:docpass` → **200** `route-pool path=/docs` (served by the ROUTE's pool, not a path-local one) | |
| 5a | Branded error page — route-pool 502 | Stop the `:9099` backend; `GET $B/api/v1/other` → **502** rendered with Arenet's branded error page (not a raw Go/Caddy error) | |
| 5b | Branded error page — path-pool 502 | Restart `:9099`; stop the `:9199` backend; `GET $B/v1/x` → **502** rendered with the SAME branded error page (shared `handle_response`, not a bare proxy error) | |
| 6 | https path backend works end-to-end | Restart `:9199`; re-run gate 3 (`GET $B/legacy/x`) → **200**, confirming the self-signed https path pool round-trips correctly with `insecureSkipVerify:true` on that path rule | |
| 7 | Pure-routing rule accepted (no protection) | `PUT` the route adding `{"pathPrefix":"/pub","upstreams":[{"url":"http://127.0.0.1:9199","weight":1}]}` (no basicAuth, no ipFilter) → **200** on save (not rejected as "no active protection"); `GET $B/pub/x` → **200** `v1-pool path=/pub/x` | |
| 8 | Edit + re-save PRESERVES per-path upstream (regression guard for the Task-7 hydration fix) | `GET` the route in the UI (or `GET $A/routes/{id}`), change an unrelated field (e.g. toggle `uploadStreamingMode`), `PUT` back the form's payload → `GET $A/routes/{id}` again and confirm `/v1` and `/legacy` STILL carry their `upstreams`/`lbPolicy`; re-run gate 2 (`GET $B/v1/x` → 200 `v1-pool`) to prove enforcement, not just storage | |

## Notes

- Gate 8 is the live-run regression guard for the fix landed in Task 7
  (`web/frontend/src/routes/routes/+page.svelte`): the edit-hydration mapper
  previously dropped `upstreams`/`lbPolicy`/`healthCheck` when loading a route
  into the form, so editing-and-saving a route with a per-path upstream
  silently wiped that pool. This gate must be run through the actual UI edit
  flow (not just a raw PUT) to catch any regression of that fix.
- Gates 5a/5b assume the shared `handle_response` branding wired in Task 3/4
  applies uniformly to both the route-level and path-level reverse-proxy
  handlers — confirm the two 502 pages are visually/structurally identical.
- **(v2.23.1)** `insecureSkipVerify` is now a PER-PATH toggle, autonomous from
  the route: a path with an https self-signed backend needs its own "Skip TLS
  verification" checkbox (shown in the "Upstream spécifique" disclosure only when
  the path pool has an https URL). It does NOT inherit — and does not affect —
  the route's own TLS-verify posture. A path pool is strict by default. (Before
  v2.23.1 a path pool inherited the route's insecure-skip-verify; that coupling
  is gone.) The per-path weight input likewise appears only when the path's LB
  is `weighted_round_robin`, mirroring the route pool.
- All backend suites (`go test ./...`, `-race ./internal/caddymgr/`) and the
  full frontend suite (`vitest` + `svelte-check`) must be green before this
  live smoke is run — see `task-7-report.md` for the automated-gate output.
