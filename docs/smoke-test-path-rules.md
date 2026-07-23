# Smoke test — Path-based rules + IP allow/deny (v1)

Live smoke against a real `go build` binary (dev mode), executed 2026-07-23 on
the `feature/path-based-rules` branch. All 7 gates PASS. CLAUDE.md
§Empirical-verification evidence: per-path basic-auth + per-path/route
source-IP allow-deny actually enforce, longest-prefix wins, route-level filter
inherits to all paths, and everything persists across restart.

## Setup

```bash
BIN=./arenet ; DATA=/tmp/pr-data ; rm -rf "$DATA"; mkdir -p "$DATA"
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  "$BIN" --dev --admin-port 127.0.0.1:8009 --data-dir "$DATA" >arenet.log 2>&1 &
TOKEN=$(grep "Setup token:" arenet.log | tail -1 | sed 's/.*Setup token: //' | tr -d '"')
curl -s -c ck -X POST http://127.0.0.1:8009/api/v1/auth/setup -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"SmokeTestPass123!\",\"email\":\"a@b.co\"}"
# test upstream on :9099 returns 200 "upstream-ok path=<path>" for every path
A=http://127.0.0.1:8009/api/v1 ; B=http://127.0.0.1:8080
```

Route created (`POST /api/v1/routes`), wire is camelCase, path-rule basic-auth
password is PLAIN (hashed server-side):

```json
{ "host":"proxy.local",
  "upstreams":[{"url":"http://127.0.0.1:9099","weight":1}],
  "ipFilter":{"mode":"deny","cidrs":["203.0.113.0/24"]},
  "pathRules":[
    {"pathPrefix":"/docs","basicAuth":{"username":"doc","password":"docpass"}},
    {"pathPrefix":"/metrics-zabbix","ipFilter":{"mode":"allow","cidrs":["127.0.0.1"]}}
  ]}
```

> Gotcha (my curl, not the product): `-H "Host: proxy.local"` needs the explicit
> space; a mangled Host header 404s before the route matches.

## Gates

### Gate 1 — public catch-all — PASS
`/api/v1/x` (no rule) → **200** `upstream-ok`. Paths with no rule proxy via the
match-less catch-all.

### Gate 2 — per-path basic-auth (+ server-side hashing) — PASS
`/docs` no creds → **401**; `-u doc:docpass` → **200**; `-u doc:wrongpass` →
**401**. The PLAIN `docpass` posted on the wire was hashed server-side
(argon2id) and verifies correctly.

### Gate 2c — prefix covers the subtree — PASS
`/docs/swagger.json` with creds → **200**. Prefix `/docs` emits
`path:["/docs","/docs/*"]`, covering the whole sub-tree.

### Gate 3 — per-path IP allow-list — PASS
`/metrics-zabbix` from `127.0.0.1` (in the allow-list) → **200**.

### Gate 4 — allow-list FAILS CLOSED — PASS (the #1 security gate)
Allow-list changed to `192.168.99.99`; request from `127.0.0.1` (NOT in the
list) → **403**. An IP outside the allow-list is blocked, not passed. Also
confirmed preserve-on-empty: the `/docs` rule updated with an empty password
kept its stored hash (`-u doc:docpass` still → 200).

### Gate 5 — longest-prefix wins — PASS
Rules `/docs` (basic-auth) + `/docs/admin` (IP-allow `192.168.99.99`).
`/docs/admin/x` from `127.0.0.1` → **403** EVEN WITH valid basic-auth creds
(the more-specific IP rule wins). `/docs/other` → **200** with creds (the
shorter `/docs` basic-auth rule applies).

### Gate 6 — route-level IP filter inherits to all paths — PASS
Route-level `deny 127.0.0.0/8`. Every path 403 from `127.0.0.1`: `/api/v1/x`
(otherwise public) → **403**, `/docs` (has basic-auth) → **403** (the route
deny fires before the per-path auth). Additive-override: the domain gate covers
all sub-paths.

### Gate 7 — restart persistence (+ preserve-on-omission) — PASS
First attempt failed by MY script error, which proved a feature: the reset PUT
*omitted* `ipFilter`, and preserve-on-omission (by design) KEPT the stored
`deny 127.0.0.0/8` → everything 403 after restart (correct — 127/8 blocks the
test host). Clearing requires an EXPLICIT `ipFilter:{mode:"off"}`, not omission.
After the explicit reset + restart: `/api` → 200, `/docs` no-creds → 401,
`/docs` with-creds → 200, `/metrics-zabbix` allowed → 200. Path-rules and the
IP filter survive a BoltDB restart and still enforce.

## Notes
- Smoke runs LOCAL: native `go build` + `curl` + a trivial test upstream. No
  Docker/VM. `client_ip` matcher honours `ARENET_TRUSTED_PROXIES`.
- All backend suites (`caddymgr`/`storage`/`api`), the caddy.Validate gate
  (Task 6), the full frontend suite (1060) + svelte-check are green.
- The dedicated reviews (Task 4 route-IP, Task 5 path-rules) verified the
  fail-closed + longest-prefix + hash_cache invariants against the Caddy
  source; this smoke confirms them at runtime.
