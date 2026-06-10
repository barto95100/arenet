<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# WAF excludes the Arenet management plane

Date: 2026-06-10
Status: SHIPPED — commit `00c93dd`
Related tickets: `#R-WAF-BLOCKS-MUTATING-METHODS`, `#R-AUTOMATION-CREDS-403`
Supersedes (partially): Item 1 (`#R-WAF-FP-uuid-paths`, commit `a6276a8`, 2026-06-08)

## Context

The CS.3 Gate 5 smoke surfaced ticket `#R-AUTOMATION-CREDS-403`: PUT on
`/api/v1/settings/automation/credentials` returned 403 with
`Server: Caddy` + `Content-Length: 0` + no slog line. Initial hypothesis
was a CSRF / auth middleware issue; the truth was different.

Empirical reproduction on AreNET-test (Day 8, 2026-06-10):

```text
# Direct against the standalone admin chi server on :8001
$ curl -i -X PUT http://127.0.0.1:8001/api/v1/settings/crowdsec ...
HTTP/1.1 200 OK
[normal response body]

# Same request via the public domain
$ curl -i -X PUT https://arenet.worldgeekwide.fr/api/v1/settings/crowdsec ...
HTTP/1.1 403 Forbidden
Server: Caddy
Content-Length: 0
```

The 403 was Caddy-internal, never reaching the chi handler (no slog line
on `routes.go:61` `slogLogger`). Live Caddy config dump confirmed:

```text
$ curl -s http://localhost:2019/config/ | jq '.apps.http.servers...'
chain handlers: routemetrics → crowdsec → arenet_waf → reverse_proxy
arenet_waf: { host: "arenet.worldgeekwide.fr", mode: "block",
              load_owasp_crs: true }
```

The boot log corroborated:

```text
waf handler provisioned route_id=b2a1a41e-... 
host=arenet.worldgeekwide.fr mode=block load_owasp_crs=true
```

Root cause: the operator had created a **self-route admin** in BoltDB
(host=`arenet.worldgeekwide.fr` → upstream=`127.0.0.1:8001`) to get TLS
+ CrowdSec bouncer + country-block on their admin UI. That route
inherited `WAFMode=block` + OWASP CRS load by default. CRS rule 911100
(PROTOCOL_ENFORCEMENT method check) rejects PUT/DELETE/PATCH because
the default `tx.allowed_methods` shipped with CRS v4 is
`GET HEAD POST OPTIONS`.

The Item 1 exclusion guard (commit `a6276a8`, Step W follow-up) had
already recognised the CRS-blocks-admin-writes problem, but only for
UUID-shaped paths `/api/v1/(routes|settings)/<UUID>`. Literal-named
admin endpoints — `/api/v1/settings/crowdsec`,
`/api/v1/settings/automation/credentials`, `/api/v1/security/crowdsec/
decisions`, and dozens of siblings (inventoried at `routes.go:60-360`)
— were never in scope. PUT or DELETE on any of those would 403.

## Decision

The Arenet management plane (everything under `/api/v1/`) is excluded
from CRS rule families 911* (PROTOCOL_ENFORCEMENT), 930* (LFI), 931*
(RFI), and 949* (anomaly aggregator), regardless of whether a user has
chosen to put the admin UI behind a self-route with WAFMode=block.

Mechanism: a single phase:1 `SecRule` injected before the CRS
`Include`s, removes those four rule families on any request whose
`REQUEST_FILENAME` matches `^/api/v1(/.*)?$`. See
`internal/waf/module.go` — `adminAPIExclusionDirective` constant +
its doc comment block.

The exclusion fires regardless of:
- the route's `WAFMode` setting (off / detect / block — the directive
  is concatenated either way, but only matters when CRS rules can
  actually trip)
- the host header (path-only matching — Coraza's `REQUEST_FILENAME` is
  `parsedURL.Path`, see `transaction.go:864`)
- whether the route was operator-created or system-default

## Justification

Three lines of reasoning support this decision.

**1. Auth is the real gate.** Every `/api/v1/` endpoint is gated by
`auth.HardAuthMiddleware` at `routes.go:143`. Admin writes have a
further `auth.RequireAdminMiddleware` at `routes.go:284`. The WAF was
producing false positives on legitimate operator writes (PUT to update
a route, DELETE to revoke a session, etc.) without protecting against
real threats — the only requests that reach the management plane are
already authenticated, and the only requests that mutate state are
already admin-authenticated. CRS adds zero defence in depth for this
surface; it adds false-positive friction.

**2. Item 1 already accepted this trade-off, narrowly.** Commit
`a6276a8` (2026-06-08) made the explicit trade-off "admin API is
trusted, no end-user input — auth + RBAC are the real gates". The
narrow UUID-pattern exclusion was a first cut; the literal-named
admin paths were always going to need the same treatment, just hadn't
surfaced in smoke yet. The CS.3 follow-up Reset Security Automation
button (`73157c9`) hitting DELETE was the trigger that exposed the
gap. Widening the regex is the natural completion of Item 1's
direction, not a new architectural commitment.

**3. The post-Step-T WAF page reinforces the separation.** The planned
WAF page (post-Step-T roadmap) will expose CRS knobs ONLY for user
proxy routes. The management plane will not be configurable from
there, because there is no operator decision to make: the management
plane is excluded by design and is not in scope for tuning.

## Implications

**For operators creating a self-route admin** (the Day-8 trigger
shape):
- No special configuration needed. Set up a route
  `host=arenet.example.com` → `upstream=127.0.0.1:<adminPort>` and
  everything works through Caddy with TLS + CrowdSec bouncer +
  country-block + whatever WAFMode the operator selected.
- WAFMode setting on the self-route is now cosmetic for `/api/v1/`
  traffic. If `WAFMode=block` is selected, the WAF still runs but the
  four FP-prone families are stripped on the management plane paths
  before they evaluate.

**For user proxy routes** (the typical "I'm putting Home Assistant
behind Arenet" shape):
- No change. CRS rules 911* + 930* + 931* + 949* still fire on every
  user route. PUT/DELETE/PATCH on a user app **outside** `/api/v1/`
  still 403s on 911100 unless the operator sets `WAFMode=detect` /
  `WAFMode=off` on that route.

**For the post-Step-T WAF page**:
- Only user proxy routes are surfaced in the UI for WAF tuning.
- Management plane WAF state is not configurable. (May be displayed
  as informational "/api/v1/ is excluded by design — see decision
  doc" if useful.)

## Trade-offs and limitations

**Known collision — user apps exposing their own /api/v1/.** The
exclusion is **path-based**, not **host-based**. So if an operator
proxies a user app whose API also lives under `/api/v1/` (e.g. a Home
Assistant install at `ha.example.com/api/v1/...`), CRS rules 911*,
930*, 931*, 949* will be stripped on that path. The other CRS families
(SQLi 942*, XSS 941*, scanner 913*, protocol 920*, etc.) still emit
events.

Mitigation: operator sets `WAFMode=detect` on the affected user route
and tunes per-app via cscli, OR uses a path-aware reverse proxy in
front (Caddy can rewrite paths) to namespace the user app's API under
something other than `/api/v1/`.

Rejected mitigation: making the exclusion host-aware (only fire on the
admin host's route). Two reasons:
1. There's no first-class "admin host" concept in the codebase. The
   admin chi router runs on a port; the host is whatever route the
   operator decides to point at it. Codifying "the host that proxies
   to `127.0.0.1:<adminPort>`" as a heuristic in the WAF would tightly
   couple the WAF builder to admin-port wiring it shouldn't know
   about.
2. Path-based matching is operator-debuggable. Paste the regex into a
   tester, see exactly what's excluded. Host-based magic surprises
   operators.

**Forward looking — if Arenet's admin chi router ever moves off
`/api/v1/`** (e.g. `/admin/`), the exclusion regex needs updating in
tandem. There is no current plan to do so. If the move happens, this
decision doc + the constant doc in `module.go` are the two places to
update.

**Anomaly scoring still happens — just doesn't block.** CRS rule
949110 (`Inbound Anomaly Score Exceeded`) is the rule that makes the
"total anomaly score ≥ threshold → block now" decision. Stripping
the 949* family means non-FP rules (SQLi 942*, XSS 941*, etc.) still
contribute to `tx.inbound_anomaly_score`, the WAF event still emits
for forensic visibility, but no rule reads the score to trigger a
block. This means a determined attacker authenticated as admin
hitting an SQLi payload at `/api/v1/routes/<UUID>?q=' OR 1=1 --`
would have the event LOGGED but the request would still reach the
chi handler. Acceptable: an admin-authenticated attacker can just
call the admin API directly anyway; the WAF is not the right gate
against an authenticated insider.

## How this maps to ENGINEERING-PRACTICES.md

- **Lesson 1 (triangulate)**: three independent signals confirmed the
  root cause before code was touched — operator curl evidence, boot
  log, live Caddy config dump.
- **Lesson 3 (read library source)**: `crowdsec@v1.6.3/.../models/
  alert.go` + the CRS shipped defaults were re-verified via the
  module source code, not from memory.
- **Lesson 4 (probe before fix)**: a temporary `TestRepro_*` was added
  before the regex change. Pre-fix it captured `next.called=false,
  events=2`. Post-fix the same test captured `next.called=true,
  events=0`. The probe ran in CI for ~30 seconds and was then
  deleted; its proof lives in this doc and in the new regression
  guards (`TestLiteralAdminPath_PUTCrowdSec_BypassesCRS911` et al.).
- **Lesson 7 (module-level imports cache references)**: the existing
  `adminAPIExclusionDirective` prepend-vs-append placement (before
  the CRS `Include`s) was preserved. Phase:1 SecRules fire in load
  order; appending the exclusion AFTER the CRS includes would let
  rule 911100 evaluate first and 403 before our `ctl:ruleRemoveById`
  fires. Trap survived because the code comment at
  `module.go:195-207` documents it explicitly.

## References

- Code: `internal/waf/module.go` — `adminAPIExclusionDirective` const
- Code: `internal/waf/module_crs_admin_exclusion_test.go` — 9 tests
- Item 1 precedent: commit `a6276a8` (2026-06-08, narrow UUID exclusion)
- Fix commit: `00c93dd` (2026-06-10)
- Lessons doc: `docs/ENGINEERING-PRACTICES.md`
- LAPI rule 911100 source: `crs/coreruleset@v4` rule
  `REQUEST-911-METHOD-ENFORCEMENT.conf`
- Coraza `REQUEST_FILENAME` source: `corazawaf/coraza/v3/internal/
  corazawaf/transaction.go:864`
