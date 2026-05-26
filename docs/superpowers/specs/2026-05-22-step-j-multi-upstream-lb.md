<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step J — Multi-upstream Load Balancing (Spec — draft, to be frozen at v0.6.0-step-j-spec)

## 1.1 Goal

Step J extends Arenet's reverse proxy from a single backend per route to a
**pool of backends per route**, with load balancing across the pool and
active health checks that automatically pull failed backends out of
rotation. This is the marquee feature.

Step J also ships two smaller, independent improvements: DNS-01 ACME
challenge support (wildcard certificates) and a visual design pass on
the Topology page. The WAF observability completion originally
considered for Step J (the `audit_waf_match` audit event and the
`X-WAF-Match` response header) has been deferred — see §1.4.

The engine doing the work is Caddy v2.11.3, whose `reverse_proxy` module
already provides multi-upstream pools, load-balancing selection policies,
and active/passive health checks natively. Step J's task is to **expose
that existing capability** through Arenet's domain model, REST API, and
UI — not to build a load balancer. This mirrors the Step I principle:
Arenet's value is a well-understood, well-tested Caddy surface, not a
re-implementation.

## 1.2 Scope

In scope for Step J:

- **Multi-upstream routes.** A route's single `UpstreamURL` becomes a pool
  `Upstreams []Upstream`, each upstream a URL plus an optional weight.
  Backward-compatible BoltDB migration of every existing route to a
  one-element pool.
- **Load balancing.** Six selection policies exposed (see §1.3):
  `round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash`,
  `random`, `first`.
- **Active health checks.** Per-route active probes against each upstream
  — configurable URI, method, interval, timeout, expected status,
  expected body, and consecutive pass/fail thresholds. An upstream that
  fails its threshold is pulled from rotation until it passes again.
- **DNS-01 ACME challenge** for issuing wildcard certificates, alongside
  the HTTP-01 path shipped in Step I.
- **Topology page visual design pass** — a polish of the page's visual
  design, incorporating the auto-fit-on-load fix (Step I Finding #10).

## 1.3 Locked decisions

Decisions taken before the spec is frozen; not to be reopened during
implementation without amending this section.

1. **Upstream model.** `Upstream = { URL string, Weight int }`. `Weight`
   is consulted only by the `weighted_round_robin` policy; it defaults to
   1 and is otherwise inert. A route always has at least one upstream.

2. **Six load-balancing policies, no more.** `round_robin` (default),
   `weighted_round_robin`, `least_conn`, `ip_hash`, `random`, `first`.
   Caddy offers twelve; the four hash policies (`header`, `cookie`,
   `query`, `uri`), `client_ip_hash`, and `random_choose` are out of
   scope (§1.4). `first` is included specifically for primary/backup
   failover (first available upstream in declared order).

3. **Active health checks only.** Passive health checks are out of scope
   (§1.4): Caddy's passive-check state is shared globally across handlers,
   which has unclear semantics for Arenet's per-route handler model.
   Active checks are per-handler and deliver the FortiWeb / HAProxy-style
   behaviour cleanly.

4. **Active health check field set.** Exposed: `uri`, `method` (default
   GET), `interval` (default 30s), `timeout` (default 5s),
   `expect_status`, `expect_body` (optional regex), `passes` and `fails`
   (consecutive thresholds). Caddy's remaining active-check fields (probe
   headers, request body, `max_size`, `follow_redirects`, port / upstream
   override) are not exposed in v1.0.

   Defaults (method GET, interval 30s, timeout 5s, passes 1, fails 1) are
   materialized Arenet-side: when a health check is enabled and a field is
   left blank, the API fills the default value into the stored Route before
   validation. The emitted Caddy config and a GET on the route therefore
   always show the effective configuration explicitly. Arenet owns these
   default values rather than inheriting Caddy's runtime defaults — notably
   the 30s interval that §1.6's threat analysis relies on.

5. **No next-host retry in v1.0.** Caddy's `reverse_proxy` load-balancing
   retry layer (`try_duration` / `try_interval` / `retry_match`) is not
   wired. Health checks remove dead upstreams between probe intervals; an
   upstream that fails *between* two active probes will error the in-flight
   requests routed to it until the next probe marks it down. This is an
   accepted v1.0 tradeoff for a homelab tool; the retry layer is a
   documented backlog item. The probe interval can be lowered to shrink
   the failure window.

6. **BoltDB migration is forward-only and backward-compatible.** Every
   pre-Step-J route (`UpstreamURL: "x"`) migrates to
   `Upstreams: [{URL: "x", Weight: 1}]`, load-balancing policy
   `round_robin`, health checks disabled. The legacy `UpstreamURL` field
   leaves the wire shape. Migration runs at boot, is idempotent, and
   follows the pattern established by Step I.4's `WAFEnabled → WAFMode`
   migration.

7. **Caddy is the engine.** All load balancing and health checking is
   performed by Caddy `reverse_proxy` v2.11.3. Arenet emits the
   corresponding JSON config and performs no balancing or probing of its
   own.

8. **DNS-01 provider — OVH only in v1.0.** DNS-01 ACME (J.4) is supported
   for exactly one DNS provider: OVH. The supported-provider set is fixed
   at build time — each provider ships as a `caddy-dns/*` module compiled
   into the Arenet binary, so adding a provider requires recompiling
   Arenet, not a runtime or database change. Other providers are a
   backlog item. The HTTP-01 path from Step I is unchanged.

## 1.4 Out of scope

Explicitly not part of Step J. Items below are deferred to a later step or
recorded in `docs/backlog-step-j.md`.

- **WAF observability completion** — the `audit_waf_match` audit event
  and the `X-WAF-Match` response header (AC #4 PARTIAL from Step I).
  Deferred. `coraza-caddy v2.5.0` — the current pinned version, and
  byte-identical to upstream `main` HEAD — exposes no hook to Coraza's
  matched rules. The only viable path is a custom Caddy module
  consuming `coraza/v3` directly (~600 lines, security-critical: a bug
  in the match handling silently weakens the WAF). That ownership is
  disproportionate to an observability surface. Revisit if
  `coraza-caddy` gains a match hook, or as a dedicated WAF step.
  Backlog.
- **Passive health checks** — see §1.3 decision 3. Backlog.
- **Next-host retry** (`reverse_proxy` retry layer) — see §1.3 decision 5.
  Backlog.
- **The six unused Caddy LB policies** — the four hash policies (`header`,
  `cookie`, `query`, `uri`), `client_ip_hash`, `random_choose`. Backlog.
- **Per-upstream `max_requests`** concurrency cap. Backlog.
- **Circuit breaker** — experimental in upstream Caddy. Not considered.
- **Dynamic upstreams** (DNS / SRV-resolved pools) — also mutually
  exclusive with active health checks in Caddy. Not considered.
- **Perimeter-mode WAF** (waf-before-auth chain order, Finding #9),
  **multi-user Basic Auth per route**, and the **Security & Threat
  dashboard** — all deferred to end-of-project / a dedicated later step
  per `docs/backlog-step-j.md` §5.

## 1.5 Range of change

Baseline: `v0.5.0-step-i` (`c44abdb`), the current `origin/main` head. The
spec is frozen at tag `v0.6.0-step-j-spec`; implementation runs from there
to `v0.6.0-step-j`. Implementation is sub-tasks J.1–J.6 (J.5 deferred,
§1.4), plus the J.7 smoke doc, mirroring Step I; any bug the smoke
surfaces is fixed in a hotfix commit as in Step I.7.

## 1.6 Threat model deltas vs Step I

New attack surface introduced by Step J, relative to the Step I baseline:

- **DNS provider credentials (new secret class).** DNS-01 ACME (J.4)
  requires API credentials for the operator's DNS provider, to create the
  `_acme-challenge` TXT records. This is a new class of stored secret. It
  must be handled with the same discipline as the Step I.5 Basic Auth
  hash for everything API-facing: never returned by the API, never
  written to audit-log payloads, never logged. The discipline does **not**
  extend to hashing — unlike a password hash, DNS provider credentials
  must be retrievable in cleartext for Arenet to use them against the
  provider's API, so they are stored recoverable. The at-rest threat
  model and the file-permission posture are specified in §5.4.
- **Active health probes (new outbound traffic).** Arenet, via Caddy, now
  issues periodic unsolicited requests to each upstream. The probe target
  is operator-configured; a misconfigured probe URI or a very short
  interval could load a backend. The 30s default interval and
  operator-only route configuration bound the risk. No new
  externally-triggerable surface.
- **`expect_body` regex (minor, operator-trusted).** The active-check
  `expect_body` field is a regular expression compiled by Caddy. A
  pathological pattern is a theoretical ReDoS vector, but the field is
  operator-supplied in a single-admin model; severity is low. No
  untrusted input reaches it.

Multi-upstream and load balancing introduce no new threat class — a route
fanning out to N backends is the same trust relationship as the
single-backend case, repeated.

## 2. Acceptance Criteria

The numbered criteria below are the authoritative checklist for the J.7
smoke and the `v0.6.0-step-j` tag. Each must end the step as PASS, PARTIAL
with a documented caveat, or N/A with justification.

**AC #1 — Multi-upstream pool.** A route accepts, persists, and returns a
pool of one or more upstreams; create / edit / get round-trips preserve
the pool and per-upstream weights.

**AC #2 — Backward-compatible migration.** Every pre-Step-J route migrates
at boot to a one-element pool (`{URL, Weight: 1}`, policy `round_robin`,
health checks disabled); the legacy `UpstreamURL` field is gone from the
wire shape; a migrated one-element route proxies exactly as before.
Migration is idempotent.

**AC #3 — Load-balancing policy selection.** Each of the six policies
(`round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash`,
`random`, `first`) is selectable per route and emitted as the correct
Caddy `selection_policy` module in the generated config.

**AC #4 — Round-robin distribution.** A multi-upstream route under
`round_robin` distributes requests across every healthy upstream in the
pool.

**AC #5 — Weighted distribution.** A route under `weighted_round_robin`
distributes requests in proportion to the configured per-upstream
weights.

**AC #6 — Active health check removes a failed upstream.** With active
health checks enabled, an upstream that fails the configured `fails`
threshold is pulled from rotation; traffic continues on the remaining
healthy upstreams.

**AC #7 — Active health check restores a recovered upstream.** An upstream
that returns to passing the `passes` threshold is put back into the
rotation.

**AC #8 — Health-check config validation.** Invalid active-health-check
configuration (missing `uri`, non-positive `interval` / `timeout`,
out-of-range `expect_status`, malformed `expect_body` regex, etc.) is
rejected at the API layer with a clear error message.

**AC #9 — DNS-01 wildcard issuance.** A route configured for DNS-01 ACME
obtains a wildcard certificate. Public-path verification depends on a
real DNS provider being available; the smoke may record this PARTIAL or
N/A with the config wiring unit-tested, as Step I did for HTTP-01 ACME.

**AC #10 — DNS provider credentials never echoed.** DNS provider API
credentials are never returned by any API response and never appear in
audit-log payloads — verified the same way as the Step I.5 Basic Auth
hash.

**AC #11 — `audit_waf_match` audit event. DEFERRED.** A WAF rule match
emits a first-class `audit_waf_match` event into the audit log.
Deferred from Step J per §1.4 (WAF observability completion): the
upstream `coraza-caddy` module exposes no hook on which to wire this
without a custom-fork-grade module. The AC number is preserved so the
later step that lands it inherits it as-is.

**AC #12 — `X-WAF-Match` response header. DEFERRED.** In WAF detect
mode, a request that matches a rule carries an `X-WAF-Match` response
header. Deferred from Step J for the same reason as AC #11; see §1.4.
The AC number is preserved.

**AC #13 — Topology visual pass.** The Topology page ships its visual
redesign and auto-fits the graph to the viewport on load (Step I Finding
#10 resolved).

**AC #14 — Frontend tests pass.** `npm run check` clean and `npm test`
green.

**AC #15 — Backend tests pass.** `go test ./...` green across all
packages.

**AC #16 — Lint / vet / format clean.** `gofmt`, `go vet`, and the
frontend linter report no issues.

**AC #17 — Bundle budget.** `npm run build` completes within the bundle
budget.

## 3. Architecture impact

### 3.1 Route schema change

Step J replaces the single `UpstreamURL string` field with an upstream pool
and adds load-balancing and health-check configuration. The change touches
the domain model (`internal/storage/routes.go`), the API wire shape
(`internal/api`), and the frontend type (`web/frontend/src/lib/api/types.ts`)
— the same three layers Step I's schema changes touched.

New domain types:

```go
type Upstream struct {
    URL    string `json:"url"`
    Weight int    `json:"weight"` // default 1; consulted only by weighted_round_robin
}

type HealthCheck struct {
    Enabled      bool   `json:"enabled"`
    URI          string `json:"uri"`
    Method       string `json:"method"`
    Interval     string `json:"interval"`      // duration string, e.g. "30s"
    Timeout      string `json:"timeout"`       // duration string, e.g. "5s"
    ExpectStatus int    `json:"expect_status"` // 0 = any 2xx (Caddy default); otherwise 100-599
    ExpectBody   string `json:"expect_body"`   // optional regex; "" = no body check
    Passes       int    `json:"passes"`        // consecutive passes -> healthy
    Fails        int    `json:"fails"`         // consecutive fails -> unhealthy
}
```

`Route` field changes:

- `UpstreamURL string` is **removed**.
- `Upstreams []Upstream` is **added** — always at least one element.
- `LBPolicy string` is **added** — one of `round_robin` (default),
  `weighted_round_robin`, `least_conn`, `ip_hash`, `random`, `first`.
- ``HealthCheck HealthCheck `json:"health_check"` `` is **added** — when
  `Enabled` is false the rest of the struct is inert and no health-check
  config is emitted. The defaults strategy (GET / 30s / 5s / 1 / 1
  materialised Arenet-side at create/update) is specified in §1.3
  decision 4 and detailed in §5.2.
- ``ACMEChallenge string `json:"acme_challenge"` `` is **added** — one of
  `http-01` (default) or `dns-01`. Detailed in §3.3 and §5.4; the
  supported provider set is locked in §1.3 decision 8.

All other `Route` fields are unchanged.

Wire shape: the API request and response structs (`routeRequest` and the
route response in `internal/api`) gain the camelCase equivalents —
`upstreams` (array of `{url, weight}`), `lbPolicy`, and `healthCheck`
(object). The legacy `upstreamUrl` field is removed from both request and
response — see §6 for the migration that rewrites stored routes.

Validation (API layer; rules detailed per sub-task in §5):

- `upstreams` must contain at least one entry; each `url` must be a valid
  `http` / `https` URL (the existing `validateUpstreamURL` logic, applied
  per element); each `weight` must be a positive integer.
- `lbPolicy` must be one of the six enum values.
- When `healthCheck.enabled` is true: `uri` is required and must start
  with `/`; `method` must be one of `GET` or `HEAD` (the probe is
  non-mutating); `interval` and `timeout` must parse as positive
  durations with `timeout < interval`; `expectStatus` must be 0 (= any
  2xx) or in the 100–599 range; `expectBody`, when set, must compile as
  a regular expression; `passes` and `fails` must each be `>= 1`. Full
  per-rule detail and the inject-before-validate ordering are in §5.2.

### 3.2 buildConfigJSON — reverse_proxy handler refactor

`buildConfigJSON` (`internal/caddymgr/manager.go`) currently emits a
hard-coded single-element upstream array:

```json
{"handler": "reverse_proxy", "upstreams": [{"dial": "host:port"}]}
```

Step J expands this to a real pool plus load-balancing and health-check
config. The emitted shape, for a route with the relevant features set:

```json
{
  "handler": "reverse_proxy",
  "upstreams": [
    {"dial": "host1:port"},
    {"dial": "host2:port"}
  ],
  "load_balancing": {
    "selection_policy": {"policy": "round_robin"}
  },
  "health_checks": {
    "active": {
      "uri": "/healthz",
      "method": "GET",
      "interval": "30s",
      "timeout": "5s",
      "expect_status": 200,
      "passes": 1,
      "fails": 1
    }
  }
}
```

Generation rules:

- **Upstreams.** Loop over `r.Upstreams`; emit one `{"dial": ...}` per
  element via the existing `upstreamDial` helper (scheme/host/port
  extraction, default-port injection). A one-element pool emits exactly
  today's shape — Step I behaviour is preserved for migrated routes.
- **Load balancing.** Always emit `load_balancing.selection_policy` with the
  `policy` field set to `r.LBPolicy`. For `weighted_round_robin`, also emit a
  `weights` array built from `r.Upstreams[].Weight` in pool order. The other
  five policies need no extra fields. Emitting the policy for a one-upstream
  route is harmless — selection is moot but valid.
- **Health checks.** When `r.HealthCheck.Enabled`, emit `health_checks.active`
  with every populated field (the defaults injection in §5.2 guarantees
  `method`, `interval`, `timeout`, `passes`, `fails` are non-blank);
  `expect_body` is emitted only when non-empty; `expect_status` is emitted
  only when non-zero (zero means "any 2xx", Caddy's documented behaviour).
  When health checks are disabled, the `health_checks` key is omitted
  entirely.

The reverse_proxy handler keeps its existing position in the per-route
handler chain (last, after WAF and headers — unchanged from Step I §3.2).
Only the handler's internal shape changes.

Anti-regression: `TestBuildConfigJSON_LoadsCleanly` (the Step I.7
`caddy.Validate()` e2e guard) is extended to cover a route exercising
multi-upstream + every LB policy + active health checks, so a malformed pool
or health-check block is caught at unit-test time.

### 3.3 DNS-01 ACME challenge

DNS-01 issues certificates by proving domain control via a DNS TXT record
rather than an HTTP request on port 80. It is required for **wildcard**
certificates (`*.example.com`), which HTTP-01 cannot issue. Step J adds
DNS-01 alongside the HTTP-01 path shipped in Step I. The supported
DNS-provider set in v1.0 is fixed at build time to one provider, OVH —
see §1.3 decision 8.

**New Go dependency.** `github.com/caddy-dns/ovh` v1.1.0 becomes a direct
dependency; it pulls `github.com/libdns/ovh` (indirect — `libdns/libdns` is
already indirect in `go.mod` from Step I). The module registers the Caddy
module ID `dns.providers.ovh`.

Caddy modules register via package `init()`, so the module must be imported
for its side effect. Following the Coraza precedent, Step J adds:

```go
import _ "github.com/caddy-dns/ovh"
```

next to the existing `_ "github.com/corazawaf/coraza-caddy/v2"` import in
`cmd/arenet/main.go`, with the same explanatory comment. The import is
duplicated in `internal/caddymgr/manager_test.go` so tests that validate a
DNS-01 config via `caddy.Validate()` can resolve `dns.providers.ovh` —
without it, the test fails with `unknown module` (the Step I Finding #2
failure mode).

**Schema additions.** DNS-01 touches the schema in two places:

- **Per route** — a new `ACMEChallenge string` field on `Route`: `http-01`
  (default) or `dns-01`. A wildcard host (`*.x.y`) requires `dns-01`;
  HTTP-01 cannot issue wildcards. This is the only route-schema addition for
  DNS-01 (the multi-upstream route-schema changes are in §3.1).
- **Instance level** — a new DNS provider configuration object, stored once
  per Arenet instance, not per route (locked decision, below). It holds the
  OVH credentials: `endpoint` (one of seven OVH regions, e.g. `ovh-eu`),
  `application_key`, `application_secret`, `consumer_key`. The exact storage
  location within Arenet's settings is detailed in §5.4.

**Why instance-level credentials.** A homelab runs one DNS provider account;
every wildcard certificate uses the same OVH credentials. Storing the
triplet per route would duplicate the same secret across N routes and
require editing N routes to rotate it. One instance-level object is set
once, secured once, rotated once. `buildConfigJSON` reads that single object
and emits the provider block into each DNS-01 ACME policy that needs it.

**Generator extension.** `buildTLSPolicies` (`internal/caddymgr/manager.go`)
is extended so that, for an ACME policy whose route uses `dns-01`, the
`acme` issuer carries a `challenges` block built from the instance DNS
provider config:

```json
{
  "module": "acme",
  "ca": "...",
  "email": "...",
  "challenges": {
    "dns": {
      "provider": {
        "name": "ovh",
        "endpoint": "ovh-eu",
        "application_key": "...",
        "application_secret": "...",
        "consumer_key": "..."
      }
    }
  }
}
```

The generator emits `challenges.dns` for any route whose `ACMEChallenge` is
`dns-01`; the wildcard-host constraint (a wildcard host requires `dns-01`)
is enforced earlier, at the API validation layer.

**Secret handling.** The OVH credentials — `application_key`,
`application_secret`, `consumer_key` — are handled with the discipline the
§1.6 threat model requires: the API never returns them, they never appear
in audit-log payloads, and they are never logged, exactly as the Step I.5
Basic Auth hash. The `endpoint` field (a region identifier, not a secret)
round-trips normally.

Anti-regression: `TestBuildConfigJSON_LoadsCleanly` is extended with a
DNS-01 + wildcard route so `caddy.Validate()` provisions `dns.providers.ovh`
and confirms the side-effect import is wired — the guard pattern that would
have caught Step I Finding #2.

### 3.4 Frontend impact

All frontend changes are on the routes page
(`web/frontend/src/routes/routes/+page.svelte`), its API types
(`web/frontend/src/lib/api/types.ts`), and the Settings page (for the DNS
provider config). No new top-level pages.

**Route form — upstream pool.** The single `upstreamUrl` text input becomes
an **upstream repeater**: an add / remove list of `{url, weight}` rows. This
reuses the repeater pattern already in place for aliases and request /
response headers — no new component primitive. The `weight` input is shown
only when the selected LB policy is `weighted_round_robin`.

**Route form — load balancing.** A `select` for the LB policy with the six
options, default `round_robin`. Shown when the pool has more than one
upstream; for a single-upstream route the selector may be hidden (selection
is moot — the route keeps the default policy).

**Route form — health checks.** A collapsible "Active health check"
sub-form, gated by an enable toggle (the `healthCheck.enabled` flag). When
enabled it exposes the §3.1 fields (`uri`, `method`, `interval`, `timeout`,
`expectStatus`, `expectBody`, `passes`, `fails`). The defaults (§1.3
decision 4) are **not** pre-filled into the form state: the UI shows the
five defaultable fields as blank inputs with the default values surfaced
as placeholders, and the server materialises the defaults at create /
update (see §5.2). `uri` is required (no default). Per-field UI rules,
the gating semantics, and the create/edit asymmetry are detailed in §5.3.

**Route form — ACME challenge.** A `select` for `http-01` (default) /
`dns-01`, shown only when TLS is enabled on the route. When `dns-01` is
selected and no instance DNS provider is configured, the form surfaces a
hint pointing to the Settings page. A wildcard host forces `dns-01` (the
selector locks to it).

**Settings page — DNS provider.** The instance-level OVH provider config
gets a section on the Settings page: an `endpoint` select (the seven OVH
regions) and three secret inputs (`application_key`, `application_secret`,
`consumer_key`) rendered as masked fields. Consistent with the Step I.5
Basic Auth treatment, the secret fields follow the write-only /
preserve-on-edit pattern — a saved credential is never echoed back; leaving
a field blank on edit preserves the stored value.

**TS types.** `RouteRequest` gains `upstreams: Upstream[]`, `lbPolicy`,
`healthCheck`, and `acmeChallenge`; `upstreamUrl` is removed. A new type
covers the Settings DNS provider object.

**Tests.** The 141-test frontend suite (Step I baseline) is extended to
cover the upstream repeater, the conditional weight field, the health-check
sub-form gating, and the ACME-challenge selector. The component test count
rises accordingly.

## 4. Sub-tasks (ordered)

Step J is implemented as six sub-task commits (J.1–J.4, J.6, J.7;
J.5 is deferred — see §1.4), in the order below. Each is committed
only when `gofmt`, `go vet`, `go build`, the Go test suite, and the
frontend checks (`npm run check`, `npm test`, `npm run build`) are all
green — the per-commit sanity gate established in Step I. Per-sub-task
design detail is in §5 (J.1–J.6); the J.7 smoke is designed in §7.

**J.1 — Multi-upstream model, migration, load-balancing policies.** Replace
`Route.UpstreamURL` with the `Upstreams` pool, add `LBPolicy`, run the
backward-compatible BoltDB migration, and wire the six LB policies through
the API and the `buildConfigJSON` generator. Backend + generator only.
Delivers AC #1, #2, #3, #4, #5.

**J.2 — Active health checks.** Add the `HealthCheck` config to the route
schema, its API validation, and the `health_checks.active` block in the
generator. Backend + generator only. Delivers AC #6, #7, #8.

**J.3 — Frontend: multi-upstream UI.** The upstream repeater, the LB-policy
selector, the conditional weight field, and the health-check sub-form on the
routes page. Frontend only. Completes the multi-upstream / health-check UI
through which AC #1–#8 are exercised.

**J.4 — DNS-01 ACME challenge.** Add the `caddy-dns/ovh` dependency and its
side-effect import, the per-route `ACMEChallenge` field, the instance-level
DNS provider config and its Settings-page UI, and the `challenges.dns`
generator extension. Delivers AC #9, #10.

**J.5 — WAF observability completion. DEFERRED — see §1.4.** Originally
scoped for AC #11 + AC #12; not implemented in Step J. The slot is kept
so the numbering of J.6 and J.7 stays stable.

**J.6 — Topology visual design pass.** A visual redesign of the Topology
page, including the auto-fit-on-load fix for Step I Finding #10. Frontend
only. Delivers AC #13.

**J.7 — Live smoke test.** The manual validation session against the
J.1–J.6 build, mirroring Step I.7: every AC exercised, findings recorded,
verdict emitted, the smoke doc written. Any bug it surfaces is fixed in a
hotfix commit before the `v0.6.0-step-j` tag. AC #14–#17 (lint / tests /
bundle) are verified as part of this gate.

## 5. Per-sub-task design

### 5.1 J.1 — Multi-upstream model, migration, load-balancing policies

J.1 is the keystone backend sub-task: it changes the route's upstream
representation from a single string to a pool, adds the load-balancing
policy field, migrates every stored route, and wires the six policies into
the generator. No frontend — that is J.3.

**Domain model** (`internal/storage/routes.go`). Add the `Upstream` type
from §3.1. On `Route`: remove `UpstreamURL string`; add
`Upstreams []Upstream` and `LBPolicy string`. The `HealthCheck` type and
field are J.2 — not touched here.

**BoltDB migration.** A new migration function in
`internal/storage/migrate.go`, a sibling of Step I.4's
`migrateWAFEnabledToWAFMode`, runs at boot. For each stored route it
detects the legacy shape — an `upstream_url` key present, `upstreams`
absent — and rewrites it:

- `upstream_url: "X"` becomes `upstreams: [{url: "X", weight: 1}]`
- `lb_policy` is set to `"round_robin"`
- the `upstream_url` key is dropped.

Because the post-J.1 `Route` struct no longer has an `UpstreamURL` field,
the migration reads the legacy value through a transitional struct that
still carries `UpstreamURL` (used only by the migration), then writes the
new shape. The migration is **idempotent**: a route already in the new
shape (`upstreams` present, no `upstream_url`) is skipped. A migrated
one-element route is equivalent in proxy behaviour to its pre-J.1 self —
locked decision 6, AC #2.

**Load-balancing policies.** `LBPolicy` accepts the six values from §1.3:
`round_robin`, `weighted_round_robin`, `least_conn`, `ip_hash`, `random`,
`first`. The API defaults `lbPolicy` to `round_robin` when the field is
omitted on create; otherwise the value must be one of the six.
`Upstream.Weight` defaults to 1 and is consulted only when the policy is
`weighted_round_robin`.

**Generator** (`internal/caddymgr/manager.go`). `buildConfigJSON` emits the
pool and `load_balancing.selection_policy` exactly as specified in §3.2:
one `{"dial": ...}` per pool entry via the existing `upstreamDial` helper,
and `selection_policy` set from `LBPolicy` — with the `weights` array
(built from `Upstreams[].Weight` in pool order) added for
`weighted_round_robin`.

**API validation** (`internal/api`). On create and update:

- `upstreams` must contain at least one entry; each `url` is validated by
  the existing per-element `validateUpstreamURL` logic (http/https scheme,
  non-empty host); each `weight` must be a positive integer.
- `lbPolicy`, when present, must be one of the six enum values.

**Tests.**

- Migration: `TestMigrate_UpstreamURLBecomesPool` (legacy route migrates to
  a one-element pool with `round_robin` and no `upstream_url`) and
  `TestMigrate_UpstreamMigration_Idempotent` (a second run is a no-op,
  byte-equality on the stored record).
- Generator: one test per policy asserting the emitted
  `selection_policy.policy`, plus one asserting the `weights` array for
  `weighted_round_robin` and one asserting a multi-element `upstreams`
  array.
- Validation: empty pool rejected, invalid upstream URL rejected, unknown
  `lbPolicy` rejected, non-positive `weight` rejected — each with a clear
  API error.
- `TestBuildConfigJSON_LoadsCleanly` (the Step I.7 `caddy.Validate()` e2e
  guard) is extended with a multi-upstream route exercising every LB
  policy, so a malformed pool or policy block fails at unit-test time.

### 5.2 J.2 — Active health checks

J.2 is a backend-only sub-task, like J.1: it adds the per-route active
health-check configuration, validates it, and emits it through the
generator. No frontend — the health-check sub-form is J.3. J.2 builds on
the upstream pool delivered by J.1: a single `HealthCheck` on the route is
applied by Caddy to every upstream in the pool, per the §1.3 decision and
empirically confirmed against Caddy v2.11.3 (`health_checks` sits at the
handler level, sibling of `upstreams`, not per-upstream).

J.2 delivers AC #6 (failed upstream pulled from rotation), AC #7
(recovered upstream restored), and AC #8 (health-check config validation),
per the sub-task mapping in §4.

**Domain model** (`internal/storage/routes.go`). Add the `HealthCheck`
type from §3.1 and a ``HealthCheck HealthCheck `json:"health_check"` ``
field on `Route`. Verbatim:

```go
type HealthCheck struct {
    Enabled      bool   `json:"enabled"`
    URI          string `json:"uri"`
    Method       string `json:"method"`
    Interval     string `json:"interval"`
    Timeout      string `json:"timeout"`
    ExpectStatus int    `json:"expect_status"`
    ExpectBody   string `json:"expect_body"`
    Passes       int    `json:"passes"`
    Fails        int    `json:"fails"`
}
```

- `Interval` and `Timeout` are Go strings (e.g. `"30s"`) — Caddy parses
  the string at unmarshal, so Arenet stays in human-readable form end-to-
  end. No int-nanosecond conversion anywhere.
- No `,omitempty` on the JSON tags — consistent with the existing `Route`
  pattern (`Aliases`, `RequestHeaders`, `ResponseHeaders` are all
  marshalled even when zero / empty).
- One `HealthCheck` per route, applied by Caddy to the whole pool —
  per-upstream overrides (`headers`, `port`, request body, etc.) are out
  of scope v1.0 per §1.3.

**No migration.** A reader who saw J.1 migrate every stored row may
expect a migration here too — there is none, and the reason is worth
making explicit.

J.2 **adds** a field to `Route`; it does not rewrite the shape of any
existing row the way J.1 does. A row persisted by J.1 has no
`health_check` key. Standard Go `json.Unmarshal` decodes a missing key
to the field's zero value, which for `HealthCheck` is
`{Enabled: false, URI: "", ..., Passes: 0, Fails: 0}` — and the generator
(below) omits the entire `health_checks` block when `Enabled` is false.
No probe runs, no behaviour change, no `migrate.go` function needed. This
was confirmed empirically with a round-trip `json.Unmarshal` test against a
J.1-era row during the §5.2 reconnaissance.

Contrast with J.1: J.1 replaced `UpstreamURL string` with
`Upstreams []Upstream` — a structural change requiring every stored row to
be rewritten before the post-J.1 code can read it. J.2 is a pure field
addition with a safe zero value; the path J.1 took is unnecessary.

**Defaults (Arenet-side injection).** Per §1.3 decision 4, Arenet
materialises the defaults rather than relying on Caddy's runtime defaults.
A small set of named constants lives next to the validation, in one place:

```go
const (
    defaultHCMethod   = "GET"
    defaultHCInterval = "30s"
    defaultHCTimeout  = "5s"
    defaultHCPasses   = 1
    defaultHCFails    = 1
)
```

The API layer injects them on every create and update where
`HealthCheck.Enabled` is true and the corresponding field is blank (zero
string or zero int). The injection runs **before** validation, so the
validation rules below face a fully-populated `HealthCheck`.

`uri` is **not** in the defaults set — it is the one field the operator
must always supply explicitly when `Enabled: true`. A blank `uri` at this
stage means the operator forgot it, not "use the default"; the validator
rejects with a clear error. There is no sensible default health-check path
that fits every backend.

The injection also covers the transition `Enabled: false → true` on a PUT
— a route flipping its health check on, with `uri` supplied and the
remaining five fields blank, receives the five defaults and validates
cleanly.

The motivation is consistency: a `GET /api/v1/routes/{id}` and the JSON
emitted to Caddy both show the effective configuration explicitly —
`interval: "30s"` rather than `interval: ""`. Operators read the route's
actual behaviour from the API; future Caddy default changes do not
silently shift Arenet's promise (notably the 30s interval that §1.6's
threat analysis relies on).

**Generator** (`internal/caddymgr/manager.go`). `buildConfigJSON` emits
the `health_checks.active` block exactly as specified in §3.2 and as
empirically confirmed against Caddy v2.11.3. The handler-level shape, for
a route with the health check enabled:

```json
{
  "handler": "reverse_proxy",
  "upstreams": [ ... ],
  "load_balancing": { ... },
  "health_checks": {
    "active": {
      "uri": "/healthz",
      "method": "GET",
      "interval": "30s",
      "timeout": "5s",
      "expect_status": 200,
      "passes": 1,
      "fails": 1
    }
  }
}
```

Generation rules:

- The emission is **unconditional when `Enabled` is true**: every field
  populated by the defaults injection appears in the JSON. This is the
  payoff of the inject-before-validate stage above — the generator never
  has to decide whether to leave a key out for "use Caddy default".
- `interval` and `timeout` are emitted as their Go string verbatim
  (`"30s"`, `"5s"`). Caddy parses the string at unmarshal — confirmed
  empirically during reconnaissance; no nanosecond conversion in Arenet.
- `expect_body` is emitted only when non-empty (a blank regex is
  semantically "no body check" and would otherwise be confusing in the
  emitted config).
- `expect_status` is emitted only when non-zero (zero means "any 2xx",
  Caddy's documented behaviour).
- When `Enabled` is false the **entire** `health_checks` key is omitted —
  no `{"active": ...}` placeholder, nothing.

**API validation** (`internal/api`). Runs after the defaults injection.
The validation is uniformly strict — there is no "blank or positive"
branching, because blanks were filled upstream.

When `Enabled` is false, the rest of the `HealthCheck` is inert and not
validated.

When `Enabled` is true:

- `uri` is required and must start with `/`.
- `method` is uppercased before the check (`strings.ToUpper`) and must
  then equal `GET` or `HEAD`. Per §1.3 decision 4 the probe is
  non-mutating; the validator enforces the set. The normalisation is
  written back into the stored Route, so a route created with `method:
  "head"` reads back as `"HEAD"`.
- `interval` and `timeout` must parse via `time.ParseDuration` and be
  strictly positive.
- `timeout < interval` — a timeout greater than or equal to the probe
  interval would let probes pile up.
- `expect_status` must be 0 (caller did not specify, meaning any 2xx) or
  a valid HTTP status code in the 100–599 range.
- `expect_body`, when non-empty, must compile via `regexp.Compile`. The
  ReDoS angle is addressed in §1.6 — not re-litigated here.
- `passes >= 1` and `fails >= 1`.

**Tests.**

- Generator: route with `Enabled: true` emits the full `health_checks.
  active` block with every populated key; route with `Enabled: false`
  emits no `health_checks` key at all; one targeted test per field
  asserting the value flows through verbatim (e.g. `interval` set to
  `"45s"` ends up as `"interval": "45s"` in the JSON).
- Validation: `uri` empty rejected; `uri` not starting with `/` rejected;
  `method` outside `{GET, HEAD}` rejected; `interval` / `timeout` not
  parseable rejected; `timeout >= interval` rejected; `expect_status`
  outside 0 or 100–599 rejected; malformed `expect_body` regex rejected;
  `passes < 1` or `fails < 1` rejected. Each with a clear API error.
- Defaults: a route created with `Enabled: true`, `URI: "/healthz"`, and
  the other five defaultable fields blank ends up stored with
  `Method: "GET"`, `Interval: "30s"`, `Timeout: "5s"`, `Passes: 1`,
  `Fails: 1`; a PUT flipping `Enabled` from false to true on a stored
  route, with `URI` supplied and the same five fields blank, injects the
  same five defaults and validates cleanly. A separate test asserts that
  a create / PUT with `Enabled: true` and blank `URI` is **rejected** —
  `uri` is required, not defaultable.
- Decode of a J.1-era row: a JSON byte sequence representing a
  pre-J.2 route (no `health_check` key) decodes via `json.Unmarshal` into a
  `Route` whose `HealthCheck.Enabled` is false, and the generator emits a
  config with no `health_checks` block. This is the J.2 equivalent of
  J.1's migration-idempotency test — but it asserts decode + generation,
  not migration (there is no `migrate.go` change in J.2).
- `TestBuildConfigJSON_LoadsCleanly` (the Step I.7 `caddy.Validate()` e2e
  guard, already extended in J.1) is extended once more with a route that
  has the active health check enabled. The fixture exercises every
  emitted field at least once, so a typo in the generator (e.g. wrong
  JSON tag, wrong nesting) is caught by Caddy's own Provision pass.

### 5.3 J.3 — Frontend: multi-upstream UI

J.3 is Step J's only frontend sub-task. It ships the UI that makes the
backend pieces J.1 and J.2 reachable from the admin: the upstream pool
editor, the load-balancing policy selector, and the active health-check
sub-form on the route create/edit modal. The frontend overview is in
§3.4; the per-sub-task design here adds the rules J.3 needs to follow
when implementing it.

J.3 does not deliver a §2 AC of its own — no AC mandates a specific UI
shape. It is the means by which the backend AC #1–#8 (delivered by J.1
and J.2) become exerciseable in the J.7 smoke. AC #14 (`npm test` green)
is the quality gate J.3 must clear before the commit.

**Component & decomposition** (`web/frontend/src/routes/routes/+page.svelte`).
J.3 stays in the existing monolithic page — no new `RouteForm.svelte`
sub-component is introduced. The Step I create/edit form already lives in
an inline `<Modal>` inside `routes/+page.svelte` (~640 lines), and every
existing repeater (aliases, request headers, response headers) is also
inlined. J.3 adds three concerns of comparable size — a fourth repeater,
a select, and a sub-form — which fit the same scale; extracting any one
of them into a separate component would create asymmetry without solving
a real problem. The page grows, the structure stays. A future refactor
that extracts the entire form is out of scope.

**Upstream pool editor.** A fourth repeater on the form, carbon copy of
the alias / header repeater pattern already in place. Each row renders
two inputs side by side:

- A URL `<Input>` bound to `formData.upstreams[i].url`, with the
  `placeholder="http://127.0.0.1:8080"` from the existing single-upstream
  field reused verbatim.
- A weight `<Input type="number">` bound to `formData.upstreams[i].weight`,
  with `min="1"` and `placeholder="1"`.

A `+ Add upstream` button at the bottom appends a row, initialised to
`{ url: "", weight: 1 }` — the `weight: 1` default matches the §3.1
domain default and avoids the user having to think about weights when
they only care about adding a backend. An `×` button per row removes the
row. The remove button is disabled on the last remaining row — the
client enforces the §3.1 "at least one upstream" rule before the server
has to. The weight input is hidden (the column collapses) when
`formData.lbPolicy !== "weighted_round_robin"`; switching back to
weighted RR restores the inputs with the previously stored weight values
(state is kept across visibility flips, not reset).

On edit-mode populate (`openEdit(r)`), the pool is mapped from the
stored route as-is — a one-upstream route migrated from Step I shows a
single-row repeater.

**LB policy selector.** A `<select>` bound to `formData.lbPolicy`, with
the six values from §1.3 decision 2 (`round_robin`,
`weighted_round_robin`, `least_conn`, `ip_hash`, `random`, `first`),
default `round_robin`. The selector is **hidden** when the pool has only
one upstream — selection is moot there. It appears as soon as a second
upstream is added and disappears if the user removes back down to one.
The underlying `formData.lbPolicy` is preserved across visibility flips
(so an admin who picked `weighted_round_robin`, removed an upstream,
then re-added one does not silently lose the choice).

**Health-check sub-form.** A single `<Checkbox>` for
`formData.healthCheck.enabled` controls the rest. When unchecked, the
eight sub-fields are rendered as disabled inputs (greyed, not editable),
and they are excluded from the client-side validation pass below. When
checked, the inputs become editable.

Crucially, **toggling the checkbox does not clear the sub-fields' state**
— a user who flips enabled off and back on finds the same values they had
typed. This matches the LB-selector behaviour for weight visibility and
prevents accidental data loss when the user is exploring the form.

The eight fields:

- `uri` — required, no default, placeholder `"/healthz"`, marked
  required in the label (asterisk and `aria-required="true"`).
- `method` — `<select>` with two options `GET` and `HEAD`, per §1.3
  decision 4. `GET` is the pre-selected option, and
  `formData.healthCheck.method` is initialised to `"GET"`; the server
  receives an explicit value, never a blank. This is a deliberate,
  contained exception to the "blank in create" rule below — a binary
  select offers no useful blank state.
- `interval`, `timeout` — text `<Input>`, `placeholder="30s"` and
  `placeholder="5s"` respectively. Inputs accept any string; client
  validation parses it.
- `expectStatus` — `<Input type="number">` with `placeholder="200"`,
  `min="0"`, `max="599"`.
- `expectBody` — text `<Input>`, optional, no placeholder.
- `passes`, `fails` — `<Input type="number">` with `placeholder="1"`,
  `min="1"`.

The §1.3 default values are sourced from a single TS constants object,
co-located with the form code, mirroring the server-side
`defaultHC*` constants of §5.2:

```ts
const HEALTH_CHECK_DEFAULTS = {
    method: 'GET',
    interval: '30s',
    timeout: '5s',
    passes: 1,
    fails: 1,
} as const;
// Must stay in sync with §1.3 decision 4 (Arenet-owned defaults).
```

This object is the source of truth on the client for the four
defaultable text/number fields' placeholders (`interval`, `timeout`,
`passes`, `fails`) and for the initial `method` select value. The
`expectStatus` placeholder (`"200"`) and the `uri` placeholder
(`"/healthz"`) are illustrative examples, **not** defaults — they live
as inline placeholder strings on the inputs and are not synchronised
with §1.3.

A comment in the source pins the relationship to §1.3 so a future change
to the server-side defaults surfaces the placeholder dependency.

**Defaults UI policy.** The form is **not** pre-filled with the
defaultable values. The reason is that the server materialises the
defaults at create/update (§5.2): pre-filling the form would create two
sources of default values, and a divergence between them would silently
mislead the operator about what is actually stored.

The chosen behaviour:

- **Create mode**: the four defaultable text/number fields (`interval`,
  `timeout`, `passes`, `fails`) are blank in the UI, with the §1.3
  values surfaced as placeholders. The user can type to override;
  leaving a field blank submits a blank string/int; the server fills it
  with the default and stores the effective value. `method` is a binary
  select, deliberately pre-set to `GET` rather than blank — a
  contained exception explained above.
- **Edit mode**: the form is populated from the stored route. Because
  the server materialised the defaults on the original create, the
  stored route already carries explicit values; the form shows them
  populated. There are no blanks to misinterpret.

The asymmetry (blank in create, populated in edit) is **intentional**:
it reflects "the server is authoritative; the UI shows what is actually
stored, never what the UI thinks should be." A user who explicitly
**clears** a defaultable field on edit and saves triggers the same
server-side default injection — the edit reads back populated again.
This is consistent and explained as such in the form's affordances.

**Validation client.** J.3 introduces the first non-trivial client-side
validation in the route form. The Step I pattern (one `$state<string>`
per validated field, e.g. `hostError`, `upstreamError`) does not scale
to ~13 new fields, so J.3 refactors to a single error map:

```ts
let errors = $state<Record<string, string>>({});
```

Keys are the formData field paths, e.g. `upstreams[2].url`,
`healthCheck.interval`, `lbPolicy`. The existing per-field error states
(`hostError`, `upstreamError`) migrate into this map; `formError` (the
banner-level error) is preserved as a separate `$state<string | null>`.

The client validation runs at submit, mirroring §5.1 (multi-upstream
rules) and §5.2 (health-check rules):

- Each upstream URL is parsed client-side; an invalid URL surfaces an
  inline error on the row before submit. Weights below 1 are rejected
  inline.
- `lbPolicy`, when visible, is bound to the select so an invalid value
  is unreachable through the UI.
- When `healthCheck.enabled` is true: `uri` non-empty and starting with
  `/`; `interval` / `timeout` parsing (a minimal client-side duration
  regex matching Go's `time.ParseDuration` shape); `timeout < interval`;
  `expectStatus` in 0 or 100–599; `expectBody`, if non-empty,
  client-tested by compiling a `new RegExp(...)` in a try/catch;
  `passes` / `fails` `>= 1`.

The server remains authoritative. The existing `fieldFromMessage()`
heuristic (`internal/api` errors with a field prefix) is preserved as a
fallback: any server-side rejection that the client did not pre-catch
still surfaces on the right row via the same heuristic, written to the
same `errors` map.

**TS types** (`web/frontend/src/lib/api/types.ts`). `RouteRequest`
gains the §3.1 fields: `upstreams: Upstream[]`, `lbPolicy: LBPolicy`,
`healthCheck: HealthCheck`. The corresponding TS types are defined
verbatim from §3.1 and §3.3. `upstreamUrl` is removed. The
`acmeChallenge` field and the Settings DNS provider type are added in
J.4, not here.

**Tests.** The 141-test frontend baseline (Step I) is extended:

- Upstream repeater: add / remove rows; a newly added row initialises
  to `{ url: "", weight: 1 }`; remove disabled on the last row; pool
  state preserved across LB-policy changes; one-upstream route from
  Step I shows a single row.
- LB selector visibility: hidden at pool size 1, shown at size ≥ 2,
  state preserved across visibility flips.
- Weight input visibility: shown only when `lbPolicy ===
  "weighted_round_robin"`, state preserved across visibility flips.
- Health-check gating: sub-fields disabled when `enabled` is false;
  toggling the checkbox does not clear the sub-field state.
- Health-check validation: each rule from §5.2 has a matching
  client-side rejection test (invalid `uri` shape, unparseable
  `interval`, `timeout >= interval`, out-of-range `expectStatus`,
  malformed `expectBody` regex, `passes < 1`, `fails < 1`).
- Defaults asymmetry: create-mode form has blank defaultable fields
  with the §1.3 placeholders surfaced; an edit-mode form populated
  from a server-side-materialised route shows the explicit values; a
  user clearing a defaultable field on edit and saving re-reads the
  field populated.
- Error map: `errors` map keyed by field path; server-side rejection
  with a known field prefix lands on the right row via the existing
  `fieldFromMessage()` fallback.

The component test count rises accordingly; the precise count is
asserted live in J.7 (AC #14).

### 5.4 J.4 — DNS-01 ACME challenge

J.4 ships DNS-01 ACME alongside the HTTP-01 path Step I delivered.
DNS-01 issues certificates by proving control of a DNS zone via a
`_acme-challenge` TXT record rather than an HTTP request on port 80; it
is the only ACME challenge that can issue **wildcard** certificates
(`*.example.com`). The supported DNS provider in v1.0 is OVH (§1.3
decision 8, §3.3); the provider is fixed at build time via an anonymous
import of `github.com/caddy-dns/ovh` in `cmd/arenet/main.go`.

J.4 delivers AC #9 (DNS-01 wildcard issuance — PARTIAL acceptable per
the AC's own wording, since the public ACME round-trip depends on a
real DNS account) and AC #10 (DNS provider credentials never echoed by
the API or audit log).

**Component & decomposition.** J.4 touches three layers: the storage
schema (`internal/storage/routes.go` for the per-route field; a new
`internal/storage/dns_provider.go` or comparable file for the
instance-level provider config), the API (`internal/api` for the
per-route field validation, the new Settings endpoints, and the secret
discipline), the Caddy generator (`internal/caddymgr/manager.go` for
`buildTLSPolicies`), and the frontend (the route form's ACME selector
in `routes/+page.svelte`, plus a new Settings-page section). No new
top-level page — the Settings page already exists from Step I.

**Domain model — route.** §3.1 lists ``ACMEChallenge string
`json:"acme_challenge"` `` as a new `Route` field. J.4 implements it:

- Values: `"http-01"` (default) and `"dns-01"`. No other values.
- Per route, not per instance: a route may use HTTP-01 even if another
  route on the same Arenet uses DNS-01, and vice versa.
- The legacy HTTP-01 path from Step I is the default — every route
  created before J.4, and every route created post-J.4 without
  explicitly setting `acmeChallenge`, gets HTTP-01.

**Domain model — instance-level DNS provider config.** A new struct
holds the OVH credentials, stored once per Arenet instance, not per
route (§3.3 "why instance-level credentials"). Verbatim:

```go
type DNSProviderConfig struct {
    Endpoint          string `json:"endpoint"`
    ApplicationKey    string `json:"application_key"`    // SECRET — never echoed by the API or audit
    ApplicationSecret string `json:"application_secret"` // SECRET — never echoed by the API or audit
    ConsumerKey       string `json:"consumer_key"`       // SECRET — never echoed by the API or audit
}
```

- `Endpoint` is the OVH region — one of the seven values from the
  go-ovh SDK's `Endpoints` map (`ovh-eu`, `ovh-ca`, `ovh-us`,
  `kimsufi-eu`, `kimsufi-ca`, `soyoustart-eu`, `soyoustart-ca`),
  verified empirically against `go-ovh@v1.7.0/ovh/ovh.go`. Not a
  secret; round-trips normally. v1.0 is restricted to those seven
  named regions; supporting a raw endpoint URL (also accepted by
  `go-ovh`) is a backlog item.
- The three `*Key` / `*Secret` fields are the OVH API credentials. The
  imperative `// SECRET` comments mirror the Step I.5 `BasicAuthPasswordHash`
  pattern (`internal/storage/routes.go:57-61`) and are the source of
  truth for the redaction discipline below.
- A single instance — Arenet stores at most one `DNSProviderConfig`.
  Storage location: a new bucket / key in BoltDB, parallel to the
  existing settings storage from Step I.
- **Lifecycle.** `DNSProviderConfig` supports create (first `PUT`),
  read (`GET`), and update (subsequent `PUT` with preserve-on-edit
  semantics). **No delete endpoint in v1.0.** Deleting the config
  while routes depend on it would silently break those routes at the
  next Arenet reload — the rejection has to happen synchronously and
  visibly, and v1.0 simply forbids the delete to avoid the design
  complexity of a referenced-routes guard. If an operator needs to
  rotate to a different OVH account, they `PUT` the new credentials
  over the existing config. A guarded delete (refuses while any
  `dns-01` route exists) is a backlog item.

**No migration; defaults.** Pure additions, no schema rewrite:

- `Route.ACMEChallenge`: a row persisted before J.4 has no
  `acme_challenge` key; standard `json.Unmarshal` decodes the missing
  key to the zero value `""`. The API and the generator both treat `""`
  as equivalent to `"http-01"` — every pre-J.4 route keeps its Step I
  behaviour with no migration. Same pattern as J.2's `HealthCheck` field
  addition (§5.2 "No migration"), confirmed empirically by the same
  `json.Unmarshal` round-trip principle.
- `DNSProviderConfig`: a fresh Arenet install has none. A route that
  attempts DNS-01 without a configured provider is rejected at the API
  layer (validation below). No "default provider" exists — the operator
  must configure OVH before any DNS-01 route is accepted.

**Generator — refactor of `buildTLSPolicies`.** The Step I signature
takes `acmeSubjects []string` and emits one ACME policy plus an
internal catch-all (`internal/caddymgr/manager.go:601-622`). J.4 needs
to know which subjects go through which challenge, because the
`challenges.dns` block on the issuer only applies to DNS-01 subjects.

The refactor introduces a partition struct passed into
`buildTLSPolicies`:

```go
type acmePartition struct {
    HTTP01 []string
    DNS01  []string
}
```

The caller (the route iteration in `buildConfigJSON`) sorts each
TLS-enabled route's subjects into one slice or the other based on the
route's `ACMEChallenge`. The two-element split keeps the function
signature local to caddymgr — no new public types leak outside the
package.

`buildTLSPolicies` then emits **up to three policies**:

1. **HTTP-01 ACME policy**, if `HTTP01` is non-empty — same shape as
   Step I's single ACME policy today (no `challenges` block; HTTP-01 is
   the Caddy default).
2. **DNS-01 ACME policy**, if `DNS01` is non-empty — the same shape
   plus a `challenges.dns.provider` block sourced from the instance
   `DNSProviderConfig`.
3. **Internal CA policy**, always — the catch-all from Step I,
   unchanged.

The emitted DNS-01 policy shape, confirmed empirically against Caddy
v2.11.3 by `caddy adapt` on a Caddyfile probe during reconnaissance:

```json
{
  "subjects": ["*.example.com", "wild.example.com"],
  "issuers": [
    {
      "module": "acme",
      "ca": "...",
      "email": "...",
      "challenges": {
        "dns": {
          "provider": {
            "name": "ovh",
            "endpoint": "ovh-eu",
            "application_key": "...",
            "application_secret": "...",
            "consumer_key": "..."
          }
        }
      }
    }
  ]
}
```

Generator rules:

- `name: "ovh"` is **always** emitted inside `provider`. Caddy's
  `DNSChallengeConfig.ProviderRaw` carries a
  `caddy:"namespace=dns.providers inline_key=name"` tag — without
  `name`, Caddy cannot resolve which provider module to instantiate
  (empirically observed: `module not registered: dns.providers.ovh`).
- A **single** issuer per ACME policy (Let's Encrypt only). Step I
  ships exactly one issuer per policy; J.4 does not introduce a
  ZeroSSL fallback even though Caddy's Caddyfile adapter emits one by
  default. Arenet's HTTP-01 policy is single-issuer today; the DNS-01
  policy stays consistent.
- The `email` and `ca` fields are inherited from the existing helpers
  (`acmeDirectoryURL`, `opts.ACMEEmail`) — no new ACME wiring beyond
  the `challenges.dns` block.

**Failure mode — module not registered.** A route configured for
`dns-01` referencing the OVH provider, on an Arenet binary that does
not have `_ "github.com/caddy-dns/ovh"` compiled in, will fail
`caddy.Validate()` at Provision time with
`module not registered: dns.providers.ovh` — the exact failure mode of
Step I Finding #2. The guard is the same:
`TestBuildConfigJSON_LoadsCleanly` (extended in J.1 and J.2) is
extended again in J.4 with a route that uses DNS-01 and a fixture
`DNSProviderConfig`. If a future commit removes the anonymous import,
the test fails before reaching the smoke.

The test must import the OVH module too (the
`internal/caddymgr/manager_test.go` file gains its own
`_ "github.com/caddy-dns/ovh"`), mirroring the existing Coraza
duplication pattern at `manager_test.go:34`. Without the test-file
import, the unit test fails with the same `module not registered`
error even when the production binary is correctly wired.

**Secret discipline.** The three OVH credentials are handled with the
discipline §1.6 spells out: API-facing protections identical to Step
I.5's Basic Auth hash; hashing **not** applicable, since Arenet must
present the credentials to OVH at every ACME renewal.

The Step I.5 pattern (`internal/storage/routes.go:57-61`,
`internal/api/auth_handlers_test.go:117-118`,
`internal/api/handler_test.go:544`) is reproduced for J.4 with three
changes from the Basic Auth template:

- **No hashing.** The three secrets are stored verbatim in BoltDB,
  inside the `DNSProviderConfig` row. Hashing would make the
  credentials unusable for the renewal request.
- **At-rest threat model — stated consciously.** The credentials sit
  in cleartext inside the BoltDB file on disk. The protection boundary
  is the file's filesystem permissions (Arenet's process user owns
  the DB file; the homelab operator is responsible for not making it
  world-readable). At-rest encryption of the BoltDB file is **out of
  scope v1.0** and is a backlog item alongside any secret-at-rest
  hardening (e.g. age, OS keychain integration). The route from
  cleartext-in-BoltDB to a more hardened posture is a future step in
  its own right, not a J.4 amendment.
- **Write-only / preserve-on-edit at the API.** A `PUT
  /api/v1/settings/dns-provider` payload with a blank secret field
  preserves the stored value; only a non-blank secret field overwrites
  it. The `endpoint` field, not being a secret, round-trips normally
  (a blank `endpoint` on PUT is a config error rejected by the
  validator). Mirrors the Step I.5 frontend pattern §3.4 already
  describes for the route Basic Auth password.

Redaction rules (mirroring Step I.5):

- API GET responses for `DNSProviderConfig` carry the `endpoint`
  field, emit the three secret fields as empty strings (matching the
  Step I.5 precedent for the Basic Auth hash), and carry one
  additional config-level flag `configured: bool` — `true` when all
  three secrets are non-empty in storage, `false` otherwise. The flag
  is the single source of truth the frontend reads to render the
  "configured" / "not configured" status without revealing anything
  about which secret is missing. There is no per-secret status,
  deliberately: leaking "secret X is set but Y is not" would expose
  partial configuration shape, and a partial config is always
  rejected by validation anyway (below), so the binary distinction is
  the only meaningful one.
- Audit-log payloads for `dns_provider_updated` (or analogous) action
  emit the three secrets as empty strings in the `before` / `after`
  JSON, matching the `password_hash":""` redaction Step I.5 already
  applies (`internal/api/auth_handlers_test.go:147`).
- No `slog` call ever logs a `DNSProviderConfig` whole; helpers that
  format the struct for logging redact the three secret fields the
  same way audit does.

**API validation.** On create / update of a `Route` with
`acmeChallenge != ""`:

- `acmeChallenge` must be exactly `"http-01"` or `"dns-01"`. Any other
  value is rejected.
- If any host in the route's `Host` + `Aliases` is a wildcard (starts
  with `*.`), `acmeChallenge` must be `"dns-01"`. HTTP-01 cannot
  issue wildcards (`*.x.y` cannot be validated by an HTTP request to
  any concrete host).
- If `acmeChallenge` is `"dns-01"`, the instance `DNSProviderConfig`
  must be present in storage and all four fields must be non-empty
  (the three secrets and `endpoint`). The validator looks up the
  config at request time and rejects the route create / update if it
  is missing.

On create / update of the instance `DNSProviderConfig` (the Settings
endpoint):

- `endpoint` must be one of the seven OVH-region constants from the
  go-ovh SDK (`ovh-eu`, `ovh-ca`, `ovh-us`, `kimsufi-eu`,
  `kimsufi-ca`, `soyoustart-eu`, `soyoustart-ca`).
- Each of the three secret fields, when non-blank on a write, is
  stored verbatim (no further format check — OVH credentials are
  opaque tokens). When blank, the stored value is preserved (PUT
  semantics).

**Frontend.** Two surfaces:

- **Route create / edit form** — a new ACME-challenge `<select>`
  appears under the TLS section, visible only when `tlsEnabled` is
  true. Two options, `http-01` (default selected, value `"http-01"`)
  and `dns-01` (value `"dns-01"`). If the host or any alias is a
  wildcard, the selector is locked to `dns-01` (greyed, with a
  one-line explanation underneath: "Wildcard hosts require DNS-01"),
  matching the §3.4 description. If `dns-01` is selected and the
  Settings DNS provider is missing or incomplete, the form surfaces
  an inline hint with a link to the Settings page.
- **Settings page — DNS provider section.** Four inputs: `endpoint`
  (`<select>` with the seven OVH-region options) and the three secret
  fields (`<Input type="password">` with the visual masking
  treatment). The save handler implements the
  write-only / preserve-on-edit pattern: blank secret fields on save
  preserve the stored value. A single configuration-level status
  badge — "DNS provider configured" / "DNS provider not configured" —
  is rendered next to the section header, bound to the `configured:
  bool` flag the API surfaces (above). The badge is the only status
  surface; no per-secret indicator, deliberately matching the API
  contract.

**Tests.**

- Generator: route with `acmeChallenge: "http-01"` emits one ACME
  policy without `challenges.dns`; route with `acmeChallenge:
  "dns-01"` emits one ACME policy with `challenges.dns.provider.name
  == "ovh"`; mixed-routes config emits **two** ACME policies (HTTP-01
  + DNS-01) plus the internal catch-all; `name: "ovh"` is always
  present on the DNS-01 policy.
- `TestBuildConfigJSON_LoadsCleanly` extended with a DNS-01 route +
  fixture `DNSProviderConfig`; the test file imports
  `_ "github.com/caddy-dns/ovh"`; a deliberate failure-mode test
  could be added (in a separate file with no OVH import) to assert
  the `module not registered` error if the import is dropped — left
  to J.4 implementation discretion.
- Redaction: `TestDNSProvider_SecretsNeverInResponseBody` covering the
  GET path for `/api/v1/settings/dns-provider`; one assertion per
  secret field. `TestDNSProvider_SecretsNeverInAuditLog` covering the
  `dns_provider_updated` action audit emission; one assertion per
  secret field in both `before` and `after` JSON.
- Validation: a wildcard host with `acmeChallenge: "http-01"` is
  rejected; `acmeChallenge: "dns-01"` with no `DNSProviderConfig` in
  storage is rejected; `acmeChallenge: "dns-01"` with a partial
  config (one secret blank) is rejected; the seven OVH-region
  constants accepted, every other `endpoint` value rejected.
- Preserve-on-edit: a PUT to `DNSProviderConfig` with one secret blank
  preserves the stored secret for that field; same PUT with all four
  fields non-blank overwrites all four.
- Lifecycle: a DELETE on `/api/v1/settings/dns-provider` returns 405
  (or 404, depending on routing — the point is no delete is wired);
  one regression test asserts the endpoint is **not** registered.
- `configured: bool`: a GET on `DNSProviderConfig` after a complete
  PUT returns `configured: true` with the three secrets emitted as
  empty strings; a GET on a fresh install (no PUT yet) returns
  `configured: false` with the three secrets also empty; a GET after
  a (rejected) partial write still returns the pre-partial state's
  `configured` value (partial writes are rejected upstream, not
  half-applied).
- Frontend: the ACME-challenge selector renders only when TLS is on;
  it is locked to `dns-01` when the host is wildcard; the
  Settings-page DNS-provider section renders the seven endpoint
  options; the password-type inputs are correctly masked; a save with
  blank secret fields after a previous save does not erase the
  stored secrets (the equivalent of the redaction tests above,
  observed through the UI).

### 5.5 J.6 — Topology visual design pass

J.6 is the last design sub-task before the J.7 smoke. It is
frontend-only, like J.3. It delivers AC #13 (Topology visual pass +
auto-fit on load) and touches AC #14 (`npm test` green) as its quality
gate. The Step J frontend overview is in §3.4, which does not carry a
Topology-specific paragraph — J.6 is fully specified here.

**Scope & bounding.** The Step J brief described J.6 as "a visual
redesign / polish of the Topology page" without a fixed cutline. §5.5
**is** that cutline. What J.6 does, and what it does not, is enumerated
explicitly so the sub-task does not balloon at implementation time.

**In scope:**

- Auto-fit the graph to the viewport on first non-empty data —
  Finding #10 from Step I (detail below).
- Migrate the page's custom header (`+page.svelte:162-173`'s
  `.title` / `.subtitle` / `.status-block`) to the standard
  `<PageHeader>` component, with the WebSocket status indicator
  moved into PageHeader's right-aligned `actions` snippet.
- Update the documentation comment on `PageHeader.svelte` (`L15-16`
  today says "Topology and Setup/Login pages stay headerless") to
  reflect the new state.

**Out of scope, explicitly:**

- **The Step F §6 "Topology refonte" plan** (xyflow / node types
  custom / minimap / weighted MetricEdge / drag-persisted node
  positions) — declined NO-GO at Step F Chunk 4a (bundle 52 kB vs the
  30 kB budget, commit `a3cb7f6`); J.6 does **not** revive it.
  Reviving any piece of it is a dedicated future step.
- **Topology code-quality debt** — extracting a `<Sparkline>` atomic
  component out of `TopologyDetailPanel`, migrating the ad-hoc
  hover-timeout tooltip in `TopologyNode` to the `<Tooltip>` atomic,
  adding Vitest coverage for the visual components (Node, Svg,
  DetailPanel). Recorded in `docs/backlog-step-j.md` §5 "Out of Step J
  scope". Not in J.6.
- **Cosmetic touch-ups beyond the header migration.** The recon
  confirmed the page is 100 % design-tokens with zero hex hardcodes
  outside tests, and no `TODO`/`FIXME`/`polish` marker in the source.
  There is no concrete named cosmetic defect to fix. J.6's visible
  change is the standardised header + the auto-fit, full stop. Any
  "polish to taste" beyond that is the scope-creep vector this
  bounding section exists to prevent.

For an originally unbounded "visual design pass", §5.5 is the bounding
— J.6 ships two named changes, period.

**AC #13 mapping.** AC #13 reads "the Topology page ships its visual
redesign and auto-fits the graph to the viewport on load". The "visual
redesign" half is fulfilled by the bounding decision recorded in this
section (option 1) plus the `<PageHeader>` standardisation; the
"auto-fits on load" half is fulfilled by the Finding #10 fix below.
Together they exhaust AC #13, and the J.7 smoke evaluates the AC at
this level — not against an open-ended "looks better" yardstick.

**Auto-fit — Finding #10.** The page's pan / zoom transform store
(`web/frontend/src/lib/topology/viewport.svelte.ts`) already exposes a
`fitView()` function that computes the route bbox and sets `{x, y, k}`
to fit it. `TopologyControls` calls it from its "Fit view" button.
The Step I smoke's stated fix ("trigger the same handler from
`onMount`, probably a one-liner") is **almost right but has a trap**:
at the bare `onMount`, the topology store is **empty** — nodes arrive
via the first WebSocket snapshot at ~1 Hz. Calling `fitView()` before
that snapshot computes a bbox over zero nodes and produces a
nonsensical transform (likely identity or NaN, depending on the bbox
implementation).

The correct trigger is **the first non-empty data tick**: a `$effect`
that watches the route count and fires `fitView()` the first time it
transitions from 0 to > 0. **It must fire once, not on every tick** —
re-fitting on every snapshot would make the viewport jump every
second as routes appear/disappear, which would be worse than the
current behaviour. The implementation guards with a local `let
hasFit = false` flag that flips to `true` on first fit.

The page already has the building blocks (the viewport store, the
`fitView()` function, the topology store's reactive route count) —
J.6 is wiring, not new logic.

**Header migration — `<PageHeader>`.** The current header
(`+page.svelte:160-174`) carries the page title, subtitle, an
optional "Waiting for first tick…" notice, and a status block whose
dot is a page-local `<span class="status-dot status-dot-{statusDot}">`
with its own CSS (`+page.svelte:248-264`). It does not use the
standard `<PageHeader>` component the other pages adopted in Step F,
and it does not use the existing `<StatusDot>` atomic (already used
by `Sidebar` and `routes/+page.svelte`).

`<PageHeader>`'s public API (`web/frontend/src/lib/components/PageHeader.svelte`)
is `title: string`, `subtitle?: string`, `actions?: Snippet`. The
`actions` slot is right-aligned next to the title — exactly the
visual position the current Topology status block occupies. J.6
migrates the header to `<PageHeader>` and **swaps the page-local
`.status-dot` span for the `<StatusDot status>` atomic** at the same
time. `<StatusDot>` accepts `status: 'up' | 'warn' | 'down' | 'info'
| 'idle'`; the existing `statusDot` derived value (one of `up` /
`warn` / `down`) is passed through as-is. The "Waiting for first
tick…" notice and the textual `statusLabel` are preserved inside the
slot:

```svelte
<PageHeader title="Topology" subtitle="Live network visualization.">
  {#snippet actions()}
    {#if showWaitingForTick}
      <span class="waiting" aria-live="polite">Waiting for first tick…</span>
    {/if}
    <span class="status" aria-live="polite">
      <StatusDot status={statusDot} />
      {statusLabel}
    </span>
  {/snippet}
</PageHeader>
```

No `PageHeader.svelte` API change needed — the existing `actions`
Snippet handles arbitrary content. The old `.title` / `.subtitle` /
`.status-block` / `.status-dot{,-up,-warn,-down}` page-local CSS
(`+page.svelte:240-264` or thereabouts) is removed. The `.waiting`
and `.status` styles are kept on the page since they describe layout
of the slot content, not the atomic.

The documentation comment on `PageHeader.svelte:15-16` ("Topology and
Setup/Login pages stay headerless — they have their own UX patterns")
is **updated** to reflect that Topology now uses PageHeader; Setup /
Login stay headerless. This update is part of J.6, not a separate
chore.

**No further cosmetic changes.** The recon explicitly looked for
named visual defects on the page (`TODO`/`FIXME`/`polish` markers,
hex hardcodes outside design tokens, off-token spacing, broken
states) and found none. The page is on-tokens. Adding "polish to
taste" without a named defect would breach the bounding above. If a
specific visual issue surfaces during the J.7 smoke, it is a
finding, not a J.6 line item.

**Tests.** The Step I frontend baseline (141 tests, extended by J.3)
is extended again:

- Fit-on-first-data: with the topology store seeded empty, then
  populated with two routes via a simulated snapshot, the viewport
  transform must equal `fitView()`'s output once and only once. A
  second snapshot must **not** re-trigger the fit; the transform
  stays untouched (or, if the user has manually panned/zoomed since,
  it stays at the user's transform).
- Auto-fit guard: with the store still empty after mount, the
  viewport transform must equal its initial value — `fitView()` must
  not have been called against zero nodes.
- Header migration snapshot: a render snapshot of the page header
  before / after the migration. The "before" matches the legacy
  custom header, the "after" matches the `<PageHeader>`-based shape
  with the status indicator inside the `actions` slot.

The component test count rises accordingly; the precise count is
asserted live in J.7 (AC #14).

## 6. Migration strategy

Step J has **one** BoltDB schema migration (J.1, the upstream-pool
rewrite). J.2 and J.4 are pure field additions with safe zero values
and need no `migrate.go` function — §5.2 and §5.4 explain why each.
This section adds the boot-time orchestration of the J.1 migration,
the consolidated post-upgrade effects table, and the rollback
posture, so the upgrade story is documented in one place. Items
deferred beyond Step J live in `docs/backlog-step-j.md`.

### 6.1 J.1 migration — trigger and idempotency mechanics

§5.1 specifies *what* the J.1 migration does (legacy row →
one-element pool, `lb_policy = "round_robin"`, drop `upstream_url`).
§6.1 specifies *how it runs at boot*, by reusing the pattern Step I.4
established empirically.

**Trigger — boot scan, no schema-version gate.** The Step I.4
migration (`internal/storage/migrate.go:55-117`) is invoked from
`NewStore` (`storage.go:84`) on every Arenet startup, immediately
after the buckets are initialised. There is no `schema_version` key
in the DB; there is no global migration marker. Idempotency is
**per-row, shape-based**: the migration probes each row's JSON for
a sentinel field, and skips rows whose sentinel says "already
migrated". For Step I.4 the sentinel was `legacy.WAFMode != ""`. The
upside of this pattern is crash-safety — a run interrupted mid-bucket
leaves the DB in a coherent partial state, and the next boot completes
whatever rows were missed without external coordination.

J.1 follows the same pattern verbatim. A sibling function
`migrateUpstreamURLToPool` is added to `internal/storage/migrate.go`
and called from `NewStore` immediately after the Step I.4 migration,
in the same boot path. Its shape-based predicate is **the inverse**:
"already migrated" means `len(legacy.Upstreams) > 0` (the new field
is present and non-empty); "needs migration" means
`legacy.UpstreamURL != ""` and `len(legacy.Upstreams) == 0`. A row
that has neither (a row a future Arenet wrote with a different shape,
or a corrupted decode) is left alone — the predicate skips
forward-compat unknowns rather than rewriting them.

**bbolt-specific note.** Step I.4 discovered that modifying a bucket
while a cursor is open on it has undefined behaviour
(`migrate.go:64-66`). The fix it took was to collect the writes
inside a `[]pending{key, val}` during the `ForEach`, then write them
all after the cursor closes, in the same `db.Update` transaction.
J.1 reproduces this exact two-phase pattern. The full implementation
— predicate, transitional-struct read, full-route round-trip, pending
writes — is not reproduced in the spec; the contract is "replicate
Step I.4's structure, with the J.1 sentinel and the J.1 mapping".

### 6.2 Effects on existing rows post-upgrade

What a route persisted before Step J looks like after the first boot
on a Step J binary. The table is a one-glance summary of the per-
field effects already described in §5.1 / §5.2 / §5.4.

The J.1 migration round-trips each row through the full `Route`
struct (`json.Unmarshal` → mutate → `json.Marshal`), so the rewritten
row carries **every** field of post-Step-J `Route` — including the
zero-value forms of fields owned by J.2 and J.4 — because none of
those fields use `omitempty` (§5.2). The columns below list the
exact post-migration JSON content.

| Field on `Route`         | Pre-Step-J row state                | Post-migration JSON                                          |
| ------------------------ | ----------------------------------- | ------------------------------------------------------------ |
| `upstream_url` (legacy)  | `"http://host:port"`                | **Key dropped** by the migration; value moved into the pool. |
| `upstreams` (new)        | absent                              | `[{"url": "<legacy>", "weight": 1}]` — one-element pool (§5.1). |
| `lb_policy` (new)        | absent                              | `"round_robin"` — written by the J.1 migration (§5.1).       |
| `health_check` (new)     | absent                              | `{"enabled": false, "uri": "", "method": "", "interval": "", "timeout": "", "expect_status": 0, "expect_body": "", "passes": 0, "fails": 0}` — full zero-value object emitted because the field has no `omitempty` (§5.2). The generator omits the `health_checks` Caddy block entirely while `enabled` is false. |
| `acme_challenge` (new)   | absent                              | `""` — empty string, treated as `"http-01"` by the API and the generator (§5.4). |

Defaults that only materialise on a **subsequent write** (not at
migration time):

| Path                                  | When it materialises                              | Default value          |
| ------------------------------------- | ------------------------------------------------- | ---------------------- |
| `HealthCheck.{Method,Interval,Timeout,Passes,Fails}` | Next `PUT /api/v1/routes/{id}` with `enabled: true`. | `GET / 30s / 5s / 1 / 1` per §1.3 decision 4. |
| Instance-level `DNSProviderConfig`    | Operator's first `PUT /api/v1/settings/dns-provider`. | None — fresh installs have no DNS provider config. |

A migrated one-upstream route proxies traffic exactly as it did
pre-Step-J: the `buildConfigJSON` shape for `Upstreams:
[{URL: ..., Weight: 1}]` collapses to today's single-element
`upstreams` array (§5.1, §3.2). **AC #2** is what verifies this.

### 6.3 Rollback v0.6 → v0.5 — posture

Rollback to a `v0.5.0-step-i` binary is **not crash-free** for
post-migration BoltDB content, by the same `DisallowUnknownFields`
posture Step I inherited from Step H.2.

- **Route rows.** Once the J.1 migration has run on a route, its
  JSON contains the full Step J shape — `upstreams`, `lb_policy`,
  `health_check`, `acme_challenge` are **all** present (none of the
  new fields uses `omitempty`; the migration's full-route
  `json.Marshal` emits each one, even at its zero value — see §6.2
  for the exact JSON). A v0.5.0 decoder will reject every one of
  those four as unknown and the route load will fail. To roll back:
  restore a pre-J.1 BoltDB snapshot, or apply a reverse migration
  (`Upstreams[0].URL → UpstreamURL`, drop the four new fields).
  Documented for completeness; not expected in practice.
- **`DNSProviderConfig` bucket.** Step J adds a new bucket parallel
  to the existing settings storage (§5.4). A v0.5.0 binary doesn't
  open or scan this bucket — no crash, but the stored OVH credentials
  become invisible until a J-or-later binary boots again. Functional
  regression only, no data corruption.
- **No partial-rollback path.** There is no "downgrade J.1 but keep
  J.4 DNS-01" intermediate posture supported. The migration is the
  single switch from the Step I schema to the Step J schema; a
  rollback restores the Step I schema as a unit.

---

## 7. Smoke test plan (skeleton, filled at J.7)

The Step J smoke doc (`docs/smoke-test-step-j.md`) is written during
J.7, following the Step F / Step I pattern. This section is the
skeleton; the smoke doc materialises it with real outputs, findings,
and a verdict. Phases:

- **0. Setup** — backend + frontend dev servers + browser; ACME
  testing uses Let's Encrypt **staging** (`https://acme-staging-
  v02.api.letsencrypt.org/directory`) to avoid rate limits.
- **Phase A — Regression Step I** — login + route CRUD + audit
  filters + `/healthz` + theme toggle + sidebar collapse + topology
  pan/zoom. Plus the AC #2 path: routes persisted before Step J must
  proxy traffic identically after the J.1 migration runs at first
  boot. Target: no behaviour change for any pre-Step-J route.
- **Phase B — New Step J features** (one entry per non-deferred
  sub-task; J.5 is `DEFERRED`, see §1.4):
  - **B.1 (J.1)** — pool with 2+ upstreams; exercise **each of the
    six LB policies** in turn (`round_robin`, `weighted_round_robin`,
    `least_conn`, `ip_hash`, `random`, `first`); for `round_robin`
    observe approximately even distribution across upstreams via
    repeated `curl`; for `weighted_round_robin` observe proportional
    distribution; for the others, observe that the policy is wired
    correctly (the smoke does not need to formally measure entropy
    on hash-based policies).
  - **B.2 (J.2)** — active health check enabled on a multi-upstream
    route; kill one backend → observe it leaves the rotation after
    `fails` consecutive misses (Caddy log + traffic re-routes);
    restart the backend → observe it re-joins after `passes`
    consecutive hits. Time the transitions against the configured
    `interval` to confirm the probe is firing. **Negative path
    (AC #8)** — POST a route with each of the following invalid
    health-check configs in turn and confirm each is rejected at the
    API layer with a clear error message: blank `uri` with `enabled:
    true`, `method: "POST"`, `timeout >= interval`, malformed
    `expect_body` regex, `passes: -1`. Each maps to one rule in §5.2
    (which is the authoritative full list — the smoke covers a
    representative sample, not every rule). Note: `passes: 0` is
    intentionally default-materialised to `1` by the API layer
    (§5.2 + §1.3 decision 4 — "blank or zero ⇒ use default"), so
    only a negative value reaches `validateHealthCheck`'s strict
    `>= 1` check.
  - **B.3 (J.3)** — **configure the J.1 + J.2 features through the
    UI**, not the API: open the route create / edit modal, add
    multiple upstreams via the repeater (+ / × buttons), pick a
    LB policy from the selector, toggle the weight column for
    `weighted_round_robin`, enable the active health-check sub-form
    and fill it. Verify the resulting `PUT` payload and the stored
    BoltDB row match the form input. This is distinct from "observe
    distribution" — it is the UI integration check for the same
    features.
  - **B.4 (J.4)** — DNS-01 ACME issuance for a wildcard host (e.g.
    `*.example.com`). Live issuance requires a real OVH account
    with an API token and DNS propagation against a real public
    domain; the smoke must **assume PARTIAL is acceptable** if that
    infrastructure is unavailable (the AC #9 wording already covers
    this). Failing that, the wiring is verified through
    `caddy.Validate()` (AC #9 PARTIAL) and through B.5 below.
  - **B.5 (J.4 secret discipline)** — DNS provider credentials never
    echoed: configure the OVH provider via the Settings page, then
    `GET /api/v1/settings/dns-provider` and confirm the three
    secret fields come back empty (only `endpoint` + `configured:
    true`); trigger an audit event by editing the provider and
    confirm the `before` / `after` JSON in the audit log carry the
    three secret fields as empty strings.
  - **B.6 (J.6)** — open `/topology` from cold and confirm the
    graph fits the viewport on first non-empty data (Finding #10
    resolved). Confirm the header is the standard `<PageHeader>`
    with the WebSocket status indicator in the right-aligned slot.
- **Phase C — AC validation matrix** — the per-AC checklist that
  drives the verdict. One row per AC in §2 order: AC #1, AC #2, AC
  #3, AC #4, AC #5, AC #6, AC #7, AC #8, AC #9 (PARTIAL acceptable
  per its own wording), AC #10, **AC #11 (DEFERRED — §1.4)**,
  **AC #12 (DEFERRED — §1.4)**, AC #13, AC #14, AC #15, AC #16,
  AC #17. Each row records PASS / PARTIAL / FAIL / DEFERRED /
  N/A-with-justification. AC #1–#13 except #11 and #12 (DEFERRED —
  §1.4) are verified by the Phase A/B/D rows above; AC #14–#17 are
  verified by running the gates directly: `npm test` (AC #14),
  `go test ./...` (AC #15), `gofmt`/`go vet` + the frontend linter
  (AC #16), and a bundle-size check against the §1 budget (AC #17).
- **Phase D — Migration validation** — boot a Step J binary against
  a pre-Step-J BoltDB snapshot (`v0.5.0-step-i`), then
  `GET /api/v1/routes/{id}` on every pre-existing route and confirm
  the JSON matches the §6.2 table exactly: `upstreams` is a
  one-element pool with `weight: 1`, `lb_policy` is
  `"round_robin"`, `health_check` is the zero-value object
  (`enabled: false`, all sub-fields zero), `acme_challenge` is `""`.
  Re-boot a second time and confirm no re-write occurs (migration
  idempotency at the row level — §6.1).

---

## 8. Tag plan

- `v0.6.0-step-j-spec` — annotated tag posted **on the commit that
  introduces this spec file** (right after the user validates the
  spec content). Freezes the design.
- `v0.6.0-step-j` — annotated ship tag posted after the J.7 smoke
  pass + final commits. Same pattern as Step I.

No intermediate tags between spec freeze and ship; the per-sub-task
commits live on `main`.

---

## 9. Implementation notes

Vigilance notes for the implementer, distinct from any narrative
already given in §5 / §6.

- **bbolt cursor-vs-Put pattern (J.1).** Pointer only — full detail
  in §6.1. The two-phase pattern is non-obvious and Step I.4 found
  out the hard way; do not naively `Put` inside the `ForEach`.
- **Auto-fit trigger on empty store (J.6).** Pointer only — full
  detail in §5.5. The store is empty at `onMount`; trigger `fitView()`
  on the first data tick, once, with a flag.
- **Library version re-check at implementation start.** This spec is
  frozen at `v0.6.0-step-j-spec` against specific upstream library
  versions: Caddy `v2.11.3`, `coraza-caddy v2.5.0`, `caddy-dns/ovh
  v1.1.0` (with `libdns/ovh v1.1.0` and `go-ovh v1.7.0`). Before
  starting J.1, re-run `go list -m -versions` on each and confirm
  no version drift since the spec freeze. If a library has moved,
  the implementation must explicitly re-check the decisions that
  depended on the old version, not silently upgrade. This is
  `CLAUDE.md` §"Empirical verification of external dependencies"
  applied at the moment of implementation.
- **J.5 deferral (WAF observability) does not auto-reopen.** The
  J.5 deferral (§1.4) is anchored to `coraza-caddy v2.5.0` exposing
  no match hook (byte-identical to its upstream `main` at the spec
  freeze date). If a newer `coraza-caddy` ships an injectable
  callback or a context-propagated transaction during the Step J
  implementation window, that is a signal to re-open J.5 — **but
  only as a conscious decision documented in a follow-up
  amendment**, never silently as a side effect of a routine
  dependency bump. The default remains: J.5 stays deferred.
- **`coraza/v3` direct consumption stays out.** Related to the
  above: even if `coraza-caddy` itself remains v2.5.0, the
  temptation to start consuming `coraza/v3` directly inside Arenet
  to extract matched rules (the ~600-line custom-module path) is
  itself the deferred work. Treat that path as the dedicated WAF
  step it would require.
- **Don't infer Caddy or Coraza runtime behaviour mid-implementation.**
  If the implementation surfaces a question of the form "does this
  Caddy / Coraza / OVH feature behave that way?", the answer is in
  the source or a targeted test harness, not in a guess. The five
  Step I.7 findings caught by the smoke were all audit-time
  inferences that the implementer trusted. Re-read `CLAUDE.md`
  §"Empirical verification of external dependencies" before
  shipping J.1.

