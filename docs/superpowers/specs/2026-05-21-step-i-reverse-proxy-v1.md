<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step I — Reverse Proxy v1.0 (Spec, frozen at v0.5.0-step-i-spec)

## 1.1 Goal

Step I closes the gap between Arenet's current shape — a *POC with
production-grade auth, audit and topology* — and a **deployable
homelab reverse proxy** users can actually put in front of services
on the open Internet. Six features turn the route from a single
host/upstream toggle into a real proxy entry: ACME-issued TLS,
automatic HTTPS redirect, alias hostnames, an in-line WAF
(Coraza / OWASP CRS), per-route Basic Auth, and custom request/
response headers.

Step I also locks the project's **positioning**: Arenet is *the
Caddy GUI you wish existed for your homelab*, not a feature-parity
clone of Zoraxy. The differentiators are the embedded Caddy engine,
Step D's argon2id-grade auth + audit, Step E's live topology, and
the Step F design system — not a long list of utility tools.

Predecessors:
- `v0.4.2-backend-cleanup` closed Step H (HEAD `3f873f8`).
- `v0.4.1-debt-cleanup` closed Step G.
- `v0.4.0-step-f` closed the design / tests step.

Successors planned (see §6.4 Future roadmap):
- Step J — multi-user Basic Auth, DNS-01 challenge, health checks,
  multi-upstream LB, IP allow/block, path-based routing, access log.
- Step K — forward-auth SSO (Authelia / Keycloak / Authentik), WAF
  rule tuning UI, backup/restore.

## 1.2 Scope

Step I delivers end-to-end:

- **ACME / Let's Encrypt** — per-route TLS toggle that, when on,
  causes Caddy to obtain and renew a public cert via HTTP-01 (port
  80 reachable on the proxy host). Self-signed `internal` issuer
  stays available for `localhost` / dev mode.

- **HTTP → HTTPS redirect** — per-route toggle (default `true` when
  TLS is on) emitting a 301 with preserved path + query.

- **Alias hostnames** — a single route can answer to a primary host
  plus an arbitrary list of aliases (all served by the same upstream,
  same TLS cert via SAN, same WAF / auth / headers config).

- **WAF (Coraza)** — three-mode toggle (`off` / `detect` / `block`).
  `detect` logs blocked requests via the existing audit channel but
  lets them through (safe shadow-mode); `block` returns 403. OWASP
  CRS is embedded as the default ruleset; no per-rule UI in v1.0.

- **Basic Auth per route** — one user/password pair per route;
  password hashed (bcrypt cost 12, aligned with Step D). Wrong
  creds → 401 Basic challenge before the request reaches the
  upstream.

- **Custom headers** — two `map[string]string` of header pairs
  applied on the request to the upstream and the response to the
  client. Implicit `op=set`; no add/remove/regex transforms in
  v1.0.

The cumulative effect: Arenet stops being a *demo proxy* and
becomes a homelab admin's actual front door, with the differentiator
(WAF + audit + auth) that no current free GUI ships out of the box.

## 1.3 Locked decisions

Twelve decisions are locked up-front (Q&A driven, captured here for
audit; no re-litigation during implementation).

| #   | Sub-task             | Decision                                                                                              |
| --- | -------------------- | ----------------------------------------------------------------------------------------------------- |
| L1  | I.1 ACME UI          | Per-route `TLSEnabled` toggle (no global switch); rendered in Add/Edit Route modal.                   |
| L2  | I.1 ACME challenge   | HTTP-01 only in v1.0; DNS-01 (wildcard) deferred to Step J.                                           |
| L3  | I.2 Redirect         | Per-route `RedirectToHTTPS` toggle, default `true` when `TLSEnabled=true`; no-op when TLS off.        |
| L4  | I.3 Aliases          | `Host string` stays primary, `Aliases []string` added; both reach the same upstream + same cert SAN. |
| L5  | I.4 WAF shape        | Enum `WAFMode` ∈ {`off`, `detect`, `block`}; replaces the existing `WAFEnabled bool`.                |
| L6  | I.4 WAF default      | New routes default to `detect` (FortiWeb-style safe-shadow); existing routes migrate per L7.         |
| L7  | I.4 WAF migration    | `WAFEnabled=true → WAFMode='block'` (semantic equivalent); `WAFEnabled=false → WAFMode='off'`.       |
| L8  | I.4 WAF badge        | Visible in `/routes` table when mode ≠ `off`: yellow for `detect`, red for `block`.                  |
| L9  | I.5 Basic Auth shape | One user/password pair per route in v1.0; multi-user list deferred to Step J.                        |
| L10 | I.5 Password storage | Plain in form → bcrypt hash backend → never re-displayed (`••• set` placeholder on Edit).            |
| L11 | I.6 Headers shape    | Two `map[string]string`: `RequestHeaders` + `ResponseHeaders`. Implicit `op=set`. No add/remove v1.0. |
| L12 | I.6 Headers UI       | Two collapsible sections, key-value rows, `+ Add header` button, in-place delete.                    |

## 1.4 Out of scope

Listed explicitly so reviewers don't ask "why isn't X in Step I".

Deferred to **Step J**:
- **Multi-user Basic Auth** per route — only one user pair in v1.0.
- **DNS-01 ACME challenge** (wildcard certs) — HTTP-01 covers 95 %
  of homelab cases.
- **Health checks** (active upstream probing) — Caddy supports it,
  but adds a UI + storage surface not yet justified.
- **Multi-upstream load balancing** — single upstream is the common
  homelab pattern.
- **IP allow/block per route** — useful but homelab firewalls
  already cover this layer.
- **Path-based routing** (sub-path → distinct upstream).
- **URL rewrite rules** beyond what header manipulation covers.
- **Access log per route** (Caddy structured log per virtual host).

Deferred to **Step K**:
- **Forward-auth SSO** (Authelia / Keycloak / Authentik) — biggest
  feature gap vs Authelia stacks; pushed to a dedicated step.
- **WAF rule tuning UI** (per-route allowlist of CRS rules for
  false-positive handling).
- **Backup / restore config** (BoltDB JSON export / import).

**Never**:
- **Web-SSH terminal** — out of product scope; opens a security
  surface unrelated to a reverse proxy.
- **mDNS scanner / IP scanner** — utility bloat (Zoraxy's path).
- **ZeroTier / GAN controller** — networking layer, not RP.
- **CIDR converter / Misc tools** — out of scope.

## 1.5 Range of change

- From: tag `v0.4.2-backend-cleanup` (SHA `3f873f8`).
- To: tag `v0.5.0-step-i` (post-smoke ship).
- Estimated effort: **20-28h** across six sub-tasks I.1 → I.6.
- Spec frozen at: `v0.5.0-step-i-spec` (this commit).

## 1.6 Threat model deltas vs Step D

Step D defined the auth/audit threat model. Step I adds three
attack surfaces:

1. **Public-Internet exposure** (via ACME) — the proxy must accept
   port 80 (HTTP-01 challenge) and 443 from the open web. The WAF
   + Caddy's built-in HTTP/2 protections handle the network layer;
   the admin API is still bound to `:8001` and is NOT exposed.

2. **Header injection on custom headers** — user-supplied header
   values are inserted into Caddy's JSON config. Caddy validates
   the JSON, but value characters that break HTTP framing
   (CR/LF) must be rejected at the API layer.

3. **Basic Auth credential storage** — bcrypt cost 12 mirrors
   Step D's user passwords. The plaintext password is never logged,
   never returned from the API, and is wiped from in-memory state
   immediately after hashing on the create/update path.

---

## 2. Acceptance Criteria

Fifteen ACs; the smoke session ships only when every one is PASS or
N/A (with N/A justified inline).

| #   | Title                  | Verification                                                                                                    |
| --- | ---------------------- | --------------------------------------------------------------------------------------------------------------- |
| 1   | ACME HTTP-01 works     | A route with `TLSEnabled=true` serves a Let's Encrypt-issued cert verified via `openssl s_client`. Smoke I.7 accepts Let's Encrypt **staging** as proof of mechanism (cert untrusted but issued and chain-valid); production cert validation on a real domain is the user's responsibility post-ship. |
| 2   | HTTP → HTTPS redirect  | `curl -I http://<host>/foo?bar=1` returns `301` with `Location: https://<host>/foo?bar=1`.                       |
| 3   | Alias hostnames        | Route with `Host="a"` + `Aliases=["b","c"]` answers HTTP 200 on all three hostnames; same upstream, same cert.   |
| 4   | WAF detect mode        | OWASP CRS-matching request reaches upstream, `audit_waf_match` event emitted, `X-WAF-Match` response header set. |
| 5   | WAF block mode         | OWASP CRS-matching request returns `403`, audit event emitted, no upstream call.                                |
| 6   | WAF migration on boot  | Routes created pre-Step I (`WAFEnabled` field only) load post-upgrade with `WAFMode` populated per L7.           |
| 7   | Basic Auth works       | Wrong creds → 401 with `WWW-Authenticate: Basic`; right creds → request reaches upstream.                       |
| 8   | Password never echoed  | `GET /api/v1/routes/{id}` never includes `basicAuthPassword`; field is `basicAuthPasswordSet: bool`.            |
| 9   | Request headers set    | `RequestHeaders={"X-Real-Foo":"bar"}` ⇒ upstream receives `X-Real-Foo: bar` (verified via upstream echo).        |
| 10  | Response headers set   | `ResponseHeaders={"X-Custom":"x"}` ⇒ client receives `X-Custom: x` on the response.                            |
| 11  | Frontend tests pass    | `npm test` keeps 141 / 141 baseline + any new Step I tests (target ≥ 145).                                       |
| 12  | Backend tests pass     | `go test ./...` clean on every package, including new `caddymgr` WAF/basic-auth tests.                          |
| 13  | BoltDB backward compat | Routes persisted by v0.4.2 binary decode without error on v0.5.0 boot (migration L7 runs idempotently).         |
| 14  | Lint / vet clean       | `npm run check`: 0 errors / 0 warnings. `go vet ./...`: clean. `gofmt -l ./internal ./cmd`: empty.              |
| 15  | Bundle budget          | Frontend gzipped bundle ≤ 500 kB (post-Step F ≈ 84 kB; Step I targets < 100 kB).                                |

---

## 3. Architecture impact

### 3.1 Route schema change (storage + API + UI)

Current `Route` struct (`internal/storage/routes.go:31-40`):

```go
type Route struct {
    ID          string    `json:"id"`
    Host        string    `json:"host"`
    UpstreamURL string    `json:"upstream_url"`
    TLSEnabled  bool      `json:"tls_enabled"`
    WAFEnabled  bool      `json:"waf_enabled"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

Target `Route` struct after Step I:

```go
type Route struct {
    ID          string    `json:"id"`
    Host        string    `json:"host"`
    UpstreamURL string    `json:"upstream_url"`
    TLSEnabled  bool      `json:"tls_enabled"`

    // Step I.2 — HTTP→HTTPS redirect, only meaningful when TLSEnabled=true.
    RedirectToHTTPS bool `json:"redirect_to_https"`

    // Step I.3 — additional hostnames served by the same upstream + cert.
    Aliases []string `json:"aliases"`

    // Step I.4 — WAF mode (replaces the bool WAFEnabled; see §6.1
    // for the WAFEnabled→WAFMode migration).
    WAFMode string `json:"waf_mode"` // "off" | "detect" | "block"

    // Step I.5 — per-route Basic Auth (single user pair in v1.0).
    BasicAuthEnabled      bool   `json:"basic_auth_enabled"`
    BasicAuthUsername     string `json:"basic_auth_username"`
    BasicAuthPasswordHash string `json:"basic_auth_password_hash"` // bcrypt cost 12

    // Step I.6 — set-only header manipulation; implicit op=set.
    RequestHeaders  map[string]string `json:"request_headers"`
    ResponseHeaders map[string]string `json:"response_headers"`

    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

**The `WAFEnabled` field is removed at the Go-struct level**; BoltDB
keeps it visible during the boot migration only (one-shot, see
§6.1). The API stops accepting `wafEnabled` (returns 400 if sent),
and starts accepting `wafMode`.

### 3.2 buildConfigJSON handler chain refactor

Current chain (`internal/caddymgr/manager.go:247-260`):

```
[metricsHandler, proxyHandler]
```

Target chain (conditional, in this order):

```
[metricsHandler, basicAuthHandler?, wafHandler?, headersHandler?, proxyHandler]
```

Where `?` = present only when the matching route flag is on.

Order rationale:
- **`metricsHandler` first** so it always sees the final upstream
  status code (Step E §11.5 invariant, unchanged).
- **`basicAuthHandler` before WAF** so a 401 short-circuits before
  WAF rule evaluation (cheaper, and WAF logs on unauth traffic are
  noise).
- **`wafHandler` before headers + proxy** so malicious requests
  never reach the upstream and don't get our custom headers
  attached.
- **`headersHandler` before proxy** so request-side header mutations
  reach the upstream and response-side mutations fire post-upstream
  (Caddy's `headers` handler handles both directions in one
  module).

Additional config changes outside the per-route chain:
- **Server-level `automatic_https`** toggled per route via the
  presence of any route with `TLSEnabled=true`.
- **Listener on `:80`** mounted unconditionally to host:
    - ACME HTTP-01 challenges (Caddy handles automatically).
    - HTTP → HTTPS 301 redirects when `RedirectToHTTPS=true`.
- **Listener on `:443`** mounted when any route has TLS on.
- **Match.host** becomes `[]string` of `[Host] ∪ Aliases` (was
  `[Host]`).

### 3.3 Go dependency additions

- `github.com/corazawaf/coraza-caddy/v2` — registered as a blank
  import in `cmd/arenet/main.go`. The Caddy module registry picks
  it up; `xcaddy` is NOT required because the module uses Caddy's
  standard registration pattern.
- Transitive cost: ≈ +150 modules (Coraza + OWASP CRS embedded
  rules). Binary size impact ≈ +3-5 MB. Acceptable.
- `golang.org/x/crypto/bcrypt` already present transitively via
  Step D's `argon2id` package; explicit import added.

### 3.4 Frontend impact

`web/frontend/src/lib/api/types.ts` — extend `Route` and
`RouteRequest` interfaces with the nine new fields (less
`BasicAuthPasswordHash`, which is server-only; the API exposes
`basicAuthPassword` write-only + `basicAuthPasswordSet: bool` read-
only).

`web/frontend/src/routes/routes/+page.svelte` — extend the
Add / Edit Route modal with five new sections:

- **TLS** — `TLSEnabled` toggle + `RedirectToHTTPS` toggle
  (disabled when TLS off, with tooltip "Enable TLS to use HTTPS
  redirect").
- **Hostnames** — primary `Host` input (existing) + `Aliases`
  repeater (tag-style input with `Enter`-to-add, `×`-to-remove).
- **WAF** — `WAFMode` dropdown (`off` / `detect` / `block`) with
  contextual tooltip on each option ("Start with Detect to spot
  false positives before enforcing").
- **Basic Auth** — `BasicAuthEnabled` toggle + Username input +
  Password input (plain on Create; on Edit, placeholder reads
  `••• set` and is left blank to indicate "unchanged"; submit
  with empty Password keeps the stored hash).
- **Custom Headers** — two collapsible sections (`Request` then
  `Response`), each with key/value rows + `+ Add header`.

`/routes` table badges:
- WAF mode badge (yellow `detect`, red `block`, hidden `off`) —
  reuses Badge variants from Step F.
- Lock icon when `BasicAuthEnabled=true`.
- TLS lock icon when `TLSEnabled=true` (existing; unchanged).

---

## 4. Sub-tasks (ordered)

Six sub-tasks, ordered by effort + dependency:

| #   | Sub-task                                | Effort | Depends on    |
| --- | --------------------------------------- | ------ | ------------- |
| I.1 | ACME / Let's Encrypt + per-route toggle | 6-10h  | —             |
| I.2 | HTTP → HTTPS redirect                   | 1-2h   | I.1           |
| I.3 | Alias hostnames                         | 2-3h   | —             |
| I.4 | WAF wire-up (Coraza + WAFMode enum)     | 4-6h   | —             |
| I.5 | Basic Auth per route                    | 2-3h   | —             |
| I.6 | Custom request / response headers       | 3-4h   | —             |

Cumulative: 18-28h.

`I.7` is reserved for the smoke session + final tag (~2-3h).

---

## 5. Per-sub-task design

### 5.1 I.1 — ACME / Let's Encrypt + per-route toggle

**Goal**: a route with `TLSEnabled=true` on a real domain receives a
publicly-trusted cert (Let's Encrypt via HTTP-01). Localhost / dev
mode keeps the existing self-signed `internal` issuer.

**Schema**: `TLSEnabled` already exists; no Route field added.

**API**: no payload shape change; the existing `tlsEnabled` field
takes new semantics (was: trigger HTTPS server; now: also trigger
ACME issuer for that host).

**buildConfigJSON change** (`internal/caddymgr/manager.go`):
- `automatic_https.disable` flips from hardcoded `true` to `false`
  when any route has `TLSEnabled=true` AND its `Host` is NOT
  `localhost` / a `.local` / a private-IP literal.
- The `internal` issuer stays the fallback for `localhost` and
  dev-mode (`--dev` flag); ACME is the default for any other host.
- Sample emitted JSON (truncated):

  ```json
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          { "issuers": [{"module": "acme"}] },
          { "subjects": ["localhost"], "issuers": [{"module": "internal"}] }
        ]
      }
    }
  }
  ```

**UI**: existing `Enable TLS` checkbox; tooltip updated from "Enable
TLS termination on :443" to "Enable TLS + auto-cert via Let's
Encrypt (HTTP-01)".

**Tests** (Go):
- `caddymgr_test.go::TestBuildConfigJSON_ACME_EnabledWhenPublicHost`.
- `caddymgr_test.go::TestBuildConfigJSON_InternalIssuerForLocalhost`.

**ACs covered**: #1.

### 5.2 I.2 — HTTP → HTTPS redirect

**Goal**: when `TLSEnabled=true` AND `RedirectToHTTPS=true`, hitting
`http://host/path?q=1` returns `301 Location: https://host/path?q=1`.

**Schema**: add `RedirectToHTTPS bool` (default `true`).

**API**: `routeRequest` and `routeResponse` gain
`redirectToHttps: bool`.

**buildConfigJSON change**:
- Caddy's port-`:80` server gains a route per TLS-enabled route
  with `redir` handler:

  ```json
  {
    "match": [{ "host": ["api.example.com"] }],
    "handle": [{ "handler": "static_response", "headers": {"Location": ["https://{http.request.host}{http.request.uri}"]}, "status_code": 301 }]
  }
  ```

**UI**: new toggle below `Enable TLS` in the modal; disabled when
TLS off; tooltip "Redirect plain HTTP to HTTPS with 301 (preserves
path + query)".

**Tests**:
- `caddymgr_test.go::TestBuildConfigJSON_HTTPRedirect_EmittedForTLSRoutes`.
- One frontend test on the form rule "RedirectToHTTPS toggle
  disabled when TLSEnabled off".

**ACs covered**: #2.

### 5.3 I.3 — Alias hostnames

**Goal**: `Route{Host: "a.example.com", Aliases: ["b.example.com",
"c.example.com"]}` answers HTTP 200 on all three names; the ACME
cert SAN list includes all of them.

**Schema**: add `Aliases []string` (default `nil`).

**API**: payload gets `aliases: string[]`. Validation:
- Each alias passes the existing `validateHost` rule (lowercase
  RFC 1035 hostname).
- An alias must not duplicate the primary `Host` or any other
  route's primary / alias (server returns 409 if it does, to keep
  Caddy match unambiguous).

**buildConfigJSON change**:
- `httpRoute.Match[0].Host = append([]string{r.Host}, r.Aliases...)`.
- ACME policy `subjects` array includes all hosts so the issued
  cert covers them via SAN.

**UI**: under the existing `Host` input, an `Aliases` tag-input
component:
- `Enter` adds the value to the list.
- `×` next to each tag removes it.
- Inline validation on each tag (hostname format).
- Empty list is the default.

**Tests**:
- `caddymgr_test.go::TestBuildConfigJSON_AliasesAreEmittedInMatchHost`.
- `routes_test.go::TestCreateRoute_RejectsDuplicateAlias`.

**ACs covered**: #3.

### 5.4 I.4 — WAF wire-up (Coraza + WAFMode enum)

**Goal**: each route can opt into WAF inspection in `detect` (log
only) or `block` (return 403) mode. OWASP CRS embedded ruleset is
loaded once at startup.

**Schema**: remove `WAFEnabled bool`, add `WAFMode string` ∈
{`off`, `detect`, `block`}. Migration runs once at boot (§6.1).

**API**: payload gets `wafMode: "off" | "detect" | "block"`.
Validation rejects any other value with `400 invalid waf_mode`.
The old `wafEnabled` boolean is rejected with `400 unknown field`
(thanks to Step H.2's `DisallowUnknownFields`, no extra code).

**buildConfigJSON change**: insert the Coraza handler between
`basicAuthHandler` and `headersHandler` when `WAFMode != "off"`.
Coraza's Caddy module config:

```json
{
  "handler": "coraza",
  "directives": "Include @owasp_crs/*.conf\nSecRuleEngine DetectionOnly"
}
```

The `SecRuleEngine` directive switches between `On` (block) and
`DetectionOnly` (detect). Per-route override is achieved by emitting
a different handler instance per route.

**Audit**: new action enum `audit_waf_match` (action #16). Fields:
`route_id`, `mode` (detect | block), `rule_id`, `rule_msg`,
`client_ip`. **Bumps the D7 audit action count from 15 to 16** —
spec amendment noted (Step I §3.1).

**UI**: dropdown `WAF` in the modal with three options. Tooltip on
each:
- `Off` — "No WAF inspection."
- `Detect` — "Inspect requests, log matches in the audit feed, but
  let them through. Recommended first step."
- `Block` — "Inspect requests and return 403 on a match. Enable
  after a few days of Detect to spot false positives."

Table badge:
- `Detect` — yellow `Badge variant="status-warn"`.
- `Block` — red `Badge variant="status-down"`.
- `Off` — hidden.

**Tests**:
- `caddymgr_test.go::TestBuildConfigJSON_WAFMode_DetectEmitsHandler`.
- `caddymgr_test.go::TestBuildConfigJSON_WAFMode_BlockEmitsBlockingDirective`.
- `caddymgr_test.go::TestBuildConfigJSON_WAFMode_OffSkipsHandler`.
- `storage_migration_test.go::TestMigrate_WAFEnabledTrueBecomesBlock`.
- `storage_migration_test.go::TestMigrate_WAFEnabledFalseBecomesOff`.
- `audit_test.go::TestAction_WAFMatch_IsRegistered` (D7 count = 16).

**ACs covered**: #4, #5, #6.

### 5.5 I.5 — Basic Auth per route

**Goal**: a route can require HTTP Basic Auth. Single user/pass
v1.0; password bcrypt-hashed (cost 12), never re-displayed.

**Schema**:
```go
BasicAuthEnabled      bool   `json:"basic_auth_enabled"`
BasicAuthUsername     string `json:"basic_auth_username"`
BasicAuthPasswordHash string `json:"basic_auth_password_hash"` // bcrypt
```

**API**:
- `routeRequest` accepts `basicAuthEnabled`, `basicAuthUsername`,
  `basicAuthPassword` (plain — wire-only field, write-only).
- `routeResponse` exposes `basicAuthEnabled`, `basicAuthUsername`,
  `basicAuthPasswordSet bool` (true iff hash present); NEVER
  exposes the hash or the plaintext.
- POST `/routes` with `basicAuthEnabled=true` requires both
  `basicAuthUsername` and `basicAuthPassword` non-empty (or
  returns 400).
- PUT `/routes/{id}` accepts an empty `basicAuthPassword` field,
  meaning "keep existing hash".

**buildConfigJSON change**: insert Caddy's `basicauth` handler
between `metricsHandler` and `wafHandler`:

```json
{
  "handler": "authentication",
  "providers": {
    "http_basic": {
      "accounts": [{"username": "admin", "password": "$2b$12$..."}]
    }
  }
}
```

**UI**:
- `Enable Basic Auth` toggle.
- When on: `Username` input + `Password` input (placeholder
  `••• set` on Edit when a hash already exists).
- Form validation: enabled + username + (Create OR password) is
  required.

**Tests**:
- `caddymgr_test.go::TestBuildConfigJSON_BasicAuth_EmitsAuthHandler`.
- `routes_test.go::TestCreateRoute_BasicAuthRequiresUsernameAndPassword`.
- `routes_test.go::TestUpdateRoute_EmptyPasswordPreservesHash`.
- `routes_test.go::TestGetRoute_NeverReturnsHashOrPlaintext`.

**ACs covered**: #7, #8.

### 5.6 I.6 — Custom request / response headers

**Goal**: arbitrary `map[string]string` of headers applied on the
forward request and the backward response.

**Schema**:
```go
RequestHeaders  map[string]string `json:"request_headers"`
ResponseHeaders map[string]string `json:"response_headers"`
```

Both default empty.

**API**: payload accepts the two maps. Validation:
- Each key matches `^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$` (RFC 7230
  token).
- Each value is single-line printable ASCII (no CR/LF) — security
  rule §1.6 #2.
- Empty key or empty value → 400.

**buildConfigJSON change**: insert Caddy's `headers` handler before
`proxyHandler`:

```json
{
  "handler": "headers",
  "request":  {"set": {"X-Real-Foo": ["bar"]}},
  "response": {"set": {"X-Custom":   ["x"]}}
}
```

Omitted entirely when both maps are empty.

**UI**:
- Two collapsible sections (`Request headers` then `Response
  headers`) inside the Add/Edit Route modal.
- Each section: rows of `[Key] [Value] [×]` + `+ Add header`
  button.
- Inline key validation on blur.

**Tests**:
- `caddymgr_test.go::TestBuildConfigJSON_HeadersHandler_EmittedWhenNonEmpty`.
- `routes_test.go::TestCreateRoute_RejectsCRLFInHeaderValue`.
- `routes_test.go::TestCreateRoute_RejectsInvalidHeaderKey`.

**ACs covered**: #9, #10.

---

## 6. Migration strategy

### 6.1 BoltDB schema migration (WAFEnabled → WAFMode)

Run **once at boot**, in the storage layer, before the first
`ListRoutes` call. Idempotent (`WAFMode` already populated ⇒
no-op).

```go
// internal/storage/migrate.go — Step I.4 boot migration.
//
// Pre-Step I routes have only WAFEnabled bool; Step I uses
// WAFMode string. This one-shot read-modify-write converts every
// row and is safe to run on each boot (no-op when WAFMode already
// set).
//
// Mapping (decision L7):
//   - WAFEnabled = true  → WAFMode = "block"  (semantic equivalent
//                                              of the pre-Step-I
//                                              behavior, which was
//                                              effectively
//                                              "blocking on every
//                                              detection").
//   - WAFEnabled = false → WAFMode = "off"
func migrateWAFEnabledToWAFMode(db *bolt.DB) error {
    return db.Update(func(tx *bolt.Tx) error {
        b := tx.Bucket(bucketRoutes)
        if b == nil {
            return nil
        }
        return b.ForEach(func(k, v []byte) error {
            var legacy struct {
                WAFEnabled bool   `json:"waf_enabled"`
                WAFMode    string `json:"waf_mode"`
            }
            if err := json.Unmarshal(v, &legacy); err != nil {
                return fmt.Errorf("migrate route %s: %w", k, err)
            }
            if legacy.WAFMode != "" {
                return nil // already migrated
            }
            var r Route
            if err := json.Unmarshal(v, &r); err != nil {
                return fmt.Errorf("migrate route %s decode: %w", k, err)
            }
            if legacy.WAFEnabled {
                r.WAFMode = "block"
            } else {
                r.WAFMode = "off"
            }
            // Step I.2 / I.3 / I.5 / I.6 defaults — kept here so a
            // single migration pass populates every new field at once.
            // RedirectToHTTPS defaults to true; everyone else defaults
            // to zero value.
            // Step I.2: default redirect-to-HTTPS only when TLS is on.
            if r.TLSEnabled {
                r.RedirectToHTTPS = true
            }
            blob, err := json.Marshal(r)
            if err != nil {
                return err
            }
            return b.Put(k, blob)
        })
    })
}
```

### 6.2 Defaults for new fields

| Field                   | Default                          | Notes                                                          |
| ----------------------- | -------------------------------- | -------------------------------------------------------------- |
| `TLSEnabled`            | `false`                          | Opt-in; unchanged from pre-Step I.                              |
| `RedirectToHTTPS`       | `true` when `TLSEnabled`, else `false` | Auto-set in the form when toggling TLS on.              |
| `Aliases`               | `[]` (empty slice)                | Distinct from `nil` for stable JSON shape.                      |
| `WAFMode`               | `"detect"` for new routes         | Safe-shadow by default (L6).                                    |
| `BasicAuthEnabled`      | `false`                          | Opt-in.                                                         |
| `BasicAuthUsername`     | `""`                             | Required when `BasicAuthEnabled`.                               |
| `BasicAuthPasswordHash` | `""`                             | Server-only; set by hash function on create / update.           |
| `RequestHeaders`        | `{}` (empty map)                 | Distinct from `nil` for stable JSON shape.                      |
| `ResponseHeaders`       | `{}` (empty map)                 | Distinct from `nil` for stable JSON shape.                      |

### 6.3 Rollback strategy

- All changes are **additive at the wire layer** (new fields,
  same JSON envelope), except the `WAFEnabled → WAFMode`
  replacement.
- A rollback to v0.4.2 binary would crash on `WAFMode` (unknown
  field rejected by `DisallowUnknownFields` ⇒ Step H.2). To roll
  back, restore a pre-migration BoltDB snapshot or apply a reverse
  migration `WAFMode → WAFEnabled` (block ⇒ true, off ⇒ false,
  detect ⇒ false). Documented for completeness; not expected in
  practice.
- All other v0.5.0 reads of pre-v0.5.0 BoltDB content succeed (the
  migration populates missing fields with defaults; the JSON
  decoder tolerates missing optional fields).

### 6.4 Future roadmap

Documented for the reader so the v1.0 scope is unambiguously
"finished".

**Step J** (next, no commitment date):
- Multi-user Basic Auth per route.
- DNS-01 ACME challenge (wildcard certs).
- Health checks (active upstream probing).
- Multi-upstream load balancing (`round_robin`, `least_conn`,
  `ip_hash`).
- IP allow/block per route.
- Path-based routing (sub-path → distinct upstream).
- Access log per route.

**Step K** (later):
- Forward-auth SSO (Authelia / Keycloak / Authentik).
- WAF rule tuning UI (per-route CRS rule allowlist).
- Backup/restore config (BoltDB JSON export / import).

**Never** (out of product scope):
- Web-SSH terminal, mDNS scanner, ZeroTier, CIDR converter (Zoraxy
  utility bloat).

---

## 7. Smoke test plan (skeleton, filled at I.7)

The Step I smoke doc (`docs/smoke-test-step-i.md`) will follow the
Step F pattern. Sections:

- **0. Setup** — backend + frontend dev servers + browser; ACME
  testing uses Let's Encrypt **staging** (`https://acme-staging-
  v02.api.letsencrypt.org/directory`) to avoid rate limits on the
  production directory.
- **Phase A — Regression Step F/G/H** — login, route CRUD, audit
  filters, /healthz endpoint, theme toggle, sidebar collapse,
  topology pan/zoom. Target: no behavior change.
- **Phase B — New Step I features**:
  - B.1: ACME on a real domain (or staging) — observe cert chain.
  - B.2: HTTP → HTTPS redirect — `curl -I`.
  - B.3: Alias hostnames — three names, one upstream.
  - B.4: WAF detect — `curl` an SQLi payload, observe
    `X-WAF-Match` header + audit row.
  - B.5: WAF block — same payload, observe 403 + audit row.
  - B.6: Basic Auth — wrong creds 401, right creds 200.
  - B.7: Custom headers — upstream echo confirms request headers;
    `curl -i` confirms response headers.
- **Phase C — AC validation matrix** — one row per AC (#1 → #15)
  with PASS / FAIL / N/A.
- **Phase D — Migration validation** — boot v0.5.0 against a v0.4.2
  BoltDB snapshot; verify `WAFMode` is populated correctly.

---

## 8. Tag plan

- `v0.5.0-step-i-spec` — annotated tag posted **on the commit that
  introduces this spec file** (right after the user validates the
  spec content). Freezes the design.
- `v0.5.0-step-i` — annotated ship tag posted after the smoke pass
  + final commits. Same pattern as Step F.

No intermediate tags between spec freeze and ship; the per-sub-task
commits live on `main` (or a feature branch, TBD with user).

---

## 9. Implementation notes

Reserved for surprises discovered during I.1 → I.6. Pre-emptive
notes:

- **ACME local testing**: use Let's Encrypt **staging** directory
  during the implementation phase (`--dev` flag toggles the issuer
  URL). Production directory only at smoke time, on the real
  homelab domain (rate-limit cost 5 certs/week/domain).
- **Coraza embedding**: the `coraza-caddy/v2` module ships the
  OWASP CRS as an embedded FS by default. Confirm at I.4 startup
  that the rules load (look for `slog Info "coraza: loaded N
  rules"` at boot).
- **WAF audit volume**: a noisy WAF mode could flood the audit
  bucket. Plan a rate limit on `audit_waf_match` events at most
  one per `(route_id, rule_id)` per minute — TBD during I.4
  implementation if observed in smoke. Documented here so the
  decision is visible.
- **Header injection defense**: reject CR/LF in header values at
  the API layer (§1.6 threat #2); the Caddy config builder
  ALSO validates, but defense in depth is cheaper than a
  post-mortem.
