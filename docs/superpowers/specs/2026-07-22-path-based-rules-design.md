# Path-based rules + IP allow/deny (v1) — Design

**Status:** design brainstormed with user 2026-07-22, 5 decisions locked
(Q1–Q5). Feature = minor bump. Structurally larger than the external-certs
work — touches storage, API, caddymgr emission, frontend, i18n.

**One-line:** Let an operator apply auth/IP protections to specific URL
**sub-paths** of an already-exposed route (e.g. basic-auth on `/docs`,
IP-allowlist on `/metrics-zabbix`, public `/api/v1`), plus a reusable
**source-IP allow/deny** filter usable at the whole-route level too — closing
a base reverse-proxy gap (NGINX `location`, Traefik `PathPrefix`, Caddy,
Zoraxy, NPM all do this).

---

## 1. Motivation

Today an Arenet route matches on **host only** (`Route.Host` + `Aliases`,
`storage/routes.go:211,238`); every protection — `AuthMode`
(none/basic/forward_auth), `CountryBlock`, `RateLimit` — applies to the whole
domain. There is **no per-path granularity** and **no source-IP allow/deny**
(only geo/country, CrowdSec reputation, rate-limit). A duplicate host is
rejected (`api/routes.go:1486`, 409), so an operator can't even split paths
across two routes.

Concrete dogfooding need on `api-bff.sct.fr` (already exposed, working):
protect `/docs` + `/docs/*` (Swagger) with basic-auth, restrict
`/metrics-zabbix` to one source IP (403 otherwise), keep `/api/v1/*` public.

The Caddy engine already supports path matchers and `client_ip` matching
natively (verified: `manager.go:1582` emits `"path":["/api/*"]` for the
forward-auth passthrough; Caddy `http.matchers.client_ip` exists at
`caddyhttp/ip_matchers.go:185`). This is a product gap in Arenet's route
model, not an engine limitation.

## 2. Locked decisions (brainstorm Q1–Q5)

| # | Decision | Rationale |
|---|----------|-----------|
| Q1 | **Override model.** A path inherits the domain's whole policy, then adds/overrides only what it declares. | Safe (never silently weakens), intuitive, and **migration-free by construction** (a route with zero path-rules = identical v2.20.3 behaviour). |
| Q2 | **v1 scope:** IP allow/deny filter at **route** AND **path** level + **basic-auth per path**. Forward-auth per path = **v2**. | Ships the 3 real needs (route-IP, path-IP, path-basic-auth) fast; forward-auth-per-path has passthrough/outpost interactions to solve separately. |
| Q3 | **Prefix matcher only.** `/docs` → emits `path:["/docs","/docs/*"]`. No exact-only, no regex. | Covers 99% of needs ("this path and everything under it") in one input; zero regex footgun. |
| Q4 | **Longest-prefix wins.** Overlapping path-rules are ordered by descending prefix length at emission; the most specific one applies. | NGINX-style; the operator never orders rules manually — it "just works". |
| Q5 | **IP filter = mode (allow \| deny) + list of IP/CIDR.** | allowlist = "only these pass, 403 else" (the Zabbix case); denylist = "block these, rest passes". One mode + one list per filter — no dual-list precedence complexity. |

## 3. Non-goals (locked)

- ❌ **Forward-auth per path** → v2 (passthrough/outpost × path-matching needs its own design).
- ❌ **Per-path WAF on/off, rate-limit, geo, redirect, headers** → later increments if a real need surfaces. v1 attaches ONLY basic-auth + IP-filter to a path.
- ❌ **Regex / exact-only path matchers** → prefix only (Q3).
- ❌ **Dual allow+deny lists with precedence** → single mode + single list (Q5).
- ❌ **Per-path override that DISABLES a global layer** (e.g. a path turning off the domain WAF). The model is additive-override (Q1): a path can add basic-auth/IP, never remove a global protection. Turning a global layer off per-path is out of scope.
- ❌ **Manual rule ordering UI** → longest-prefix is automatic (Q4).

## 4. Architecture

### 4.1 New reusable brick — `IPFilter` (storage)

Mirrors the `countryblock.Config` shape (`internal/countryblock/…`) — the
established per-route static-gate pattern.

```go
// internal/storage/ipfilter.go (new)
type IPFilter struct {
    Mode  string   `json:"mode"`            // "" (off) | "allow" | "deny"
    CIDRs []string `json:"cidrs,omitempty"` // IP or CIDR entries
    // StatusCode override for a blocked request. 0 = default 403.
    // Allowed non-zero: 403, 444 (mirrors country-block's allow-list).
    StatusCode int  `json:"statusCode,omitempty"`
}
func (f IPFilter) Validate() error // mode ∈ {"","allow","deny"}; each CIDRs
// entry parses via net.ParseCIDR OR net.ParseIP (bare IP → /32 or /128);
// allow/deny mode requires ≥1 entry; StatusCode ∈ {0,403,444}.
```

**Emission** uses the Caddy **`client_ip`** matcher (`ip_matchers.go:185`),
NOT `remote_ip` (`:69`). `client_ip` honours `ARENET_TRUSTED_PROXIES` /
X-Forwarded-For (Arenet distrusts XFF by default — `main.go:1236`,
`manager.go:3259`); `remote_ip` would see a fronting load-balancer's IP.
- **allow mode:** a route/subroute with matcher `{not:{client_ip:{ranges:[…]}}}`
  → `static_response` 403 (block everything NOT in the list), placed before
  the normal chain.
- **deny mode:** matcher `{client_ip:{ranges:[…]}}` → 403 (block the listed).

> Empirical gate: the exact matcher shape (`not` wrapper vs a dedicated
> handler) must `caddy.Validate()` and be confirmed by the live smoke — the
> block-if-not-in-list shape is the one to verify.

### 4.2 Route model extension (migration-free)

Two additive `omitempty` fields on `storage.Route` (`storage/routes.go`):

```go
type Route struct {
    // … existing, unchanged …
    IPFilter  *IPFilter   `json:"ip_filter,omitempty"`   // whole-domain source-IP gate
    PathRules []PathRule  `json:"path_rules,omitempty"`  // per-sub-path overrides
}

type PathRule struct {
    PathPrefix string                       `json:"path_prefix"` // "/docs" → ["/docs","/docs/*"]
    BasicAuth  *storage.BasicAuthRouteConfig `json:"basic_auth,omitempty"` // reuses the existing brick; PasswordHash is a SECRET (redact-on-GET)
    IPFilter   *IPFilter                    `json:"ip_filter,omitempty"`
}
```

Reuses `BasicAuthRouteConfig{Username, PasswordHash}` verbatim
(`routes.go`) — same secret discipline (`password_hash` never echoed).

Validation (`Route.Validate`): each `PathRule.PathPrefix` must start with `/`,
no whitespace, ≤256 chars; a rule must declare at least one of BasicAuth /
IPFilter (an empty rule is rejected); no two rules share the same PathPrefix
(exact-duplicate prefixes are a config error — overlapping *different*
prefixes are fine, resolved by longest-prefix, Q4). Each `IPFilter.Validate()`.

### 4.3 Caddy emission (the load-bearing core)

Current per-route chain is a flat handler slice wrapped in a `subroute`
(`manager.go:wrapInSubroute`), order:
`rate_limit → country_block → crowdsec → authentication → waf → headers → reverse_proxy`.

The override model emits as follows:

1. **Route-level IPFilter** (`Route.IPFilter`): emit its block-handler early,
   as a sibling of `country_block` (same slot — cheap static policy before
   crowdsec/auth/waf, `manager.go:1733`). Applies to the whole domain,
   including all paths (inheritance).
2. **Path-rules**: replace the single trailing `reverse_proxy` with a
   **`subroute` of path-matched inner routes**, emitted **sorted by
   descending PathPrefix length** (Q4 longest-prefix), each:
   `{match:{path:[prefix, prefix+"/*"]}, handle:[<path IPFilter?>, <path basic-auth?>, reverse_proxy]}`
   followed by a **final match-less inner route** `{handle:[reverse_proxy]}`
   as the catch-all (paths with no rule → plain proxy). Caddy evaluates inner
   routes in slice order and a matched route runs to completion
   (`reverseproxy.go` fall-through semantics, verified for the error-template
   fix), so longest-first ordering + a trailing catch-all gives correct
   precedence with no dropped requests.

Because the model is **additive-override**, the global layers (WAF, CrowdSec,
country, route-IPFilter) stay in the outer chain and apply to every path; a
path-rule only *adds* basic-auth / path-IPFilter in front of the proxy for its
sub-tree.

### 4.4 Layer order / precedence (unchanged global, path overrides last)

Global order is unchanged: `CrowdSec → GeoIP/country → route-IPFilter → WAF →
auth → rate-limit → proxy`. Path overrides insert at the **auth/IP slot just
before the proxy**, so a protected path is still covered by the domain's WAF +
reputation + geo, and adds its own access gate on top. Coherent with Q1.

## 5. API (wire) — mind the wire-field gap

**RECURRING BUG (memory `route_wire_field_gap_regression`):** any new
`storage.Route` field surfaced over the API must be added to the
`routeRequest` struct, the create map, the update map, AND the response, or
`DisallowUnknownFields` 400s every route POST/PUT. New fields here:
`ip_filter` (route level) + `path_rules`. Add all four wire points + a
`routes_path_rules_test` / `routes_ip_filter_test` guard (the checklist from
the memory). `PasswordHash` in path-rule basic-auth follows the redact-on-GET
/ preserve-on-edit discipline of the existing route basic-auth.

Endpoints: **no new endpoints** — path-rules and route IP-filter ride on the
existing `POST/PUT /routes` (they are Route fields).

## 6. Frontend (editor section — "don't lose the operator")

In the existing route editor (`web/frontend/src/…/routes` form):

- **Route-level "Filtrage IP source"**: a small section next to the existing
  Country-block section — Mode (Off / Allowlist / Denylist) + a chip/list
  input for IP/CIDR entries. Collapsed/empty by default.
- **"Règles par chemin" (path-rules)**: a **collapsed section** by default —
  an operator who doesn't use it sees only a titled, empty affordance. Expanded,
  it's a list of cards; each card = `[Préfixe /docs]` + `[Basic-auth: off | user+pass]`
  + `[Filtre IP: off | allow | deny + list]`. "Add rule" appends a card.

Style/interaction mirrors the existing WAF / CountryBlock sections so it reads
as part of the same editor. All copy through `t()`, EN + FR parity.

## 7. Testing (empirical, load-bearing Caddy path)

- **Unit (storage):** `IPFilter.Validate` (mode/CIDR/status), `PathRule`
  validation (prefix shape, ≥1 protection, no dup prefix), longest-prefix sort.
- **caddymgr JSON-shape:** a route with route-IPFilter + 2 path-rules emits the
  early IP block-handler + a path-matched subroute sorted longest-first + the
  catch-all proxy; `client_ip` (not `remote_ip`) is used.
- **caddy.Validate:** the emitted config provisions cleanly (fold into the
  canonical `TestBuildConfigJSON_LoadsCleanly` fixture per the one-Validate-
  per-package convention).
- **Live smoke (mandatory — E1-class runtime checks):** run a binary + a test
  upstream; on a proxied route assert:
  1. `/docs` → 401 without creds, 200 with correct basic-auth.
  2. `/metrics-zabbix` (allow mode, one CIDR) → 200 from an allowed source,
     403 from another. Verify `client_ip` honours `ARENET_TRUSTED_PROXIES`
     (set a trusted proxy + X-Forwarded-For, confirm the XFF IP is the one
     matched — the whole reason to use `client_ip` over `remote_ip`).
  3. `/api/v1/x` → public (catch-all, no override).
  4. Longest-prefix: rules on `/docs` (basic-auth) and `/docs/admin`
     (IP-allow) → `/docs/admin/x` hits the IP rule, `/docs/other` hits
     basic-auth.
  5. Route-level IP-deny → the denied source gets 403 on EVERY path;
     inheritance holds (a path-rule without its own IP-filter still inherits
     the route deny).
  6. WAF/CrowdSec still fire on a path-protected sub-path (additive-override:
     global layers not bypassed).

## 8. Process weight

FULL cycle — this is structurally larger than external-certs (2 storage
entities, 4 API wire points, non-trivial caddymgr emission, a new editor
section, i18n). Subagent-driven with **dedicated review on the caddymgr
emission** (the gateway's request path; a wrong matcher = an access-control
hole) and on the **IPFilter allow-mode `not`-matcher shape** (a subtle
inversion bug = fail-open). ONE final opus whole-branch review. Live smoke
non-negotiable (allow-mode inversion + client_ip/trusted-proxy behaviour are
only settled empirically).

## 9. Open verification items (settle during implementation, not assumed)

- The exact Caddy allow-mode matcher shape (`{not:{client_ip:{ranges}}}` +
  `static_response 403` vs a dedicated handler) — pick the one that
  `caddy.Validate`s AND fails-closed (deny when uncertain). Smoke gate 2/5.
- Interaction of a path-rule subroute with the existing forward-auth
  passthrough route and the error-template `handle_response` blocks on the
  same route (ordering within the emitted subroute list). Confirm no conflict
  via caddy.Validate + smoke on a route that has BOTH forward-auth (domain)
  and a path-rule.
