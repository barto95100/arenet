# Per-Route Basic Auth — Enable Caddy's Hash Cache — Design

**Date:** 2026-07-13
**Status:** Approved (root cause + approach validated by operator)

## Problem

A route with **Basic Auth** enabled, proxying an SSE-heavy upstream
(Dockhand: many concurrent, reconnecting `text/event-stream` connections),
drives the Arenet VM to **100% RAM + swap**, causing slowness, freezes, and
`502 Bad Gateway`. With `auth=none` on the same route the SSE streams work
fine (operator-confirmed) — so the cause is the Basic Auth handler.

### Root cause (confirmed in code + runtime)

Arenet emits per-route Basic Auth with **argon2id** at a cost calibrated
for an interactive admin login — **64 MiB memory, 3 iterations, 4 lanes per
verification** (`internal/auth/types.go:167-169`), reused verbatim for the
per-route hot path (`internal/auth/basicauth.go:34-43`).

Caddy's `http_basic` provider **re-verifies the hash on every request**
unless its optional hash-verification cache is enabled
(`caddyauth/basicauth.go:171-173` — `if hba.HashCache == nil { return
compare() }`, a full `argon2.IDKey` derivation each time). Arenet emits the
provider **without** `hash_cache` (`internal/caddymgr/manager.go:1562-1573`
— only `hash`, `realm`, `accounts`).

Consequence: every SSE (re)connection = a fresh HTTP request = a full
64 MiB argon2id derivation before the request reaches the proxy (auth runs
before `reverse_proxy` in the chain). N concurrent reconnecting SSE streams
× 64 MiB each, with no caching, exhausts RAM → swap → freeze. Runtime
confirmation: the operator's Proxmox monitor showed RAM **and** swap at
100%, which is the argon2id memory signature (not merely CPU).

## Goal

Enable Caddy's built-in Basic Auth **hash cache** on the emitted
`http_basic` provider, so repeated verifications of the same credential
(exactly the SSE-reconnection pattern) collapse to a single argon2id
derivation plus cache hits — eliminating the memory/CPU amplification.
This is the mechanism Caddy documents for precisely this situation.

## Why the hash cache (Caddy best practice)

Caddy's own doc-comment on the field (`caddyauth/basicauth.go:48-57`):

> "If non-nil, a mapping of plaintext passwords to their hashes will be
> cached in memory (with random eviction). This can **greatly improve the
> performance of traffic-heavy servers that use secure password hashing
> algorithms** …"

That is exactly our case (a secure, expensive hash on a traffic-heavy
proxied route). The cache:
- keys on `hashedPassword + plaintext` (`basicauth.go:176`), so all
  connections using the **same route credential** share one entry;
- uses **singleflight** (`basicauth.go` — `hba.HashCache.g`) to collapse
  concurrent identical verifications into one hash computation — directly
  neutralizing a burst of simultaneous SSE reconnects;
- evicts randomly when full (internal, no configuration).

### Documented tradeoff (acceptable here)

The cache keeps plaintext passwords in memory longer. Per Caddy's comment,
this is acceptable because Basic Auth already receives the plaintext
password over the wire on every request — the cache does not create a new
exposure class. For a homelab reverse proxy this is the standard,
recommended tradeoff. We note it in the emitted-config comment.

## Design

The `Cache` struct (`caddyauth/basicauth.go`) has **no JSON-configurable
fields** — all state (`mu`, `g`, `cache`) is internal, initialized in
`Provision` when `HashCache != nil` (`basicauth.go:133-136`). So enabling
the cache is emitting an **empty object** for the `hash_cache` key; there is
no size or TTL to tune (eviction is internal + random).

In `internal/caddymgr/manager.go`, the `RouteAuthBasic` case
(~lines 1562-1573), add `"hash_cache": map[string]any{}` to the
`http_basic` provider map:

```go
"http_basic": map[string]any{
    "hash":  map[string]any{"algorithm": "argon2id"},
    "realm": fmt.Sprintf("Arenet route %s", r.Host),
    // hash_cache enables Caddy's per-credential verification cache
    // (caddyauth.Cache): repeated verifications of the same
    // credential collapse to one argon2id derivation + cache hits,
    // with singleflight coalescing concurrent identical checks.
    // Without it, Caddy re-runs the full 64 MiB argon2id hash on
    // EVERY request — catastrophic for SSE-heavy upstreams that open
    // many reconnecting streams (RAM+swap exhaustion). Empty object
    // = enabled; the cache has no tunable fields (internal random
    // eviction). Tradeoff: plaintext passwords live in memory a bit
    // longer, acceptable since Basic Auth receives them per-request
    // over the wire anyway.
    "hash_cache": map[string]any{},
    "accounts": []map[string]any{
        {
            "username": r.BasicAuth.Username,
            "password": r.BasicAuth.PasswordHash,
        },
    },
},
```

Nothing else changes: the argon2id cost stays as-is (correct for the login
path; the cache makes its per-request reuse cheap), the handler chain order
is untouched, forward-auth and none modes are untouched.

### Applies to ALL basic-auth routes, by design

The `hash_cache` is emitted for **every** route with `AuthMode ==
RouteAuthBasic`, not only SSE routes. This is deliberate and correct:

- The per-request argon2id cost is **not SSE-specific** — SSE merely
  *amplified* it (many reconnects). Any traffic-heavy basic-auth route (an
  SPA making dozens of requests per load, a polled API) pays the same
  64 MiB-per-request cost and benefits equally.
- Caddy exposes the cache **per `http_basic` provider**, not per traffic
  type. There is no reliable way to detect "this route does SSE" at config
  time, and doing so would be fragile and against the Caddy API. A blanket
  enable is the intended usage.
- No downside to enabling it everywhere: a lightly-used route holds one or
  two cache entries (negligible memory); a heavily-used route is spared the
  exhaustion. Security is unchanged (Basic Auth already transmits the
  plaintext credential per request; the cache adds no new exposure class).

So the fix corrects the root cause across all basic-auth routes, not just
the SSE symptom the operator happened to observe.

## Validation against the real Caddy API (empirical)

Per the project's "empirical verification of external dependencies" rule,
the emitted JSON is validated two ways in tests (mirroring the existing
`TestBuildConfigJSON_LoadsCleanly` / `_HandlersAllResolvable` pattern —
see [[caddy_v2_empirical_invariants]]):
- The full config with a Basic Auth route must pass `caddy.Validate()`
  (proves `hash_cache: {}` is an accepted shape for the http_basic
  provider in the vendored Caddy v2.11.3 — confirmed: field is
  `HashCache *Cache json:"hash_cache,omitempty"`, provisioned from an empty
  object).
- A regression guard asserts the emitted Basic Auth provider JSON contains
  the `hash_cache` key, so a future refactor can't silently drop it and
  re-introduce the RAM exhaustion.

## Testing

The existing test scaffolding covers both needs — minimal additions:

1. **Emission guard:** extend `TestBuildConfigJSON_BasicAuth_EmitsAuthHandler`
   (`internal/caddymgr/manager_test.go:859`) — it already navigates to the
   `http_basic` provider map (`httpBasic`). Add one assertion that
   `httpBasic["hash_cache"]` is present (a non-nil `map[string]any`). This
   guards against a future refactor silently dropping the key and
   re-introducing the RAM exhaustion.
2. **Validates cleanly:** `TestBuildConfigJSON_LoadsCleanly`
   (`manager_test.go:1075`) **already** builds a `RouteAuthBasic` route
   (`everything.example.com`) and runs `caddy.Validate()` on the emitted
   config. Once `hash_cache: {}` is emitted, this existing test proves the
   shape is accepted by the real vendored Caddy v2.11.3 — no new
   `caddy.Validate` test needed; just confirm it stays green.
3. Forward-auth and none routes are unaffected (existing tests stay green).

## Runtime verification

Rebuild; configure the Dockhand route with Basic Auth; load the SSE-heavy
UI and confirm:
- The stream stays open (no freeze/502 loop).
- `arenet` process RAM stays bounded (no runaway to swap) under repeated
  SSE reconnections.
- A `curl -u user:pass` loop against the route shows the **first** request
  paying the argon2id cost (~100 ms) and subsequent identical-credential
  requests returning fast (cache hits) — the direct signature of the fix.

## Non-goals (YAGNI)

- No change to the argon2id cost parameters (the cache solves the hot-path
  cost; lowering the cost would weaken the login hash and require re-hashing
  stored route passwords — rejected in brainstorming).
- No SSE-specific detection/bypass (unnecessary once the cache is on).
- No change to forward-auth or the WAF (both ruled out as the cause).

## Files summary

| Action | File |
| --- | --- |
| Modify | `internal/caddymgr/manager.go` (~line 1562: add `hash_cache: {}` to the emitted http_basic provider) |
| Modify | `internal/caddymgr/manager_test.go` (extend `TestBuildConfigJSON_BasicAuth_EmitsAuthHandler` with a `hash_cache`-present assertion; `TestBuildConfigJSON_LoadsCleanly` already covers `caddy.Validate` on a basic-auth route) |

## Global constraints (from CLAUDE.md)

- Match Caddy's actual API (verified: `HashCache *Cache json:"hash_cache,omitempty"`, vendored v2.11.3); validate emitted JSON with `caddy.Validate()`.
- gofmt -s clean, go vet clean; AGPL header already present (no new files).
