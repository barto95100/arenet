<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Redirections — design

**Target version**: v2.44.0 (route state) then v2.45.0 (path rule)
**Date**: 2026-09-24
**Origin**: operator request, 2026-09-24, after a Stalwart backend that
serves nothing at `/` produced a 404 on every visit to its bare FQDN.

---

## The two needs, and why one feature cannot cover both

The operator asked for a redirect "at the route level, next to Active
and Maintenance, for the whole FQDN". That shape is right for one of
the two needs and **impossible** for the other.

**Moving a domain.** `old.example.com` should answer 301 to
`https://new.example.com`. The whole host redirects; nothing is
proxied. A route-level state is exactly right.

**A landing path.** `stalwart.example.com/` should send the browser to
`/admin/login`, while everything else keeps being proxied. A
whole-host redirect **cannot** express this: the target is on the same
host, so it would redirect to itself. Infinite loop, browser gives up
after ~20 hops.

So: two scopes, one mechanism.

---

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Route-level redirect is a **state**, mutually exclusive with Active / Maintenance / Disabled | A redirecting route does not proxy. Making it a toggle would force us to define what a redirect combined with a WAF, auth and a rate limit means — three questions with no useful answer. Maintenance already set this precedent. |
| D2 | Status codes offered: **301** and **302** only | The pair the operator asked for, and the pair a browser-facing domain move needs. 307/308 (method-preserving) are a non-goal — see below. |
| D3 | `preservePath` toggle, **default on** | A domain move wants `old.example.com/a/b` → `new.example.com/a/b`. Emitted as `{http.request.uri}`, which carries path **and** query. Off means every request lands on the target as given. |
| D4 | With `preservePath` on, the target must carry **no path** (`https://host` or `https://host/`) | Appending `{http.request.uri}` to a target that already has a path produces `/app/a/b` — silently wrong. Refuse at save rather than emit it. |
| D5 | Route-level loop guard: the target host must differ from the route host **and every alias** | Same host means the redirect matches its own target. This is refused at save, in the one place the operator can still fix it. |
| D6 | Path-level redirect lives on `PathRule`, and needs a new **exact-match** mode | Path rules match by prefix today, and a `/` prefix matches everything — including the target. Exact match is what makes `/` → `/admin/login` expressible at all. |
| D7 | Path-level loop guard: refuse a target the rule itself would match | Exact rule `/` with target `/` loops; prefix rule `/app` with target `/app/x` loops. Same reasoning as D5, applied to the path. |
| D8 | TLS and certificate management are **unchanged** on a redirecting route | The route still terminates TLS to answer the redirect. A redirect served over a broken certificate is a browser warning, not a redirect. |
| D9 | A redirecting route emits **no** WAF, auth, rate limit or country block | Mirrors maintenance: the state replaces the proxy chain. Path-level redirects are the opposite — they replace the proxy **for that path only**, and the route's protections still apply everywhere else. |
| D10 | A route without a redirect emits **byte-identical** Caddy JSON | The project's standing non-regression rule. Guarded by a test. |

### Non-goals

**307 / 308.** They preserve the request method, which matters for an
API that receives POSTs. It also means a browser will re-POST to the
new host, which is a different decision with different consequences.
Out of scope until someone has that need; adding two constants later
costs nothing.

**Regex rewrites, redirect chains, per-country or per-header
redirects.** Each is a routing language, not a redirect. Arenet has a
path rule mechanism; if this grows, it grows there.

**Redirecting a disabled route.** A disabled route serves nothing at
all, by definition. The states stay exclusive.

---

## Emission

Route-level, mirroring `buildMaintenanceRoute` — a `static_response`
in place of the proxy handler:

```json
{"handler": "static_response",
 "status_code": 301,
 "headers": {"Location": ["https://new.example.com{http.request.uri}"]}}
```

`{http.request.uri}` is Caddy's replacer for the path **and** query
string. Omitted when `preservePath` is off.

Path-level, inside the route's subroute, before the proxy:

```json
{"match": [{"path": ["/"]}],
 "handle": [{"handler": "static_response", "status_code": 302,
             "headers": {"Location": ["/admin/login"]}}],
 "terminal": true}
```

### Verified, not assumed — Caddy's `path` matcher

Read at `caddyhttp/matchers.go` in v2.11.4, before anything was built
on it:

**It is exact without a wildcard.** A pattern with no `*` falls
through the substring / prefix / suffix fast paths to
`path.Match(matchPattern, reqPathForPattern)` (`:536`), commented
*"globular matching, which also is exact matching if there are no
glob/wildcard chars"*. So `"path": ["/"]` matches `/` and nothing
else. D6 stands.

**It lowercases the request path but not the pattern** (`:436`,
`reqPath := strings.ToLower(r.URL.Path)`). The pattern is only run
through the replacer (`:450`) — never lowercased. **A pattern
containing an uppercase letter can therefore never match anything.**
That is a silent, total failure: the rule simply never fires, with no
error anywhere. Arenet must refuse an uppercase path at save and say
why. Added as D11.

**`path.Match` treats `*`, `?` and `[` as glob metacharacters.** A
literal `[` in a path pattern will not mean what the operator typed.
Out of scope to handle; worth knowing when a bug report arrives.

| # | Decision | Rationale |
|---|---|---|
| D11 | Refuse an exact-match path containing an uppercase letter | Caddy would accept the config and the rule would never fire. A refusal at save, naming the reason, beats a rule that silently does nothing. |

---

## Empirical validation gates

1. `caddy.Validate()` accepts both emitted shapes — the Step I.7
   lesson, and the same guard that caught `selection_policy` and the
   missing `l4close` import.
2. A route with no redirect emits byte-identical JSON to the previous
   version (D10).
3. The exact-path matcher really is exact: a rule on `/` must not
   match `/admin/login`. Asserted against a real config, not assumed
   from documentation.
4. Both loop guards refuse at save, with a message naming the target
   and why.

---

## What this does NOT fix

The operator's Stalwart 404 has a second half this feature does not
touch: the **health check** probing `/` on a backend that serves
nothing there. That was fixed separately (v2.43.1) by showing the
probe's verdict in the form and by naming the health check in the
rollback message. A redirect makes the bare FQDN pleasant for a human;
it does not make a wrong probe right.
