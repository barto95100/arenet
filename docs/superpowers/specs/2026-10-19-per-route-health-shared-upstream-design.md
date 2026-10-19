<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec. Draft for operator review.
-->

# Per-route health for shared upstreams — design

- **Date:** 2026-10-19
- **Target version:** v2.76.0
- **Status:** DRAFT — awaiting operator review
- **Related:** [route-health-notifications](2026-10-17-route-health-notifications-design.md); memories `route-health-notifications`, `hc-reload-reconcile-not-reset`.

## 1. Problem

When several routes point at the **same upstream dial address**, Arenet
shows **all of them** with the same health, and notifies **all of them**
on one route's failure — even when the others are actually up.

Reproduced 2026-10-19: `meet.hacf.fr`, `sso.hacf.fr`, `www.hacf.fr` all
proxy to `10.66.0.2:80` (a Traefik that fans out to different containers
by Host). The container behind `meet` was stopped. Result:

- The route-list table showed **all three badges DOWN (red)**, though
  `www` was serving normally.
- A single notification fired: *"Every upstream of 3 routes is
  unreachable via 10.66.0.2:80"*, listing all three.

## 2. Root cause (verified)

Caddy keys per-upstream health in a **global pool by dial address**:

```go
// caddy v2.11.4 modules/caddyhttp/reverseproxy/hosts.go:130
existingHost, loaded := hosts.LoadOrStore(u.String(), host) // u.String() == "10.66.0.2:80"
// :308  var hosts = caddy.NewUsagePool()  — process-global
```

So every `reverse_proxy` handler dialing `10.66.0.2:80` shares **one**
`*Host` and **one** health flag. Each route's active HC probes with its
own `Host`/`uri`, but all results are written to that shared flag. A
failing probe from `meet` marks the shared host unhealthy; a succeeding
probe from `www` marks it healthy — they **collide and flap**, and the
`healthy`/`unhealthy` events carry only `{"host":"10.66.0.2:80"}`, with no
way to tell which route's probe produced them.

Arenet consumes those events into an **address-keyed** tracker
(`caddyhc.HCStatusTracker`), and both consumers read it by address:

- **Badge:** `internal/api/routes_health.go` `aggregateStatus` →
  `status.Status(u.URL)` per upstream.
- **Notifier:** `internal/routehealth` index maps `addr → []routes`;
  `OnTransition` marks every route on that address.

Therefore a shared upstream collapses N routes to one (wrong) verdict.
This is inherent to Caddy's address-keyed pool — Arenet cannot derive
per-route health from the events alone.

## 3. Key insight

Arenet already owns a tool that **is** per-route: `internal/routecheck`
probes a route **end-to-end through Caddy** — it hits Caddy's own
listener with the route's `Host`, so the probe traverses
`Arenet → upstream → backend` exactly as real traffic does. For the repro
that disambiguates cleanly:

- `routecheck(www)` → listener, `Host: www.hacf.fr` → Traefik → www
  backend (up) → 2xx → **up**.
- `routecheck(meet)` → `Host: meet.hacf.fr` → Traefik → meet backend
  (down) → 502/404 → **down**.

So the fix is to make the **per-route reachability** (not the shared
address status) the source of truth **for routes whose upstream is shared**.

## 4. Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Introduce a **per-route health status**, authoritative for routes on a **shared** upstream; routes with a **unique** upstream keep the cheap address-keyed tracker status unchanged (byte-identical behaviour). | Bounds cost + risk to the only ambiguous case; no regression for the common case. |
| D2 | A **shared upstream** = a normalized dial address used by ≥2 enabled routes. The notifier index already computes this (`byAddr`); lift it into a shared helper. | Single source of truth for "is this address shared". |
| D3 | Per-route status comes from an **HC-replay probe**: dial each upstream directly with the route's **Host** + the route's HC **uri/method/headers**, and judge by the route's **expect_status + expect_body** — i.e., exactly what the per-route active HC would see if Caddy didn't collapse it by address. This is the same logic as the "Tester le contrôle" button the operator already trusts. NOT `routecheck` (its "any non-5xx = ok" would mis-read a down backend that makes Traefik answer 404). Dialing the shared upstream with the route's Host still disambiguates, because Traefik fans out by Host. | Matches the operator's configured HC criteria and the trusted Test button; accurate on 4xx-returning down backends. |
| D3a | The evaluator carries its **own compact probe** (dial + expect check + netguard SSRF), it does NOT extract the API's `probeHealthCheck`. The repo deliberately duplicates probe logic to keep the diagnostic plane and the data plane on separate code paths (see the `upstreamDialForProbe` comment, routes_test_health_check.go). | Follows the repo's stated convention; no API-layer refactor, lower regression risk. |
| D4 | Probing cadence for shared routes: **(a) on a Caddy event** for the shared address (accelerator, within the notifier's existing debounce window) **and (b) periodically** at the route's HC interval (floor e.g. 10s), so a route recovers in the UI even when the shared host keeps flapping and emits no distinct event. | Events alone are unreliable on a flapping shared host; the periodic floor guarantees convergence. |
| D5 | Both the **badge** (`aggregateStatus`) and the **notifier** read the per-route status for shared routes. One evaluator, two consumers — they can never disagree again. | The reported bug is precisely badge and notifier disagreeing with reality in the same way; fix once. |
| D6 | The topology graph's per-**upstream** badge (the node for `10.66.0.2:80`) still reflects Caddy's shared address state and is **out of scope** (it is genuinely one shared host). Only the **route-level** badge/list and notifications become per-route. | Honest: the upstream node *is* shared; the route is the right granularity to disambiguate. |
| D7 | Flapping control: a shared route's status changes only after the per-route probe's existing retry policy (3×) confirms it, and the notifier keeps its debounce + reminder. No new flap state machine. | Reuse proven policy; avoid notification storms from a flapping shared host. |

## 5. Design

```
            Caddy active HC (per route, shared host pool)
                      │  healthy/unhealthy {host: addr}
                      ▼
            caddyhc.HCStatusTracker  (address-keyed, unchanged)
                      │ OnTransition(addr)
                      ▼
          ┌─────────────────────────────────────────────┐
          │ RouteHealthEvaluator (new)                   │
          │  - shared(addr)? ── no ──▶ use tracker status│
          │                   └─ yes ─▶ routecheck(route) │
          │                             per affected route│
          │  caches per-route status; periodic refresh    │
          └─────────────────────────────────────────────┘
                 │                         │
                 ▼                         ▼
       badge (aggregateStatus)     notifier (confirm before paging)
```

- **Unique upstream** (the overwhelming common case): nothing changes —
  `aggregateStatus` and the notifier read the tracker exactly as today.
- **Shared upstream:** the evaluator supplies a per-route status derived
  from `routecheck`. The badge shows it; the notifier includes a route in
  a "down" message only if its per-route probe failed.

### Consumer changes
- `routes_health.go aggregateStatus`: when `r`'s upstream(s) are shared,
  read per-route status from the evaluator instead of `status.Status(url)`.
- `routehealth.Notifier.OnTransition`: for a shared address, confirm each
  affected route via the evaluator (within the debounce window) and only
  buffer edges for routes that actually changed per-route state.

## 6. Non-goals

- Changing Caddy's address-keyed host pool or giving each handler an
  isolated host (not possible without distinct dial addresses, which
  would break routing). The **upstream node** badge stays shared (D6).
- Per-route health for routes that do **not** share an upstream — their
  behaviour is byte-identical to today.
- Replacing Caddy's active HC with Arenet-driven probing globally (too
  big; we only disambiguate the shared case).

## 7. Empirical validation gates

1. **Repro test (the reported case):** two routes (`a.test`, `b.test`)
   → same upstream; a stub that answers 200 for Host `a.test` and 502 for
   Host `b.test`. Assert the badge: `a.test` = healthy, `b.test` = down.
   Assert the notification lists **only** `b.test`.
2. **Non-regression:** a route with a **unique** upstream produces the
   exact same badge and the exact same tracker reads as today (the
   evaluator is bypassed). Golden/byte-identity on the config and the
   `aggregateStatus` output for the unique-upstream fixtures.
3. **Flapping:** with `a` up and `b` down on a shared host emitting
   alternating events, assert the notifier sends **one** down edge for
   `b` (debounced) and **no** edge for `a`, over N event cycles.
4. **Recovery without a distinct event:** bring `b`'s backend up; assert
   the periodic refresh (D4b) flips `b`'s badge to healthy and fires one
   recovery notification, even if the shared host emitted no `b`-specific
   event.

## 8. Risks

- **Probe load:** bounded to shared-upstream routes, on event + a floored
  interval. Worst case a handful of extra through-Caddy GETs per interval.
- **Self-probe through Caddy:** `routecheck` already hits the local
  listener; confirm it is not gated by the route's own auth/WAF in a way
  that would false-negative (routecheck targets the HC path / a benign
  path — validate against a gated route in gate #2).
- **Debounce vs. periodic interaction:** the periodic refresh must not
  double-notify with the event path; the notifier's `last[routeID]`
  dedupe already guards this — gate #4 asserts it.
