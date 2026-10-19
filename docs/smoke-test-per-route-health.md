<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
-->

# Smoke test — per-route health for shared upstreams (v2.76.0)

Validates that routes sharing one upstream are shown and notified **per
route**, not collapsed to the shared address's health.

## Setup (the reported shape)

- A reverse proxy that fans out by Host (e.g. Traefik) at `10.66.0.2:80`,
  with two backends behind it: one for `meet.<domain>`, one for
  `www.<domain>`.
- Two Arenet routes, BOTH pointing at `http://10.66.0.2:80`, each with an
  active health check (`uri`, `expect_status`, optionally `expect_body`).
- Route-health notifications enabled on BOTH routes, same email channel.

## Procedure

1. Both backends up → both routes show **healthy** (green) in the route
   list. No notification.
2. Stop the container behind **meet** only.
3. Within ~10 s (the periodic re-probe) **and** on the next active-HC
   event, the route list shows **meet DOWN (red)** and **www HEALTHY
   (green)** — not both red.
4. Exactly one notification arrives, naming **only meet** — never www.
5. Restart meet's backend. Within ~10 s meet returns to **healthy** and a
   single **recovery** notification arrives (even though the shared Caddy
   host may not have emitted a meet-specific event).

## What proves it

- **Before v2.76:** step 3 painted all routes on `10.66.0.2:80` red, and
  step 4 sent "Every upstream of N routes is unreachable via 10.66.0.2:80"
  listing www too (www was up).
- **v2.76:** the evaluator probes each shared route directly with its own
  Host (`probeRouteUpstreams`), judged by the route's own HC criteria
  (`expect_status` / `expect_body`), so meet and www get independent
  verdicts that feed both the badge and the notifier.

## Non-regression

A route with a UNIQUE upstream is untouched: its badge and notifications
still come from the address-keyed tracker, byte-identical to v2.75.x. The
evaluator only engages when an upstream address is used by ≥2 enabled
routes.

## Out of scope

The topology graph's **upstream node** (`10.66.0.2:80`) still reflects
Caddy's single shared host — it genuinely is one shared backend address.
Per-route disambiguation is at the route level, which is where it belongs.
