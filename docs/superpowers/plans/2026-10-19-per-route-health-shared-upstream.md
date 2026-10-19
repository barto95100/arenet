<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan. Follows the 2026-10-19 per-route-health spec.
-->

# Per-route health for shared upstreams — implementation plan

- **Spec:** [2026-10-19-per-route-health-shared-upstream-design.md](../specs/2026-10-19-per-route-health-shared-upstream-design.md)
- **Target:** v2.76.0
- **Branch:** `feature/per-route-health-shared-upstream`

Each task compiles, is tested, and commits on its own. Guard discipline:
fail-first tests, `cp` backups for reinjection, byte-identity on the
unique-upstream (non-regression) path.

## T1 — shared-upstream detector (storage-level helper, pure)

- New `internal/routehealth/shared.go`: `SharedUpstreams(routes) map[string]int`
  (normalized addr → count of enabled routes using it) and
  `IsRouteShared(r, shared) bool`.
- Reuses `caddyhc.NormalizeAddr`; counts only enabled routes.
- **Test:** three routes same addr → shared; one route unique → not;
  disabled routes excluded.
- Pure function, no deps — lands first so the evaluator and both
  consumers import one definition of "shared".

## T2 — RouteHealthEvaluator core + compact HC-replay probe (no wiring yet)

- New `internal/routehealth/probe.go`: a compact `routeProbe(ctx, r,
  dialer) status` that, for each upstream, dials it directly with the
  route's `Host` (= `hc.ProbeHost(r.Host)`), the HC `uri/method/headers`,
  and judges by `expect_status` + `expect_body`. Healthy only if an
  upstream answers to the HC criteria. SSRF-guarded via `internal/netguard`.
  Owned here (duplicated, per spec D3a), NOT extracted from the API.
- New `internal/routehealth/evaluator.go`: `Evaluator` holding a `prober`
  (interface `probe(ctx, storage.Route) string` so tests fake it), a
  `clock`, a `logger`, `perRoute map[routeID]status` + `since`, and the
  shared set from T1.
- `Refresh(routes)`: recompute shared set + shared route list; DROP cache
  entries for routes no longer shared.
- `RouteStatus(routeID) (status string, ok bool)`: ok=false when the
  route is not shared (caller falls back to the tracker).
- **Tests:** a fake prober — shared route probed + cached; unique route →
  `RouteStatus` ok=false; Refresh evicts stale. Probe unit test against an
  httptest server: Host-routed 200 → healthy, 502/404-with-expect-200 →
  unhealthy, body-regex mismatch → unhealthy.
- No goroutines yet — deterministic.

## T3 — event-driven + periodic probing (lifecycle)

- `OnSharedEvent(addr)`: if addr is shared, probe each affected route
  now and update the cache; emit a per-route transition callback
  (`onRouteTransition(routeID, old, new, at)`) on change.
- `Start(ctx)`: periodic loop at `min(route HC interval, floor 10s)`
  re-probing all shared routes; `Stop()` via ctx cancel. Injected clock
  so tests fire ticks deterministically (mirror the notifier's clock
  pattern).
- **Tests (-race):** event probe flips cache + fires callback once;
  periodic tick converges a recovered route with no event; stop is clean.

## T4 — badge consumes per-route status

- `internal/api/routes_health.go aggregateStatus`: inject the evaluator
  (via the handler, like `SetHCStatusReader`). For a route whose upstream
  is shared AND the evaluator has a verdict: return healthy/down from the
  per-route status (bypass the per-upstream tracker loop). Otherwise
  **unchanged**.
- **Tests:** repro fixture (a.test up / b.test down, shared) → a healthy,
  b down. **Non-regression:** unique-upstream route → identical output and
  identical tracker reads as today (gate #2). Byte-identity on the
  existing routes_health fixtures.

## T5 — notifier confirms per-route before paging

- Wire the evaluator into `routehealth.Notifier`. In `OnTransition`, for a
  shared address, consult the evaluator's per-route status (freshly
  probed by T3's `OnSharedEvent`, which runs first on the same event) and
  buffer an edge only for routes whose per-route aggregate changed.
- Routes on unique upstreams: unchanged path.
- **Tests:** shared host, b down / a up → one "down" edge for b, none for
  a (gate #1 + #3). Flapping emits one debounced edge (gate #3).

## T6 — wiring in cmd/arenet/main.go

- Construct the evaluator with `routecheck.New(mgr.HTTPListen,
  mgr.HTTPSListen)`, the tracker, the dispatcher.
- `hcTracker.SetOnTransition` fans out to BOTH the notifier and
  `evaluator.OnSharedEvent` (compose the two callbacks).
- `mgr.SetReloadHook` fans out to `notifier.Refresh` AND
  `evaluator.Refresh` (reuse the v2.75.4 self-seed: setting the hook
  replays the last applied routes, so the evaluator is seeded at boot).
- `evaluator.Start(ctx)` for the periodic loop; stop on shutdown.
- Inject the evaluator into the API handler for the badge.
- **Test:** a boot-order test like v2.75.4's — the composed hook seeds
  both consumers.

## T7 — docs + smoke

- `docs/smoke-test-per-route-health.md`: the Traefik repro, step by step.
- Wiki-seed migration note (EN + FR) for v2.76.0: shared-upstream routes
  now show per-route health in the list and notify per route.
- Update memory `route-health-notifications` with the shared-upstream
  resolution.

## Validation gates (from the spec §7)

1. Repro: a.test healthy / b.test down on a shared upstream → correct
   badges + notification names only b.
2. Non-regression: unique upstream byte-identical.
3. Flapping: one debounced down edge for b, none for a.
4. Recovery without a distinct event: periodic refresh flips b green +
   one recovery notification.

## Open questions for the operator

- **Scope of per-route probing:** shared upstreams only (this plan), or
  ALL routes (more accurate, more load)? Default: shared only.
- **Periodic floor:** 10s proposed. Acceptable, or tie strictly to each
  route's HC interval?
