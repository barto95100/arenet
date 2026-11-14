<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan — auto-classify writer health visibility. Target: v2.82.0.
-->

# Auto-classify writer health visibility — plan

Spec: `docs/superpowers/specs/2026-11-14-automation-health-metrics-design.md`

## T1 — read-only health surface (automation)

- `internal/automation/health.go` (new): `HealthSnapshot` struct +
  `HealthReporter` interface + `(*DefaultManager).HealthSnapshot()` reading
  the writer's `LoginFailed()` and the Engine's `TotalPush*` counters.
- Fix the lying comment in `watcher_client.go:233` (promised a metric that
  never existed) to name the real gauge.
- Tests `health_test.go`: configured/not-configured + login-failed
  propagation via a 401 test server. Reinjection: dropping the
  `WriterLoginFailed` assignment fails it.

## T2 — Prometheus endpoint (api)

- `internal/api/metrics_prometheus.go` (new): a `prometheus.Collector` over
  an injectable `automationSnapshot` (default reads `automation.GetManager()`
  type-asserted to `HealthReporter`), a dedicated registry, and the
  `prometheusMetrics` handler via `promhttp`.
- `routes.go`: mount `GET /metrics` at the root inside a `HardAuthMiddleware`
  group (viewer-accessible, token or session) — NOT under `/api/v1`, to keep
  the Prometheus convention and avoid colliding with the JSON
  `/api/v1/metrics/*` API.
- `go.mod`: promote `prometheus/client_golang` indirect → direct.
- Tests `metrics_prometheus_test.go`: exposition content (whole-line match,
  not substring — the gauge's HELP text starts "1 when…" and would satisfy a
  substring check regardless of value), healthy-zero, no-manager-zeros.

## T3 — OpenAPI + docs

- `internal/api/openapi/backup-system.yaml`: document `GET /metrics`
  (`servers: [{url: /}]`, `x-arenet-role: viewer`, text/plain 200) so
  `TestOpenAPI_CoversEveryRoute` passes — every router route must be
  documented.
- `docs/operations/monitoring.md` (new): the three monitoring endpoints, the
  `/metrics` auth model, the four metrics, the alert expression, and
  Prometheus/Zabbix/Datadog/Nagios scrape snippets.

## Gates

`go build`, `go vet`, `gofmt -s`, `go test -race ./internal/api/
./internal/automation/`, full `./internal/api/` package (OpenAPI coverage).
Reinjection proof for the two load-bearing guards (gauge flip; login-failed
propagation).

## Known pre-existing flake (not introduced here)

`TestOpenAPI_RolesMatchTheRouter` can panic intermittently in
`SnapshotHandler.ServeHTTP` (topology_snapshot.go:112) because the test
harness wires a nil `store`; it surfaces only under the full parallel
package run and is independent of this change (the targeted test passes on
`origin/main` and on this branch). Not fixed here.

## Out

No other metrics (WAF/rate-limit/per-route have their own API), no `/healthz`
change, no auth scheme beyond the existing token/RBAC, no release tag without
operator go-ahead.
