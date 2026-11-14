<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec — auto-classify writer health visibility (Prometheus). Target: v2.82.0.
-->

# Auto-classify writer health visibility — design

**Target version:** v2.82.0 (feature — a new `/metrics` endpoint)

## Problem

The Security Automation writer (the machine-account path that POSTs bans to
CrowdSec LAPI) fails **silently**. If the machine credential breaks (password
rotated, `cscli machines delete arenet`, LAPI auth changed), the writer sets
a sticky `loginFailed` and stops banning. The synchronous surfaces (Scenarios
tab, manual ban, Live LAPI) show an error to the operator; the **asynchronous
auto-classify writer does not** — it only logs a slog line and bumps internal
counters.

Those counters exist but are exposed **nowhere**:
`automation.Engine.TotalPushSuccess/Permanent/Dropped()` (`trigger.go:797-799`)
have no caller outside tests, and `watcher_client.go:233` even claims an
`automation_login_failures_per_hour` metric that **does not exist** (no
Prometheus collector in `internal/automation`). An operator supervising with
Zabbix/Nagios/Datadog/Prometheus has no scrapable signal that auto-banning
stopped.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | Add a Prometheus text-format `GET /metrics` endpoint on the admin plane. | Prometheus exposition is the one format every monitoring tool ingests (Zabbix Prometheus preprocessing, Nagios plugins, Datadog OpenMetrics, Prometheus native). One surface, universal. |
| 2 | **Authenticated** — requires a token (service account / API token under RBAC), NOT unauthenticated like `/healthz`. The admin plane still binds `127.0.0.1` by default. | Operator decision (2026-11-14): shipped to every Arenet user, so an unauth network endpoint is a footgun if the admin plane is ever published. Metrics reveal operational data (push volume, writer state). Every monitoring tool sends a static `Authorization: Bearer <token>` header (Zabbix HTTP agent, Prometheus `authorization`, Datadog, Nagios), so a token costs one config line and closes the exposure. |
| 3 | Use `prometheus/client_golang` (already in the module graph, promoted to a direct dep) with a dedicated `*prometheus.Registry` — not the global default registry. | Idiomatic, dep already present, avoids hand-rolling text format. A dedicated registry keeps Arenet's metrics isolated from any library's global registrations. |
| 4 | A custom collector reads the live `Engine` counters on each scrape; no duplicated state. The writer login state is exposed as a gauge `arenet_automation_writer_login_failed` (1/0). | The Engine already holds the atomic counters; a collector is a read-only view. The gauge answers the operator's real question ("is the writer broken right now?"). |
| 5 | Scope v1 to automation health only. The registry + endpoint are built to let other Arenet metrics register later. | Point 3 is the need; a kitchen-sink metrics export is out of scope. Extensible, not speculative. |
| 6 | `/healthz` is **unchanged** — not a single field added. | Operator contract: Zabbix reads `{"status":"ok","uptime_seconds":N}` every minute. |
| 7 | Fix the lying comment at `watcher_client.go:233`; name the real metric. | A comment promising a metric that does not exist is a documented-but-unguarded hazard (guard skill). |

## Metrics exposed (v1)

| Metric | Type | Meaning |
|---|---|---|
| `arenet_automation_writer_login_failed` | gauge | 1 when the writer's last login failed (sticky), 0 otherwise or when no writer is configured. |
| `arenet_automation_pushes_total{result="success"}` | counter | Bans successfully POSTed to LAPI. |
| `arenet_automation_pushes_total{result="permanent"}` | counter | Dropped on a permanent error (bad creds / bad shape) — the silent-failure signal. |
| `arenet_automation_pushes_total{result="dropped"}` | counter | Dropped after retry exhaustion (LAPI unavailable). |

A monitoring alert fires on `arenet_automation_writer_login_failed == 1` or a
rising `…pushes_total{result="permanent"}`.

## Non-goals

- Exposing WAF / rate-limit / per-route metrics here (those have their own API
  already). v1 is automation health only.
- A dedicated metrics auth scheme: `/metrics` reuses the existing API-token /
  service-account auth + an RBAC permission, not a new credential type.
- Any change to `/healthz`, to the writer's behaviour, or to the push path.

## Empirical gates

- `TestMetricsEndpoint_ExposesAutomationHealth`: a request to `/metrics`
  returns the gauge + the three counters in Prometheus text format, reading a
  fake Engine's counters. Reinjection: a login-failed writer flips the gauge
  to 1.
- `TestMetricsEndpoint_NoWriter`: gauge reads 0 (not absent) when automation
  is unconfigured.
- `TestHealthz_Unchanged`: `/healthz` body is still exactly
  `{"status":"ok","uptime_seconds":N}` (byte-shape pinned).
- Gates: `go build`, `go vet`, `gofmt -s`, `go test -race ./internal/api/
  ./internal/automation/`.

## Operator-facing

- Wiki: a short "Monitoring" section — scrape `http://127.0.0.1:8001/metrics`,
  the four metrics, and the recommended alert expression. Zabbix / Nagios /
  Datadog one-liners.
- No UI change.
