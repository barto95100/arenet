<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Monitoring Arenet

Arenet exposes three endpoints for external monitoring, all on the admin
plane (`:8001`, bound to `127.0.0.1` by default).

| Endpoint | Auth | Format | Purpose |
|----------|------|--------|---------|
| `/healthz` | none | JSON | Liveness: `{"status":"ok","uptime_seconds":N}`. For Docker `HEALTHCHECK`, k8s probes, uptime monitors. |
| `/system/health` | none | JSON | Subsystem status + counts + latency, for dashboards (Uptime Kuma, blackbox_exporter). No secrets. |
| `/metrics` | **token** | Prometheus text | Operational metrics for Zabbix / Nagios / Datadog / Prometheus. **v2.82.0+**. |

`/healthz` and `/system/health` are unauthenticated on purpose — they carry
no sensitive data and probes rarely send credentials. `/metrics` is
**authenticated**, because it reports operational detail and Arenet may be
deployed with the admin plane published.

## `/metrics` — authentication

`/metrics` requires a token, sent as `Authorization: Bearer <token>`. Create
a read-only **service account** (Settings → Users → Service accounts), copy
its token, and give it to your monitoring tool. A viewer-role account is
enough — `/metrics` is read-only.

```bash
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8001/metrics
```

## Metrics exposed (v1)

Scope v1 is the **auto-classify writer** (Security Automation → CrowdSec),
which otherwise fails silently when its machine credential breaks.

| Metric | Type | Meaning |
|--------|------|---------|
| `arenet_automation_writer_login_failed` | gauge | `1` when the writer's last CrowdSec LAPI login failed — **automatic banning has stopped** until the operator fixes the machine credential. `0` otherwise (including when automation is not configured). |
| `arenet_automation_pushes_total{result="success"}` | counter | Bans successfully pushed to LAPI. |
| `arenet_automation_pushes_total{result="permanent"}` | counter | Dropped on a non-retryable error (bad credential or rejected payload) — the signal that needs a human. |
| `arenet_automation_pushes_total{result="dropped"}` | counter | Dropped after retry exhaustion against an unreachable LAPI. |

### Recommended alert

Fire when the writer is broken, or permanent-drops are climbing:

```
arenet_automation_writer_login_failed == 1
or increase(arenet_automation_pushes_total{result="permanent"}[15m]) > 0
```

## Scraper snippets

**Prometheus** (`prometheus.yml`):
```yaml
scrape_configs:
  - job_name: arenet
    metrics_path: /metrics
    authorization:
      credentials: "<token>"
    static_configs:
      - targets: ["127.0.0.1:8001"]
```

**Zabbix** — HTTP agent item, URL `http://127.0.0.1:8001/metrics`, add a
request header `Authorization: Bearer <token>`, then a *Prometheus pattern*
preprocessing step per metric (e.g. `arenet_automation_writer_login_failed`).

**Datadog** — the OpenMetrics check with
`openmetrics_endpoint: http://127.0.0.1:8001/metrics` and
`headers: {Authorization: "Bearer <token>"}`.

**Nagios / Icinga** — any `check_http`-style plugin that sends the bearer
header and greps the metric line.

> If you reach `/metrics` from another host, remember the admin plane is
> `127.0.0.1`-only by default; expose it deliberately (and keep the token
> secret) or scrape over an SSH tunnel / from the same host.
