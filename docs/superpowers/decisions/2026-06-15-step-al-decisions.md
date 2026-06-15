<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step AL — Alerting V1: eight design decisions

Date: 2026-06-15
Status: ACCEPTED (operator-validated, pre-code)
Related spec: `docs/superpowers/specs/2026-06-15-step-al-alerting.md` (un-deferred from `_deferred/2026-05-31-step-r-alerting.md`)
Related tickets: Phase 6 alerting workstream — successor to Day 13 stabilisation cycle (commits `a234dbc` Bug #1 frontend timeout + `cd09a34` Bug #2 backend `ReloadFromStore` timeout).

## Context

Step AL is the un-deferred alerting work originally drafted in May
2026 as "Step R", set aside before arbitrage so the OKLCH visual
migration (also named Step R) could take the slot. The May spec
listed ten open decisions (D1..D10) with recommendations but no
final operator sign-off. After the Day 13 stabilisation cycle
closed the two intermittent bugs (#R-FRONTEND-PUT-NO-TIMEOUT,
#R-CADDY-ADMIN-DEADLOCK), the operator validated eight of those
decisions for V1 implementation; D8 (Settings UI density) and D9
(per-route filtering) stay deferred indefinitely per their own
recommendations.

This ADR is the single active reference for what V1 ships. The
spec's §1.3 "OPEN decisions" block is preserved verbatim as
historical context but the binding values live here.

## Decision summary

| # | Topic | V1 choice | Status |
|---|-------|-----------|--------|
| D1 modulé | Channel kinds shipped V1 | Webhook + email (Slack + Discord deferred V2) | ACCEPTED |
| D2 | Trigger model classes V1 | Threshold + state (event-based deferred V2) | ACCEPTED |
| D3 | Boot-degraded health surface | New `GET /api/v1/system/health` endpoint | ACCEPTED |
| D4 | Dedupe / cooldown model | Per-(rule_id, channel) cooldown LRU; no resolution detection V1 | ACCEPTED |
| D5 | Severity + per-channel filter | 4-level severity (info/warning/critical/emergency) + per-channel `min_severity` filter | ACCEPTED |
| D6 | `alert_event` persistence | New SQLite table + 3 audit actions (`alert_rule_created/updated/deleted`) | ACCEPTED |
| D7 | Sender ABI | Per-kind struct implementing common `AlertSender` interface | ACCEPTED |
| D10 | Polling cadence | Fixed 30s tick V1 (configurable V2 if operator asks) | ACCEPTED |
| D8 / D9 | UI density + per-route filtering | Deferred indefinitely (YAGNI floor) | DEFERRED |

## D1 modulé — Channels V1: webhook + email

**Decision**: V1 ships **webhook** + **email (SMTP)**. **Slack** and
**Discord** deferred V2 as opportunistic add-ons.

**Justification**:
- **Webhook** is the lingua franca for alertmanager-compatible
  tooling — operators with custom destinations (Pushover,
  Gotify, ntfy, ops-team-specific webhooks) all consume
  generic JSON POST. Shipping webhook V1 covers the
  "any-destination" baseline.
- **Email (SMTP)** is the monitoring-infrastructure standard.
  Every homelab operator has at least one email address;
  every existing monitoring stack (Prometheus Alertmanager,
  Zabbix, Nagios) ships email by default. An alerting feature
  that ships without email feels incomplete.
- **Slack + Discord** are popular but optional. They share
  80% of the webhook implementation (kind-specific payload
  templating); deferring them V2 trades ~3-4h of immediate
  scope reduction for an additive V2 release that fits the
  "opportunistic homelab UX" pattern.

**Effort delta vs the May 2026 D1.C recommendation**
(webhook + Slack + Discord, skip email):
- +5-6h on AL.1 for SMTP wiring (from-address validation, auth
  variants PLAIN/LOGIN/CRAM-MD5, TLS/STARTTLS posture, maildev
  smoke harness)
- -3-4h on AL.1 for skipped Slack + Discord wrappers
- **Net: +2h on AL.1**

The total Step AL V1 effort estimate stays in the **47-58h
range** documented in the design review.

## D2 — Trigger model: threshold + state

**Decision**: V1 ships **threshold-based** + **state-based**
triggers. **Event-based** triggers (specific audit action →
alert) defer to V2.

**Justification**:
- Threshold-based (rate > X over window Y) covers the most
  common operator concern: "WAF blocks > 50/min for 5
  minutes". Polls aggregated metric buckets.
- State-based (boot-degraded toggle) covers "LAPI unreachable
  for 5 minutes". Polls per-component health markers via the
  D3 `/system/health` endpoint.
- Event-based ("any `config_restored_rejected` audit row →
  alert") is genuinely useful for security signals but
  needs its own design surface (event correlation,
  per-action dedupe, audit-bucket subscription vs polling).
  Defer V2 with dedicated design pass.

## D3 — Boot-degraded health surface

**Decision**: V1 ships a **new** `GET /api/v1/system/health`
endpoint. Distinct from the existing `/healthz` (Caddy-native
liveness probe — kept minimal for orchestrator parsers).

**Component fields exposed** (V1):
- `caddy`: `ok` / `degraded` (last reload status + ts)
- `db` (BoltDB): `ok` / `degraded` (read probe success)
- `metrics` (SQLite): `ok` / `degraded` (observability store
  open + recent insert success)
- `crowdsec`: `configured` + `last_poll_ok` /
  `not_configured` / `unreachable`
- `certmagic`: `ok` / `degraded` (last cert renewal attempt
  status across managed domains)

**Why a new endpoint vs extending `/healthz`**: `/healthz` is
the orchestrator liveness contract (systemd, docker, k8s).
Parsers expect a stable boolean shape. Adding rich
per-component fields breaks that contract. The new endpoint
sits at `/api/v1/system/health` under the admin auth gate
(viewer-readable, admin-write only — same posture as the
read-only observability endpoints).

## D4 — Dedupe / cooldown

**Decision**: V1 ships **per-(rule_id, channel) cooldown LRU**.
**No resolution detection** V1.

**Implementation shape**:
- LRU cache keyed `(rule_id, channel_id)` → last-fire
  timestamp.
- Default cooldown per rule: 15 min for threshold, 1 hour
  for state. Operator-tunable per rule.
- Resolution detection (auto-fire "incident resolved" when
  the condition clears) deferred V2 — requires incident
  state persistence + per-channel "resolved" templates +
  resolution-vs-cooldown-clear disambiguation.

**Trade-off acknowledged**: operator who fixes the issue
quickly (under the cooldown window) gets no "resolved"
notification. V2 candidate when operator feedback requests
it.

## D5 — Severity + per-channel filter

**Decision**: V1 ships **4 severity levels**
(info/warning/critical/emergency) + **per-channel
`min_severity` filter**.

**Operator usage pattern**:
- Webhook channel `min_severity=info` → receives everything
- Email channel `min_severity=critical` → only paged on
  critical/emergency (e.g. "service down" not "blocked
  request spike")

**Why 4 levels**: aligns with syslog severity vocabulary
(LOG_INFO, LOG_WARNING, LOG_ERR/LOG_CRIT, LOG_EMERG).
Operators reading the dashboard expect the well-known
escalation gradient.

## D6 — `alert_event` persistence

**Decision**: V1 ships a **new SQLite table** `alert_event` +
**3 new audit actions**.

**`alert_event` schema** (V1):
- `id` (primary key)
- `timestamp` (UTC ISO 8601)
- `rule_id` (FK to BoltDB rule)
- `severity` (one of the 4 D5 levels)
- `channels_fired` (JSON array of channel ids that received
  this alert; empty when all suppressed by min_severity
  filters)
- `payload_json` (the full alert payload — webhook body shape)

**Audit actions** (V1):
- `alert_rule_created`
- `alert_rule_updated`
- `alert_rule_deleted`

Note: alert *fires* go to `alert_event` (system action,
high-volume); only rule CRUD (operator-action,
low-volume) goes to audit per the existing pattern (M/Q/N
events vs audit).

**Retention**: 30 days (mirrors `waf_event` / `decision_event`
/ `throttle_event` / `cert_event` retention).

## D7 — Sender ABI

**Decision**: V1 ships a **per-kind sender struct** (`WebhookSender`,
`EmailSender`) implementing a common interface:

```go
type AlertSender interface {
    Send(ctx context.Context, evt AlertEvent) error
}
```

**Justification**:
- Clean per-kind file separation (`sender_webhook.go`,
  `sender_email.go`)
- Test seam via the interface (fake `AlertSender` in unit
  tests, no need for HTTP/SMTP boot)
- V2 Slack + Discord add cleanly as new struct + interface
  satisfaction — no central switch statement to grow

## D10 — Polling cadence

**Decision**: V1 ships **fixed 30s tick**.

**Justification**:
- Threshold rules see 2 ticks per minute-bucket window —
  consistent with the metric source aggregation cadence.
- State rules see ≤30s detection latency, well under any
  homelab "actionable" threshold.
- Configurable per-rule cadence (D10.B) deferred V2 if
  operator feedback identifies a use case.

## Deferred decisions

- **D8 — Settings UI density** (unified card vs split):
  default to unified card with two sub-sections (Channels
  list + Rules list). Density concern addressable with a
  tabbed inner layout if needed during AL.4 implementation.
- **D9 — Per-route alert filtering**: defers indefinitely.
  Metric sources roll up across routes today; route-level
  alerting would require a separate aggregation pass-
  through. YAGNI floor.

## V1 sequencing + effort

**Sequential order**: **AL.1 → AL.3a → AL.2 → AL.3b → AL.4 → AL.5**

- AL.3a = `/system/health` endpoint alone (≈4-5h, **quick
  win**: external monitoring can scrape immediately, before
  the full alerting pipeline lands).
- AL.3b = remaining alert CRUD endpoints + `alert_event`
  table + audit actions.
- AL.2 (rule engine + watcher) depends on AL.3a for the
  state-rule reader.

**Total V1 effort estimate**: 47-58h.

## Risk points (V1)

1. **Watcher concurrency** (AL.2): rule engine reads from
   multiple metric sources + state endpoint, dedupe LRU is
   concurrent-write-safe. Critical-path test surface.
2. **`/system/health` "what counts as degraded"** semantics
   (AL.3a): false positives (transient blip flagged
   degraded) erode operator trust; missed signals defeat the
   purpose. Empirical calibration during AL.3a smoke.
3. **Cooldown LRU semantics** (D4): operator who fixes the
   issue under the cooldown gets no resolution notification.
   Documented trade-off — V2 candidate.
4. **Channel auth token discipline** (D7 + J.4 pattern):
   secrets storage in BoltDB with the same encrypted-at-
   rest posture as DNS provider credentials. Smoke test
   verifies the secret never reaches a log line or audit
   JSON.

## References

- Spec: `docs/superpowers/specs/2026-06-15-step-al-alerting.md`
- Historical "Step R" deferred banner:
  `docs/superpowers/specs/_deferred/README.md` (historical
  un-defers section)
- J.4 secret discipline pattern:
  `internal/storage/dns_provider.go` (OVH) +
  `internal/storage/automation_config.go` (Step P.3
  watcher creds)
- Buffered sink pattern: `internal/waf/sink.go:100-141`
- Day 13 stabilisation completion: commits `a234dbc`
  (frontend timeout) + `cd09a34` (backend reload timeout)
  — Step AL builds on the now-stable PUT/POST route flow
  and the proven goroutine-dump pprof discipline.
