# Step R — Alerting Phase 3 (DEFERRED)

> **Status: DEFERRED 2026-05-31.** Originally drafted as Step R
> right after Step P (auto-classify) shipped. Deferred before
> arbitrage / freeze because the OKLCH visual migration + IA
> reorg took the Step R slot as a higher-priority operator-
> visible improvement. The alerting work remains valuable and
> well-scoped — the OPEN decisions section below already
> captured the design surface; reopening this spec later means
> re-running the D1-D10 arbitrage and moving the file back to
> `../` (the active specs directory). Step letter for the
> reopened spec is TBD — likely the next free letter after
> the visual-migration + production-deploy work lands.

---

**Original status line (pre-defer):**
**Status**: DRAFT — decisions open for arbitration.
**Author**: Ludo + Claude.
**Predecessors**:
- Step M (WAF event rate), Step Q (throttle event rate + auth failures), Step N (CrowdSec decision rate), Step P (automation push / drop counters) — the metric sources alerting subscribes to.
- Step J.4 (DNS provider) / Step P.3 (watcher credentials) — the J.4 secret discipline pattern Step R applies to SMTP credentials + webhook tokens.

Why "Step R": Q is Step Q (throttle / rate-limit signals). Step S is the next free letter after R; we use R for "rules / reactions" matching the alerting domain. No formal convention forces it; the letter is just the next free slot.

---

## 1. Goal & scope

### 1.1 Goal

Close the **observation → notification** loop. Today Arenet surfaces WAF / throttle / CrowdSec / auth-failure signals in `/security/*` dashboards and the auto-classify loop (Step P) acts on them by pushing to LAPI. An operator who's NOT watching the dashboard or LAPI has no proactive signal — they have to be looking to see something is wrong. Step R adds **proactive notifications**: an operator-configured rule set fires alerts to channels (webhook / email / Discord / Slack) when interesting things happen.

**Three signal classes** alerting subscribes to:

1. **Threshold crossings** on existing rate metrics: WAF blocks/min, throttle blocks/min, CrowdSec decision rate, auth failures/min, automation push rate, automation drop rate.
2. **Boot-degraded states**: LAPI unreachable, OVH provider unconfigured (when managed-domains active), watcher credentials missing (P engine boot-degraded), observability storage failure, Caddy reload failed.
3. **Systemic errors**: schema migration error, Caddy load error, audit append error.

Alerting is **opt-in per rule + per channel** — fresh-install Arenet sends no notifications until the operator configures a channel and enables at least one rule.

### 1.2 Scope (5 sub-tasks — mirror M/Q/N/O/P cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| R.1 | Channel storage + sender clients | `Channel` BoltDB type + per-kind sender (webhook / email / Discord / Slack). Each sender is a small HTTP client (or SMTP for email) with J.4 secret discipline on tokens / passwords. AC #13 buffered-channel + drop-on-full per channel. |
| R.2 | Rule engine + watcher | Polling watcher (~30s tick) over the 3 signal classes. RuleSet + dedupe / cooldown LRU to suppress notification spam on persistent conditions. Emits `Alert` intents to the channel sender pipeline. |
| R.3 | REST API + storage + audit | `/settings/alerts/channels` CRUD + `/settings/alerts/rules` CRUD + `GET /alerts/recent`. Audit actions `alert_channel_changed`, `alert_rule_changed`, `alert_fired`. New `alert_event` table for the recent-feed + replay history. |
| R.4 | Frontend | New "Alerting" Card in Settings (Row 2.8 between Automation and OIDC). Channel list + rule list editors. `/security` dashboard widget showing the N most-recent alerts. |
| R.5 | Smoke + tag | Live smoke against a real webhook endpoint (httptest server on localhost). Trigger a threshold crossing, verify the alert lands. Tag `v1.4.0-step-r`. |

### 1.3 OPEN decisions (to arbitrate at draft review)

#### D1 — Channel kinds: which ship in v1.4, which deferred

The user named four: webhook (generic JSON POST), email (SMTP), Discord (webhook variant), Slack (webhook variant).

- **D1.A — All four in v1.4.** Webhook is the substrate; Discord + Slack are thin wrappers over webhook with their kind-specific payload shape (Slack uses `text: "..."` + `blocks: [...]`; Discord uses `content: "..."` + `embeds: [...]`). Email is the outlier — SMTP wire is different + requires a from-address + auth. Pros: complete v1.4. Cons: SMTP testing in smoke is harder (need a local SMTP server like maildev), and the email payload templating is its own design surface.
- **D1.B — Webhook only for v1.4, deferred Discord/Slack/email.** Webhook is sufficient for operators willing to set up an intermediate proxy (e.g. AlertManager → multi-channel fan-out). Discord/Slack v1.5; email v1.6. Pros: smallest scope. Cons: operators expect first-class integrations for the major platforms.
- **D1.C — Webhook + Slack + Discord in v1.4 (skip email).** The three webhook-substrate channels share 80% of the implementation. Email is the outlier that bloats v1.4. Pros: most-bang-for-buck — covers the common homelab notification channels. Cons: email-only operators (no Slack/Discord) wait until v1.5.

**Recommendation: C.** Webhook + Slack + Discord all share the HTTP-POST-with-JSON-body shape; the kind-specific payload templating is small (one function per kind). Email's SMTP wire + from-address + auth + smoke-harness setup is the outlier that doubles the spec surface. Defer to v1.5 cleanly. The recommendation can flip to A if email is a hard launch requirement.

#### D2 — Trigger model: threshold-based vs state-based vs event-based

Three trigger model classes were named:

- **D2.1 — Threshold-based** (rate > X over window Y): "WAF blocks > 50/min for 5 minutes". Polls aggregated metric buckets.
- **D2.2 — State-based** (boot-degraded toggle): "LAPI unreachable for 5 minutes". Polls per-component health markers.
- **D2.3 — Event-based** (specific audit action fires): "any `config_restored_rejected` audit row → alert". Subscribes to the audit append path or polls the audit bucket.

Three sub-arbitrages:

**D2.A — All three classes in v1.4, single Rule struct with discriminated trigger field.** The Rule's `trigger` field is a union `{kind: "threshold"|"state"|"event", ...kind-specific-params}`. Pros: covers every named signal class. Cons: bigger Rule shape; UI has 3 trigger-kind forms.

**D2.B — Threshold-only in v1.4, defer state + event.** Smallest v1.4 surface; the LAPI-down / OVH-unconfigured signals are deferred to a "Phase 4" alerting iteration. Pros: smallest scope. Cons: the spec's framing explicitly lists boot-degraded states; an alerting feature that ignores them feels incomplete.

**D2.C — Threshold + state in v1.4, defer event.** Covers the operator's most-likely use cases ("WAF spike", "LAPI down"). Event-based alerts are the niche case (audit-driven). Pros: balanced scope. Cons: event-based is genuinely useful for `config_restored_rejected` (security signal — someone tried to take over the instance).

**Recommendation: C** for v1.4. **A** is the right end state, but the event-based subset is small enough (literally one audit action set today) that deferring it doesn't lose much. The state-based subset is operator-meaningful and the spec framing names it explicitly, so include it.

#### D3 — Boot-degraded health surface: how does alerting observe it?

Per the survey, there's no centralized per-component health endpoint today. Boot-degraded states are visible via logs, handler `disabled` flags, and engine atomics.

- **D3.A — New `GET /api/v1/system/health` endpoint** (admin-only, returns per-component status). The alerting state-based rules query this endpoint at watcher tick cadence. Pros: clean operator-facing surface; future dashboard widget can reuse it. Cons: new endpoint surface; the per-component status fields are a mini-design surface (what counts as "degraded"?).
- **D3.B — Extend existing `/healthz` with detail fields**. Pros: no new endpoint. Cons: breaks the liveness-only contract `/healthz` has (orchestrator probes parsing a more complex shape).
- **D3.C — Alerting reads from the same heterogeneous sources operators do**: log scrape + handler `disabled` flags + engine atomics. Pros: zero new endpoint surface. Cons: brittle (log format drift breaks alerting; cross-cutting reads need many imports), and the alerting code becomes a hodgepodge of source-specific probes.

**Recommendation: A.** A clean new endpoint is the right shape. The per-component status fields are: `observability_store` (ok / degraded), `crowdsec_bouncer` (configured + last_poll_ok / not_configured / unreachable), `automation_engine` (configured + writer_ok / not_configured / login_failed), `dns_provider` (configured / not_configured), `caddy_last_reload` (ok + ts / error + ts + err_msg). Each field is a small computation from already-available sources. The endpoint is admin-auth gated (don't expose internal degradation publicly).

#### D4 — Dedupe / cooldown: how to prevent alert spam

A condition that persists (e.g. "LAPI unreachable" for 30 minutes) shouldn't fire 60 alerts (one per watcher tick). Three options:

- **D4.A — Per-(rule, channel) cooldown LRU**, mirror of Step P's `cooldownLRU`. After an alert fires, suppress re-fires for the same (rule, channel) until cooldown expires. Default cooldown per-rule: 15 min for threshold, 1 hour for state, immediate for event-based (every event is its own alert). Pros: known pattern; small implementation. Cons: operator must wait the cooldown to see "resolved" state if they fixed the issue quickly.

- **D4.B — Cooldown + resolution detection** (paged alerting like PagerDuty). Each fired alert opens an "incident"; when the condition clears, fire a "resolved" notification. Pros: most operator-friendly. Cons: tracking incident state is a real persistence surface; the per-channel "resolved" message templates are their own design surface.

- **D4.C — Just rate-limit notifications globally** (e.g. max 1 per channel per 5 minutes). Pros: simplest. Cons: legitimately-distinct alerts get suppressed by an unrelated spammy one.

**Recommendation: A.** B is the right end state for a mature alerting product but doubles the v1.4 surface. A is the homelab-appropriate floor: operator sees the alert, fixes the issue, the cooldown expires after 15min/1h and the rule re-arms. If the operator wants "resolved" notifications, that's a v1.5 candidate. C is the wrong granularity — alerts should be per-condition, not globally rate-limited.

#### D5 — Severity / categorization

Should alerts have a severity field (info / warning / critical) with per-channel filtering?

- **D5.A — Severity field + per-channel filter** (e.g. "email channel only receives critical, webhook channel receives everything"). Pros: lets operators reduce email noise. Cons: bigger Rule shape, bigger Channel shape, bigger UI.
- **D5.B — No severity, every rule fires to every channel it's mapped to.** Pros: smallest scope. Cons: every alert lands on every channel — operators with both Slack + email get duplicate notifications.
- **D5.C — Severity field but NO per-channel filter** (every channel receives every alert; severity is just a label / prefix in the notification text). Pros: middle ground; payload templates can colorize by severity (Slack red/orange/yellow). Cons: doesn't solve the email-noise concern.

**Recommendation: A.** Per-channel severity filtering is the operator-meaningful knob — "page me on critical, slack-message me on warning, ignore info". The implementation cost is one int field on Rule + one int field on Channel + a `>=` compare at dispatch time. Bigger UI cost than C but pays for itself the first time an operator gets paged at 3am for a warning-level signal.

#### D6 — `alert_event` table retention + shape

The audit trail of fired alerts needs persistence so operators can replay history.

- **D6.A — New SQLite table `alert_event`** (mirrors `waf_event` / `decision_event` / `throttle_event` shape). Fields: `id, ts, rule_id, channel_id, severity, summary, payload_json, status (sent/failed/dropped), sent_at, err_msg`. Retention 30d default (matches the other event tables). Pros: consistent storage shape; operators already know the retention policy. Cons: another SQLite table to migrate.
- **D6.B — Use the audit bucket** for fired alerts (`ActionAlertFired` audit action). Pros: no new table. Cons: audit is per-action with fixed schema; the alert-specific fields (channel_id, severity, status) would land in `Message` or `AfterJSON` as ad-hoc strings — operator can't `SELECT WHERE severity = 'critical'` cleanly.
- **D6.C — Both** (audit for the operator-action trail of CHANGES to alerts; alert_event for the FIRED history). Pros: separation of concerns. Cons: bigger surface.

**Recommendation: C.** Audit captures `alert_channel_changed` + `alert_rule_changed` (operator actions); `alert_event` captures fired events (system actions). This matches the existing M/Q/N pattern: `waf_event` for system events is separate from `route_created` in audit. Schema migration is small (single new table, idempotent CREATE).

#### D7 — Notification channel kind ABI: how does each channel type differ in the codebase?

Each sender needs to translate an `Alert` (kind-agnostic shape) into a wire-specific payload. Three approaches:

- **D7.A — Per-kind sender struct with `Send(alert) error` method.** Webhook, Slack, Discord, Email are each types implementing a `Sender` interface. Pros: clean per-kind separation; tests can fake one easily; new kinds add cleanly. Cons: more files, more imports.
- **D7.B — Single `Sender` with kind-dispatch switch.** All four kinds in one function with `switch channel.Kind { case "webhook": ... case "slack": ... }`. Pros: one file. Cons: long function, harder to test per-kind, harder to extend.
- **D7.C — Plugin-style registry**: senders register themselves at init. Pros: extensible. Cons: overengineered for 3-4 kinds.

**Recommendation: A.** Per-kind sender struct. Mirror of how `internal/storage/managed_domain.go` separates the validator from `internal/caddymgr/managed_domain.go` (predicate) — clean per-concern files. Tests inject fakes one-per-kind.

#### D8 — Settings UI: 1 unified Card or per-channel-kind sub-Cards?

- **D8.A — Single "Alerting" Card with two sub-sections** (Channels list + Rules list). Add/edit/delete via inline forms. Pros: one place to look; consistent with the SSL/Certs + Security Automation Cards. Cons: the Card gets dense (especially with severity filters + per-channel rule mapping).
- **D8.B — Two top-level Cards**: "Alert Channels" + "Alert Rules". Pros: each Card stays simple. Cons: Settings page grows by two Cards.

**Recommendation: A.** Pattern consistency with the prior Settings Cards. The density concern is real but addressable with a tabbed inner layout (Channels tab + Rules tab) if needed during P.4 implementation.

#### D9 — Multi-tenant / per-route alerts

The user explicitly named this as an arbitrage point.

- **D9.A — Skip for v1.4.** Alerts are instance-global; a homelab Arenet typically has one operator and one notification preference. The complexity of "alert me on WAF spike for routes X+Y but not Z" is real but rare in homelab.
- **D9.B — Per-route alert filtering** in v1.4. Each rule has an optional `route_ids: []` field; empty = all routes. Pros: handles the multi-tenant case. Cons: bigger Rule shape; UI needs a route picker.

**Recommendation: A** for v1.4. Defer per-route filtering until an operator actually asks for it (the YAGNI floor). The metric sources (WAF block rate etc.) already roll up across routes; adding per-route filtering at the alert layer when the metric source aggregates globally would also require route-level aggregation pass-through.

#### D10 — Polling cadence + alignment

How often does the watcher tick?

- **D10.A — Fixed 30s tick.** Threshold rules see 2 ticks per minute-bucket window; state rules see a 30s detection latency. Pros: predictable; matches the Step P engine's spirit (5s for P, 30s for less-time-sensitive R).
- **D10.B — Configurable per-rule.** Some rules need fast detection (LAPI down), others tolerate latency (slow WAF spike). Pros: operator tuning. Cons: more knobs.
- **D10.C — Sub-second event-driven** (audit append → immediate alert). Pros: lowest latency. Cons: producer-side instrumentation needed (audit-side `AlertEmitter` callback); the spec rejected this shape for the threshold/state classes.

**Recommendation: A.** 30s is the right tradeoff. State-rule detection latency caps at 30s + the boot-degraded condition's own debounce (the rule's window field). Operators rarely need faster. C would add producer-side coupling; B adds knobs without clear use cases at v1.4 (deferred until operator feedback).

---

## 2. Acceptance criteria

(Pre-arbitration draft — final list may shift based on D-arbitration outcomes.)

**AC #1 — Webhook channel sends JSON POST.** Operator configures a webhook channel pointing at a test endpoint; a threshold rule fires; the test endpoint receives a JSON POST with `{ts, rule_id, severity, summary, payload}`.

**AC #2 — Slack channel sends Slack-shaped payload.** Operator configures a Slack incoming webhook URL; a critical alert fires; the Slack endpoint receives `{text, blocks: [...]}` shape parsable by Slack.

**AC #3 — Discord channel sends Discord-shaped payload.** Same as Slack but Discord shape (`{content, embeds: [...]}`).

**AC #4 — Threshold rule fires on metric crossing.** WAF block rate exceeds operator-configured threshold over operator-configured window; rule fires.

**AC #5 — State rule fires on boot-degraded condition.** LAPI bouncer reports unreachable for the rule's debounce window; rule fires.

**AC #6 — Cooldown LRU suppresses re-fires.** Same (rule, channel) fired within the cooldown window emits no second notification.

**AC #7 — Per-channel severity filter.** Channel A configured `min_severity=critical`; warning-level rule fires; channel A receives no notification, channel B (configured `min_severity=info`) receives one.

**AC #8 — `alert_event` row persists per fire attempt.** Status `sent` / `failed` / `dropped`, with err_msg on failure.

**AC #9 — Audit `alert_channel_changed` + `alert_rule_changed` + `alert_fired` events emit.** Operator PUT to channels/rules emits the changed audit row. System-emitted fires emit the fired audit row.

**AC #10 — `GET /alerts/recent` returns the alert_event tail.** Operator-friendly query surface for "what did Arenet alert on recently". Viewer-accessible.

**AC #11 — `GET /api/v1/system/health` returns per-component status.** Admin-auth gated. Fields per D3: `observability_store`, `crowdsec_bouncer`, `automation_engine`, `dns_provider`, `caddy_last_reload`.

**AC #12 — Channel down → buffered + drop, no data-plane impact.** Slow webhook endpoint or down email server → notifications buffer (capacity 256 per channel), drop on full, counter increments, AC #13 invariant holds.

**AC #13 — Data plane integrity under alerting failure.** Mirror of M/Q/N/P AC #13: alerting subsystem failure does NOT block data plane (Caddy reverse proxy, WAF, rate-limit all unaffected).

**AC #14 — Caddy reload doesn't disrupt the watcher.** Watcher is a goroutine outside Caddy lifecycle (same as N consumer + P engine).

**AC #15 — Boot-degraded: no channels configured.** Watcher starts in dry-run mode; rules tick but emit no notifications. Operator can configure channels later; the next tick picks them up.

**AC #16 — Tests pass.** `go test ./... -count=1` clean.

**AC #17 — Lint clean.** `go vet`, `gofmt`, `svelte-check`.

**AC #18 — Schema delta.** New SQLite table `alert_event` + new BoltDB bucket `alerts` (channels + rules subkeys). Idempotent on re-boot.

**AC #19 — Bundle budget < 3 kB gz.** Frontend addition.

**AC #20 — Viewer-accessible reads.** `GET /settings/alerts/channels` + `GET /settings/alerts/rules` + `GET /alerts/recent` viewer-readable. PUTs admin-only.

**AC #21 — Step P unchanged.** Step P's automation engine + audit emissions all unchanged.

---

## 3. Architecture (high-level — to flesh out post-arbitration)

```
internal/alerting/                       (NEW)
  channels.go                            — Channel BoltDB type + per-kind Sender
                                           interface
  sender_webhook.go                      — generic JSON POST sender
  sender_slack.go                        — Slack-shaped payload wrapper
  sender_discord.go                      — Discord-shaped payload wrapper
  rules.go                               — Rule type + RuleSet (threshold +
                                           state) + Severity enum + Validate
  watcher.go                             — 30s polling watcher, dedupe / cooldown
                                           LRU, fan-out to per-channel queues
  dispatch.go                            — per-channel queue + drop counter (AC
                                           #12), goroutine pumping the queue
                                           through Sender.Send
  audit.go                               — AuditEmitter interface (decouples
                                           imports), thin adapter wires to
                                           audit.Store.Append in main.go

internal/observability/
  alert_event.go (NEW)                   — alert_event SQLite table + insert
                                           + query
  storage.go                             — + schema migration v5 (or vNext)
                                           with the alert_event CREATE

internal/storage/
  alerts_config.go (NEW)                 — channels + rules BoltDB buckets,
                                           CRUD with J.4 secret discipline on
                                           channel auth tokens / SMTP passwords

internal/api/
  alerts_handlers.go (NEW)               — CRUD endpoints + GET /alerts/recent
  system_health.go (NEW)                 — GET /api/v1/system/health per AC #11
  audit/actions.go                       — + alert_channel_changed,
                                           alert_rule_changed, alert_fired
                                           (32 → 35)

cmd/arenet/
  main.go                                — wire watcher + dispatch + the
                                           per-source metric/state probes;
                                           AC #15 boot-degraded if no channels
  alerting_adapters.go (NEW)             — adapters mirror automation_adapters
                                           shape: per-source MetricReader,
                                           StateReader, AuditEmitter
                                           implementations

web/frontend/src/routes/settings/+page.svelte
                                         — new "Alerting" Card (Row 2.8 between
                                           Security Automation and OIDC)

web/frontend/src/routes/security/+page.svelte
                                         — dashboard widget showing the N
                                           most-recent alerts (mirrors the
                                           MixedEventList shape)
```

**Dependency direction**: `alerting → observability + audit + storage`. Watcher reads metric buckets + audit auth-failure scan + Engine atomics (or via thin reader interface). No reverse imports.

---

## 4. Risks & mitigations (sketch — finalise post-arbitration)

| Risk | Mitigation |
|------|------------|
| Notification spam on persistent condition | D4 cooldown LRU. Default 15min threshold / 1h state. |
| Channel-down blocking other channels | Per-channel queue + drop-on-full (AC #12). |
| Webhook endpoint TLS-cert-invalid (operator's internal cert) | Sender config: optional `insecure_skip_verify` per webhook (J.4 secret discipline, audit logs but operator owns the choice). |
| SMTP password at rest | J.4 secret discipline (already present pattern). |
| /system/health endpoint returns false "ok" when subsystem actually broken | Health computation reads the EXACT signals the subsystem uses to flag itself (handler `disabled` flags, engine atomic counters). Don't invent new health checks; mirror existing ones. |
| State rule fires on the boot-window when subsystems are still starting | Watcher's first tick is 30s after boot (debounced by the rule's own window field). |
| Per-rule cooldown miscalibration causing missed alerts | Default cooldowns conservative (15min); operator-tunable per rule. Audit log shows fired vs cooldown-suppressed so operator can tune. |
| Channel URL leak in logs | Sender logs the channel ID + the response status, never the URL. |

---

## 5. Out of scope (for v1.4)

- Email (SMTP) channel — D1.C defers to v1.5.
- Event-based trigger class (D2.3) — defers to v1.5; v1.4 ships threshold + state.
- Resolution detection (D4.B paged alerting) — defers to v1.5.
- Per-route alert filtering (D9.B) — defers indefinitely (YAGNI until operator asks).
- Sub-second event-driven alerts (D10.C) — defers indefinitely.
- Cross-instance correlation (e.g. "fire only if both Arenet instances see the spike") — not on the homelab roadmap.

---

## 6. Appendix — references

- Survey of metric surfaces: `internal/observability/aggregator.go:254, 273, 298` (per-rate Bump methods).
- Buffered sink + drop counter pattern: `internal/waf/sink.go:100-141`.
- Writer with backoff: `internal/automation/trigger.go:598-703`.
- J.4 secret discipline: `internal/storage/dns_provider.go` + `internal/storage/automation_config.go` (P.3).
- Settings card insertion point: `web/frontend/src/routes/settings/+page.svelte:1248-1249` (between Automation Card and OIDC Card).
- Audit action enum + count test: `internal/audit/actions.go:27-109` + `actions_test.go:27` (32 today; R adds 3 → 35).
- Health endpoint: `internal/api/health.go:44-50` (liveness only; R adds the new detailed `/api/v1/system/health` per D3.A).
