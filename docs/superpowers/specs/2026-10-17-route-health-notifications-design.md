<!-- Arenet — design spec. AGPL-3.0-or-later. See LICENSE. -->

# A route going down tells someone

**Target version:** v2.75.0
**Status:** design locked, plan not written
**Decided:** 2026-10-17, after an 11-hour Traefik outage behind AreNET passed silently

## The report

The Traefik container behind several AreNET routes stayed stopped for
eleven hours. Every route to that backend went to `503`: Caddy's active
health checker marked the upstream unhealthy, `caddyhc` recorded it, the
topology graph showed it red — and nobody was told. The failure was
detected the whole time; it was never *delivered*. (It surfaced only
because the operator's own admin OIDC login, whose IdP `sso.hacf.fr` is
one of those routes, started returning "identity provider unreachable".)

The alerting subsystem already delivers cert-expiry, WAF-rate and
system-health events to webhook / email / Discord channels. Route health
is the obvious missing source, and the one the operator actually needed.

## What already exists (reused, not rebuilt)

Counted against the code, so the build is only the delta:

| Capability | Where | Reuse |
| --- | --- | --- |
| Channels (webhook/email/Discord), per-channel `MinSeverity` | `alerting/sender_*.go`, `alerting/config.go` | as-is |
| Dispatch + fan-out to channels | `alerting/dispatcher.go` (`Dispatch`, public at :332) | as-is |
| "Test channel" button | `api/alerting_channels.go:607` `testAlertChannel`, route `POST /channels/{id}/test` | as-is |
| Channel URL is a sealed secret (encrypted at rest, redacted in API/logs/audit) | #291/#297 (F21/F22/F27) | as-is |
| Confirmed up/down (passes/fails already applied) | Caddy emits `healthy`/`unhealthy` only on a state transition after its own thresholds; `caddyhc/tracker.go` records them | as-is |
| Per-upstream granularity | `caddyhc` tracker is keyed by upstream address | as-is |
| Per-route active health-check config | `storage.Route.HealthCheck` (`storage/routes.go:797`) | adjacent |

`alerting/source.go` already names `route_health_state` as a planned V2
source — this spec is that line item, built event-driven rather than
polled (see D1).

## Decisions

| # | Decision | Rationale |
| --- | --- | --- |
| D1 | **Event-driven notifier, not a polled rule source.** A new in-process notifier subscribes to `caddyhc` transitions (a callback the tracker invokes only when a status actually changes), mirroring the `certinfo` event-handler pattern. It builds `AlertEvent`s and calls the existing `Dispatcher.Dispatch`. | The existing `StateEvaluator` (`alerting/evaluator.go`) is **level-triggered** — it fires every tick the state matches, de-noised only by `cooldown.go`. The spec needs edge-triggered up→down / down→up with an outage *duration*, which a level rule cannot produce. Polling would also re-derive transitions the tracker already observes. |
| D2 | **Reuse channels by reference; never inline a URL.** The per-route setting stores a channel **ID**, not a webhook URL. | Zero new secret surface: the sealed-URL machinery (D11) keeps working untouched, and a route row carries no credential to leak or to seal. |
| D3 | **Opt-in per route: `{enabled, channelId}`.** Default off. Stored on the route and carried on **both axes** — storage (JSON tag + migration default + backup/restore) AND API (wire shape, validation, front types) per ENGINEERING-PRACTICES Lesson 8. | A silent default-on would spam every existing install on first probe flap. The operator asked for an explicit per-route choice. |
| D4 | **Event taxonomy.** (a) route **down** = every upstream of the route unhealthy; (b) route **recovered** = first upstream healthy again, message carries the outage duration; (c) **upstream degraded** = some-but-not-all upstreams unhealthy on a multi-upstream route. | "My service is unreachable" (all down) is the headline; a single degraded backend is useful but secondary, and distinguishing them stops a partial flap from reading as a full outage. |
| D5 | **Confirmation is inherited, not re-implemented.** No extra debounce for "is it really down" — Caddy's `passes`/`fails` thresholds already gate the `healthy`/`unhealthy` events `caddyhc` sees. | Re-counting would double-debounce and delay the alert for no gain. The health-check config (`storage.Route.HealthCheck`) is where an operator tunes sensitivity. |
| D6 | **Group by upstream over a short coalescing window.** When one upstream address flips unhealthy and *N* routes use it, the notifier waits a small window (default 3s, bounded) and emits **one** message listing the affected routes, not *N*. | The reported outage hit several routes on one Traefik; *N* identical pages is the noise the operator explicitly called out. |
| D7 | **Optional reminder while still down.** Per-route (or global default) interval; re-notify every *R* minutes until recovery, then one "recovered" with total duration. Reuses the `cooldown.go` interval mechanism. | An 11-hour outage should nag, not fire once and be scrolled past. Off by default so it is a choice. |
| D8 | **Record the transition timestamp in the tracker.** Add a `since time.Time` beside the status so `recovered` can state the duration. | The tracker today stores only the status string; duration needs the down-edge time, and the tracker is the only place that sees the edge. |
| D9 | **Extract the probe SSRF guard into a shared package and route all outbound channel dials through it.** `api/probe_dialer.go` (`probeTargetBlocked`, `newProbeDialer`) → `internal/netguard`, used by the webhook and Discord senders and the `/test` path. | `sender_webhook.go:59` uses the default transport today — it can POST to `169.254.169.254` (cloud IMDS). Same class as the probe sink that was already guarded. Shipped as a **separate PR ahead of this feature** (it fixes an existing gap regardless). One implementation, no drift. |
| D10 | **Severity: down = Critical, degraded = Warning, recovered = Info.** | Drives per-channel `MinSeverity` filtering so an operator can route only outages to a pager-like channel and keep recoveries on a quieter one. |
| D11 | **Secrets posture unchanged.** The notify setting adds no URL; the channel it references keeps its encrypted-at-rest, never-returned-in-clear, audit-masked URL. | The 2026-09-27 webhook-leak class (F21/F22/F27) is closed; this feature must not reopen it by inlining a URL (see D2). |
| D12 | **Audit on create/modify of the per-route notify setting**, and the SSRF-guarded `/test` already audits. | Consistency with channel CRUD; an alerting target change is a security-relevant config change. |

## Non-goals

- **Replacing the rule framework.** Threshold/state rules stay as they
  are; this is a dedicated notifier beside them, not a rewrite.
- **Cert / WAF / system-health events** — already shipped as
  `source_cert_*`, `source_waf_event_rate`, `source_system_health`.
- **Uptime history / SLA reporting.** That is the health-history
  surface (`2026-10-04-health-history-design.md`), not an alert.
- **Per-path-rule health.** The health check is per route pool
  (`storage/routes.go:496`); per-path is out of scope.
- **Escalation / on-call rotation / acknowledgement.** One message to a
  chosen channel, optionally repeated (D7). No paging policy engine.
- **A new Caddy JSON shape.** The `caddyhc` event handler is already
  wired into the emitted config; the notifier is an in-process consumer
  of the tracker, so `buildConfigJSON` is byte-identical.

## Security — staying clean at the next audit

The operator's constraint is explicit: *no HIGH/MEDIUM/LOW from this
feature at the next scan.* The surfaces and their defences:

1. **SSRF (outbound).** The `/test` button and every channel dial is an
   attacker-influenceable-at-config-time outbound request. D9 routes
   them through the shared link-local/IMDS guard (private addresses
   stay reachable — a homelab webhook is often private, exactly as the
   probe guard already decided at `probe_dialer.go:77`). Dial-time
   check, post-DNS, so a hostname resolving to `169.254.169.254` is
   refused.
2. **Secret exposure.** D2/D11: no URL on the route; the channel's URL
   stays sealed. Guard with a literal-JSON wire test that the notify
   setting's API response, the logs and the audit rows carry no URL.
3. **Injection into the message.** The route host and ID are operator
   input. Webhook/Discord bodies are JSON (`encoding/json` escapes);
   the email sender's HTML path must escape them. No raw interpolation.
4. **Request-body bound.** The notify-setting PUT reuses the API's
   `http.MaxBytesReader` cap (F4/F31), no unbounded decode.
5. **No new placeholder sink.** The message is built in Go, not through
   Caddy's replacer, so the F42 reflector class does not apply.

## Empirical validation gates

The feature is "delivered" only when each of these is proven against a
running binary or a targeted harness, not asserted:

1. **Edge, not level.** A scripted up→down→up on one upstream produces
   **exactly two** messages (one `down`, one `recovered` carrying a
   non-zero duration), never one-per-tick.
2. **Grouping.** Three routes sharing one upstream, that upstream flips
   unhealthy → **one** message naming all three, within the coalescing
   window.
3. **Degraded vs down.** A two-upstream route with one upstream down
   emits `degraded` (Warning); both down emits `down` (Critical).
4. **Reminder cadence.** With the reminder on at interval *R*, a
   sustained outage re-notifies on *R*, not faster; recovery stops it
   and states total duration.
5. **Secret never leaks.** `GET` of the route/notify config, the
   process logs, and the audit rows contain no channel URL — literal
   JSON assertion, per [[test-the-wire-not-the-struct]].
6. **SSRF refused.** A channel (and the `/test` button) pointed at
   `169.254.169.254`, and at a name resolving to it, is refused at dial
   time; a private-address target still connects.
7. **Hydration parity.** Create via the form → read back via the API →
   re-render the form shows the same `{enabled, channelId}`, given the
   recent settings-tab/API drift ([[2026-10-13-settings-tabs-keep-typed-input-design]]).
8. **Non-regression.** `buildConfigJSON` byte-identical (no new Caddy
   shape); `go test -race ./...` and `caddy.Validate` clean.

## Open questions for the plan

- **Where the per-route setting lives:** a field on `storage.Route`
  (e.g. `HealthNotify *HealthNotifyConfig`) vs a side table keyed by
  route ID. A field rides backup/restore and the route CRUD for free;
  the plan picks one and states the migration.
- **Global defaults** for the reminder interval and the coalescing
  window: a settings entry vs per-route only. Lean: a global default
  with a per-route override, but not blocking for V1 (per-route only is
  acceptable if simpler).
- **Multi-upstream "down" timing:** the route-down edge is the moment
  the *last* healthy upstream flips. Confirm the tracker callback can
  see the full upstream set for a route, or whether the notifier must
  consult the route's upstream list from storage at event time.
