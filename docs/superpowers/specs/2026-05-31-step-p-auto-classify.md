# Step P — Auto-classify loop (Arenet → LAPI write-back)

**Status**: FROZEN 2026-05-31 — all 12 decisions arbitrated (D1, D2.1, D2.2, D2.3, D3.1, D3.2, D3.3, D4, D5, D6, D7, D8), rationale-of-record locked.
**Author**: Ludo + Claude.
**Predecessor**: Step N (CrowdSec read-side: StreamBouncer consumes LAPI's decision stream).
**Inverse direction**: P writes decisions BACK to LAPI based on Arenet's own observations (WAF / throttle / auth failures).

---

## 1. Goal & scope

### 1.1 Goal

Close the observation → action loop. Today Arenet observes WAF blocks, rate-limit (throttle) events, and auth failures, then surfaces them in `/security/*` dashboards. An operator who wants to act on those observations has to manually `cscli decisions add` for each pattern they care about. Step P automates that conversion: a trigger engine watches the three event streams, applies operator-configured rules (per-category enable / severity threshold / window-count threshold), and pushes the matching decisions to LAPI via `POST /v1/decisions`. The bouncer (Step N) then enforces the auto-ban at the proxy edge on the next stream poll — closing the loop within ≤60s of the original observation.

The feature is **opt-in per category**. Default state on a fresh boot is "all disabled" — an operator must explicitly enable each automation channel in Settings.

### 1.2 Scope (5 sub-tasks — mirror M/Q/N/O cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| P.1 | LAPI watcher client | Raw HTTP write client (POST /v1/alerts /decisions) with JWT login, credential storage (BoltDB), token refresh. Distinct from the read-side bouncer client. |
| P.2 | Trigger engine | Watches WAF / throttle / audit event streams via a polling consumer, applies operator-configured rules, emits Decision-shaped intents to the writer. AC #13 buffered-channel + drop-on-full. |
| P.3 | REST API + storage | `/settings/automation` GET/PUT for the rule set (per-category enabled, threshold, window). `effectiveAutomation` derived field on the route response surfacing "covered" routes. Audit events: `automation_decision_pushed` / `automation_rule_changed`. |
| P.4 | Frontend | Settings → "Security Automation" Card (sibling of SSL/Certificates) with per-category toggles + threshold inputs. `/security/decisions` row badge `auto:<source>` for Arenet-originated decisions. Audit-log filter for the new actions. |
| P.5 | Smoke + tag | Live smoke against the same containerized LAPI as N.5: generate WAF SQLi → verify decision appears in LAPI within 60s → bouncer enforces ban → tombstone via `cscli decisions delete` → auto-classify respects the tombstone (cooldown). Tag `v1.3.0-step-p`. |

### 1.3 Locked decisions

(All decisions arbitrated 2026-05-31; rationale of record preserved.)

#### D1 — Watcher credential model → **A (dedicated watcher per Arenet)**

CrowdSec auth has three roles: **bouncer** (API key, GET-only on decisions), **watcher / agent** (JWT login from machine-id+password, full write surface), and **admin** (cscli-only). POST /v1/decisions requires watcher creds — confirmed via source read at `crowdsec@v1.6.3/pkg/apiserver/controllers/controller.go:115-129` (write endpoints under `jwtAuth`, not `apiKeyAuth`).

- **D1.A — Dedicated watcher per Arenet instance.** Operator runs `cscli machines add arenet-writer` on their CrowdSec host, pastes the machine-id + password into Arenet's Settings page (new sub-section under the Security Automation Card). Arenet calls `/v1/watchers/login` on boot to mint a JWT, refreshes before expiry. Clean least-privilege separation; operator can revoke the writer without touching the reader. Two credential surfaces in the UI (the existing N read-side bouncer key + the new write-side watcher creds).

- **D1.B — Reuse the existing read-side bouncer key.** Not feasible — bouncer keys don't have POST permission on /v1/decisions.

- **D1.C — Use `cscli` from inside Arenet.** Requires the cscli binary on the Arenet host.

**Decision: A.** Forced by upstream auth design — D1.B is structurally impossible (bouncer keys are GET-only by upstream choice, source-cited above). Between A and C, A is the consistent posture with Step N's D9 (rejected in-process cscli for the same operational-coupling reason). The "two credential surfaces" cost is one extra form in the Settings page; the gain is least-privilege separation that lets the operator rotate one without touching the other. Implementation: Settings → Security Automation, a new credentials sub-form with three fields (LAPI URL — pre-fills from the existing bouncer config, machine-id, password). Validation on submit: hit `/v1/watchers/login` once and confirm 200. Same redaction discipline as the OVH provider (J.4): password emitted as empty on GET, preserve-on-edit on PUT.

**Rejected — D1.B:** not feasible. Listed for completeness only.
**Rejected — D1.C:** operational coupling we've consistently refused. cscli is a CLI tool meant for human operators, not a runtime dependency.

#### D2.1 — Reader architecture → **A (per-source polling, 5s interval)**

Three event streams feed the trigger engine: WAF events (observability `waf_event`), throttle events (observability `throttle_event`), and audit log auth failures (BoltDB `audit` bucket).

- **D2.1.A — Per-source polling consumer.** Trigger engine polls each store on a fixed interval (5s), tracking a "last-seen" cursor per source. Decisions emitted to a shared write-side sink. Simple, no producer-side coupling. 5s latency before LAPI receives the decision; on a 30/s WAF burst, 150 events accumulate per poll.
- **D2.1.B — In-process event subscribers.** Existing WAF/throttle sinks gain a `Subscribe(chan Event)` method; the trigger engine receives every emit synchronously. Sub-second latency; backpressure is the existing sink's drop-on-full path. New subscribe-pattern surface; existing sinks need a minor refactor.

**Decision: A.** The 5s latency is invisible end-to-end: the LAPI stream poll is 60s anyway (per spec N D7.A — Caddy bouncer + Arenet mirror both on 60s ticks), so the bouncer cache cannot enforce an auto-ban faster than ~60s after the originating event regardless of how fast Arenet pushes it. A 5s poll cadence is well inside that ceiling. The per-source polling consumer reuses the existing `Query*` surface (`audit.Store.QueryByActionRange`, `observability.Store.QueryWafEvents`, `observability.Store.QueryThrottleEvents`) verbatim, no producer-side refactor. Backpressure handled by the trigger engine's own AC #13 buffered channel before the writer.

**Rejected — D2.1.B:** The latency win it claims is invisible at the operator-observable layer (bouncer cache cadence dominates). The refactor cost (Subscribe surface on three existing sinks + their tests) is not worth a sub-second latency gain that disappears downstream.

#### D2.2 — Granularity: aggregated vs immediate → **A (aggregated per (src_ip, source, category) over window)**

- **D2.2.A — Aggregated per (src_ip, source, category/tier) over a sliding window.** "Ban 1.2.3.4 if ≥N SQLi events in W seconds". Operator-facing: per-rule the operator picks (threshold, window_seconds). Default for SQLi might be (2, 60s) — the second event within 60s is the confirmation signal that a single accidental SQLi from a real user isn't enough to trigger.
- **D2.2.B — Immediate per event.** Every matching event → immediate decision push. No aggregation. Dead simple. A single false-positive WAF rule can auto-ban a legitimate user in one request.

**Decision: A.** B is too aggressive for the homelab target. Most homelab operators have a small user base where one false-positive equals one angry user that the operator will hear about within minutes. A's window-and-threshold model gives operators a knob to tune the false-positive rate without disabling the category entirely. Default thresholds will be conservative (SQLi=2 in 60s; AUTH=10 in 5min) and tuneable per rule.

**Rejected — D2.2.B:** the failure mode is operator-visible and damages trust in the feature. A single false-positive that auto-bans a real user from their own homelab is the kind of incident that gets the feature switched off permanently. A's aggregation costs nothing in user-perceived latency (the second event happens within seconds when the IP is truly attacking) and saves the false-positive case.

#### D2.3 — Category granularity → **A (per OWASP category toggle)**

- **D2.3.A — Per OWASP category.** Toggle each of {SQLi, XSS, RCE, LFI, PROTOCOL, OTHER} independently. Operator decides which are auto-bannable. Throttle: per-tier toggle (Tier 1 / Tier 2). Auth failure: single toggle (count-based threshold).
- **D2.3.B — Single global toggle.** "Auto-classify on/off" — applies a fixed default rule set.

**Decision: A.** The whole spec premise is "SQLi auto-ban OUI, scan léger NON" — the per-category granularity is the feature. Wraps the rule set in an operator-meaningful UI: SQLi/RCE are unambiguous attack signals worth auto-banning on; PROTOCOL/OTHER are typically noisy (broken clients, debugging tools) and should default to off. The UI shape: a per-category section in the Security Automation Card, each section a (toggle, threshold, window, duration, cooldown) tuple.

**Rejected — D2.3.B:** forces an all-or-nothing choice that doesn't match the operator's actual risk model. The spec's framing demands per-category control.

#### D3.1 — Scope: IP-only vs CIDR aggregation → **A (IP-only v1.3; CIDR deferred to v1.4)**

- **D3.1.A — IP-only for v1.3.** Auto-classify always pushes a single-IP decision. Simpler trigger logic (no clustering / CIDR-detection heuristic to write). A botnet hitting from 200 IPs in /24 spawns 200 individual decisions.
- **D3.1.B — IP + per-/24 CIDR aggregation.** When ≥N IPs in the same /24 trigger within the window, escalate to a /24 decision and tombstone the individual IP decisions. Handles the botnet case cleanly. Clustering heuristic with edge cases (the /24 might overlap with a legitimate cloud provider range; need a do-not-aggregate-known-clouds list).

**Decision: A.** Ship IP-only in v1.3. The mock UI promise ("185.142.86.0/24 · SQLi · auto" in `/security/decisions`) is already satisfied by Step N's StreamBouncer consumer — the row shape exists; community CrowdSec blocklists routinely carry /24 entries that already render via the existing `shortScenario()` helper. CIDR auto-classify is a future v1.4 surface, documenting up front lets the operator know what to expect. The 200-IPs-in-a-/24 botnet case is a known limitation; the workaround is operator-facing (`cscli decisions add --range`) until v1.4 lands.

**Rejected — D3.1.B:** the cluster-detection heuristic is a non-trivial spec on its own (overlap with cloud-provider ranges, false-positive amplification when a single bad IP in a shared CIDR brings down legitimate neighbours, the "do-not-aggregate" list maintenance). Carrying that complexity in v1.3 alongside the rest of P would either bloat the step beyond a sensible size or ship a half-baked clusterer. Defer cleanly.

#### D3.2 — Duration per rule → **A (per-rule configurable with sensible defaults)**

- **D3.2.A — Operator-configurable per rule.** Each rule in the rule set carries `duration_seconds`. Defaults: SQLi=4h, XSS=1h, RCE=24h, PROTOCOL=15min, LFI=4h, OTHER=15min, AUTH-burst=4h, Throttle-tier1=15min, Throttle-tier2=1h.
- **D3.2.B — Single global duration.** One value applies to all auto-bans.
- **D3.2.C — Fixed (non-configurable) per category.** Hard-coded defaults; operator can't tune.

**Decision: A.** Same posture as D2.3: the operator-facing knob is the feature. Defaults chosen by OWASP severity rough mapping (RCE > SQLi/LFI > XSS > PROTOCOL/OTHER) so a fresh-boot operator gets reasonable behaviour without thinking about it; the operator who DOES think about it can tune per rule. B would force the operator to choose between "long enough to deter RCE" (24h) and "short enough not to lock out a false-positive XSS for a day" (1h) — a real trade-off the per-rule model resolves. C is the same trap as B but with hidden defaults.

**Rejected — D3.2.B:** single global value is the wrong granularity; operator can't differentiate severity-1 false-positives from severity-5 confirmed attacks.
**Rejected — D3.2.C:** removes the operator's ability to tune for their environment; same anti-knob posture rejected throughout this spec.

#### D3.3 — Scenario naming → **A (prefix `arenet/<category>`, no schema migration)**

- **D3.3.A — Prefix convention `arenet/<category>` (e.g. `arenet/waf-sqli`, `arenet/throttle-tier2`, `arenet/auth-burst`).** The `/security/decisions` view's `shortScenario()` helper renders the suffix (e.g. "waf-sqli"). The "auto" provenance is signalled by the `arenet/` prefix (vs `crowdsecurity/...` for community / `unknown` for cscli-added). The frontend gets a derived `isArenetAuto` boolean from a shared helper. Additive: no schema change, no migration.
- **D3.3.B — A separate `origin` wire field.** Currently dropped per spec N D5.B. Re-add it so the frontend can read `decision.origin === "arenet"` explicitly. Cleaner, but a schema migration + N-side code change.

**Decision: A.** Prefix convention is additive — no schema change, no migration, no N-side code touched. The frontend filter is a `startsWith("arenet/")` check, ~5 lines. Future-proof: if we later add an `origin` field for richer provenance (community / cscli / arenet / agent / etc.), the `arenet/` prefix stays valid as a secondary marker and we don't have to walk back the prefix discipline.

**Rejected — D3.3.B:** the schema-migration + N-code change cost is real (decision_event table column add + storage.go writes + N.2 spec amendment) for a win that's already captured by the prefix convention. The "cleaner" claim is aesthetic — at the wire level, prefix-on-scenario is just as machine-parseable as a separate field.

#### D4 — Idempotence across reboot → **B (pre-push LAPI GET — LAPI is source of truth)**

A botnet attack triggers Arenet auto-ban at T=0. The decision lands in LAPI with `expires_at = T+4h`. Arenet reboots at T=10min. The trigger engine's "last-seen" cursor is reset. On the next event from the same IP — say at T+20min — does Arenet push a duplicate decision to LAPI?

LAPI accepts duplicate decisions for the same `(scope, value)` — it stacks them, the longest-expiry one wins for the bouncer's cache. So a duplicate isn't dangerous to the data plane. But it's noisy in the LAPI's `cscli decisions list` output and the audit log.

- **D4.A — LAPI-side check before push.** Trigger engine maintains an in-memory dedupe LRU keyed on `(scope, value, scenario)`. On reboot, the LRU is empty, so the first event re-pushes. Noisy across reboot.
- **D4.B — Pre-push LAPI query.** Before POST /v1/decisions, Arenet does GET /v1/decisions?ip=<value> and skips if an active decision exists from the same scenario. Idempotent across reboots. One extra HTTP round-trip per potential push.
- **D4.C — Persistence of the dedupe LRU.** The LRU is mirrored to BoltDB; reboot reads it back. Idempotent across reboots without extra HTTP. BoltDB write per push; the persisted LRU drifts from LAPI state if `cscli decisions delete` runs out-of-band.

**Decision: B.** LAPI is the source of truth for "is this IP currently banned?" — querying it directly means there's no parallel state to keep in sync. Cost: one extra HTTP round-trip per potential push, against loopback or LAN LAPI (sub-millisecond round-trip), bouncer-key authenticated (reuses the existing N read-side credential — no new auth). This cost is acceptable because the push frequency is intrinsically low — by D2.2.A the trigger engine only emits intents at threshold crossings of an aggregated window, not per-event. Even under a heavy attack the push rate is typically a handful per minute, not per second. C's drift risk (persisted LRU diverging from LAPI when an operator unbans manually) is the architectural killer; A's reboot-noise is small but real and observable to operators.

**Rejected — D4.A:** acceptable noise floor for some operators, but the cost of B (one cheap loopback GET) is so low that there's no reason to accept the noise.
**Rejected — D4.C:** parallel state (in-memory + BoltDB + LAPI) creates drift risk by construction. Source-of-truth discipline says: don't.

#### D5 — Operator anti-loop: cooldown window → **A (cooldown per (src_ip, scenario), default 24h SQLi / 7d AUTH, asymmetric by category)**

Operator-loop scenario:
1. Arenet pushes ban on 1.2.3.4 (SQLi auto-classify).
2. Operator decides it was a false positive and runs `cscli decisions delete --ip 1.2.3.4`.
3. The same IP triggers another SQLi event at T+5min.
4. Should Arenet auto-ban again?

- **D5.A — Honor the tombstone for a cooldown window per (src_ip, scenario).** When the trigger engine sees a deletion in the StreamBouncer's `deleted[]` slice (Step N consumes this), it records a tombstone with TTL = cooldown_seconds. Within the cooldown, no auto-classify ban for that (ip, scenario). After the window, normal triggering resumes. The cooldown is operator-configurable per rule.
- **D5.B — Honor the tombstone permanently per (src_ip, scenario).** Once an operator unbans, Arenet never auto-bans that pair again. Unbounded storage growth; an attacker fingerprint the operator legitimately wants to re-ban after some time has to be manually re-enabled.
- **D5.C — Don't honor tombstones at all.** Operator's `cscli delete` is just a cache flush; the next event re-bans. Operator-loop scenario is real and hostile.

**Decision: A.** Cooldown gives the operator a "skip auto-classify for N hours" lever without permanent state growth. The cooldown defaults are deliberately **asymmetric by category** — this is the rationale-of-record worth documenting up front so it doesn't look weird on review:

- **AUTH-burst cooldown default: 7 days.** When an operator unbans an IP that auto-classify banned for an auth-failure burst, the most common cause is "legitimate user fat-fingered their password 10 times in 5 minutes". The operator's unban reflects "this is a real user, please leave them alone". Re-engaging the auto-trigger within hours would hostile-loop against that judgment. A long cooldown trusts the operator's intent for longer. (If the user STILL needs to be banned a week later because they're sharing credentials with an attacker, the operator can re-ban manually.)

- **SQLi/RCE/XSS/LFI cooldown default: 24 hours.** When an operator unbans an IP that auto-classify banned for a WAF rule, the most common cause is "I think this was a false positive from my own WAF rule, let me check the request". The operator's unban reflects suspicion of a false positive, but they may not be sure. A shorter cooldown re-engages the auto-trigger if the same IP keeps producing matches after the operator's investigation window — exactly the case where the false-positive theory was wrong.

- **PROTOCOL/OTHER/Throttle cooldown default: 4 hours.** Lower-severity signals where the operator's unban is more likely a maintenance action than a deep judgment call. Re-engagement on a shorter window is appropriate.

The asymmetry is the point: cooldown duration encodes "how much do we trust the operator's judgment of false-positive-ness for THIS category?". Operators can tune per-rule, but the defaults model the typical mistake distribution by category.

**Rejected — D5.B:** unbounded growth + the legitimate "ban this IP again after some natural cooldown" case becomes a manual-config-burden. The operator who unbanned today doesn't want to be the operator who has to remember-to-re-enable in a month.
**Rejected — D5.C:** the operator-loop is a real and hostile failure mode. Ignoring tombstones means an operator who unbans IS adversarial to the system, which is exactly upside-down.

#### D6 — Tombstone source: reuse N's Sink.Tombstone channel → **A**

The tombstone signal that feeds the D5 cooldown LRU can come from two places:

- **D6.A — StreamBouncer's `deleted[]` slice (Step N consumer).** When LAPI emits a delete, the bouncer's stream poll surfaces it via `Sink.Tombstone(uuid)`. The trigger engine listens to the same channel and records the tombstone. Real-time within ticker interval; single source of truth. Requires plumbing — the trigger engine has to subscribe to the existing crowdsec Sink's tombstone path, or the Sink has to fan out.
- **D6.B — Pre-push LAPI query (extending D4.B).** Before each potential auto-ban, query LAPI to see if there's a recent deletion. No plumbing, reuses D4.B's HTTP path. LAPI's `/v1/decisions` doesn't expose a "recently deleted" view — would need to track the decision_event table's `expires_at` updates (Arenet's own mirror).

**Decision: A.** Plumbing cost is one channel + one LRU insertion in the existing Step N `Sink.Tombstone` code path. The Arenet-side mirror already stores tombstoned rows by setting `expires_at = NOW` (per the spec §3.8 convention from O); the trigger engine reads its own observability store to seed the cooldown LRU at boot, then listens to the channel for real-time updates within the next 60s ticker cycle. Reuses N's plumbing verbatim, no out-of-band API surface needed.

**Rejected — D6.B:** LAPI doesn't have a "recently deleted" query surface. Implementing the dedup against the decision_event table's `expires_at = NOW` rows would re-create A's plumbing in a more convoluted way.

#### D7 — AC #13 carry-forward: buffered channel + drop-on-full → **A**

When LAPI is unreachable for the write path, the trigger engine must NOT block.

- **D7.A — Buffered channel + drop-on-full** (mirror of WAF / throttle / decision sinks). Trigger engine emits to a bounded channel (e.g. 1024); a writer goroutine drains and POSTs. If LAPI is down, the writer retries with exponential backoff; the channel fills; the trigger engine drops new events with a counter increment. Identical AC #13 pattern. Dropped decisions ARE lost (the source events stay in their respective tables for forensics; the auto-classify side just didn't act on them).
- **D7.B — Persistent queue in BoltDB.** Decisions queued to disk; writer goroutine drains and removes on successful POST. Survives reboots + LAPI outages. New storage surface; queue management (TTL, max size) is its own design.

**Decision: A.** Consistent with the established AC #13 pattern across M (waf sink), Q (throttle sink), and N (decision sink) — operators already understand the drop-on-full shape. The "loss" claim is misleading: the SOURCE events (WAF block, throttle block, audit auth failure) stay in their durable tables for forensics — only the auto-classify ACTION on them is lost on a write-side drop, which means the IP doesn't get auto-banned, which means the WAF still blocked the request anyway (the source-side defence is unaffected). The operator surface is the new `auto_classify_dropped_per_min` counter in `/metrics/summary`; non-zero values mean either LAPI is down or trigger volume exceeds the buffer, both of which are visible operational signals.

**Rejected — D7.B:** the durable queue claims to prevent loss, but the events ARE already durable in their source tables. A second durability layer (BoltDB queue) for the action-side adds storage + lifecycle management (TTL, max size, replay-on-boot) for a marginal win — the operator who reboots Arenet during an LAPI outage gets at most ~60s of missed auto-bans, against an event source that's still fully observable in the WAF/throttle dashboards. Not worth the new surface.

#### D8 — Settings UI placement → **A (new Card sibling of SSL/Certificates)**

- **D8.A — Sibling of "SSL / Certificates" in the Settings page.** New top-level Card on the Settings page. Discoverable; consistent with O.4's D9.B precedent.
- **D8.B — Sub-section of a future "Security" page.** Defer Step P inside Settings (D8.A); when a Security page is created later, move it.

**Decision: A.** Same posture as Step O.4's D9.B. The Settings page is the operator's config home; adding Cards is the expected pattern and a fresh-install operator finds it within one scroll. The "Security" top-level page is a future restructuring concern — until that lands, the Settings home is the right place. The card title is "Security Automation" (not "Auto-classify") because "automation" reads as the broader concept the operator is opting into; the per-category toggles inside the card make the specifics concrete.

**Rejected — D8.B:** premature page restructuring. The Security page doesn't exist yet; spec'ing P against a hypothetical future page would either delay P or commit us to creating the Security page now (which is its own scope).

---

## 2. Acceptance criteria

(Frozen 2026-05-31, reflects D1-D8 arbitration outcomes.)

**AC #1 — POST /v1/decisions succeeds with valid watcher creds.** Operator configures watcher (machine-id + password); Arenet logs in, gets a JWT, holds it. Manual trigger (e.g. test endpoint or first real WAF event) produces a decision in LAPI verified via `cscli decisions list`.

**AC #2 — JWT refresh before expiry.** LAPI JWT expires after a configurable lifetime (default 1h on CrowdSec). Arenet refreshes before expiry without operator intervention.

**AC #3 — Per-category enable/disable.** When SQLi auto-classify is enabled and XSS is disabled, a SQLi event triggers a decision push but an XSS event does not.

**AC #4 — Severity / tier threshold.** A WAF rule emits an event with `severity=2`; the operator's SQLi rule has `min_severity=3`. No decision pushed.

**AC #5 — Window-count threshold.** Single SQLi event from 1.2.3.4 — no push (default `threshold=2, window=60s`). Second SQLi from same IP within 60s — push.

**AC #6 — Idempotence across reboot (D4.B path).** Arenet reboots with an active SQLi ban on 1.2.3.4 in LAPI. New SQLi event from 1.2.3.4 within the existing ban window — no duplicate push (pre-push GET shows the existing decision).

**AC #7 — Operator tombstone cooldown (D5.A path).** Operator `cscli decisions delete --ip 1.2.3.4`. New SQLi event from 1.2.3.4 within cooldown window — no auto-push. After cooldown expires — auto-push resumes.

**AC #8 — Auth-failure burst trigger.** N login failures from the same source IP within window → decision pushed.

**AC #9 — Decision wire shape.** Pushed decision carries `scenario = "arenet/waf-sqli"` (or category-appropriate); `scope = "ip"`; `duration` matches the rule's config.

**AC #10 — Audit event per push.** Each auto-classify decision generates an audit event `automation_decision_pushed` with the triggering source IP, source category, and the originating event ID.

**AC #11 — Rule changes audited.** `PUT /settings/automation` emits `automation_rule_changed` with before/after JSON (passwords redacted — same J.4 pattern).

**AC #12 — `/security/decisions` shows the "auto" prefix.** Decision row from Arenet auto-classify renders the `scenario` as `arenet/waf-sqli` via `shortScenario()`. A frontend helper marks the row with an `auto` badge in MixedEventList.

**AC #13 — Data plane integrity under LAPI write failure.** LAPI unreachable for the write path → Arenet stays up. Trigger engine buffers ≤1024 pending decisions then drops new ones with a counter increment. WAF / throttle / data-plane paths unaffected.

**AC #14 — Caddy reload doesn't disrupt the auto-classify pipeline.** Route mutations trigger Caddy reloads (per N AC #14). The trigger engine + writer are NOT inside Caddy's lifecycle (same as N's mirror consumer) — they survive every reload.

**AC #15 — Watcher creds boot-degraded.** Empty watcher creds at boot → trigger engine NOT started; sink runs as no-op drain; `/settings/automation` GET returns 200 with `enabled: false` per category. Boot succeeds without errors.

**AC #16 — Tests pass.** `go test ./... -count=1` clean.

**AC #17 — Lint clean.** `go vet`, `gofmt`, `svelte-check`.

**AC #18 — Schema delta.** New BoltDB bucket `automation` for the rule set + watcher credentials. New SQLite column NOT needed (decisions are in `decision_event` already from N).

**AC #19 — Bundle budget < 3 kB gz.** Frontend addition.

**AC #20 — Viewer-accessible reads.** `GET /settings/automation` available to viewer role; PUT requires admin.

**AC #21 — Step N read-side unchanged.** The Step N StreamBouncer consumer is untouched; the trigger engine consumes Sink.Tombstone events via a side channel (D6.A) without modifying the Sink's existing contract.

---

## 3. Architecture

### 3.1 Where the new logic lives

```
internal/automation/                    (NEW)
  watcher_client.go                     — raw HTTP POST /v1/alerts + /v1/decisions,
                                          JWT login + refresh (D1.A path)
  trigger.go                            — multi-source poller (5s tick per D2.1.A),
                                          rule engine, dedupe LRU (D4 in-memory cache
                                          for pre-push GET results), cooldown LRU
                                          (D5.A asymmetric defaults by category)
  rules.go                              — Rule type + RuleSet type + per-category
                                          enable (D2.3.A) + threshold + window +
                                          duration + cooldown
  global.go                             — singleton wiring (same pattern as
                                          crowdsec.SetGlobalSink); nil-tolerant
                                          for AC #15 boot-degraded

internal/storage/
  automation_config.go (NEW)            — RuleSet BoltDB type + watcher creds
                                          (machine_id + password, J.4 secret
                                          discipline)
  storage.go                            — add bucketAutomation

internal/crowdsec/
  sink.go                               — + Tombstone fanout channel for D6.A
                                          subscription; existing absorbTombstone
                                          path is unchanged (AC #21 from spec N).
                                          The fanout is opt-in: trigger engine
                                          installs a listener via a registration
                                          method; nil listener = no fanout cost.

internal/api/
  automation_handlers.go (NEW)          — GET / PUT /settings/automation
                                          (PUT admin-only; GET viewer-accessible
                                          per AC #20)
  audit/actions.go                      — + automation_decision_pushed,
                                          automation_rule_changed (J.4 audit
                                          redaction for passwords)

cmd/arenet/main.go                      — wire trigger engine goroutine; AC #15
                                          nil-tolerant (empty watcher creds → no
                                          trigger engine, no-op writer)

web/frontend/src/routes/settings/
  +page.svelte                          — new "Security Automation" Card sibling
                                          of SSL/Certificates (D8.A)

web/frontend/src/routes/security/decisions/
  +page.svelte + MixedEventList         — "auto" badge via scenario.startsWith(
                                          "arenet/") helper (D3.3.A)
```

### 3.2 The trigger engine's main loop (descends from D2.1 + D2.2 + D2.3)

```
for each rule R in enabled rule set:
  events ← Query<source>(R.source, R.category, since=cursor[R.source], to=now)
  for each event:
    group by (src_ip, scenario(R))
  for each group with count ≥ R.threshold within R.window_seconds:
    if cooldownLRU contains (group.src_ip, scenario(R)): skip (D5.A)
    if pre-push GET shows active LAPI decision: skip (D4.B)
    emit Intent{scope: "ip", value: group.src_ip, scenario: "arenet/" + R.category,
                duration_seconds: R.duration_seconds} to writer channel
  cursor[R.source] = max event timestamp
sleep 5s
```

The three `Query<source>` calls map to:
- WAF: `observability.Store.QueryWafEvents(filter)` with the rule's category.
- Throttle: `observability.Store.QueryThrottleEvents(filter)` with the rule's tier.
- AUTH: `audit.Store.QueryByActionRange(audit.AuthFailureActions(), from, to, limit)`.

Each cursor is per-source (not per-rule) so multiple rules targeting the same source share one read pass.

### 3.3 The writer goroutine (descends from D7.A)

```
for {
  select {
  case intent := <- writerChan:
    pushWithBackoff(intent)
  case <- ctx.Done():
    return
  }
}

pushWithBackoff(intent):
  for retry := 0; retry < maxRetries; retry++ {
    if ensureJWT() {  // D1.A login + refresh
      if POST /v1/alerts (carrying the decision) succeeds:
        emit audit event automation_decision_pushed (AC #10)
        return
    }
    sleep exponential backoff
  }
  // failed all retries; log + drop counter
```

`writerChan` is bounded at 1024 (D7.A). The intent producer (trigger engine) does a non-blocking send + increments `automation_dropped` counter on channel-full — identical pattern to the WAF/throttle/decision sinks' `Emit()` methods.

LAPI decisions are CREATED via `POST /v1/alerts` (the canonical write surface — decisions are children of an alert in LAPI's data model per the survey citation in §6). The alert wraps a single decision payload; LAPI's response includes the decision UUID we then mirror into our `decision_event` table via the existing N consumer's stream poll within ≤60s.

### 3.4 Dedupe LRU vs cooldown LRU (descends from D4.B + D5.A)

Two separate LRUs, distinct purposes:

- **Dedupe LRU** is an in-memory cache of the result of pre-push GET calls (D4.B). Key: `(scope, value, scenario)`. Value: `(active_in_lapi: bool, ts_checked)`. TTL: short (e.g. 60s) — within the TTL we skip the GET and trust the cache; on TTL expiry we re-query LAPI. Bypassed entirely if we observe a tombstone event for the key (the cache is invalidated immediately).

- **Cooldown LRU** is the operator-loop guard (D5.A). Key: `(src_ip, scenario)`. Value: `(tombstone_ts, cooldown_until_ts)`. TTL: long (per-rule, 24h–7d default by category). Seeded at boot by reading the observability `decision_event` table for tombstoned-recently rows (rows where `expires_at < now` AND `expires_at > now - longest_cooldown`); live-updated by subscribing to the Step N `crowdsec.Sink` tombstone fanout (D6.A).

The two LRUs do NOT share keys or lifecycle. Dedupe is a transient performance optimisation; cooldown is a semantic guard against operator-loop.

### 3.5 Watcher credential lifecycle (descends from D1.A)

```
boot:
  read watcher creds from BoltDB (J.4 secret discipline)
  if empty: log "automation: no watcher creds, trigger engine disabled"; return nil
  POST /v1/watchers/login → JWT
  log "automation: watcher logged in, JWT expires_at=..."

runtime:
  every (JWT.expiry - 5min):
    re-login with stored creds → fresh JWT
    on failure: log WARN; mark engine paused; retry next refresh tick

PUT /settings/automation/credentials:
  validate new creds by hitting /v1/watchers/login
  on success: persist (preserve-on-edit pattern); refresh JWT immediately
  on failure: reject 400 with the LAPI error message
```

The watcher-creds form is co-located with the per-category toggles in the Settings Card (D1.A + D8.A). Empty creds → trigger engine boots disabled per AC #15.

### 3.6 D6.A plumbing: Step N Sink fanout

The Step N `crowdsec.Sink` exposes a new opt-in fanout for tombstones. Pattern:

```go
// internal/crowdsec/sink.go (extended)
type Sink struct {
    // ... existing fields ...
    tombstoneListener func(uuid string)  // opt-in; nil = no fanout
}

// SetTombstoneListener installs a callback invoked on every
// successful absorbTombstone. nil unregisters. Called by the
// trigger engine at boot.
func (s *Sink) SetTombstoneListener(fn func(uuid string)) { ... }
```

The trigger engine's listener writes the (src_ip from the decision_event row, scenario) tuple into the cooldown LRU. Lookup-from-uuid: the trigger engine resolves uuid → (src_ip, scenario) via a quick observability store read; this read is cheap because the decision_event table is small (≤30d retention, ≤10k rows on a homelab).

This preserves spec N's AC #21 (Step N read-side unchanged) — the absorbTombstone code path is identical when no listener is installed.

### 3.7 The empty-watcher-creds short-circuit (descends from AC #15 + D5.A invariant from O.2 carry-forward)

A boot with empty watcher creds is the equivalent of O's "empty managed-domains" state: the feature must be a strict no-op. Concretely:

- The trigger engine goroutine is NOT spawned.
- The writer goroutine is NOT spawned.
- `GET /settings/automation` returns 200 with the persisted rule set (operator can still configure rules ahead of pasting creds), and `credentialsConfigured: false`.
- `PUT /settings/automation/rules` accepts edits but emits no decisions until creds land.
- The new `automation_dropped_per_min` metric reads 0 forever.

This is the AC #13 boot-degraded carry-forward from M/Q/N/O — Arenet boots fully, the feature is dark.

### 3.8 Audit trail (descends from AC #10 + AC #11 + the §5 risks "rule change clobber" row)

Two new audit actions:

- `automation_decision_pushed` — emitted by the writer goroutine after successful POST. Carries `target_id = "<scope>:<value>"`, `after_json = {scenario, duration, triggering_event_id}`. Operators see "who got banned + why" in a single audit row.
- `automation_rule_changed` — emitted by `PUT /settings/automation/*`. Carries `before_json` and `after_json` with passwords redacted (J.4 pattern). The operator's intent is captured in the diff.

Both actions are added to the `allActions` enum (audit/actions_test.go bump from 30 → 32).

### 3.9 Dependency direction

```
automation → crowdsec.Sink (tombstone listener, §3.6)
automation → observability.Store (event queries, decision_event seed for cooldown LRU)
automation → audit.Store (auth-failure query)
automation → storage.Store (rule set + watcher creds, §3.5)
automation → audit emitter (§3.8)
```

No reverse arrows. The crowdsec package does not import automation; the trigger engine consumes the fanout via callback, the Sink stays unaware of who's listening.

---

## 4. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| **D1.A** watcher creds in BoltDB at rest | Same secret discipline as J.4 DNS provider: password emitted blank on GET; preserve-on-edit on PUT; audit BeforeJSON/AfterJSON redact. BoltDB file POSIX permissions (0o600) is the at-rest threat boundary, same as J.4 (the operator owns the file). |
| **D2.2.A** false-positive auto-bans legitimate user | Window + threshold model. Defaults conservative (SQLi threshold=2 in 60s; AUTH threshold=10 in 5min). Operator-configurable per rule. Confirmed-attacker case still triggers within seconds (second event lands within the window); single-event false-positive doesn't. |
| **D2.1.A** 5s polling cadence misses bursts | Pure scan logic. Each tick reads ALL events since the last cursor — a 30/s burst yields ~150 events in one tick, the rule engine aggregates them, the threshold trips, the decision emits. No event loss from cadence; only the 5s latency before the engine sees the events. Latency is invisible (LAPI 60s ticker dominates). |
| **D3.1.A** botnet across many IPs | Documented v1.4 deferred. v1.3 emits one decision per IP; a 200-IP botnet → 200 decisions. Operator workaround: `cscli decisions add --range <cidr>`. Spec §5 names CIDR auto-classify as a future surface. |
| **D4.B** pre-push GET adds one round-trip per push | Loopback / LAN LAPI round-trip is sub-millisecond. Push frequency is intrinsically low under D2.2.A's aggregated model — only threshold-crossings emit, not every event. Even under heavy attack: a handful of pushes per minute, not per second. Acceptable cost for the source-of-truth idempotence (D4 rationale). |
| **D5.A** asymmetric cooldown defaults look weird to a reviewer | Documented inline in §1.3 D5: AUTH 7d (operator unbans typically reflect "real user, please leave them alone"); SQLi/RCE/XSS/LFI 24h (operator unbans typically reflect "I think this was a false positive, let me check"); PROTOCOL/OTHER/Throttle 4h (maintenance-action unbans, faster re-engagement appropriate). The asymmetry encodes "how much do we trust the operator's judgment of false-positive-ness for THIS category?". Defaults tuneable per rule. |
| **D5.A** cooldown LRU memory growth | Per-(src_ip, scenario) entry, TTL ≤7d (the longest default). Cap at 10k entries (same as M/Q/N LRU caps). Eviction by LRU when cap reached. On a homelab the steady-state size is dozens, not thousands — cap is defensive. |
| **D6.A** Sink fanout breaks Step N AC #21 (read-side unchanged) | Listener is opt-in via `SetTombstoneListener`; nil listener = no fanout invocation, original `absorbTombstone` path unchanged. Pinned by an extension to `TestSink_AbsorbTombstone_NoListener_Untouched`. The §3.6 plumbing is additive only. |
| **D7.A** LAPI write down mid-process | Buffered channel + drop-on-full (1024 cap). Writer goroutine retries with exponential backoff. Drop counter `automation_dropped` surfaced in `/metrics/summary`. The source events stay in their durable tables (waf_event / throttle_event / audit) for forensics — the auto-classify action on them is lost on drop, the source-side WAF/throttle defence is unaffected. |
| Rule change clobbers in-flight decisions | Trigger engine reads the RuleSet snapshot at engine-tick (every 5s); rule changes take effect on the next tick. A decision emitted under the OLD rules continues to its writer pipeline; future ticks use the NEW rules. Pinned by a unit test: change a rule mid-tick, assert the in-flight intent still has the OLD scenario suffix on the audit row, and the next-tick intent has the NEW one. |
| **D1.A** watcher creds drift silently (JWT login starts failing) | A WARN log line on every login retry. Metrics counter `automation_login_failures_per_hour` in `/metrics/summary`. Operator sees in audit (`automation_login_failed` event — added to the action set) + dashboard. The trigger engine doesn't re-fire intents while paused; events accumulate in their source tables and the cursor advances on next successful re-login (any backlog older than the JWT-expiry window is implicitly dropped on the next tick's cursor advancement, which is acceptable — the alternative is a flood of stale decisions when the operator fixes creds days later). |
| **D8.A** Settings page bloat | The new Card adds ~6 kB raw / ~1.8 kB gz to settings/_page.svelte. Combined Step P frontend delta under the AC #19 3 kB gz budget (settings Card + decisions-page badge logic). Measured at P.4. |
| Decision push race: two trigger ticks see the same threshold-crossing | The per-source cursor is monotonic. If tick N reads events up to time T and emits, tick N+1's cursor is at T+1. The same event cannot trigger twice. Pinned by a unit test with a fixed clock. |

---

## 5. Out of scope (for v1.3)

- CIDR auto-classify (D3.1.A defers — v1.4 candidate).
- Multi-provider DNS auto-classify (no, this is the CrowdSec side; not related to O's DNS providers).
- Email / Slack alerts on auto-ban events (notification surface, separate spec).
- Auto-classify based on observability metrics rather than discrete events (e.g. "ban this IP if its req/s spikes above X") — counter-based triggers are a different shape, defer.
- Manual review queue ("hold the decision for operator confirmation before pushing") — opposite of auto-classify, separate feature.

---

## 6. Appendix — references

- Step N spec for the read-side architecture: `docs/superpowers/specs/2026-05-29-step-n-crowdsec.md`.
- CrowdSec watcher auth: `crowdsec@v1.6.3/pkg/apiserver/controllers/controller.go:115-129`.
- CrowdSec watcher login endpoint: `POST /v1/watchers/login` → JWT response.
- CrowdSec alert/decision write endpoint: `POST /v1/alerts` (the canonical write — decisions are children of an alert in LAPI's data model).
- WAF event severity field: `internal/waf/event.go:85-99`.
- Existing buffered-sink pattern: `internal/waf/sink.go:55-204`.
- Tombstone propagation from StreamBouncer to crowdsec.Sink: `internal/crowdsec/sink.go::absorbTombstone`.
