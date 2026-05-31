# Step P — Backlog

Items deferred from Step P work. Same convention as
`docs/backlog-step-o.md` / `docs/backlog-step-n.md` /
`docs/backlog-step-m.md` / `docs/backlog-step-q.md`.

## 1. Feature gaps

### Finding #P-1 — `min_severity` field on Rule

The WAF event surface exposes a `severity` field (1-5) — Coraza
emits it per rule match; M.1 persists it in the `waf_event`
table. Step P's `Rule` struct doesn't consume it: the trigger
engine's threshold gate counts events by `(src_ip, source)`
without filtering on severity first.

**Operational consequence**: an operator who enables
`arenet/waf-sqli` auto-classify gets the SAME threshold
behaviour for a severity-5 SQLi (UNION SELECT against a known
auth table — confirmed attack) and a severity-2 SQLi (a typo
in a search field that happens to match a permissive CRS
rule — likely benign). The category-only filter is too
coarse for the operator who wants "auto-ban on serious
attacks, leave noisy weak signals alone".

**Spec amendment shape** (light, mostly additive):

- `internal/automation/rules.go`: extend `Rule` with
  `MinSeverity int` (0 = any severity, otherwise minimum
  inclusive). Default per Source: SQLi/RCE/LFI=3, XSS=2,
  PROTOCOL=4, OTHER=4 (sensible cutoffs from CRS severity
  distribution). Throttle + auth-burst rules don't apply
  (no severity field on those events) — validator treats
  `MinSeverity` as ignored when not relevant.
- `automation.Rule.Validate`: accept `MinSeverity` in
  `[0..5]` when the rule is enabled + applicable to a
  WAF source.
- `internal/automation/sources.go` + `cmd/arenet/
  automation_adapters.go`: extend `SourceEvent` with
  `Severity int`; `automationWafReader` projects
  `WafEvent.Severity` into it.
- `internal/automation/trigger.go::tick()`: before the
  threshold count, filter events by `e.Severity >= rule.
  MinSeverity` (skip the filter when MinSeverity is 0 OR
  the rule's Source is not WAF).
- Frontend: add a per-row "Min severity" column to the
  Settings → Security Automation rules table; numeric
  input 0-5, hint that 0 disables the filter.
- Unit tests: extend the trigger engine tests with a
  severity-mixed event fixture; assert that
  threshold=2/min_severity=3 with 1×sev5 + 1×sev2 does
  NOT trip (only 1 event passed the severity gate).
- Smoke (live, deferred to the step that ships #P-1):
  fire 2 SQLi events with different severities, observe
  that only the high-severity one counts toward the
  threshold.

**Recommendation.** Faisable en step intermédiaire isolé
(one focused sub-task with its own spec arbitrage if
non-trivial defaults need agreement) OR bundled into the
next sécurité-themed step. The implementation surface is
small but spans backend + frontend + tests, so it deserves
its own ROI consideration rather than being smuggled into
an unrelated step.

**Triage.** Operator-meaningful feature gap. The current
category-only filter ships as a v1.3 limitation;
documented up front in this backlog so a future operator
who hits the "false-positive on a sev-2 rule" pain point
finds the resolution path here.

### Finding #P-2 — Live auth-burst evidence in smoke

AC #8 of the P.5 smoke matrix was marked N/A (live) /
unit-pinned only. The trigger-engine's auth-burst rule
(`automation.SourceAuthBurst`) is exercised at the
unit-test layer (`internal/automation/trigger_test.go`
includes `SourceAuthBurst` in the rule fixture set) +
the audit reader adapter (`automationAuditReader` in
`cmd/arenet/automation_adapters.go`) is integration-tested
against the audit bucket. Live end-to-end evidence —
"N login failures from the same IP within window →
auto-classify push lands in LAPI" — was not run because
the P.5 smoke harness was WAF-focused and didn't include
a login-failure driver.

**Extension shape** (pure test addition, no production
code touched):

- Smoke harness step: configure `arenet/auth-burst` rule
  with `threshold=3 window=60s` (smoke-friendly).
- Driver: 3+ `POST /api/v1/auth/login` with bogus password,
  all from `127.0.0.1` within the window.
- Asserts:
  - `audit` bucket has 3+ `login_failure` rows.
  - On the next 5s trigger tick, `cscli decisions list`
    shows a decision with `scenario="arenet/auth-burst"`.
  - The `automation_decision_pushed` audit row's `message`
    field names the auth-burst source correctly.

**Recommendation.** Bundle into the next smoke
consolidation cross-step (a future iteration of the
M.5-3 spirit covering auth-burst alongside the existing
waf / throttle / crowdsec sinks) OR run as a standalone
harness extension whenever the auth-burst path needs
production confidence. Today the unit tests pin the rule
+ adapter shape; the missing piece is a single integration
run.

**Triage.** Test-coverage gap, not a functional bug. The
auth-burst rule is wired end-to-end (engine reads audit
events, projects to SourceEvent, threshold-gates correctly
per unit tests, writer pushes alerts). What's missing is
written evidence that the wire-up actually works under
live load.

---

## 2. Cross-cutting notes

### Note — TTL alignment is load-bearing: dedupe LRU 60s ↔ N poll cadence 60s

The trigger engine's dedupe LRU TTL (`internal/automation/
dedupe.go::dedupeTTL = 60 * time.Second`) is intentionally
aligned to the Step N StreamBouncer polling cadence
(`internal/crowdsec/live_source.go::SleepInterval = 60s`).
The alignment is **load-bearing for the D4 mirror-checker
correctness story**:

- Immediately after a successful PushAlert, the trigger
  engine self-records the (scope, value, scenario, active=
  true) entry in the dedupe LRU.
- The N consumer's next stream poll (≤60s away) catches
  the new decision and populates the `decision_event`
  mirror table.
- After dedupeTTL expires (60s), subsequent ticks miss
  the in-memory cache and fall through to the
  `HasActiveDecision` mirror checker — which by then has
  the row.

**If either TTL drifts out of sync**, the gap between
"dedupe LRU expired" and "mirror has the entry" lets
duplicate pushes leak through (the cooldown LRU catches
those that follow a tombstone, but not the initial
post-push window).

**Cross-references for the alignment**:
- `docs/smoke-test-step-p.md` §5 findings — the live
  smoke evidenced both protection layers but did NOT
  isolate the mirror-checker (cooldown short-circuited it).
- `internal/automation/dedupe.go::dedupeTTL` — comment
  block notes the 60s value matches the LAPI stream-poll
  ticker. (Does not currently flag the alignment as
  load-bearing — a follow-up edit could sharpen that
  reminder.)
- `internal/crowdsec/stream.go::SleepInterval` — the N
  side constant. No cross-reference to dedupeTTL today;
  if either constant moves, a reader of just one file
  won't see the dependency. Worth adding a one-line
  comment on both sides if a follow-up touches them.
- `internal/automation/trigger.go::tick()` — the lookup
  precedence (cooldown → dedupe → mirror via
  ActiveDecisionChecker).

**If a future step changes either cadence**:
- Tightening the N ticker (e.g. 30s) is safe — the dedupe
  LRU stays at 60s, the mirror is always fresh enough.
- Loosening the N ticker (e.g. 120s) **OR** shortening
  dedupeTTL below the N ticker would re-open the gap. The
  current code comments don't surface this explicitly on
  both sides; a future change should re-verify the
  invariant and consider sharpening the in-code reminders.

This isn't a backlog "item" with action — it's a
load-bearing alignment fact that a reader of the dedupe
TTL constant would want to know without having to walk
the smoke doc. Documented here for cross-reference
visibility.
