<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Engineering Practices — Arenet

> Lessons captured from real diagnostic + shipping sessions
> (Step W bundle, 2026-06-07 to 2026-06-09). Each principle
> here was learned the hard way, with cost. Apply them.

This document is **load-bearing**: read it before opening a
non-trivial investigation, before drafting a spec, and
during code review on any fix that claims to address a root
cause. If you encounter a lesson worth recording (4+ hour
bug, "wait that's not how I thought it worked" moment),
add it here. See [§Contributing new lessons](#contributing-new-lessons).

## Quick reference

| # | Principle | When to remember |
|---|---|---|
| 1 | Triangulate from 3+ sources | Before declaring a root cause |
| 2 | Timestamp every test action | Before reading logs |
| 3 | Read library source | Before proposing a fix |
| 4 | Empirical probes > speculation | When hypotheses pile up |
| 5 | Observability is a deliverable | When writing a spec |
| 6 | Mislabeled state = security bug | When error labels look "off" |
| 7 | Module-level imports cache refs | When test mocks don't take |

---

## Lesson 1 — Triangulate from 3+ sources before identifying a bug

**Principle**: Never declare root cause from a single
signal. Confirm via at least three independent sources:
logs + code + runtime probe + library source. One signal
is a guess. Two signals can both be wrong in the same
direction. Three signals from independent observation
surfaces converge on truth.

**Example**: W.bugfix series 2026-06-08. Initial discovery
report (`f907748` *docs(step-w): discovery — WAF mode
lifecycle bugs*) flagged THREE WAF mode bugs ranging from
"label conflation" to "mode never reaches Coraza" to
"per-route override silently ignored." After
triangulation — `journalctl -u arenet` timestamps cross-
referenced against `internal/caddymgr/manager.go` state
diffs cross-referenced against Coraza's
`transaction.go:328-340` invariant — only **one** bug
(`a1366b9` *W.bugfix #1 — mode-aware sink labels*) was
real. Bugs #2 and #3 turned out to be timeline confusion:
stale journal output from a previous boot misread as
current behaviour. Without the triangulation pass, we
would have shipped two unnecessary fixes and possibly
broken working code.

**Antipattern**: "I see `BLOCK 403` in the logs, so the
WAF is blocking — the bug must be that Coraza is in
BLOCK mode when the spec says DetectionOnly." Single
source, single conclusion, wrong root cause.

**How to apply going forward**: Before opening a fix PR,
ask: *Can I cite three sources that converge on the same
conclusion?* Examples of independent sources:

- structured log entries with timestamps you trust
- the source code path the entry would have walked
- a runtime probe (curl, journalctl --since, a debug print)
- the library's own source code for any invariant we rely on
- a unit test that reproduces the claim deterministically

If you can only cite one or two, keep probing. The cost of
an extra probe is measured in minutes; the cost of a wrong
fix is measured in commits and operator trust.

---

## Lesson 2 — Timestamp test actions against logs

**Principle**: Every test action must be timestamped
externally *before* reading logs. Without an external time
anchor, log entries from background processes (the WAF
sink batch, the metrics ticker, the certmagic renewer)
get attributed to your action and the diagnosis goes
sideways.

**Example**: Multiple Step W smoke validation sessions on
the `AreNET-test` host (192.168.99.10). The natural reflex
was "do the thing, then `journalctl -u arenet --no-pager
| tail -200` and search." This buried the
country_block-relevant lines under unrelated `waf handler
provisioned`, `metrics tick`, and `healthz` noise. The
discipline that actually worked:

```bash
date                                # captures wall-clock T0
curl -X PUT https://.../routes/<id> # the action under test
ssh arenet-test 'journalctl -u arenet --since "30 seconds ago"'
```

The `--since "30 seconds ago"` scope, anchored against
the `date` output captured BEFORE the action, eliminates
~95% of attributional ambiguity on a chatty service like
Arenet (which emits boot signals, per-frame WS metrics,
and TLS renewal heartbeats independently of operator
actions).

**Antipattern**: "Let me grep the last 1000 log lines for
the bug." 1000 lines on an Arenet test host = ~3 minutes
of background chatter from unrelated subsystems. The
signal-to-noise ratio is wrong by an order of magnitude.

**How to apply going forward**: Adopt the `date` + `--since`
pattern as muscle memory. For multi-step actions, capture
`date` between each step so log windows can be narrowed
per step:

```bash
date && curl ... step-1
date && curl ... step-2
date && curl ... step-3
# then on the host, journalctl --since "<T0>" --until "<T1>"
```

On the frontend side, the equivalent is `console.time` /
`console.timeEnd` brackets around the action, or the
Network panel's "preserve log" + start-time column.

---

## Lesson 3 — Read library source before proposing a fix

**Principle**: Documentation lies, source doesn't. When a
library doesn't behave as the docs say, open the source
and read. Thirty minutes reading source beats four hours
of "configure harder."

**Example 1** — Coraza v3
`internal/corazawaf/transaction.go:328-340`: in
`DetectionOnly` mode, rule matches are stored in
`detectionOnlyInterruption`, NOT in `interruption`.
Arenet's sink originally read only `interruption` →
DetectionOnly matches looked identical to "no match,"
which produced the mode-label bug behind `a1366b9`. The
docs description of DetectionOnly was technically
accurate ("logs but does not block") but missed the
mechanical consequence on the field we were reading. Only
the source made the invariant unambiguous, and the fix
became 1 line + 12 tests.

**Example 2** — `d3-timer/src/timer.js:10-11`:

```js
var clock = (typeof performance === "object" &&
             performance.now) ? performance : Date;
var setFrame = ... window.requestAnimationFrame.bind(window) ...
```

The module **captures references at module-load time**.
vitest's `useFakeTimers({ toFake: ['performance',
'requestAnimationFrame'] })` patches the *globals* in
`beforeEach`, but d3-timer's `clock` and `setFrame` already
hold the originals. The WorldMap V.8.HF1 test flake
(commits `b0521e0` and then deeper fix `8943b51`) was
unsolvable until we opened the file. The fix bypassed
d3-timer entirely via a test seam (`_tickForTest`).

**Antipattern**: "The Coraza docs say DetectionOnly logs
but does not block, so my sink should see the same field
populated as in Block mode. Let me reconfigure the WAF
harder." or "vitest's `toFake: ['performance']` should
just work — let me add `requestAnimationFrame` and
`cancelAnimationFrame` to the list and re-run."

**How to apply going forward**: When stuck on dependency
behaviour, the first move is `find node_modules/<pkg>/src
-name '*.ts' -o -name '*.js' | xargs grep -l <symbol>` (or
`find vendor/<module>` for Go deps). Bookmark the relevant
source path with a `file:line` citation in any spec or
review comment that depends on that behaviour. CLAUDE.md
§*Empirical verification of external dependencies* codifies
this rule for the project: an unverified "I assume X does
Y" is a latent finding until proven.

---

## Lesson 4 — Empirical probes beat speculative fixes

**Principle**: Before writing a fix, instrument the bug.
Add print/log/probe statements that prove the hypothesis.
Speculation without data wastes commits and burns operator
trust ("did this fix really land?").

**Example**: d3.timer flake diagnosis on 2026-06-09. Three
hypotheses were plausible:

- **A**: vitest fake-timers don't propagate to d3's
  cached `clock` reference (import order)
- **B**: rAF is faked but never advanced (the test's
  `advanceTimersByTimeAsync` doesn't reach jsdom's rAF
  shim)
- **C**: `t`-rounding inside the bezier interpolator
  collapses to the same SVG path on consecutive frames

Instead of trying each in sequence (the fix-and-pray
trap), the diagnostic was a probe `.test.ts` file with
two `console.log` blocks running under the same
`useFakeTimers` config:

```
perf before: 0       d3.now before: 1061.337125
perf after:  500     d3.now after:  1061.337125
perf delta:  500     d3 delta:      0
samples: []
```

Two observations definitively settled it: faked
`performance.now` DID advance (B partially ruled out for
performance) and d3 NEVER saw it (A confirmed); the
d3.timer callback NEVER fired (B confirmed for rAF too);
C was made moot by the absence of any callback firing at
all. The fix in `8943b51` was scope-distinct, narrow,
and shipped on the first attempt because the probe told
us exactly what to fix.

**Antipattern**: "Let me try fix X — oh that didn't work
— let me try fix Y — oh that didn't work either — let me
try fix Z." Three commits, three reverts, no diagnosis.
The previous attempt at this fix (`b0521e0`) shipped
without the probe, and the flake came back at the next
iteration because the underlying cause was unprobed.

**How to apply going forward**: For any bug that survived
one fix attempt, **stop coding** and add probes. The probe
IS the diagnostic. Probes are cheap (10 lines, throwaway)
and the data they produce is more valuable than a hundred
hypotheses. Once the probe nails the cause, delete the
probe and write the fix. Examples of cheap probes:

- a temporary `*_test.ts` file with `console.log` calls
- `log/slog` lines at `LevelDebug` with structured fields
  on the suspected boundary (controlled by an env var)
- a `pprof` capture for performance bugs
- a 5-line `grep`-able structured log emitted only when
  the bug condition triggers

---

## Lesson 5 — Observability is a first-class deliverable

**Principle**: Logging, metrics, and event sinks belong in
the spec, NOT in "we'll add it later." A feature without
observability is a feature you can't operate, can't
debug, and can't certify. Treat boot signals + diff logs +
sink + event bus subscription as **baseline scope**, not
polish.

**Example**: Step W country_block, commits `60b05d8`
(W.3 — caddymgr emit), `03e35f7` (W.4 — sink +
GeoEvent + schema v7→v8), `7cd0dbd` (W.5 — frontend UI),
all shipped in the same milestone as the gate handler
itself. The cumulative effect:

- **Boot signal** at sink construction emitting seven
  fields:
  `country block sink wired present=true status_code=403
  trusted_ips_count=0 sample_pct=10 cooldown=15s
  retention_days=30 obs_store_present=true`
- **Config diff log** at `mgr.Apply` emitting before/after
  state per route mutation
- **Per-route provisioned log** with `mode` +
  `country_list_count` at every Caddy reload
- **GeoEvent sink** wired to the same Activity Log
  pipeline as WAF/CrowdSec/auth, with the 6th legend
  entry on the WorldMap so blocks are visible

The cumulative effect: the entire Step W smoke
validation completed in **under 30 minutes** with all 10
gates green. Without those signals, validation would
have meant SSHing into the test host and running
strace-equivalent probes for every assertion. The Step W
release notes (`36b4666` *docs(step-w): release notes for
v1.6.0-step-w*) document this directly.

**Antipattern**: "Ship the feature, observability is
polish. We'll add metrics in step W+1." This pattern bites
twice: first when operators ask "is it actually working?"
and you can't answer without writing the observability
backfill; second when the polish step gets bumped by the
next feature and the observability debt compounds.

**How to apply going forward**: When writing a spec,
**dedicate ≥20 % of the scope** to observability. Concrete
checklist for any new feature:

- [ ] Boot signal emitted at construction with all
      configuration values
- [ ] Diff log emitted on every `Apply` / state change
- [ ] Per-instance provisioned log with relevant cardinality
- [ ] Event sink subscription if the feature produces
      operator-visible decisions (block, redirect, throttle)
- [ ] Activity Log entry mapping if the feature surfaces
      in `/observability/logs`
- [ ] WorldMap legend entry if the feature produces
      geo-tagged events
- [ ] Smoke test gate that asserts the boot signal lands

If any box is unchecked at spec time, the feature is not
spec-complete.

---

## Lesson 6 — Mislabeled state is a security bug, not a typo

**Principle**: When error or state labels don't accurately
reflect what happened in the system, you've created false
confidence. Operators read the label and form a mental
model. If the label says "BLOCK" but the request went
through, the operator's mental model is wrong and they
will make security-relevant decisions on it. **This is a
security bug**, not a logging cleanup task. Treat it as
such in severity and in commit subject.

**Example**: Pre-W.bugfix #1 (resolved in `a1366b9`),
Arenet's WAF event sink emitted `BLOCK 403` labels for
**all** Coraza rule matches, including matches in
`DetectionOnly` mode where Coraza recorded the rule hit
in `detectionOnlyInterruption` but did NOT block the
request. Operators reading `/observability/logs` saw rows
labelled "BLOCK 403" and assumed attacks had been
neutralized. They weren't — the requests reached the
upstream service. The label conflated detect/block,
creating a real security gap (false sense of protection)
across every route configured in DetectionOnly mode for
shadow-mode rollout. The fix (`a1366b9`) introduced
mode-aware Action + StatusCode columns at the sink layer,
backed by a schema v6→v7 migration.

**Antipattern**: "It's just a typo in the log message."
or "We can rename it next sprint." Both reactions treat
the symptom as cosmetic and miss the operator-trust
implication. A label is part of the security contract.

**How to apply going forward**:

- Audit **every** error/state string in user-facing
  surfaces (logs UI, badges, status pills, alert text,
  release notes) for semantic accuracy
- If a label could mislead an operator about what
  happened, file it as a `fix(security):` or
  `fix(observability):` bug, not a `chore:` polish
- Include a regression test that pins the label-to-state
  contract (e.g., the W.4 sink tests assert
  `Action="block"` ⇔ request did not reach upstream)
- When introducing a new state (e.g., a new WAF mode,
  a new gate decision), enumerate every surface that
  needs the label and add them in the same commit, not
  later

---

## Lesson 7 — Module-level imports cache references

**Principle**: Libraries that read globals at module load
(e.g. `const x = performance` or
`const rAF = window.requestAnimationFrame`) capture
references **AT IMPORT TIME**. Mocks or patches applied
later don't update the cached refs. This breaks vitest's
`useFakeTimers`, jest's `jest.useFakeTimers`, sinon's
`useFakeTimers`, and any test framework that assumes
"patching the global at runtime reaches all consumers."

**Example**: `d3-timer/src/timer.js:10-11` is the textbook
case:

```js
var clock = (typeof performance === "object" &&
             performance.now) ? performance : Date;
var setFrame = typeof window === "object" &&
               window.requestAnimationFrame
  ? window.requestAnimationFrame.bind(window)
  : function(f) { setTimeout(f, 17); };
```

`WorldMap.svelte` runs `import * as d3 from 'd3'` at the
top of the test file. That import resolves d3-timer →
the two `var` declarations execute → `clock` and
`setFrame` now hold references to the ORIGINAL
`performance` object and the ORIGINAL bound
`window.requestAnimationFrame`.

Subsequently, `beforeEach` runs:
`vi.useFakeTimers({ toFake: ['performance',
'requestAnimationFrame', 'cancelAnimationFrame'] })`.
This patches the *globals*, so user code reading
`performance.now()` directly gets the fake. But d3-timer
never re-reads the globals; it uses its cached
references, which still point to the real performance
object and the real rAF. Result: `d3.now()` returns
wall-clock time even when faked, and `d3.timer`
callbacks never fire because the rAF binding it holds
isn't the one vitest's fake-timers controls.

This was confirmed with a 20-line probe (Lesson 4):

```
perf delta: 500ms,  d3 delta: 0ms
samples: []  (d3.timer callback never fired)
```

Previous fix `b0521e0` (adding `'performance'` to
`toFake`) was necessary but insufficient because the
cache reference is what defeats it. The deeper fix
`8943b51` bypasses d3.timer entirely via a test seam
(`_tickForTest`), with a doc comment citing
`d3-timer/src/timer.js:10-11` so the next reader
understands the trade-off.

**Antipattern**: Trusting `vi.useFakeTimers` (or any
runtime-patching mock) to "just work" without verifying
the library doesn't pre-cache. Symptom: the test asserts
A, the mock should produce A, but the test sees B and
nobody knows why.

**How to apply going forward**: When a mock seems applied
but the test still sees real behaviour, run a diagnostic
matrix:

1. Does the global read directly produce the mocked value?
   (`console.log(performance.now())` after `useFakeTimers`)
2. Does the library API read produce the mocked value?
   (`console.log(d3.now())` after the same setup)

If (1) is mocked and (2) is not, the library is caching
the global at module load. Options to resolve:

- **Bypass via a test seam** in the component or function
  under test (the path `8943b51` took — lowest risk, no
  upstream coupling)
- **Dynamic import after mock setup** (`const lib = await
  import('lib')` inside the test, after `useFakeTimers`).
  Only works if the test infrastructure supports it and
  the library does its caching inside an init function
  rather than at module top-level
- **Fork or wrap the library** so the cached binding is
  resolvable to the mock (last resort, maintenance cost)

Whichever you pick, leave a doc comment with the
`file:line` citation so the next reader doesn't repeat the
debug cycle. CLAUDE.md §*Empirical verification of external
dependencies* gives the project policy for this.

---

## Antipatterns (cheat sheet)

Quick negative reference for fast scan. If you catch
yourself doing any of these, stop and re-read the
relevant lesson.

- "I'm sure it's X" without three-source confirmation
  ([Lesson 1](#lesson-1--triangulate-from-3-sources-before-identifying-a-bug))
- Reading one log line and declaring root cause
  ([Lesson 2](#lesson-2--timestamp-test-actions-against-logs))
- Configuring harder when source says otherwise
  ([Lesson 3](#lesson-3--read-library-source-before-proposing-a-fix))
- Fix-and-pray loops without instrumentation
  ([Lesson 4](#lesson-4--empirical-probes-beat-speculative-fixes))
- Treating logging/metrics as post-feature polish
  ([Lesson 5](#lesson-5--observability-is-a-first-class-deliverable))
- Cleaning up error-label typos as cosmetic
  ([Lesson 6](#lesson-6--mislabeled-state-is-a-security-bug-not-a-typo))
- Trusting global mocks without verifying library imports
  ([Lesson 7](#lesson-7--module-level-imports-cache-references))

## When to revisit this doc

- **Before opening any non-trivial bug investigation** —
  Lessons 1-4 give you the diagnostic frame
- **Before writing any spec** (Step T, T+1, ...) — Lesson
  5 gates the observability scope; Lessons 6-7 anchor the
  label-and-mock contract
- **During code review for fixes** — does the fix address
  the root cause (Lesson 1), or paper over symptoms
  (Lesson 6)? Did the author probe (Lesson 4) or
  speculate?
- **After any session that yielded a new lesson** —
  UPDATE THIS FILE. The cost of capture is minutes; the
  cost of re-learning is days.

## Contributing new lessons

If you encounter a 4+ hour bug or a "wait that's not how
I thought it worked" moment, capture it here. The
template:

```markdown
## Lesson N — [Title]

**Principle**: [1-2 sentences. Frame it as a rule, not
an observation. The rule should be applicable to future
work, not a recap of the bug.]

**Example**: [Real case from our work + commit ref(s).
Include the failing-then-fixed contrast. Cite
`file:line` for any library invariant the lesson
depends on.]

**Antipattern**: [What NOT to do. Make this concrete —
quote the kind of internal monologue or commit message
that would indicate the lesson is being ignored.]

**How to apply going forward**: [Operational guidance.
Checklist, snippet, or workflow the next reader can
follow without re-deriving the lesson.]
```

When you add a lesson:

1. Append it to the numbered sequence (don't insert
   mid-list — link integrity matters for the antipatterns
   cheat-sheet)
2. Add a row to the [Quick reference](#quick-reference)
   table
3. Add a bullet to the
   [Antipatterns cheat sheet](#antipatterns-cheat-sheet)
4. Commit on its own (`docs(practices): capture lesson N
   — ...`), no code mixed in

Lessons are valuable *because* they reflect real
incidents. Don't water them down to be more general;
keep the specific example, the commit ref, the
`file:line` citation. The next operator reading this
doc benefits more from "in commit `a1366b9` we shipped
the wrong label and ..." than from "always label
things accurately."
