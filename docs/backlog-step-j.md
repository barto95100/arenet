# Step J — Backlog

Items deferred from Step I (Reverse Proxy v1.0, tagged `v0.5.0-step-i`).
Source: `docs/smoke-test-step-i.md` §3 Findings + §5 Acknowledged debt.

This file is the entry point for the Step J spec — every item below
was consciously shipped-around in v1.0, not forgotten. Pick them up
when scoping Step J.

---

## 1. Methodology rule — adopt before any Step J work

Five of the six bugs fixed in the Step I.7 hotfix (Findings #2, #4,
#6, #7, #8 — all but #5, which was a frontend-default / missing-
backend-normalize issue) shared the **same root cause**: an audit-time
claim about how an external dependency (Caddy, Coraza, OWASP CRS)
behaves at runtime, inferred from docs or package names and never
verified empirically. Each one passed unit tests against a broken
config because the tests exercised structure, not runtime semantics.

**Rule for Step J and beyond:**

> Any audit-time claim about the runtime behaviour of an external
> dependency (Caddy, Coraza, CRS, certmagic, etc.) must be verified
> empirically before it is treated as settled — either by reading
> the upstream source with an explicit `file:line` citation, or by
> a targeted test harness that demonstrates the invariant. An
> unverified "I assume X does Y" is a latent finding until proven.

Action: copy this rule into `CLAUDE.md` so it is active for every
future session, not just this backlog.

The Step I.7 mitigation pattern worth keeping:
`TestBuildConfigJSON_LoadsCleanly` runs `caddy.Validate()` on the
emitted JSON — it provisions every module (including Coraza loading
the embedded CRS) without starting listeners. `TestBuildConfigJSON_
HandlersAllResolvable` asserts every emitted handler ID exists in the
Caddy registry. Extend this pattern to any new Caddy-facing config.

---

## 2. Deferred findings (from Step I smoke §3)

### Finding #3 — Strip `Authorization` header before upstream forward

When a route has Basic Auth enabled, Caddy's reverse_proxy forwards
the `Authorization: Basic <base64>` header to the upstream verbatim.
Base64 is not encryption — the upstream sees the route credentials in
clear. Acceptable for a single-user homelab (upstream is under the
same admin), but a real leak surface.

Scope: add a `header_up -Authorization` directive when Basic Auth is
active, with an opt-in "forward credentials to upstream" toggle for
legitimate auth pass-through cases. Secure default = strip.

Note: I.6 custom headers can SET headers but not REMOVE them, so
there is no admin-side workaround today — this needs real backend
work.

### Finding #9 — Optional perimeter-mode WAF (waf-before-auth)

On a route with both WAF and Basic Auth, the handler chain runs
`authentication` before `waf`. An anonymous malicious request gets
a 401 before the WAF ever inspects it — the WAF only protects
authenticated traffic. This is intentional (spec §3.2, commit I.4:
perf + WAF log signal-to-noise) and documented, but it does not
match the "FortiWeb-light" positioning where a WAF is expected to be
a perimeter shield.

Scope: a per-route choice between two chain orders —
- `gated` (current): `[metrics, auth, waf, headers, proxy]`
- `perimeter`: `[metrics, waf, auth, headers, proxy]`

Possible designs: extend the `WAFMode` enum (`perimeter-block` /
`perimeter-detect`), or a separate orthogonal `WAFPosition` field
(`after-auth` / `before-auth`). Spec it properly — not a hotfix.

### Finding #10 — Topology auto-fit on load

The Topology page opens in a zoomed state where the graph overflows
the viewport; the user must click "Reset view" to see the whole
graph. Expected: zoom-to-fit on component mount.

Scope: trigger the same handler as the "Reset view" button from the
Topology component's `onMount` — likely a one-liner. Pure UX polish,
non-blocker.

Scope note: see §5 — now part of a broader Topology visual design
pass, not just the auto-fit fix.

### AC #4 PARTIAL — `audit_waf_match` event + `X-WAF-Match` header

AC #4 (WAF detect mode) shipped PARTIAL. The spec §2 verification
text mentions an `audit_waf_match` audit event and an `X-WAF-Match`
response header — both deferred during I.4. Caddy's structured log
is the observability surface today; first-class Arenet audit
emission needs a custom Coraza module wrapper.

Scope: the module wrapper enables both the audit event and the
response header. Estimated ~3h (per smoke doc §5).

**Update 2026-05-24** — the ~3h estimate was wrong. Empirical recon
during the Step J spec showed `coraza-caddy v2.5.0` (current, byte-
identical to upstream `main` HEAD) exposes no hook to Coraza's
matched rules. The only viable path is a custom Caddy module
consuming `coraza/v3` directly (~600 lines, security-critical). Was
scoped into Step J as J.5, then deferred — see §5 "Out of Step J
scope" and `2026-05-22-step-j-multi-upstream-lb.md` §1.4.

---

## 3. Acknowledged debt (from Step I smoke §5)

Larger features explicitly out of scope for v1.0, recorded so the
Step J / K spec can pick them up:

- **WAF rule tuning UI** — per-route allowlist of CRS rules to
  silence false positives. (Step K, spec §6.4)
- **DNS-01 ACME challenge** — wildcard certs. (Step J)
- **Multi-upstream load balancing + active health checks.** (Step J)
- **Multi-user Basic Auth per route.** (Step J)
- **Forward-auth SSO** — Authelia / Keycloak / Authentik. (Step K)
- **Backup / restore config** — BoltDB JSON export / import. (Step K)

---

## 4. Notes carried from the smoke

- The Step I commit history is not strictly linear by sub-task
  number (I.4 landed after I.5 / I.6). Acknowledged, left as-is —
  no rebase. Mentioned only so it does not surprise a later reader
  of `git log`.
- v1.0 release notes should mention two upgrade behaviours:
  - Routes with pre-Step-I `WAFEnabled=true` migrate to
    `WAFMode="block"` and will actively block matching requests.
  - When WAF + Basic Auth are both enabled, Basic Auth gates first
    (Finding #9).

---

## 5. Step J scope decision (2026-05-22)

Priorities set at the close of Step I, before the Step J spec is written.

### Step J core — to spec (priority order)

1. **Multi-upstream per route with load balancing + active health checks.**
   The marquee feature of Step J. A route must support multiple backend
   upstreams instead of a single one. Scope to spec:
   - Load-balancing policy selection (round-robin, weighted round-robin,
     least-connections, etc. — full enum decided in the spec).
   - Active health checks per upstream, FortiWeb / HAProxy style:
     configurable check type (HTTP probe with expected status / body
     match, TCP connect, ...), check interval, rise/fall thresholds
     before a backend flips up/down.
   - An unhealthy backend is automatically pulled from rotation; traffic
     fails over to the remaining healthy upstreams.

2. **TLS — DNS-01 ACME challenge** for wildcard certificates.

3. **AC #4 completion** — `audit_waf_match` audit event + `X-WAF-Match`
   response header (detect mode). Custom Coraza module wrapper. Note:
   this also produces the WAF events the future Security dashboard
   (see below) will consume — it is a building block for that step.

4. **Topology page — visual design pass.** Broader than Finding #10's
   auto-fit: a real visual polish of the page (flagged as wanting to
   look better / "plus joli"). The auto-fit zoom folds into this work.

### Out of Step J scope

- **WAF observability completion** — `audit_waf_match` audit event +
  `X-WAF-Match` response header (AC #4 PARTIAL from Step I; was the
  Step J J.5 sub-task, now deferred). `coraza-caddy v2.5.0` — current
  pinned, byte-identical to upstream `main` HEAD — exposes no hook to
  Coraza's matched rules. Only viable path is a custom Caddy module
  consuming `coraza/v3` directly (~600 lines, security-critical: a bug
  in the match handling silently weakens the WAF). Ownership
  disproportionate to an observability surface. Revisit if
  `coraza-caddy` gains a match hook, or as a dedicated WAF step. See
  spec `2026-05-22-step-j-multi-upstream-lb.md` §1.4.
- **§5.3 — Extended frontend test suite for the Routes page —
  BLOCKING BEFORE THE `v0.6.0-step-j` TAG.** Promoted from
  REPORTÉE to blocking on 2026-05-25 after the J.6 commit: the
  scaffold pre-requisite this entry once cited turned out to be
  stale — `@testing-library/svelte v5.3.1` + jsdom have been
  installed since Step F, and the J.6 page-render tests prove
  the harness works. The remaining work is the test suite
  itself, scheduled to land **inside J.7** before the tag is
  cut.

  Scope, exact (spec §5.3 + the J.3 review notes):
  - Upstream-pool repeater add / remove tests (including the
    "last row cannot be removed" guard).
  - LB-selector visibility flip: shown only when the pool has
    ≥ 2 upstreams; lbPolicy value preserved across visibility
    flips (remove a row, re-add, the selector re-appears with
    the previous choice).
  - Weight-column visibility flip: shown only for
    weighted_round_robin; per-row weight values preserved when
    the column hides and re-appears.
  - Health-check sub-form gating: sub-fields disabled when
    `enabled` is off, sub-field state preserved across the
    toggle (typed values do not erase on off-and-back-on).
  - Validation rules — each §5.2 rule with a matching client-
    side rejection test (URI required when enabled, method
    enum, interval / timeout duration shape, timeout < interval,
    expectStatus in 100..599 or 0, expectBody is a valid regex,
    passes ≥ 1, fails ≥ 1).
  - Error-map round-trip: `fieldFromMessage` correctly maps
    every server message shape (host, lbPolicy, upstreams[N]
    .url, upstreams[N].weight, healthCheck.<sub>) to the right
    `errors[…]` key, and the markup binds those keys back to
    the offending field.
  - openEdit → HC sub-form → submit round-trip: pin that all
    9 HealthCheck fields survive an unchanged round-trip (the
    audit on the J.3 commit was manual; this test makes it
    automatic).

  No infra dependency. Schedule: J.7, before the tag.
- **Topology code-quality debt (out of J.6 scope).** Extract a
  `<Sparkline>` atomic component out of `TopologyDetailPanel` (the SVG
  path is built manually today, 30+ lines); migrate the ad-hoc
  hover-timeout tooltip in `TopologyNode` to the existing `<Tooltip>`
  atomic; add Vitest coverage for the visual components (Node, Svg,
  DetailPanel currently have zero component tests, while the store has
  412 test-lines and the WS client 361). J.6 ships the header
  migration + the auto-fit only — these structural cleanups are
  recorded here so they are not forgotten.
- **Migration pattern debt: full-Route round-trip is fragile.** Step
  I.4's original `migrateWAFEnabledToWAFMode` did `Unmarshal → Route
  → mutate → Marshal`, which silently drops every JSON key absent
  from the current Route struct. The bug stayed latent until Step
  J.1 removed `Route.UpstreamURL`: I.4 then started eating
  `upstream_url` on every pre-J.1 row before J.1's migration could
  see it. Caught by `TestMigrate_ChainedOrder_WAFThenUpstream`
  during J.1; fixed by rewriting I.4 as a `map[string]any`
  passthrough (set new key, delete old key, re-marshal — every other
  key passes verbatim). The Step J.1 migration itself (`migrate
  UpstreamURLToPool`) is **kept** in the full-Route round-trip
  pattern: it is correct under §6.1 because no Step J commit removes
  a field from Route — only additions — so the round-trip injects
  zero values for new fields and drops nothing. **Rule for future
  migrations:** any step that REMOVES a field from Route (or any
  storage struct) MUST write its migration in the passthrough-map
  pattern; full-Route round-trip is only safe for steps that
  exclusively add fields. **Caveat — float64 type assertion:**
  `map[string]any` decodes every JSON number as `float64`, so a
  passthrough migration that reads a numeric field (e.g. a future
  step touching `weight`, `expect_status`, `passes`, `fails`) must
  type-assert `.(float64)`, not `.(int)` — the latter panics. I.4
  is safe because it only reads `string` and `bool`.
- **Finding #9 — perimeter-mode WAF (waf-before-auth).** Low-priority;
  the current order works. Revisit near project end.
- **Multi-user Basic Auth per route.** Refine near project end.
- **Security / Threat dashboard.** The /security page is a disabled
  sidebar stub today ("Coming in a later step"). Its intended scope
  per roadmap.md — live rate-limited IPs, top-N failed-attempt IPs,
  CSV / iptables / FortiGate exports, outbound webhook system with
  HMAC, optional CSRF / GeoIP hardening — is large enough to be its
  OWN dedicated step with its own spec. NOT a Step J item. roadmap.md
  still labels it "Step F", which is stale: Step F shipped only the
  disabled sidebar shell, not the page. To be re-assigned to a
  dedicated later step.
