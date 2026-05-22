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

### AC #4 PARTIAL — `audit_waf_match` event + `X-WAF-Match` header

AC #4 (WAF detect mode) shipped PARTIAL. The spec §2 verification
text mentions an `audit_waf_match` audit event and an `X-WAF-Match`
response header — both deferred during I.4. Caddy's structured log
is the observability surface today; first-class Arenet audit
emission needs a custom Coraza module wrapper.

Scope: the module wrapper enables both the audit event and the
response header. Estimated ~3h (per smoke doc §5).

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
