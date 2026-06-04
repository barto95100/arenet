<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Step J — Closeout

Retrospective consolidation of Step J ("Multi-upstream Load Balancing
+ DNS-01 ACME + Topology visual pass"). Step J shipped per spec
through commits `8972365` → `aee0525` and was tagged `v0.6.0-step-j`
on 2026-05-26. This document is a single point of reference that maps
the §2 acceptance criteria to their delivering commits, notes the one
piece of §5.5 that was subsequently superseded by the v1.1.x Topology
v2 rewrite, and lists the deferred items per §1.4.

The doc was written on 2026-06-07 against `main` at `7f24292` (post-
Critique 11 polish), after Step N (`v1.1.0-step-n`, 2026-05-30) and
Topology v2 + Stage B + Critique 11 (`v1.1.0` / `v1.1.0-rc1`,
2026-06-04). It does not introduce a new ship tag — Step J's tag
already exists at `v0.6.0-step-j`.

## Spec reference

- Spec: [docs/superpowers/specs/2026-05-22-step-j-multi-upstream-lb.md](superpowers/specs/2026-05-22-step-j-multi-upstream-lb.md)
- Original baseline: `v0.5.0-step-i` (`c44abdb`)
- Spec freeze tag: `v0.6.0-step-j-spec` (2026-05-24)
- Ship tag: `v0.6.0-step-j` (2026-05-26, points at commit `aee0525`)
- Closeout-doc reference point: `7f24292` (2026-06-07, post-Critique
  11 polish on the v1.1.x line)

**Status: CLOSED.** All non-deferred §2 acceptance criteria DONE.
Two deferred per §1.4 (AC #11, AC #12 — WAF observability, blocked by
upstream `coraza-caddy` until a match hook lands). One piece of §5.5
(Topology `<PageHeader>` migration) was SUPERSEDED by the post-J
Topology v2 rewrite — AC #13's intent is still satisfied by Phase 2,
just via a different design path.

## AC matrix

Each row maps a §2 acceptance criterion to its delivering commit(s)
and a file anchor where the implementation lives today. Where the
post-J v1.1.x line further extended the work, the additional commits
are listed for traceability.

| AC | Summary | State | Delivering commit(s) | File anchor (current `main`) |
|----|---------|-------|----------------------|------------------------------|
| #1 | Multi-upstream pool: persist + round-trip + per-upstream weights | DONE | `8972365` (J.1) | `internal/storage/routes.go` `Upstream{URL,Weight}` at L128; wire shape at `internal/api/handler.go:470` |
| #2 | Backward-compatible BoltDB migration | DONE | `8972365` (J.1) | `internal/storage/migrate.go::migrateUpstreamURLToPool` at L165, called from `storage.go:136` |
| #3 | Six LB policies selectable + emitted | DONE | `8972365` (J.1) | `LBPolicies` canonical list at `routes.go:114`; generator at `caddymgr/manager.go:629-651` |
| #4 | Round-robin distribution | DONE | `8972365` (J.1) + J.7 smoke `aee0525` (50/50 observed) | `caddymgr/manager.go` selection_policy emission |
| #5 | Weighted distribution | DONE | `8972365` (J.1) + J.7 smoke `aee0525` (20/80 observed on 1:4) | `caddymgr/manager.go:637-642` (`weights` array) |
| #6 | Active HC removes failed upstream | DONE | `c867b2e` (J.2) + J.7 smoke `aee0525` (T+2.9s transition) | `caddymgr/manager.go:682` (`health_checks.active` emission) |
| #7 | Active HC restores recovered upstream | DONE | `c867b2e` (J.2) + J.7 smoke `aee0525` (T+2.4s transition) | Same as #6 |
| #8 | HC config validation | DONE | `c867b2e` (J.2) | `internal/api/validation.go::validateHealthCheck` at L258 + `materialiseHealthCheck` at L311 |
| #9 | DNS-01 wildcard issuance | DONE (promoted from PARTIAL by J.7 smoke) | `fd840d5` (J.4) | `_ "github.com/caddy-dns/ovh"` at `cmd/arenet/main.go:56`; `buildACMEPolicy` at `caddymgr/manager.go:1448`; live issuance verified end-to-end against LE staging in 17 s during J.7 smoke (`aee0525`) |
| #10 | DNS provider credentials never echoed | DONE | `fd840d5` (J.4) | `internal/storage/dns_provider.go::DNSProviderConfig` at L47; redaction confirmed across wire / audit / BoltDB-cleartext-with-file-perm-boundary by J.7 smoke |
| #11 | `audit_waf_match` audit event | DEFERRED | (per §1.4) | Not implemented. `coraza-caddy` v2.5.0 exposes no match hook — disproportionate ownership |
| #12 | `X-WAF-Match` response header | DEFERRED | (per §1.4) | Not implemented. Same reason as #11 |
| #13 | Topology visual pass + auto-fit on load | DONE (via different path) | `a2ae797` (J.6) shipped the §5.5 design; subsequent `566536d` (`#R-TOPO-v2-phase3`) replaced the entire page with the Svelte Flow rewrite — AC #13's intent (visual redesign + auto-fits on load) is satisfied by Phase 2's `fitView` prop on `<SvelteFlow>` at `topology/+page.svelte:317`. See "Deviations" below for the §5.5 supersession |
| #14 | Frontend tests pass | DONE | J.7 smoke verdict `aee0525` (174/174 at the time); current `main` 124/124 on the post-rewrite test surface | `npm run check` 0/0/0 + `npm test` green on `main` |
| #15 | Backend tests pass | DONE | J.7 smoke verdict `aee0525` (7 packages green); current `main` `go test -race -count=1 ./...` green | All packages incl. new `internal/caddyhc/` (added post-J for Stage B) |
| #16 | Lint / vet / fmt clean | DONE | J.7 smoke verdict `aee0525`; current `main` `go vet ./...` clean | — |
| #17 | Bundle budget | DONE | J.7 smoke verdict `aee0525` (8 kB gz vs 30 kB budget) | `npm run build` succeeds on `main` |

## Sub-task verdict

One row per spec §4 sub-task.

| Sub-task | Scope | Verdict | Delivering commit |
|----------|-------|---------|-------------------|
| **J.1** | Multi-upstream model + migration + 6 LB policies | DONE per §5.1 | `8972365` |
| **J.2** | Active health checks (storage + validation + generator) | DONE per §5.2 | `c867b2e` |
| **J.3** | Frontend multi-upstream UI (repeater + LB selector + HC sub-form) | DONE per §5.3 | `03cfe61` |
| **J.4** | DNS-01 ACME (route field + provider config + generator + UI) | DONE per §5.4 | `fd840d5` |
| **J.5** | WAF observability completion | DEFERRED per §1.4 | n/a |
| **J.6** | Topology visual pass (`<PageHeader>` migration + auto-fit) | DONE then SUPERSEDED | `a2ae797` (shipped) → `566536d` (`#R-TOPO-v2-phase3` rewrote the page). See "Deviations" |
| **J.7** | Live smoke test + close-out doc | DONE | `30c388f` (test-suite block) + `aee0525` (smoke report — `docs/smoke-test-step-j.md`) |

## Deviations from spec

Two named deviations from the spec as written.

### §5.5 Topology `<PageHeader>` migration — SUPERSEDED

Spec §5.5 specified two named cosmetic changes on the Topology page:

1. Auto-fit the graph to the viewport on first non-empty data
   (resolving Step I Finding #10).
2. Migrate the page's custom header to `<PageHeader>` + the
   `<StatusDot>` atomic.

Both shipped in J.6 (`a2ae797`, 2026-05-25) and were verified PASS
in the J.7 smoke (`aee0525`, 2026-05-26).

Post-J, the v1.1.x line introduced `#R-TOPO-v2` (Topology Phase 1/2),
which rebuilt the Topology page from scratch using `@xyflow/svelte`
(Svelte Flow). Phase 3 (commit `566536d`, "promote v2 as the
canonical /topology, drop legacy stack") replaced the J.6 page
entirely. The `<PageHeader>` migration was DROPPED in that rewrite
— Phase 2 ships its own custom `<header class="topo-header">` with
eyebrow + `<h1>` + lede paragraph, and its own custom
`.live-indicator` pill (not the `<StatusDot>` atomic).

**AC #13 intent is still satisfied.** Phase 2 delivers a visual
redesign that's substantially more ambitious than §5.5's bounded
"two-named-changes" scope. The auto-fit half is satisfied
declaratively via the `fitView` prop on `<SvelteFlow>` (data lands
before the canvas mounts in Phase 2's load order, so fit-on-mount
behaves correctly without the "first non-empty data" guard the spec
foresaw).

**Decision rationale** (per the 2026-06-07 audit): Routes and
Topology both have intentional custom headers carrying richer content
than the `<PageHeader>` slot can accommodate cleanly. `<PageHeader>`
remains the convention for the simpler pages (Settings, Security,
Observability). Retrofitting Topology back to `<PageHeader>` was
considered and declined — would regress operator-validated visual
decisions from the v1.1.x line for no functional gain.

**Action**: none. Both the J.6 work and its supersession are
historical records; no further work needed.

### §7 J.7 smoke document — DELIVERED then EXTENDED

Spec §7 outlined a single smoke document (`docs/smoke-test-step-j.md`)
covering AC #1–#17. That document landed at `aee0525` (2026-05-26)
with the J.7 smoke verdict.

Post-J, the v1.1.x line ran multiple operator-side browser smokes for
its own scope (Stage B redeploy verdict for `#R-TOPO-real-health-probe`;
Critique 11 multi-round smoke for the Routes page health badges; the
Routes/Topology cross-check after the IP-typo fix). Those smokes
validated the deltas the v1.1.x line introduced on top of Step J's
foundation — they did not re-validate Step J's ACs (which the J.7
smoke already covered).

**Action**: none. `docs/smoke-test-step-j.md` is the authoritative
record of Step J validation; the v1.1.x smokes are evidence that
Step J's foundation continued to function correctly through the
subsequent v1.1.x work.

## Deferred items (per spec §1.4)

Unchanged from the original spec; recorded here for completeness so a
future reader doesn't need to chase the spec to find them. The
authoritative backlog entries live in `docs/backlog-step-j.md`.

- **AC #11 — `audit_waf_match` audit event.** Deferred. `coraza-caddy`
  v2.5.0 exposes no match hook on which to wire this without a
  custom-fork-grade module. Backlog.
- **AC #12 — `X-WAF-Match` response header.** Deferred. Same reason as
  AC #11. Backlog.
- **J.5 — WAF observability completion.** Deferred. Tied to AC #11 +
  AC #12 above. Backlog.
- **Passive health checks.** Deferred per §1.3 decision 3. Backlog.
- **Next-host retry** (`reverse_proxy` retry layer). Deferred per §1.3
  decision 5. Backlog.
- **The six unused Caddy LB policies** — the four hash policies
  (`header`, `cookie`, `query`, `uri`), `client_ip_hash`,
  `random_choose`. Deferred per §1.4. Backlog.
- **Per-upstream `max_requests`** concurrency cap. Deferred per §1.4.
  Backlog.
- **Circuit breaker.** Not considered (experimental in upstream Caddy).
- **Dynamic upstreams** (DNS / SRV-resolved pools). Not considered
  (mutually exclusive with active health checks in Caddy).
- **Perimeter-mode WAF**, **multi-user Basic Auth per route**, and the
  **Security & Threat dashboard**. Deferred to dedicated later steps
  per `docs/backlog-step-j.md` §5.

## Version note

Spec §8 planned `v0.6.0-step-j` as the ship tag, which **was posted**
on 2026-05-26 (the tag points at commit `aee0525`, the J.7 smoke
close-out commit). Step J's tag exists.

The naming sequence broke after Step J. Step N adopted a
`v1.1.0-step-n` tag (2026-05-30, points at commit `820c0cc`) — the
jump from `v0.6.x` to `v1.1.x` was a deliberate version bump
signalling the
architecture shift the v1.1.x line carried (Topology v2 live data
feed, Stage B real health probe, Critique 11 honest route status). No
intermediate `v1.0.x` tag exists in the repo today; the line went
straight from `v0.6.0-step-j` to `v1.1.0-step-n` to `v1.1.0` /
`v1.1.0-rc1`.

**This closeout doc does NOT introduce a new tag.** Step J shipped
under `v0.6.0-step-j` per spec; that tag remains the canonical
reference. Future Steps continue branching from the v1.1.x line, not
from the v0.6.x series.

## Cross-references

- **Spec**: [docs/superpowers/specs/2026-05-22-step-j-multi-upstream-lb.md](superpowers/specs/2026-05-22-step-j-multi-upstream-lb.md)
- **J.7 smoke report**: [docs/smoke-test-step-j.md](smoke-test-step-j.md)
- **Step J backlog (deferred items + scope decisions)**: [docs/backlog-step-j.md](backlog-step-j.md)
- **Post-J Topology v2 / Stage B / C11 backlog**: [docs/backlog-step-r.md](backlog-step-r.md)
  — contains `#R-TOPO-real-health-probe` (RESOLVED via Stage B),
  `#R-TOPO-hc-bootstrap-down` (open trade-off), `#R-ROUTES-health-honest`
  (RESOLVED via Critique 11), and others
