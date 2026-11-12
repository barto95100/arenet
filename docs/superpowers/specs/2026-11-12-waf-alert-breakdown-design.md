<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec — WAF event-rate alert breakdown. Target: v2.80.x.
-->

# WAF event-rate alert breakdown — design

**Target version:** v2.80.x (patch — additive, no schema/API change)

## Problem

The `waf_event_rate` alert (operator rule "waf-spike") fires on a count —
"32 WAF events in the last 5 minutes" — but carries **nothing about which
IPs, which CRS rules, or which routes/paths** drove the spike. The
operator (hacf) receives the mail and cannot retrace what it was about:
the source only counts, and by the time they open the Logs page the
events may have aged past the recent-rows window.

A second, smaller issue: the operator's mail template claimed the count
was "deduplicated (one IP repeating the same attack counts once per
minute)". `CountWafEvents` is a plain `SELECT COUNT(*)` — there is **no
dedup**. The prose was misleading.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | The `waf_event_rate` source attaches a breakdown to `SourceValue.Context`: `topIPs`, `topRules`, `topPaths`, each a top-5 `[]WafEventGroup{Key,Count}`. | The template context already forwards `.Context`; this is the only place a template can read structured per-spike detail. |
| 2 | Breakdown is computed by a new store method `TopWafEventGroups(filter, column, limit)` using SQL `GROUP BY … COUNT(*) ORDER BY c DESC`. | Exact counts. Reusing `QueryWafEvents` (capped at 100 rows) would compute a top-N over a truncated sample and could misrank. |
| 3 | `column` is whitelisted (`src_ip`, `rule_id`, `request_path`, `route_id`, `category`); it is interpolated into SQL, the filter values are bound. | The column can't be parameterised in SQL; a whitelist is the safe equivalent. |
| 4 | Breakdown is **best-effort**: skipped when count is 0, or when a sub-query errors. The alert still fires on the count. | The count is the contract; the detail decorates it and must never fail the send. |
| 5 | The count path is **unchanged** — no dedup added. The misleading "deduplicated" prose is removed from the operator template (operator config, not shipped code). | Real dedup would lower counts and silently change when existing hacf thresholds fire. Operator chose "remove the text" (2026-11-12). |
| 6 | Top-N fixed at 5; blank key values skipped (`col <> ''`). | Enough to act on; a blank row ("") is noise. A configurable N is V2. |
| 7 | Route dimension exposed as **request path** (`topPaths`), not route host. | The source has no routes→host resolver; the path is in `WafEvent` and is more directly actionable. Raw `route_id` is available via the whitelist if needed later. |

## Non-goals

- Configurable top-N or extra dimensions (V2).
- Resolving `route_id` → host in the alert (needs a routes resolver the
  source doesn't hold).
- Real per-IP/minute dedup of the count (rejected — would move thresholds).
- Any new API route or stored-schema change.

## Empirical gates

- `TestTopWafEventGroups_RanksAndRespectsWindow` (observability): exact
  counts, window/filter honoured, blank skipped, non-whitelisted column
  rejected. Reinjection: reversing `ORDER BY` fails it.
- `TestWafEventRateSource_AttachesBreakdownContext` / `_NoBreakdownWhenEmpty`
  (alerting): Context shape + absence on empty window. Reinjection:
  dropping the `v.Context =` assignment fails it.
- `TestBreakdownRendersInBodyTemplate` (alerting): the operator-facing
  wire — a body template ranging over `.Context.topIPs` renders the
  offenders through `newAlertEventTemplateContext` + `renderTemplate`.
- Gates: `go test -race`, `go vet`, `gofmt -s`, frontend `npm run check`
  + i18n parity.

## Operator-facing

- Rule editor (admin): a hint under the body template, shown only for the
  `waf_event_rate` source, listing `.Context.topIPs/topRules/topPaths`.
- Wiki (`Alerting.md` / `-FR`): the template-context reference was wrong
  (`.Rule.Name`, `.Value.Float`, `.At` — none exist); corrected to the
  real fields (`.RuleName`, `.Value`, `.Labels`, `.Context`) and the WAF
  breakdown documented with an example body.
