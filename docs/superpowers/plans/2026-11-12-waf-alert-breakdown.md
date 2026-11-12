<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan — WAF event-rate alert breakdown. Target: v2.80.x.
-->

# WAF event-rate alert breakdown — plan

Spec: `docs/superpowers/specs/2026-11-12-waf-alert-breakdown-design.md`

## T1 — store: exact top-N (observability)

- `internal/observability/storage.go`: add `WafEventGroup{Key,Count}`,
  `wafGroupColumns` whitelist, and `TopWafEventGroups(ctx, filter,
  column, limit)` — `GROUP BY column COUNT(*) ORDER BY c DESC, k ASC`,
  reusing `wafEventPredicates`, skipping blank keys, limit clamped [1,50].
- Test `waf_event_group_test.go`: ranking, window/filter, blank-skip,
  bad-column rejection.

## T2 — source: attach breakdown (alerting)

- `internal/alerting/source_waf_event_rate.go`: widen `WafEventReader`
  with `TopWafEventGroups`; in `Read`, when `count > 0`, build
  `v.Context` = {topIPs:src_ip, topRules:rule_id, topPaths:request_path},
  each top-`wafBreakdownTopN` (5); best-effort (skip on error/empty).
- Update fakes (`stubWafReader`, `countingWafReader`).
- Tests `source_waf_event_rate_breakdown_test.go`: Context shape, empty
  window → no Context, end-to-end template render.

## T3 — operator surfaces

- `RuleModal.svelte`: conditional hint (source == waf_event_rate) listing
  the breakdown variables + `templatesWafBreakdownHint` i18n (FR+EN).
- Wiki `Alerting.md` / `Alerting-FR.md`: fix the wrong template-context
  reference; document the breakdown with an example body.

## T4 — operator action (not code)

- The misleading "deduplicated" line lives in the hacf rule's body
  template (operator config). Provide the corrected + enriched template
  text to paste after upgrade. Immediate zero-code fix: paste the
  dedup-line-removed template now.

## Gates

`go test -race ./internal/alerting/ ./internal/observability/`, `go vet`,
`gofmt -s`, `go build ./...`, frontend `npm run check` + i18n parity.
Reinjection proof for the two load-bearing guards (store ordering; source
Context assignment).

## Out

No API route, no stored-schema migration, no release tag without operator
go-ahead.
