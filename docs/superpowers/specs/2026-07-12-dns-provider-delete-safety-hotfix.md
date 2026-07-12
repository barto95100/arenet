# DNS provider save-safety hotfix (v2.12.2)

**Date**: 2026-07-12
**Status**: Design approved (Option 2), pending implementation
**Type**: Bug hotfix (patch). Ship on main → tag v2.12.2.

## Symptom (beta-tester report)

An operator's route configured for DNS-01 silently ends up served by a
self-signed cert (Caddy internal CA), with **no error and no log**. The
route's stored `acmeChallenge` still reads `dns-01`, but the emitted
Caddy config drops it from every ACME policy.

## Root cause (empirically confirmed 2026-07-12)

Two distinct defects, plus a broader class discovered during the audit.

### Bug #1 — DNS provider handlers never reload Caddy
`internal/api/dns_provider.go` — **none** of `createDNSProvider` (:190),
`updateDNSProvider` (:224), `deleteDNSProvider` (:276) call
`h.caddy.ReloadFromStore`. Every other mutating settings handler does
(managed_domain.go:236, forward_auth_provider.go:266/338,
error_templates.go, backup_handlers.go). Consequences:
- **delete**: removing the provider leaves the live Caddy config
  referencing it; the storage change (0 providers) is not reflected
  until the *next* unrelated reload — at which point per-route DNS-01
  hosts become provider-less.
- **update**: fixing OVH credentials does not take effect in Caddy until
  some other event forces a reload — the operator's correction is
  silently ignored in the running config.
- **create**: less impactful (a route can't be dns-01 without a provider
  due to the edit-time 400), but for consistency it should reload too.

### Bug #2 — silent DNS-01 fallback in the config generator
`internal/caddymgr/manager.go:2185-2189` (`buildTLSPolicies`):
```go
if len(partition.DNS01) > 0 {
    if prov, ok := defaultDNSProvider(opts.DNSProviders); ok {
        policies = append(policies, buildACMEPolicy(partition.DNS01, opts, &prov))
    }
    // no else → DNS-01 hosts silently dropped; fall through to the
    // internal catch-all (self-signed), no log, no warning.
}
```

### Reproduction (verified against the real binary + live Caddy :2019)
1. Configure an OVH provider; create route `*.new.com` dns-01 → Caddy emits DNS-01. ✅
2. Delete the provider (HTTP 204) → **no reload**; config stays DNS-01 (stale).
3. Any next reload (e.g. create another route) → `*.new.com` **absent from all ACME policies** → served by internal catch-all (self-signed). Storage still says `dns-01`. No log, no warning. 🐛

### Not bugs (tested, healthy — do not touch)
- Create route dns-01 without a wildcard → correct DNS-01.
- Wildcard created afterwards → route becomes `inherited`, served by the wildcard policy.
- dns-01 at route create/edit with no provider → **400** (validation already exists).

## Fix (Option 2 — reload + warning + delete-guard)

### Fix #1 — reload Caddy in all three DNS provider handlers
Add `h.caddy.ReloadFromStore(r.Context())` after the storage write in
`createDNSProvider`, `updateDNSProvider`, `deleteDNSProvider`, mirroring
`forward_auth_provider.go`. On reload error: log + return 500 (the
storage mutation already committed — same posture as the other handlers;
a full rollback is out of scope for this hotfix and matches how
forward-auth behaves).

### Fix #2 — make the fallback loud
In `buildTLSPolicies` (manager.go:2185), when `partition.DNS01` is
non-empty but `defaultDNSProvider` returns `ok == false`, emit
`slog.Warn` naming the orphaned hosts (so the drop is visible in the
journal) before falling through. Defense-in-depth: with Fix #3 the
delete path can no longer create this state, but import/manual-DB paths
still can. Keep it a Warn (not an error) — the host still gets a
self-signed cert, so the data plane stays up.

### Fix #3 — block provider delete while routes depend on it (409)
In `deleteDNSProvider`, before deleting, also check routes (not just
managed domains): list routes, collect those with
`acmeChallenge == "dns-01"`. Since per-route DNS-01 has no per-route
providerId (it uses the single default provider), ANY dns-01 route
depends on the provider collection; deleting the last/only provider
orphans them. Rule:
- If deleting this provider would leave the dns-01 routes with **no
  configured provider remaining**, return **409** with
  `{code: "provider_in_use_by_routes", params: {routes: [hosts...]}}`.
- Precise predicate: block iff `ListDNSProviders (minus this one)` has
  zero `configured` providers AND at least one route has
  `acmeChallenge == "dns-01"`. (Deleting a spare provider while another
  configured one remains is safe — the default just shifts.)
- The existing managed-domain 409 (`provider_in_use`) stays as-is; a
  provider can be blocked by wildcards, routes, or both.

### Fix #4 — frontend: translate the new 409
`DNSProvidersSection.svelte` delete handler: handle
`code === "provider_in_use_by_routes"` → toast from
`t('settings.dnsProviders.delete.error409Routes', { routes })`. Add the
key to en.json + fr.json (parity guard from v2.12.1 enforces both).

## Empirical validation gates
- Bug #1 delete: create provider + dns-01 route → delete provider → **409** (Fix #3 blocks it). Then remove the dns-01 route → delete → 204 → live Caddy no longer references the provider (Fix #1 reload).
- Bug #1 update: change provider endpoint → GET Caddy /config/ reflects the new endpoint immediately (Fix #1 reload).
- Bug #2: force the orphan state via a path Fix #3 doesn't guard (e.g. two providers, a dns-01 route, delete one then the other is impossible via API — so test buildTLSPolicies directly at unit level with an empty provider map + a DNS01 partition → assert the Warn fires and no ACME policy is emitted for those hosts).
- Non-regression: delete a spare provider while another configured one remains + a dns-01 route exists → **204** (not over-blocked). Managed-domain 409 still works. i18n parity test passes.

## Scope
- Backend: dns_provider.go (3 reloads + delete route-guard), manager.go (1 Warn). ~40 lines + tests.
- Frontend: DNSProvidersSection.svelte (1 branch) + 2 i18n keys. ~15 lines + test.
- Workflow: direct in-session (small, ~1-2h), TDD + empirical smoke. Ship on main → tag v2.12.2.

## Out of scope / backlog
- Full transactional rollback on reload failure in DNS provider handlers (forward-auth doesn't do it either; consistency-first).
- Per-route providerId selection (routes use the default provider; managed domains are the per-account surface).
