<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Arenet Roadmap

> Realigned 2026-09-21 against the git tags (latest: **v2.25.1**,
> 2026-07-26). The tags stay the authoritative record of what shipped:
> `git for-each-ref --sort=creatordate --format='%(refname:short) %(subject)' refs/tags`.
> Design detail for each feature lives in `docs/superpowers/specs/`.

## Shipped

### Phase 1 — Core POC (v0.1 → v0.4)

| Tag | Step | Content |
|---|---|---|
| v0.1.0-poc | A–C | Embedded Caddy, BoltDB persistence + reload, REST API + admin UI |
| v0.2.0-step-d | D | Single-admin auth, audit log, HIBP password check, idle lock |
| v0.3.0-step-e | E | Topology + live metrics over WebSocket |
| v0.4.0-step-f | F | Design polish, custom topology, component tests |
| v0.4.1 / v0.4.2 | G, H | Frontend + backend debt cleanup |

### Phase 2 — Reverse proxy & security (v0.5 → v1.0)

| Tag | Step | Content |
|---|---|---|
| v0.5.0-step-i | I | Reverse Proxy v1.0: TLS/ACME, HTTPS redirect, aliases, WAF modes (off/detect/block), basic auth, headers |
| v0.6.0-step-j | J | Multi-upstream load balancing, health checks, DNS-01 ACME (OVH) |
| v0.7.0-step-k | K | Route auth (basic / forward-auth), admin multi-user + RBAC + OIDC, backup/restore |
| v0.8.0-step-l | L | Observability: per-route timeseries (req/s, 4xx/5xx, p95, WAF) |
| v0.9.0-step-m | M | Security dashboard |
| v1.0.0-step-q | Q | Rate-limit events + auth-failure timeline |
| v1.1.0-step-n | N | CrowdSec integration (LAPI mirror + bouncer) |
| v1.2.0-step-o | O | Wildcard certificates (managed domains) |
| v1.3.0-step-p | P | CrowdSec auto-classify loop (write-back to LAPI) |
| v1.4.0-step-r | R | OKLCH visual migration |
| **v1.0.0** | S | **First production release** (Docker multi-arch, systemd installer) |

### v1.x — Production hardening (2026-06)

- **v1.1.0** Topology v2 (live data feed + real health probe)
- **v1.2.0 / v1.3.0** Step T/U: certificate runtime refactor; cert events in the activity log
- **v1.4.0 / v1.5.0** Step V/V1: geographic threat map + normal-traffic monitoring
- **v1.5.x** WAF mode-aware labels, WebSocket bypass
- **v1.6.x** Step W: per-route country blocking (HTTPS + HTTP chains)
- **v1.7.x / v1.8.0** CrowdSec settings UI + hot-reload, live LAPI/scenarios, manual IP ban
- **v1.9.0** WAF exclusion of the management plane
- **v1.10.0** HTTPS upstreams + `insecureSkipVerify` + test-upstream endpoint
- **v1.11.0** Step AL: alerting subsystem (Discord / webhook / SMTP, threshold + state rules)

### v2.x — Feature line (2026-06 → 2026-07)

| Version | Content |
|---|---|
| **v2.0.0** | Production milestone with alerting |
| v2.1.0 | Aliases as first-class topology nodes |
| v2.2.0 – v2.3.0 | Multi-wildcard UX; OWASP CRS per-route toggle |
| v2.6.0 | Rate-limit observability + `/logs` refactor |
| v2.7.0 | Custom error pages (per-route templates, placeholders) |
| v2.8.x | Per-route WAF tag exclusion; cert renewal failure alerts; Host header preservation |
| v2.9.x | Cert stale-failure badge; graceful Caddy reload (HC tracker preserved); branded catch-all; **i18n FR/EN** of the whole UI |
| v2.10.x | Documentation + wiki in FR/EN |
| v2.11.0 | Optional email at setup |
| v2.12.x | Multiple DNS-provider configs; opt-in update checker; effective config logged at boot |
| v2.13.x | Sidebar notification panel; alerting flood fix (edge-triggered state rules); basic-auth hash cache |
| v2.14.x | MaxMind GeoIP auto-update; reverse-proxy error pages; Docker cert storage fix |
| v2.15.0 | Route enable/disable; data-dir permission hardening |
| v2.16.0 | Delete orphan certificates |
| v2.17.x – v2.18.x | 3-state route control (Active / Maintenance / Disabled); maintenance page with Retry-After, per-route message, IP bypass, auto-refresh |
| v2.19.x – v2.20.x | External certificates (bring-your-own, fullchain split) + CSR generation; JSON/API errors preserved (not branded) |
| v2.21.0 | Path-based rules (basic auth + source-IP allow/deny per prefix) + domain-wide IP filter |
| v2.22.0 | Country flags in the country-block selector |
| v2.23.x | Per-path upstream pools (with per-path skip-verify + weights) |
| v2.24.x | Path pools in the topology graph; IP-filter 403 uses the branded page |
| v2.25.x | Topology: one cluster per route with per-prefix sections + hub→section lines |

## Open backlog

Gathered from the "non-goals / backlog" sections of the shipped specs.
No ordering commitment — each item gets its own brainstorm → spec → plan cycle.

### Routing & topology
- **Per-path live traffic** (req/s + errors per path rule): per-(route, path)
  counter in `internal/metrics/middleware.go`, carried in the metrics
  snapshot, animating the existing hub→section lines (the `structural`
  edge flag goes away). *Most-cited next item.*
- Per-path forward-auth; per-path WAF / rate-limit / geo / headers
- `trusted_proxies` plumbing for XFF-based IP filtering
- Metrics dashboards: dim disabled / maintenance routes, "show disabled" filter
- Scheduled maintenance windows (auto-end)

### Certificates & DNS
- External certs: renewal workflow (reuse CSR / regenerate / new details, auto-rotate `CertID`)
- PKCS#12 / JKS import; external managed domain (wildcard external cert)
- ACME revocation on certificate delete
- ~~DNS providers: Cloudflare, Route53…; connection test~~ → in progress on
  `feature/dns-providers-multi-type` (v2.26.0: 9 types + test connection)
- Per-route DNS provider selection; DNS-01 propagation settings (resolvers, timeout)

### Security
- Threat export: CSV of malicious IPs, iptables / FortiGate rule generators
- Outbound security webhooks with HMAC signature + retry
- Other IP-reputation feeds (e.g. AbuseIPDB)
- Custom WAF rule editor
- 2FA / TOTP for admin accounts

### Operations
- Prometheus metrics export
- Update checker: prerelease opt-in, env toggle, in-app changelog
- High availability / clustering; multi-tenant isolation (long term)

### Test debt
- Remaining `.svelte` pages without component tests (e.g. `/login`, `/audit`)
