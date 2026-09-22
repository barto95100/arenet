<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — Caddyfile import (v2.40.0)

Date: 2026-09-22. Real binary (macOS, `--dev`, HTTP :8080), Python HTTP
server on 127.0.0.1:9912 as the backend. A route for `apps.localhost`
was created first (WAF block) to exercise the conflict path.

Caddyfile used: global options block, a snippet with `log`, a site with
two addresses + `reverse_proxy` (lb_policy, health_uri, header_up) +
`header` + `encode`, an `http://` site with `basic_auth`, a site with
`handle_path` + site-wide `reverse_proxy` + `tls { dns ovh }` +
`php_fastcgi`, and a site with only `respond`.

## Preview (writes nothing)

| Block | Expected | Observed |
|---|---|---|
| global options | reported | "global options block ignored…" |
| snippet `(logging)` | expanded by Caddy, no noise | no warning |
| `home.localhost, www.home.localhost` | importable, alias, TLS | importable, alias `www.home.localhost`, no warning |
| `http://legacy.localhost` | importable, TLS off, basic auth reported | importable, TLS off, 1 warning (line 24, basic auth) |
| `apps.localhost` | importable, conflict, path rule, DNS-01 | conflict true, path rule `/files`, `acmeChallenge=dns-01`, warnings: DNS provider (line 34), `php_fastcgi` (line 37) |
| `nothing.localhost` | not importable | `importable=false`, reason "no reverse_proxy in this block", `respond` reported |
| routes in storage | unchanged | unchanged, no Caddy reload |

## Import

| Step | Expected | Observed |
|---|---|---|
| import the 4 hosts | 2 created, 2 skipped | created `home.localhost`, `legacy.localhost`; skipped `apps.localhost` ("a route already serves this host") and `nothing.localhost` (its reason) |
| traffic `home.localhost`, `www.home.localhost` | served (TLS route → redirect) | 301 |
| traffic `legacy.localhost` | served over HTTP | 200 (backend) |
| import `apps.localhost` with `replace` | replaced | replaced, route now points at 127.0.0.1:9912, `wafMode=detect`, `acme=dns-01`, path rule `/files` |
| stored values | as previewed | health check enabled on `home.localhost`, `X-Forwarded-Host` request header, TLS flags per block |

**Finding (fixed before the PR):** `tls { dns ovh }` produced a spurious
"tls option \"ovh\" not imported" — the provider name and its block were
read as further tls options. The provider is now named in the warning
("configure the ovh provider…"), its arguments are consumed, and a real
unsupported option (`resolvers`) is still reported.
`TestParse_DNSProviderArgumentsConsumed` pins it.

Unit coverage: every mapping of the table, warning lines, multi-address
blocks, unix / placeholder upstreams, port-only blocks, invalid
Caddyfile. API: preview writes nothing, import creates only what was
asked, conflict skipped / replaced, rollback when Caddy refuses, audit.
UI: modal (analyse, preselection, conflict, replace, import, errors) and
the Routes page button.

Verdict: **pass**.
