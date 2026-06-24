# Arenet Wiki

Welcome. This wiki is the **how-to** companion to the [README](https://github.com/barto95100/arenet/blob/main/README.md) — task-oriented guides for every feature, written for the operator running Arenet on their homelab.

If you're new : start with [Installation](Installation), then follow [Routes](Routes) to get your first proxied host live. Everything else is feature-by-feature reference.

---

## Quick navigation

### Get started
- **[Installation](Installation)** — Docker, native systemd, first-boot wizard
- **[Routes](Routes)** — your first reverse proxy route, TLS, upstreams, aliases
- **[Topology](Topology)** — live dashboard with real-time traffic visualization

### Security stack
- **[WAF](WAF)** — Coraza + OWASP CRS, per-route opt-out, rule/tag exclusion
- **[CrowdSec](CrowdSec)** — community IP reputation, LAPI bouncer setup
- **[Country Block](Country-Block)** — GeoIP-based allow/deny lists per route
- **[Rate Limit](Rate-Limit)** — events/window throttling per route
- **[OIDC SSO](OIDC-SSO)** — authentik / Keycloak / Authelia integration + RBAC

### Operations
- **[Backup & Restore](Backup-Restore)** — full config export, sentinel-resolution import, disaster recovery
- **[Alerting](Alerting)** — channels, threshold + state rules, Discord/email/webhook
- **[Custom Error Pages](Custom-Error-Pages)** — per-route HTML templates with Caddy placeholders
- **[Troubleshooting](Troubleshooting)** — symptoms diagnostic, common pitfalls, log decoding

---

## What is Arenet ?

Arenet is a **single-binary reverse proxy** that combines [Caddy v2](https://caddyserver.com) (the HTTP engine, auto-HTTPS + HTTP/3 + ACME) with :

- An **admin UI** to configure routes, certificates, security settings
- An **integrated security stack** : WAF (Coraza + OWASP CRS), IP reputation (CrowdSec), country blocking, rate limiting
- A **live observability surface** : topology dashboard with real-time particles, per-route metrics, unified activity log, audit trail
- A **native alerting subsystem** with multi-channel routing (Discord, email, webhook)
- **Backup/restore** of the entire config via UI

All as **one Go binary** (~100 MB) backed by BoltDB + SQLite — no sidecars, no external dependencies beyond the operator's own infra (DNS, optional CrowdSec instance, optional SMTP server, optional IdP).

## Who is it for ?

Designed for the operator running **5 to 50 routes on a single host** (homelab, small business, freelance). Not designed for multi-tenant cloud deployments, not designed for k8s ingress controller scenarios. If you want production posture without production complexity, Arenet is the target audience.

## How is this wiki organized ?

- **Get-started pages** are tutorials with copy-paste commands you can follow top-to-bottom.
- **Feature pages** explain a single capability in depth : what it does, when to use it, how to configure it, common pitfalls.
- **Operations pages** cover lifecycle tasks (backup, recovery, alerting wiring).
- Every page ends with a "**See also**" linking related topics and the relevant files in the `docs/` folder of the main repo (for operators who want to dig into the architecture).

If you find a gap or want to contribute a page, [open an issue](https://github.com/barto95100/arenet/issues).

## Version coverage

This wiki tracks **Arenet v2.9.x** (the current stable release line). Older versions may differ in feature surface ; check the [release notes](https://github.com/barto95100/arenet/releases) when in doubt.

## Where things live (cheat sheet)

| Concept | UI path | API path | Storage |
| ------- | ------- | -------- | ------- |
| Routes | `/routes` | `/api/v1/routes` | BoltDB `routes` bucket |
| Certificates | `/certs` | `/api/v1/certificates` | Caddy storage + cert tracker |
| WAF events | `/security` | `/api/v1/security/events` | SQLite `waf_event` table |
| Cert events | `/logs` (CERT badge) | `/api/v1/observability/cert-events` | SQLite `cert_event` table |
| Audit log | `/audit` | `/api/v1/audit/events` | BoltDB `audit` bucket |
| Alerting rules | `/alerting` (Rules tab) | `/api/v1/alerting/rules` | BoltDB `alert_rules` bucket |
| OIDC config | `/settings` | `/api/v1/settings/oidc` | BoltDB `oidc_config` key |
| Users | `/users` | `/api/v1/users` | BoltDB `users` bucket |
| Backup snapshot | `/settings` (Backup section) | `/api/v1/admin/backup` + `/admin/restore` | All buckets serialized to JSON |

Default admin port : `:8001` (loopback by default ; set `ARENET_ADMIN_BIND=0.0.0.0:8001` for LAN access).
