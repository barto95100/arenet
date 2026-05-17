# Arenet Roadmap

## Phase 1 — Core POC + Auth (in progress)

- ✅ Step A — Skeleton + Caddy embedded
- ✅ Step B — BoltDB persistence + Caddy reload
- ✅ Step C — REST API + Admin UI (v0.1.0-poc)
- 🚧 Step D — Local auth (single-admin) + basic audit log
- ⏳ Step D2 — Multi-users + roles (admin/editor) + advanced audit
- ⏳ Step D3 — SSO OIDC (Authentik, Authelia, Keycloak compatible)
- ⏳ Step E — Topology + live metrics (WebSocket, D3.js)

## Phase 2 — Security & Operations

### Step F — Security & Threat dashboard
- Page UI /security (currently disabled placeholder)
- Threat dashboard:
  - Currently rate-limited IPs (real-time)
  - Top N IPs by failed attempts over rolling windows (24h / 7d / 30d)
  - Timeline visualization
  - Per-IP detail: attempt count, last seen, attempted usernames
- Export & integration:
  - Export CSV of malicious IPs
  - Copy-as-iptables-rule generator
  - Copy-as-FortiGate-rule generator
- Webhook system (configurable):
  - Outbound POST on tier 2 rate limit hit
  - Configurable target URL (n8n, Make, FortiGate API, Unifi, custom scripts)
  - HMAC signature for authenticity
  - Retry policy with exponential backoff
- Optional hardening:
  - Explicit CSRF tokens (synchronizer pattern) — reconsider if threat model changes
  - GeoIP-based blocking
  - Behavioral anomaly detection

### Step G — WAF integration (Coraza)
- Coraza WAF as Caddy module
- Per-route WAF enable/disable (already in route schema)
- OWASP CRS rules
- Custom rule editor

### Step H — IP reputation
- CrowdSec bouncer integration
- AbuseIPDB lookup
- Automatic block list ingestion

## Phase 3 — Advanced features (TBD)

- Multi-tenant / multi-domain isolation
- High availability / clustering
- Prometheus metrics export
- Backup/restore tooling
- API tokens (Bearer auth) for CI/Ansible integrations
- 2FA / TOTP for admin accounts

## Notes

- Phases are indicative, not strict. Step ordering may shift based on real-world usage feedback.
- Step D scope is deliberately minimal to enable real-world deployment quickly. Multi-user, SSO, and advanced security features come after Arenet is in production use.
