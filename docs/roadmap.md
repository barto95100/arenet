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

### Test coverage debt (carried from Step D)

- **Svelte component tests deferred to Phase 2**. Step D Chunk 6
  shipped `/login`, `/setup`, `/audit` pages and the Sidebar
  modification WITHOUT unit tests for the `.svelte` components.
  Tests for `.svelte.ts` stores and `.ts` API clients ARE present
  (~55 Vitest tests, ≥86% coverage on lib/api + lib/stores).
- **Why deferred**: testing `.svelte` components needs
  `@testing-library/svelte` (or `@vitest/browser`) + jsdom DOM
  cleanup setup + render helpers. Non-trivial scaffold for the
  small surface introduced in Step D pages.
- **Phase 2 action**: install `@testing-library/svelte` +
  `@testing-library/jest-dom`, add tests for:
  - `/login/+page.svelte`: form validation, 401 inline error
    mapping, rememberMe state, redirect on success.
  - `/setup/+page.svelte`: error-message heuristic mapping
    (username / password / displayName), 403 token error, 404
    "admin exists" surface.
  - `/audit/+page.svelte`: filter debounce, "Load more" cursor
    pagination, empty/error states.
  - `LockScreen.svelte`, `ChangePasswordModal.svelte` (Chunk 7).
  - `Sidebar.svelte`: 5-item list, active-state highlighting,
    disabled-state ARIA.
- **Manual test coverage during Step D**: each chunk validated
  via `npm run build` + manual interaction in `npm run dev`.

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
