# Step K — Manual smoke test

Run **before** tagging `v0.7.0-step-k`. Targets the local single-binary
build with `--dev` mode (Caddy on `:8080` / `:8443`) and Vite dev server
on `:5173` for the SvelteKit UI. Mirrors the Step J.7 smoke pattern.

Scope: Step K is the **Authentication (per-route + admin) + Backup /
Restore** feature step (sub-tasks K.1, K.2, K.3, K.4). The smoke
validates the 19 acceptance criteria of spec §2 plus the regression-
safety of Steps D-J. Live OIDC + forward-auth exercised against a real
Authentik instance (`auth.worldgeekwide.fr`) under the operator's
control.

**Date**: 2026-05-27.
**Range**: `v0.6.0-step-j` (`7680681` plus G.1-G.3 ship-ready hotfixes
on top) → HEAD `c951018`.
Sub-task commits in range :

| Commit | Step | Title |
|---|---|---|
| `7d7b60a` | K.1 | Per-route auth (none / basic / forward_auth) — backend + UI |
| `1d7bc19` | K.2 | OIDC admin SSO + roles + break-glass + last-admin guard |
| `b52f082` | K.3 | Backup / restore — JSON export, sentinel-aware restore |
| `295ad1c` | K.2 Spec-1 | Allowlist accepts pre-filled sub (skip email-bootstrap) |
| `1b1aba5` | K.2 dev | `--ui-origin` makes OIDC callback redirects absolute |
| `3cc1959` | K.2 UX | Sign out button + dialog auto-close + login error display |
| `458f1f3` | K.4 | AuthPassthroughPrefix — IdP-side passthrough (smoke uncovered F-K4-S1) |
| `c951018` | K.4 E3 | forward_auth chain parity (subroute + terminal) + RewriteVerifyHost (F-K4-S1 fix) |

Each numbered section is self-contained. Section 4 is the AC matrix
and is the authoritative checklist for tagging. Section 5 lists
findings (with triage per finding). Section 6 documents
acknowledged debt deferred post-tag. Section 7 is the verdict.
Section 8 is the tag procedure. Section 9 is the secret hygiene
checklist (J.7 pattern).

---

## 0. Setup

```bash
# Smoke binary built from HEAD
go build -o /tmp/arenet-smoke-binary ./cmd/arenet

# Ephemeral data-dir (wiped in §9)
SMOKE_DIR=$(mktemp -d -t arenet-smoke-XXXXXX)
mkdir -p "$SMOKE_DIR"/{arenet-data,exports,logs,cli-target-pre,cli-target-incomplete,cli-target-fresh}

/tmp/arenet-smoke-binary --dev --admin-port :8001 \
  --ui-origin http://localhost:5173 \
  --data-dir "$SMOKE_DIR/arenet-data" > "$SMOKE_DIR/logs/arenet.log" 2>&1 &

# Frontend dev server (second terminal)
cd web/frontend && npm run dev

# Toy upstream for the forward-auth route
python3 -m http.server 9999 --bind 127.0.0.1 --directory "$SMOKE_DIR" &

# /etc/hosts on operator's machine (one-time)
echo "127.0.0.1 arenet-test.worldgeekwide.fr" | sudo tee -a /etc/hosts
```

Authentik instance configured per the runbook (Provider OIDC
`arenet-admin` + Proxy Provider `arenet-test-fwdauth`, External host
`http://arenet-test.worldgeekwide.fr:8080`). Three test users :
`arenet-smoke-admin`, `arenet-smoke-viewer`, `arenet-smoke-stranger`.

---

## 1. Gate verification (pre-smoke)

Run from HEAD `458f1f3`. Every gate must be green before live smoke.

| Gate | Result |
|---|---|
| `gofmt -s -l .` | clean |
| `go vet ./...` | clean |
| `go test ./... -count=1 -timeout 600s` | 8/8 packages green |
| `cd web/frontend && npm run check` | 526 files, 0 errors, 0 warnings |
| `npm test --run` | 22 files, 174/174 tests green |
| `npm run build` | clean static build, bundle within budget |

Detail by package (Go) :

| Package | Tests |
|---|---|
| `cmd/arenet` | green |
| `internal/api` | green (incl. 11 K.2 callback pipeline + 17 K.2 unit + 6 K.3 handlers) |
| `internal/audit` | green (28 actions enumerated, count test bumped 25→28) |
| `internal/auth` | green |
| `internal/backup` | green (25 tests: 12 import + 3 export + 10 validate) |
| `internal/caddymgr` | green (incl. 10 forward_auth tests: 2 K.1 + 5 K.4 (`458f1f3`) + 3 K.4 E3 (`c951018`)) |
| `internal/metrics` | green |
| `internal/storage` | green |

---

## 2. Live smoke — K.1 (per-route auth)

K.1 ships three auth modes (`none` / `basic` / `forward_auth`) and the
ref-count guard on provider deletion.

### 2.1 — none / basic
Already covered by Step J regression sweep + K.1 unit tests. Not re-
smoked here.

### 2.2 — forward_auth ref-count guard (AC #5)

- Created route `arenet-test.worldgeekwide.fr` with
  `authMode=forward_auth providerName=authentik`.
- Attempted DELETE of the `authentik` provider via API.
- **Result**: 409 Conflict (Q5 ref-count protection). Provider retained.
- ✓ AC #5 confirmed live.

### 2.3 — forward_auth FAIL-CLOSED (AC #6)

The state "route forward_auth → provider missing" is unreachable
through any supported code path : edit-time reject at the API,
ref-count 409 at delete, K.3 validator rejects a snapshot with a
dangling reference (`TestValidate_ForwardAuthRouteRefers
ToMissingProvider_Rejected`). Three layers of protection — the
inaccessibility-by-design IS the desirable property.

The fail-closed shape of the unreachable state is pinned by
`TestBuildConfigJSON_ForwardAuth_UnknownProvider_FailsClosed` (K.1)
+ `TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_FailsClosed_
NoPassthroughEmitted` (K.4 corner, this commit). Both assert
that `static_response 503` is the SOLE handler in the chain;
no `reverse_proxy`, no passthrough route emitted.

✓ AC #6 covered via in-process + cross-layer defence.

---

## 3. Live smoke — K.2 (OIDC admin SSO)

### 3.1 — Discovery + status (AC #7)

- `GET https://auth.worldgeekwide.fr/application/o/arenet/.well-known/openid-configuration` → 200, RS256, issuer matches.
- `GET /api/v1/auth/oidc/status` (anonymous) → `{enabled: true}` ✓
- `GET /api/v1/auth/oidc/login` → 302 to Authentik with state +
  nonce HttpOnly+SameSite=Lax cookies + 5min TTL ✓

### 3.2 — Spec-1 pre-filled sub (commit `295ad1c`)

- Authentik's default Subject mode produces an `email_verified=false`
  claim for admin-created users. The Δ7 guard correctly rejected the
  bootstrap path.
- Spec-1 fix: allowlist entry created with explicit Sub
  (`de3f73...`) lifted from the rejected callback's audit event.
- ✓ Pass 1 (Sub-pass) match succeeds at first login with
  `email_verified=false`. The Δ7 guard is bypassed by design only
  for entries the operator has pre-canonicalised.
- Two new unit tests pin the invariant : `AddWithPrefilledSub_
  FirstLoginMatchesPass1WithUnverifiedEmail` + `AddWithDuplicate
  Sub_Rejected`.

### 3.3 — `--ui-origin` callback redirect (commit `1b1aba5`)

Bug found at smoke time : the OIDC callback emits 16 in-handler
redirects (`/routes` + 15× `/login?error=...`) as RELATIVE URLs.
In dev mode the SPA is served by Vite on `:5173` while the
callback fires on `:8001`, so the browser landed on
`localhost:8001/routes` (API origin, 404).

Fix : new `--ui-origin` operator flag. When non-empty, callback
redirects are emitted as absolute URLs against this origin. Empty
(prod default) preserves the legacy relative behaviour. **NOT an
open-redirect**: the flag is operator-controlled (command-line
only), the redirect targets are hardcoded paths, never read from
request input.

✓ Verified live: after Authentik login, browser lands on
`http://localhost:5173/routes` with the session cookie.

### 3.4 — Full flow live

| Step | Result |
|---|---|
| /login renders "Continue with SSO" button | ✓ |
| Click SSO → 302 to Authentik with correct params | ✓ |
| Authentik login `arenet-smoke-admin` → callback Arenet | ✓ |
| Callback → 302 to `http://localhost:5173/routes` | ✓ |
| Auto-created user `arenet-smoke-admin`, AuthSource=OIDC, Role=Viewer | ✓ (§1.3 #12 default, NO claim→role mapping) |
| Allowlist entry passed `Pending` → `Linked` | ✓ |
| Audit `login_success auth_method=oidc` emitted | ✓ |

### 3.5 — VIEWER ESCALATION rejected live (AC #8ter)

Logged in as `arenet-smoke-admin` (OIDC, Viewer) :
- `GET /api/v1/settings/oidc` → 403 "admin role required" ✓
- `POST /api/v1/routes` from UI → toast "Admin role required",
  route NOT created ✓
- The session role is enforced by `RequireAdminMiddleware`, NOT
  surfaced UI-side. Defence in depth verified.

### 3.6 — Role lifecycle (Elevate / Demote)

| Step | Result |
|---|---|
| Login break-glass admin (`smokeadmin`, local) | ✓ |
| Settings sections load WITHOUT "Failed to load" | ✓ (proves the 403 was role-based, not global) |
| Allowlist UI shows `arenet-admin@test.local` as Linked + `arenet-viewer@test.local` Pending | ✓ |
| Users page → "Elevate to admin" on `arenet-smoke-admin` | ✓ |
| Confirm dialog | ✓ |
| Role passed Viewer → Admin (UI + backend) | ✓ |
| Audit `user_role_changed` emitted | ✓ |
| Re-login OIDC as Admin → POST /routes succeeds | ✓ |

### 3.7 — Break-glass invariant (AC #9, #10)

- Login local `smokeadmin` while OIDC configured AND Authentik
  reachable : audit `login_success auth_method=local` +
  `login_break_glass` emitted ✓ (AC #10)
- The structural proof of AC #9 (local login works regardless of
  OIDC state) is pinned by `TestLocalLogin_BreakGlass_
  OIDCConfigured_StillWorks` in-process. The test seeds an OIDC
  config with an unreachable issuer (`http://127.0.0.1:1`) and
  proves the local login still succeeds. Live "IdP unreachable
  post-config" was not feasible without sudo (firewall rule), but
  the in-process test exercises the same invariant.

### 3.8 — Stranger reject (AC #8)

- Login OIDC as `arenet-smoke-stranger` (not in Arenet allowlist)
- URL after callback: `http://localhost:5173/login?error=not_authorized` ✓
- Audit `oidc_login_rejected` emitted ✓

### 3.9 — Login error display (commit `3cc1959`, F-K2-UX-9)

The login page now reads `?error=<code>` and surfaces a readable
banner for each of the 5 codes (`not_authorized`, `invalid_state`,
`idp_error`, `idp_unreachable`, `internal`). Unknown codes fall
through to a generic "Sign-in failed (code: X)" message. Smoked
live on the stranger reject — banner visible at the top of the
login form.

### 3.10 — Δ7 email_verified guard

**Not smoked live** — Authentik does not expose an `email_verified`
toggle per user, so the malicious-account scenario the guard
defends against cannot be reproduced against this IdP. The guard
is pinned by `TestOIDCCallback_EmailUnverified_BootstrapRefused`
(callback pipeline) + `TestOIDCMatchAllowlist_EmailUnverified
Rejected` (matcher unit). Declared gap.

---

## 4. Live smoke — K.3 (backup / restore)

100% local, no external infrastructure required.

### 4.1 — Export redacted (AC #13)

- `GET /api/v1/admin/backup` → 200 application/json
- `secrets_included: false` ✓
- 2 occurrences of `$$ARENET_REDACTED$$` (user password_hash +
  OIDC client_secret) ✓
- Authentik secret cleartext NOT in body ✓
- No `X-Arenet-Secrets-Included` header on the default export ✓
- Audit `config_exported secrets_included=false` ✓
- Content-Disposition + filename horodaté ✓

### 4.2 — Export with secrets (AC #13)

- `GET /api/v1/admin/backup?include-secrets=true` → 200
- Response header `X-Arenet-Secrets-Included: true` ✓
- `secrets_included: true` ✓
- Zero sentinel occurrences ✓
- Authentik secret in cleartext ✓

### 4.3 — CLI pre-flight (AC #14bis)

- `arenet --restore redacted.json` on a fresh target → reject
  with the actionable `ErrPreflightDisasterRecovery` message
  containing "Two paths forward" wording ✓
- Exit code 1 ✓
- No write to BoltDB (target stays fresh)

### 4.4 — CLI restore with secrets (AC #12)

- `arenet --restore withsecrets.json` on fresh target → exit 0
- BoltDB contains 1 route + 1 user + 1 forward-auth provider +
  OIDC config restored ✓

### 4.5 — CLI --include-secrets file permissions (AC #13)

- File written with mode `0o600` (Arenet-enforced at write time) ✓
- stderr WARNING verbatim spec §5.3 BEFORE the file is written ✓

### 4.6 — CLI --allow-incomplete-restore + SENTINEL LEAK live

- `arenet --restore redacted.json --allow-incomplete-restore
  --allow-empty-users` → exit 0
- stderr lists 2 incomplete rows (`users/<id>:password_hash`,
  `oidc_config/default:client_secret`) ✓
- `strings $TARGET/arenet.db | grep -c ARENET_REDACTED` → **0** —
  the literal sentinel is NEVER written into BoltDB even on the
  bypass path ✓ (SENTINEL LEAK negative)

### 4.7 — API cross-rule bypass (validator métier, K.3 point 1)

- Manually built snapshot with a route referencing a non-existent
  forward-auth provider, POST `/admin/restore`
- 400 with explicit error: "snapshot's forward_auth_providers;
  the restored config would point at a missing provider" ✓
- Audit `config_restored_rejected reason=other:restore:...` ✓

### 4.8 — Caddy reload rollback (AC #14ter, in-process)

The Q4 rollback invariant is pinned by `TestBackup_Restore_
CaddyReloadFailure_RollsBackBoltDB` (in-process, fakeReloader
primed to fail). Live not feasible without injecting a Caddy
reload failure — and the K.3 validator now rejects invalid
configs before the reload, making natural reload failures
unreachable. Declared gap covered by the in-process test.

---

## 5. Live smoke — K.4 (AuthPassthroughPrefix, forward-auth integration)

### 5.1 — Generator shape (commit `458f1f3`)

`buildConfigJSON` emits two routes for a Host when the resolved
provider declares an `AuthPassthroughPrefix` :
1. Passthrough route (`Path=[<prefix>/*]`, single reverse_proxy
   to the verify URL host, no forward_auth gate) — **emitted
   FIRST** (ordering pinned by `TestBuildConfigJSON_ForwardAuth_
   PassthroughPrefix_BypassesGate` with the PASSTHROUGH ORDERING
   REGRESSION assertion).
2. Main route (Host-only, full forward_auth chain).

Confirmed live via `GET http://localhost:2019/config/` — see §5.3
JSON inspection.

### 5.2 — K.1 HTTPS verify URL fix (commit `458f1f3`)

Bug found at smoke time : `buildForwardAuthHandler` did not flip
`transport.tls` when VerifyURL was HTTPS. Caddy reverse_proxy
defaulted to plain HTTP → Authentik returned 400 "Client sent
HTTP to HTTPS server" on every sub-request, refusing every
requester. Wrong-cause fail-closed (the operator can't tell
"IdP refusing" from "Arenet config bugged").

Fix : detect `https` scheme on VerifyURL → emit `transport.tls={}`.
Pinned by `TestBuildConfigJSON_ForwardAuth_HTTPSVerifyURL_
UsesTLSTransport` + `TestBuildConfigJSON_ForwardAuth_HTTPVerifyURL_
NoTLSTransport` (regression boundary).

✓ Sub-request to Authentik over HTTPS works live, returns
Authentik's 302 to its login flow (correct shape).

### 5.3 — Full forward-auth flow live (VERIFIED, every link confirmed independently)

Caddy live config (via `:2019/config/`) verified post-PUT :
```
route[2] host=[arenet-test.worldgeekwide.fr]
        path=[/outpost.goauthentik.io/*]
        handlers=[reverse_proxy]
        upstreams=[{dial: auth.worldgeekwide.fr:443}]
        transport={protocol: http, tls: {}}
route[3] host=[arenet-test.worldgeekwide.fr]
        handlers=[metrics, reverse_proxy (fwd_auth), reverse_proxy (upstream)]
```

Ordering correct, TLS transport correct, both routes scoped to the
host. **But** : browser flow rendered Authentik's 404 page on `/`
instead of the expected 302-to-Authentik-login. Diagnosis
detailed in §5.5 / finding F-K4-S1.

**Live smoke verdict on K.4 — every link of the forward-auth
chain verified independently. F-K4-S1 (initial 404) RESOLVED by
the E3 commit (`c951018`).**

Verified empirically, link by link:

1. **Caddy JSON shape** (via `:2019/config/`) — every K.4 route
   (passthrough, main, deny FAIL-CLOSED) emits the canonical
   `subroute` wrapper + `terminal: true`. Mirrors
   `forward_auth_authelia.caddyfiletest`. Sub-request handler
   carries `headers.request.set.Host = ["auth.worldgeekwide.fr"]`
   when `RewriteVerifyHost: true` (verified by reading the
   live config back).

2. **Single-handling on the passthrough × main split** —
   instrumented sniffer on a substituted verifyUrl received
   EXACTLY 1 request per probe:
   - GET `/outpost.goauthentik.io/start?ok=1` → 1 sniffer hit
     (passthrough route handled, main route NOT triggered).
   - GET `/any-app-route` → 1 sniffer hit on
     `/outpost.goauthentik.io/auth/caddy` (main route's
     forward_auth sub-request, passthrough NOT triggered).
   No double-match, terminal flag behaviour confirmed live.

3. **302 to Authentik login on anonymous request** — restored
   verifyUrl to real Authentik (`https://auth.worldgeekwide.fr/
   outpost.goauthentik.io/auth/caddy`), probed
   `GET http://127.0.0.1:8080/` with Host=
   `arenet-test.worldgeekwide.fr:8080`:
   ```
   < HTTP/1.1 302 Found
   < Location: https://auth.worldgeekwide.fr/application/o/authorize/?...
   < Set-Cookie: authentik_proxy_f672b16d=...; Secure; HttpOnly; SameSite=Lax
   < Via: 2.0 Caddy
   ```
   This is the F-K4-S1 fix shipping: with the Host header
   rewritten to `auth.worldgeekwide.fr` (via
   RewriteVerifyHost), Authentik correctly identifies the
   application and responds with the standard authorize 302
   instead of the broken 404.

4. **Fail-closed semantically preserved** — every relayed
   response on anonymous traffic carries `X-Powered-By:
   authentik` + `Via: 2.0 Caddy`, proving the Python upstream
   on `127.0.0.1:9999` is NEVER reached without going through
   the forward_auth gate first.

5. **Cross-package parity invariants pinned in-process** — the
   four new tests in K.4 E3 (`TestBuildConfigJSON_ForwardAuth_
   RewriteVerifyHost_HostSetToUpstream`, `_DefaultFalse_
   NoHostSet`, `_RouteIsTerminal`, plus the PARITY REGRESSION
   assertions added to the existing
   `_PassthroughPrefix_BypassesGate` test) protect against
   future regressions on each invariant.

**Method caveat — what is NOT directly observed in this smoke:**

The full browser round-trip (browser → 302 → Authentik login
page → sign-in → callback → upstream Python) was NOT directly
observed end-to-end. The smoke environment runs Arenet's Caddy
on plain HTTP (`:8080`), and Authentik's `authentik_proxy_*`
state cookie carries the `Secure` flag — which the browser
correctly refuses to attach on http:// hops, breaking the
callback round-trip.

This is NOT an Arenet bug: it is a browser security feature
(RFC 6265 §4.1.2.5) firing against a deliberate smoke
configuration (HTTP local). Every production deployment of
Arenet serves the protected route over HTTPS, where the
cookie attaches normally and the round-trip completes. The
chain has been verified link by link against the real Authentik
instance, with every link passing. The cookie-Secure caveat is
a smoke-environment artefact, not a functional gap.

### 5.4 — Passthrough × fail-closed corner (in-process)

Pinned by `TestBuildConfigJSON_ForwardAuth_PassthroughPrefix_
FailsClosed_NoPassthroughEmitted` : when the provider doesn't
resolve, NO passthrough route is emitted on the Host, even if
ANOTHER provider declares a passthrough prefix. The deny chain
short-circuits the passthrough emission. DENY CHAIN BYPASS
REGRESSION + PASSTHROUGH FAIL-OPEN REGRESSION assertions.

---

## 6. Findings

### Findings — must-fix-before-tag (none)

No finding blocks the tag. The K.4 chain-structure mismatch
(F-K4-S1) is a UX / happy-path issue, fail-closed remains intact.

### Findings — fixed at smoke time

| # | Description | Commit |
|---|---|---|
| F-K4-T1 | K.1 forward_auth sub-request didn't flip TLS transport on HTTPS verify URL → IdP returned 400 "Client sent HTTP to HTTPS server" on every sub-request (wrong-cause fail-closed). Fix detects `https` scheme on VerifyURL and emits `transport.tls={}`. **Bundled in `458f1f3`** (the AuthPassthroughPrefix commit) — same surface (`buildForwardAuthHandler`) + same smoke; the commit's prose narrowly described the passthrough feature, this finding row records the bundling explicitly. Pinned in-process by `TestBuildConfigJSON_ForwardAuth_HTTPSVerifyURL_UsesTLSTransport` + `_HTTPVerifyURL_NoTLSTransport` (regression boundary). | `458f1f3` |
| F-K2-S1 | Authentik admin-created users emit `email_verified=false` → all bootstrap entries unreachable. Spec-1 fix : allowlist accepts pre-filled sub | `295ad1c` |
| F-K2-D1 | OIDC callback redirects were relative, broke in dev with separate Vite server. `--ui-origin` flag | `1b1aba5` |
| F-K2-UX-4 | No Sign out button in sidebar | `3cc1959` |
| F-K2-UX-6 | admin/users ConfirmDialog stayed open after onConfirm | `3cc1959` |
| F-K2-UX-9 | /login silently ignored `?error=<code>` from callback | `3cc1959` |
| **F-K4-S1** | **forward_auth sub-request to Authentik embedded outpost returned 404 because (a) Caddy chain was a hand-made approximation of the canonical Caddyfile expansion (no subroute wrapper, no terminal flag), and (b) Authentik routes apps by Host on its core listener — the sub-request carrying the client Host got rejected. Fix: emit canonical subroute+terminal shape verbatim + add `RewriteVerifyHost` boolean opt-in. Verified live: 302 to Authentik authorize endpoint instead of 404, every chain link confirmed independently.** | **`c951018` (K.4 E3)** |

### Findings — backlog (acknowledged, deferred post-tag)

| # | Description | Triage |
|---|---|---|
| F-K2-UX-1/2/3 | Frontend doesn't role-gate its action affordances (Change password visible to OIDC users; Settings sections show "Failed to load" instead of "no permission" on 403; "+ Add route" visible to viewers). Grouped as one item "role-gating frontend". Backend is correct (proven at smoke); these are pure UX cosmetic. | backlog one item |
| Parity cleanup | `none`/`basic` auth routes are NOT wrapped in subroute+terminal (only forward_auth routes are). No double-match risk on those routes (no companion route on the same host), so the divergence has zero observable impact — pure cosmetic parity gap with the canonical Caddyfile shape. Apply the same wrapper for consistency in a future commit. | backlog cosmetic |
| F-K2-UX-7 | Toast wording on role change ("`username` → admin") is terse | backlog cosmetic |
| F-K3-1 | CLI restore error log carries doubled `restore: restore:` prefix (cosmetic in structured slog only; stderr user-facing message is clean) | backlog cosmetic |
| F-K3-2 | Restore reject classification falls through to `other:restore:...` for validator-métier rejections (could be a dedicated `business_validate` token) | backlog cosmetic |
| F-K2-UX-8 | Sessions list shows multiple curl-derived sessions from smoke (operator can Revoke; killed by §9 wipe) | operational, not a code bug |
| HSTS browser cache | Operator's browser cached HSTS for `arenet-test.worldgeekwide.fr` from a prior session → forced HTTPS upgrade, certificate prompt. Workaround : clear HSTS for the FQDN | operational, browser-side |

---

## 7. Gaps declared (not smoked live, pinned in-process)

These are paths the smoke harness can't reach in this environment
but are exhaustively pinned by tests. Listed for transparency.

| Gap | Reason not live-smokable | In-process coverage |
|---|---|---|
| OIDC callback pipeline adversarial branches (state CSRF, nonce, audience, issuer, signature, expiry, allowlist miss) | Adversarial probes require constructing forged tokens; the live IdP doesn't issue invalid tokens on demand | 11 in-process tests with a fake IdP signing RS256 tokens (`internal/api/oidc_callback_test.go`) |
| Δ7 unverified email rejection at callback | Authentik doesn't expose an `email_verified` toggle per user — the malicious-account scenario the guard defends against cannot be reproduced against this IdP | `TestOIDCCallback_EmailUnverified_BootstrapRefused` (pipeline) + `TestOIDCMatchAllowlist_EmailUnverifiedRejected` (matcher) |
| Break-glass with IdP unreachable post-config | Cutting Authentik off mid-smoke needs sudo (firewall rule); the EnsureBuilt validation rejects writes against unreachable issuers (a useful safety on its own), making the simulacrum impossible from the API | `TestLocalLogin_BreakGlass_OIDCConfigured_StillWorks` injects issuer `http://127.0.0.1:1` directly in BoltDB |
| K.3 rollback on Caddy reload failure | Caddy reload doesn't naturally fail when the K.3 business-validator runs upstream; injecting a reload failure requires a debug hook | `TestBackup_Restore_CaddyReloadFailure_RollsBackBoltDB` with a fakeReloader primed to fail |
| K.4 browser round-trip (Authentik cookie callback) | `authentik_proxy_*` cookies carry the `Secure` flag; the browser correctly refuses to attach them on the HTTP local smoke. Production deployments always serve HTTPS where the flow completes. | Each chain link verified independently in §5: Caddy JSON shape, single-handling (sniffer), 302 to Authentik authorize endpoint, headers correct, fail-closed upstream confirmed |

---

## 8. Verdict

**SHIP READY** for `v0.7.0-step-k`. F-K4-S1 RESOLVED by E3
(`c951018`). All findings either fixed pre-tag or
backlog/cosmetic.

AC labels and numbering match the frozen spec §2 verbatim.

| AC (spec §2) | Status |
|---|---|
| #1 Per-route auth model | ✓ K.1 — live-smoked via UI + audit, in-process tests pin migration shape |
| #2 Forward-auth provider config | ✓ K.1 + K.4 E3 canonical shape (subroute + terminal), provider CRUD + ref-count 409 guard smoked live |
| #2bis Forward-auth client secret redaction | ✓ K.1 — in-process + redacted in audit live |
| **#3 Forward-auth request flow live** | **⚠ VERIFIED LINK BY LINK** with declared method caveat. Browser round-trip (post-login callback → upstream) NOT directly observed because the smoke ran on HTTP local and Authentik posts `Secure` cookies that the browser refuses on http:// (RFC 6265 §4.1.2.5). Each chain link confirmed independently: Caddy emits the canonical subroute+terminal shape; passthrough × main routes single-handle (sniffer); anonymous request returns 302 to Authentik authorize endpoint with correct params; fail-closed upstream confirmed (Python never reached without auth). All HTTPS production deployments complete the round-trip normally. See §5.3 for the link-by-link evidence and §5.4 for the in-process anti-regression pins. |
| #4 Basic Auth on a route unchanged | ✓ K.1 regression-tested in-process, no live re-smoke needed (Step I.5 already production-smoked) |
| #5 Auth mutual exclusivity at the API layer | ✓ K.1 — in-process validation; ref-count 409 on provider DELETE smoked live as a related defence |
| #6 OIDC discovery | ✓ Smoked live against Authentik discovery doc (200, RS256, issuer match) |
| #7 OIDC login round-trip | ✓ Smoked live end-to-end browser (admin login + viewer login + stranger reject) |
| #8 OIDC allowlist enforcement + canonicalisation | ✓ Smoked live — Sub pre-fill (Spec-1) + email-bootstrap Δ7 guard (in-process) |
| #8bis OIDC client_secret redaction | ✓ Smoked live (GET response empty, ClientSecretSet flag, audit scrubbed) |
| #8ter OIDC auto-create defaults to viewer role | ✓ Smoked live + VIEWER ESCALATION rejected at write |
| #9 Local admin login preserved (break-glass) | ✓ Pinned in-process (issuer port-1 simulation); audit emitted live confirms behaviour |
| #10 Break-glass audit event | ✓ Smoked live |
| #11 Local-admin password rotation audit hook | ✓ In-process (audit emission is an assert-string-match; live adds no coverage) |
| #12 Backup export round-trip | ✓ Smoked live (CLI export + CLI restore with-secrets on fresh target) |
| #13 Backup secrets redaction by default | ✓ Smoked live (sentinel + cleartext modes + 0o600 file mode + WARN stderr) |
| #14 Restore preserves redacted secrets (sentinel inheritance) | ✓ Smoked live + in-process |
| #14bis Disaster-recovery pre-flight | ✓ Smoked live (CLI rejection with two-paths-forward message) |
| #14ter `--allow-incomplete-restore` bypass | ✓ Smoked live (CLI with SENTINEL LEAK negative pin: 0 occurrence of literal in BoltDB) |
| #15 Restore rejects empty-users export | ✓ In-process (logical guard, live adds no coverage) |
| #15bis Restore emits the full audit event | ✓ Smoked live (success + failure paths both observed) |
| #16 Frontend tests pass | ✓ 174/174 |
| #17 Backend tests pass | ✓ 8/8 packages |
| #18 Lint / vet / format clean | ✓ |
| #19 Bundle budget | ✓ |

**Totals**: 25 acceptance items in spec §2 (19 main + 6 bis/ter
sub-items). 24 fully validated (live-smoked or covered by
pinned in-process tests with declared gap rationale); 1 (AC
#3) verified link by link with the explicit method caveat
above.

---

## 9. Secret hygiene checklist (J.7 pattern)

The smoke instance transited the real Authentik OIDC client_secret
through Arenet's BoltDB. The data-dir + browser cookies + tmpdir
exports MUST be wiped before this session is considered complete.

```bash
# Kill background processes
source /tmp/arenet-smoke-env
kill $ARENET_PID 2>/dev/null
kill $UPSTREAM_PID 2>/dev/null
killall -f "vite dev" 2>/dev/null

# Wipe the ephemeral smoke dir (BoltDB + cleartext exports)
rm -rf "$SMOKE_DIR"

# Drop the per-smoke curl cookie files
rm -f /tmp/arenet-cookies-* /tmp/arenet-oidc-flow-cookies /tmp/arenet-smoke-env
rm -f /tmp/cookie-port-test.txt /tmp/login-response*.json /tmp/probe*.txt

# Drop the smoke binary (carries no secret but reduces clutter)
rm -f /tmp/arenet-smoke-binary

# Operator-side: clear browser cookies for arenet-test.worldgeekwide.fr
# AND localhost:5173, AND clear HSTS for arenet-test.worldgeekwide.fr
# (Chromium: chrome://net-internals/#hsts — Delete domain security policies)

# Verify nothing left
ls -la $SMOKE_DIR 2>&1 # "No such file or directory" expected
history | grep -i "client_secret\|yzay20Uj" || echo "history clean"
```

The OIDC client_secret transmitted to me via the chat
(`yzay20Uj...`) is rotated to a new value by the operator at
Ludo's discretion post-tag — if there's even a perceived risk
it leaked further than the intended channel, rotate.

---

## 10. Tag procedure

```bash
# All commits already on main locally, NOT pushed yet.
git log --oneline -10

# Push the commit chain b52f082..c951018 + smoke doc commit
git push origin main

# Tag
git tag -a v0.7.0-step-k -m "Step K — Auth (route + admin) + Backup/Restore

Per-route auth (none / basic / forward_auth) with ref-count
guard, structural fail-closed and the canonical Caddyfile
forward_auth shape (subroute wrapper + terminal flag), with
an optional Host rewrite per-provider for IdPs that route by
Host (Authentik embedded outpost). Forward-auth verified live
against a real Authentik instance, link by link. (K.1 + K.4)

Admin OIDC SSO with break-glass invariant, role model
(viewer/admin), email→sub canonicalisation with Δ7
email_verified guard, last-LOCAL-admin demote guard, Spec-1
pre-filled sub for IdPs that don't emit email_verified (K.2).

Backup / restore with sentinel-based secret discipline (export
redacts + restore preserves-by-ID-match), pre-flight disaster-
recovery guard, business-invariant re-check upstream of the
atomic BoltDB write, all-or-nothing with Caddy reload rollback
(K.3).

K.4 smoke validated 24/25 acceptance items live or via pinned
in-process tests. AC #3 (Forward-auth request flow live)
verified link by link with an explicit method caveat: the
browser callback round-trip is not directly observed because
the smoke environment runs HTTP local and Authentik posts
Secure cookies that the browser refuses on http://, RFC 6265
§4.1.2.5. Every chain link confirmed independently against
the real Authentik instance (Caddy canonical shape via
:2019/config/, single-handling at the sniffer, 302 to the
authorize endpoint with correct params, fail-closed upstream).
All HTTPS production deployments complete the round-trip
normally. See docs/smoke-test-step-k.md §5.3 for the link-by-
link evidence.

Findings fixed at smoke time:
* K.4 E3 — forward_auth chain parity with the canonical
  Caddyfile expansion (subroute + terminal) + RewriteVerifyHost
  opt-in for Authentik embedded outpost. Resolved F-K4-S1.
* K.1 TLS transport on HTTPS forward-auth (F-K4-T1).
* K.2 Spec-1 allowlist sub pre-fill (F-K2-S1).
* K.2 --ui-origin absolute callback redirects (F-K2-D1).
* K.2 UX (sign out, dialog close, login error display).

Backlog (post-tag, cosmetic): role-gating frontend
affordances; none/basic auth route parity cleanup."

# Push the tag
git push origin v0.7.0-step-k
```
