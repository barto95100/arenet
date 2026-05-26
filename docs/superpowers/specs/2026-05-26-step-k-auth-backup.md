# Step K — Authentication (route + admin) + Backup/Restore

**Status:** FROZEN — tagged `v0.7.0-step-k-spec` on 2026-05-26.
**Target implementation tag:** `v0.7.0-step-k` after the K.4 smoke verdict PASS.
**Author:** Claude + Ludovic Ramos.
**Date frozen:** 2026-05-26.

---

## 1.1 Goal

Step K closes three roadmap items from the Step J backlog (`docs/
backlog-step-j.md` §5):

1. **Per-route authentication choice** beyond the single-credential
   HTTP Basic Auth shipped in Step I.5. The operator should be able
   to delegate route auth to an external IdP (Authelia / Authentik /
   Keycloak / etc.) via `forward_auth`, while keeping the existing
   Basic Auth as a first-class option for routes that do not warrant
   a full SSO setup.
2. **OIDC SSO on the admin console** (control plane). Arenet acts as
   an OIDC Relying Party against an external IdP for the admin
   login, with team SSO + audit-trail mapping per identity. The
   local admin account stays as a permanent break-glass fallback.
3. **Backup / restore of the BoltDB configuration as JSON**. Export
   the routes / settings / DNS provider config / users into a
   versioned-in-git-friendly JSON file; restore from a previously-
   exported file at boot or via the admin UI.

WAF rule tuning UI (the other Step K candidate on the backlog) is
**explicitly out of scope** — see §1.4.

## 1.2 Scope

Four sub-tasks. K.4 is the live smoke + tag (not optional —
project discipline mirrors Step J's J.7). The WAF tuning UI item
that originally carried a placeholder K.5 number is DEFERRED, see
§1.4 — it does NOT get a number in this step:

| Sub-task | Surface       | Subject |
|----------|---------------|---------|
| K.1      | backend + UI  | Per-route `forward_auth` (Authelia / Authentik / Keycloak / generic OIDC IdP). Basic Auth (Step I.5) preserved unchanged. |
| K.2      | backend + UI  | OIDC SSO on admin login + viewer/admin role model. Local admin account preserved as break-glass. |
| K.3      | backend + UI  | Backup / restore: JSON export of the full Arenet config; JSON import via admin UI + boot-time `--restore` flag. |
| K.4      | smoke + tag   | Live smoke test plan + `v0.7.0-step-k` release. Required by project discipline (mirror Step J §J.7). |

Each named sub-task is one commit per the §8 plan (same convention
as Step J: spec freeze tag → per-sub-task commits → smoke doc → tag).

## 1.3 Locked decisions

The eleven non-negotiables that shape the rest of the spec:

1. **K.1 keeps Basic Auth.** Basic Auth (Step I.5) is **NOT removed,
   NOT extended**. It stays single-credential per route. Multi-user
   Basic Auth — listed in Step I backlog and pre-pinned for Step J
   before being deferred — is **not in scope for K** either. An
   operator who needs multi-user identity per route uses K.1's
   `forward_auth` against an IdP. Status quo on Basic Auth removes
   a UI-complexity vector (per-route user management,
   password rotation, role assignment) that is solved upstream by
   any of the IdPs K.1 supports.

2. **K.1 per-route auth is mutually exclusive.** A route picks
   exactly one of: `none` (default), `basic` (Step I.5), or
   `forward_auth`. No layering ("basic auth AND forward auth on
   the same route") — empirically confused, and the IdP already
   protects what needs protecting.

3. **K.1 `forward_auth` provider config is instance-level.**
   Arenet stores one or more named `ForwardAuthProvider` rows in
   BoltDB (parallel to `DNSProviderConfig` Step J.4); a route's
   `forward_auth` field references a provider by name. An operator
   typically configures a single Authelia instance once and points
   every route at it. Multiple providers are allowed for
   environments mixing Authelia and Authentik (e.g. staging vs
   prod).

4. **K.2 OIDC SSO is additive, never replacement.** The local admin
   account (bootstrapped via the boot-time setup token, Step D /
   spec §4) **remains a permanent login path** regardless of OIDC
   configuration state. Toggling OIDC on does NOT disable the
   `POST /api/v1/auth/login` endpoint with username/password. This
   is the break-glass invariant.

5. **K.2 local login MUST NOT depend on OIDC.** Concretely: the
   local login handler does not call any OIDC code path, the local
   session middleware (`SoftAuthMiddleware` / `HardAuthMiddleware`)
   does not call OIDC code, and a misconfigured OIDC provider
   (unreachable IdP, expired discovery doc, invalid client secret)
   cannot block local login. The OIDC code lives in its own
   handlers and middleware that can fail open against the local
   path.

6. **K.2 break-glass usage is audited.** Every local-credential
   login (action `login_success` with `auth_method: "local"`) is
   already audited via Step D. When OIDC is configured AND the
   most recent OIDC user-level activity is non-zero (i.e. OIDC
   has been used at least once on this instance), a subsequent
   local-credential login emits an additional audit event
   `login_break_glass` so the operator gets a clear post-mortem
   signal "we fell back to the local account on YYYY-MM-DD". On
   a fresh install where OIDC is not configured or never used,
   no `login_break_glass` is emitted — the local path is just
   the only path.

7. **K.2 local-admin credential rotation is in scope.** The
   `POST /api/v1/auth/me/password` endpoint already exists (Step
   D), so the rotation API is built. What K.2 adds is a UI
   surface plus an audit hook: rotating the local-admin password
   while OIDC is configured emits `local_admin_password_rotated`
   to flag the change in the audit trail. Out of scope: forcing
   rotation at install (a homelab where SSO sits 24/7 might
   never log in locally, so a forced rotation policy serves no
   one). Out of scope too: rotation of the local-admin
   *username* (rare enough to handle by direct BoltDB edit when
   needed).

8. **K.3 secret handling on export: secrets EXCLUDED by default,
   opt-in via an explicit `--include-secrets` flag.** Per-route
   `BasicAuthPasswordHash`, the DNS provider OVH credentials, the
   `forward_auth` provider's client secret (K.1), the OIDC client
   secret (K.2), and the local admin's `PasswordHash` are
   redacted in the default export — the JSON carries a
   `"$$ARENET_REDACTED$$"` sentinel string where the secret value
   would be. Import handles the sentinel: an imported row whose
   secret is `"$$ARENET_REDACTED$$"` carries forward the
   currently-stored secret for the same logical key (matching by
   ID for users / route IDs / provider names). A `--include-
   secrets` opt-in dumps the secrets in cleartext (analogous to
   `--show-secrets` patterns in other tools); the file is then
   treated as sensitive by file-perm convention `0o600` (matching
   the BoltDB at-rest posture from §1.6 J.4) and the export wire
   shape and the CLI both warn explicitly.

9. **K.3 export is whole-config.** No partial export ("export just
   the routes"). The export is a single JSON document
   representing the full Arenet config: routes, DNS provider,
   forward-auth providers, OIDC config, users. Partial selection
   would invite restore-vs-current-state merge complexity
   (Step K' problem, not Step K). Restore is replace-all (same
   contract as Caddy's `caddy.Load` — full new state, no diff).

10. **K.3 restore lives behind an explicit operator action.**
    Two paths: (a) CLI `--restore /path/to/backup.json` at boot
    time, which loads the file at startup before Caddy starts;
    (b) admin UI button "Import configuration" that triggers a
    POST with the file body. Both confirm-twice (CLI prints a
    one-line diff summary then waits 5 s; UI shows a modal with
    "this will replace the current configuration" wording). No
    silent restore, no automatic restore, no "apply on file
    change" daemon mode.

11. **K-wide invariant: per Step J §1.3 decision 7, all
    behaviour is delivered through Caddy's standard modules.**
    `forward_auth` is a Caddy core directive (already in the
    `standard` module set Arenet imports), nothing new to
    compile. OIDC is implemented as an Arenet API surface using
    the `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`
    libraries; the SSO callback lands on `/api/v1/auth/oidc/...`
    Arenet endpoints, not on a Caddy module. Backup/restore is
    pure storage layer, no Caddy interaction.

12. **K.2 introduces a viewer/admin role model.** Today's User
    struct has no `Role` field — Step D phase 1 shipped a
    single-admin model (every user is admin). K.2 introduces
    two roles, **`viewer`** (read-only access to the admin UI:
    list routes, view audit, view topology — but no CRUD on
    routes / settings / users) and **`admin`** (full access,
    today's behaviour). The locked default for an OIDC-auto-
    created user (§5.2 allowlist auto-create flow) is
    **`viewer`** — the operator must explicitly elevate to
    `admin` via a dedicated endpoint
    (`POST /api/v1/admin/users/{id}/role`, body
    `{"role": "admin"}`). This guards against an
    over-permissive OIDC allowlist mistake (adding a `sub`
    intending viewer-only access).

    Local-source users created via the boot-time setup token
    keep their current behaviour: the first local admin is
    `admin` (the setup flow is by definition trusted, and a
    homelab with zero admin is locked out). Migrated pre-K
    users default to `admin` too (§6.4) — they were admin
    before, they stay admin.

13. **K.2 allowlist is identity-per-entry, keyed by email at
    create time + canonicalised to `sub` post-login.** Two-
    step lifecycle to resolve the chicken-and-egg problem
    (the operator does not know the OIDC `sub` of a user
    before that user's first login):

    - **Step 1 — operator invites by email** in the Settings
      UI ("Add OIDC identity" form: email + optional display
      name). The entry is persisted with `Email != ""`, `Sub
      = ""`. The UI lists it under "pending first login".
    - **Step 2 — first login of the user** at
      `/api/v1/auth/oidc/callback`: the validated ID token
      carries both `email` (standard claim) and `sub`. The
      callback matches the token's `email` against the
      allowlist. On match with an entry where `Sub == ""`,
      Arenet canonicalises: the entry's `Sub` field is set to
      the token's `sub` value, and subsequent logins by the
      same identity match by `Sub` (the stable OIDC
      identifier — emails can change at the IdP, `sub` is
      contractually stable).

    No domain-wide or group-wide entries — identity-per-entry.
    Rationale: a domain- or group-allowlist grants admin
    trivially to a new employee added to the IdP, defeating
    the conservative default (§1.4 "OIDC group sync"). Per-
    identity forces the operator's explicit gesture for each
    new authorized human, while the email-then-sub
    canonicalisation removes the bootstrap chicken-and-egg.

    On allowlist removal: the operator deletes an entry; the
    matching Arenet user row (if it exists post-canonicalise)
    stays in the users bucket but cannot log in again
    (post-removal allowlist match fails). The operator may
    separately delete the user row from the admin Users UI.

    Cohesive with decision 12 (default-viewer): the operator
    adds the email once, the user lands as `viewer` on
    first canonicalised login, then the operator decides
    whether to elevate. Two explicit gestures separated; no
    implicit elevation path.

14. **K.1 ForwardAuthProvider DELETE differs from J.4
    DNSProviderConfig "no delete".** Intentional asymmetry,
    flagged so a future reader doesn't see it as an oversight.
    Reasoning: a `ForwardAuthProvider` is a named entity
    referenced by N routes (1-provider → N-routes); deleting
    it leaves dangling references that the route validate()
    + Caddy reload would catch, but the failure mode is
    confusing. K.1 picks reference-guarded DELETE (409 with
    the offending route IDs in the response body), so the
    operator gets a clear "reconfigure these routes first"
    message. A `DNSProviderConfig` in J.4 has no such
    reference layer — at most one OVH config exists per
    instance, routes reference "dns-01" as a challenge type
    (not a provider name), and the J.4 erasure path (PUT all
    blank) was the better choice there. The two patterns
    coexist because the referential model is genuinely
    different; do not unify them in a refactor.

## 1.4 Out of scope

Explicitly NOT part of Step K. Items below are deferred to a later
step or recorded in the backlog.

- **WAF rule tuning UI (the prior Step K backlog candidate).** This
  feature has two technical variants per the recon recorded in
  commit `adba91e`:
  - *Variant "manual"*: an allowlist editor (per-route list of CRS
    rule IDs to silence) + a description hover panel for each CRS
    rule. Shippable today against `coraza-caddy v2.5.0` because
    it does not need any match-observation hook (the operator
    identifies the rule from external observation — Caddy logs,
    his own debugging).
  - *Variant "integrated"*: live match observation in the admin UI
    + click-to-allowlist. Requires a `coraza/v3`-based custom
    Caddy module owned by Arenet (~600 LoC, security-critical: a
    bug in match handling silently weakens the WAF). Confirmed in
    the recon: `coraza-caddy v2.5.0` is the latest release as of
    2026-05-26 and embeds its match callback in a closed log
    sink (`coraza.go:103-104`); no upstream hook to plumb
    through.

  Both variants need a richer surface than what Step K already
  carries. The "integrated" variant is its own step (let us call
  it Step K2 — "WAF observability") because the custom module is
  a real ownership decision. The "manual" variant is reasonable
  but loses much of its operator value without the
  observability piece (an allowlist editor whose target rules
  are not visible in the UI is a config file). Decision:
  **WAF tuning waits for the observability step**; the
  observability step is itself parked until Coraza upstream
  re-shapes its API or Arenet decides to take on the ~600 LoC.

- **Forward-auth provider full coverage.** K.1 ships with
  Authelia / Authentik / Keycloak / generic OIDC IdP support.
  "Generic OIDC" means "any provider that speaks the standard
  OIDC discovery doc + the auth_request semantic Caddy
  `forward_auth` consumes". Niche providers that require custom
  request shaping (e.g. some enterprise gateways) are out of
  scope; they can be added as named providers in a follow-up step
  the same way the K.1 list extends today.

- **Multi-user Basic Auth per route.** Confirmed deferred —
  see §1.3 decision 1.

- **OIDC role / group mapping to Arenet permissions beyond
  "admin".** K.2 ships an admin-only authorization model: every
  authenticated OIDC identity that lands on Arenet is treated as
  an admin (because Arenet's user model only has one role today,
  spec §4 Step D). Multi-role (operator / viewer / route-owner)
  is a separate refinement: the OIDC claims would need a mapping
  table, and the API surface would need RBAC. Out of K, recorded
  as a roadmap item.

- **OIDC group sync to Arenet user list.** K.2 does NOT
  auto-create Arenet user rows from OIDC group membership. The
  first OIDC login of an unknown identity is rejected with a
  clear error pointing at the admin UI's "Authorized OIDC
  identities" allowlist (K.2 §5.2). Auto-provisioning would lower
  the bar to mistakes (an over-permissive OIDC group sync grants
  admin trivially); explicit allowlist is the conservative
  default.

- **Backup encryption at rest.** K.3 exported files are protected
  by file-system permissions (`0o600`), same posture as the
  BoltDB file. An age / GPG encryption wrapper around the export
  is a feature of the operator's deployment pipeline, not of
  Arenet. Out of scope.

- **Backup retention / rotation policy / scheduled exports.** K.3
  is one-shot operator-triggered. A cron-like scheduler is
  another roadmap item.

- **Restore-against-current-state diff / merge.** K.3 restore is
  always replace-all (§1.3 decision 9). Surface-aware merge
  ("import these routes, keep my OIDC config") is K2-or-later.

## 1.5 Range of change

Baseline: `v0.6.0-step-j` (`aee0525`), the current `origin/main`
head modulo the four post-tag doc commits (`58c6591`,
`d53a37c`, `adba91e`, and this spec). The spec is frozen at tag
`v0.7.0-step-k-spec`; implementation runs from there to
`v0.7.0-step-k`. Implementation is sub-tasks K.1 → K.4 (4
sub-tasks, no skipped numbers — the WAF tuning UI item that
would have been numbered is DEFERRED out of the step entirely,
see §1.4).

Expected sub-task footprint:

| Sub-task | Backend (Go) | Frontend (Svelte) | Tests |
|----------|--------------|-------------------|-------|
| K.1      | ~400 LoC     | ~250 LoC         | ~200 LoC unit + smoke |
| K.2      | ~750 LoC     | ~350 LoC         | ~300 LoC unit + smoke |
| K.3      | ~500 LoC     | ~200 LoC         | ~200 LoC unit + smoke |
| K.4      | 0            | 0                | smoke doc (~700 LoC) |

Aggregate ~2 350 LoC of code across the three feature sub-tasks
+ ~700 LoC smoke doc. K.2 grew slightly vs the initial draft to
account for the viewer/admin role model + admin users
management UI introduced by §1.3 decision 12.

## 1.6 Threat model deltas vs Step J

What Step K changes in the threat model. Same format as Step J
§1.6.

**Δ1 — Per-route forward_auth introduces an inbound dependency on
the IdP.** A route protected by `forward_auth` is unavailable
when the IdP is unreachable. This is the trade-off the operator
accepts when delegating auth. K.1's UI surfaces the IdP health
status (last sub-request OK / FAIL / unknown) so the operator
notices before a real user reports the outage. Out of scope:
fallback to Basic Auth if IdP is down (would defeat the entire
SSO model).

**Δ2 — OIDC SSO introduces a federated identity surface.** A
compromised IdP user is an admin on Arenet. Mitigation: the
allowlist of authorized OIDC subjects (K.2 §5.2 decision 8) — only
the subjects in the list can log in, not the entire IdP user
population. The break-glass local account (§1.3 decision 4)
mitigates the "IdP is compromised AND I cannot rotate" scenario:
the operator logs in locally and disables OIDC.

**Δ3 — OIDC redirect URI is a CSRF-class attack surface.** The
OIDC `state` parameter MUST be cryptographically random per
request, bound to the session, and validated on callback. The
nonce parameter MUST be in the ID token and validated. Standard
OIDC RP hardening, called out so the implementation does not
skip it.

**Δ4 — Backup files contain secrets when opt-in.** §1.3 decision 8
specifies `0o600` + explicit `--include-secrets` flag + a wire-
shape warning, but the file once written is at the mercy of
the operator's storage choices (git history, S3 bucket,
Dropbox). The CLI warns; the operator is responsible.

**Δ5 — Restore can lock the operator out.** A restore that contains
no users (e.g. exported when the users bucket was empty) wipes
the admin. K.3 mitigates: import refuses to apply if it would
empty the users bucket; if the source file genuinely has zero
users, the operator must explicitly pass `--allow-empty-users`,
which then re-triggers the boot-time setup-token flow on next
boot. UI version of the same rule: confirm-twice modal with the
"this configuration has no admin users; you will need to use the
boot-time setup token to log in" message.

**Δ6 — `forward_auth` provider secret + OIDC client secret live
in BoltDB cleartext.** Same posture as the OVH credentials in
J.4: file-perm boundary (`0o600`), no at-rest encryption, the
secret is recoverable (replayed at every IdP call) so hashing is
not applicable. Audit + GET responses redact (same Step I.5 /
J.4 pattern, see §5.x designs).

**Δ7 — OIDC invite-hijack via unverified email.** The K.2
allowlist canonicalisation flow (§1.3 decision 13) bootstraps
an entry from a `sub == ""` pending state by matching the
incoming ID token's `email` claim against the entry's
`email`. An IdP-side malicious account that registers (or
claims) someone else's email address could canonicalise into
a pending invite that was intended for the real owner of the
email. Mitigation, mandatory per §5.2: the email-match pass
REQUIRES `token.email_verified == true`. An IdP that allows
unverified-email accounts (some legacy or misconfigured
deployments) cannot exploit the invite — the canonicalisation
silently falls through to the no-match rejection. Operators
relying on Arenet are by transitivity relying on their IdP's
email verification flow being sound; the guard ensures
Arenet does not amplify a misconfigured IdP into an invite
hijack.

---

## 2. Acceptance Criteria

The numbered criteria below are the authoritative checklist for
the K.4 smoke and the `v0.7.0-step-k` tag. Each must end the step
as PASS, PARTIAL with a documented caveat, or N/A with
justification.

**AC #1 — Per-route auth model.** Each route persists an explicit
auth mode (`none` / `basic` / `forward_auth`) and round-trips
create/edit/get unchanged. Pre-Step-K routes migrate to `basic`
when `BasicAuthEnabled` was true, `none` otherwise.

**AC #2 — Forward-auth provider config.** An operator can
configure one or more named providers (Authelia / Authentik /
Keycloak / generic) via the Settings UI + the
`/api/v1/settings/forward-auth/providers` API. The provider
config carries the verify URL, the auth-request path, the
headers-to-copy list, and the client secret if applicable.

**AC #2bis — Forward-auth client secret redaction.** The
client secret of every configured forward-auth provider is
never echoed by API GET responses (returned as the empty
string with a `clientSecretSet: bool` flag), never appears in
audit-log `before`/`after` payloads (event
`forward_auth_provider_updated`), and never appears in slog
output. Mirrors Step I.5 BasicAuth + Step J.4 OVH credential
discipline.

**AC #3 — Forward-auth request flow live.** A route protected by
a configured forward-auth provider: an unauthenticated request
gets the IdP redirect; the IdP authentication round-trips back
to the route; on success the request reaches the upstream with
the configured headers copied (e.g. `Remote-User`,
`Remote-Email`).

**AC #4 — Basic Auth on a route unchanged.** A route protected by
Basic Auth (Step I.5 behaviour) functions identically after K.1.
No regression, no behaviour shift on the existing route auth
chain (Step I.7 Finding #9 chain order auth-before-WAF is
preserved).

**AC #5 — Auth mutual exclusivity at the API layer.** A POST /
PUT request that attempts to enable two auth methods at once
(e.g. `basicAuthEnabled: true` AND `forwardAuth.providerName:
"authelia"`) is rejected with a clear error message at the API
layer, before reaching storage. The form prevents this state in
the first place (radio button group), but the backend is the
last line of defence.

**AC #6 — OIDC discovery.** When OIDC is configured, Arenet
fetches and caches the IdP discovery document (`/.well-known/
openid-configuration`) at config time + at a configurable
interval. The cached doc is used for the `authorization_endpoint`,
`token_endpoint`, `userinfo_endpoint`, `jwks_uri`.

**AC #7 — OIDC login round-trip.** `GET /api/v1/auth/oidc/login`
initiates the auth flow, redirects to the IdP, the callback
(`GET /api/v1/auth/oidc/callback`) validates state + nonce +
ID-token signature, maps the identity to an Arenet session, and
the operator lands in the admin UI authenticated.

**AC #8 — OIDC allowlist enforcement + canonicalisation.** A
login attempt from an OIDC identity not in the allowlist
(matched neither by `sub` nor by `email`) is rejected with a
clear error message + an `oidc_login_rejected` audit event.
The operator adds identities to the allowlist by email via
the Settings UI; the first successful login canonicalises
the entry's `sub` field (the IdP-stable identifier) and
subsequent logins match by `sub`. The chicken-and-egg
problem (`sub` is unknown before first login) is resolved by
the two-step email-then-sub flow per §1.3 decision 13.

The email-pass canonicalisation **requires the ID token's
`email_verified` claim to be present AND `true`**: an
unverified-email token never canonicalises an invite,
guarding against the IdP-side invite-hijack attack surface
(§5.2 callback logic). A token with `email_verified == false`
or with the claim absent that matches a pending invite by
email is rejected with `oidc_login_rejected` (recording the
reason for trace).

**AC #8bis — OIDC client_secret redaction.** The OIDC client
secret is never echoed by API GET responses
(`GET /api/v1/settings/oidc` returns `clientSecret: ""` with a
`clientSecretSet: bool` flag), never appears in audit-log
`before`/`after` payloads for the `oidc_configured` or
`oidc_updated` events, and never appears in slog output. Mirrors
the AC #2bis discipline for the forward-auth client secret.

**AC #8ter — OIDC auto-create defaults to viewer role.** A first
allowed login from an OIDC `sub` that has no matching Arenet
user row auto-creates a user with `Role: "viewer"` (NOT
`admin`). Elevation to `admin` requires an explicit
`POST /api/v1/admin/users/{id}/role` call by an existing
admin. Migrated pre-K users keep `Role: "admin"`.

**AC #9 — Local admin login preserved (break-glass).** With
OIDC configured AND the IdP unreachable (DNS NXDOMAIN, TCP
refused, HTTP 500 from discovery), the local admin can still
log in via `POST /api/v1/auth/login` with username/password.
Verified empirically by stopping the local Authentik / Authelia
during the smoke.

**AC #10 — Break-glass audit event.** A local-credential login
that happens while OIDC has been used at least once on the
instance emits a `login_break_glass` audit event in addition to
the regular `login_success`. A first-install local login (OIDC
never configured) emits only `login_success`.

**AC #11 — Local-admin password rotation audit hook.** Calling
`POST /api/v1/auth/me/password` while OIDC is configured emits
a `local_admin_password_rotated` audit event (Step D's
`password_changed` event is preserved; this is in addition,
specifically tagged for the OIDC-active context).

**AC #12 — Backup export round-trip.** `arenet --export
backup.json` writes a JSON file representing the full Arenet
config. A subsequent `arenet --restore backup.json` on a fresh
instance reproduces the original config byte-for-byte modulo
timestamps + IDs.

**AC #13 — Backup secrets redaction by default.** The default
export does NOT contain plaintext secrets — all
`PasswordHash`, `BasicAuthPasswordHash`, OVH credentials,
forward-auth client secrets, OIDC client secret in the export
JSON are the literal string `"$$ARENET_REDACTED$$"`. The
opt-in `--include-secrets` flag dumps cleartext, with an
explicit warning on stderr + the export JSON top-level field
`"secrets_included": true`.

**AC #14 — Restore preserves redacted secrets.** Restoring an
export that has `"$$ARENET_REDACTED$$"` sentinels merges the
current Arenet's stored secrets back into the restored rows
matched by logical identity (per the §5.3 sentinel
ID-match rules: routes by `id`, users by `id`, DNS provider by
bucket key, forward-auth provider by `name`, OIDC config by
bucket key). A restored row whose secret field is the sentinel
AND whose logical identity does not match an existing target
row is rejected with a clear error naming the field, the
entity, AND the two recovery paths (re-export with
`--include-secrets`, or `--allow-incomplete-restore`). All-
or-nothing transaction: any single rejection rolls the whole
restore back. NEVER writes the sentinel literal into a target
field.

**AC #14bis — Disaster-recovery restore on a fresh instance
fails loudly when secrets are missing.** Importing a no-
secrets export (`secrets_included: false`) onto a fresh-target
instance (no users, no DNS provider, no forward-auth provider,
no OIDC config) aborts with the dedicated pre-flight error
message naming the missing surfaces and offering the same two
documented paths forward (re-export with `--include-secrets`,
or pass `--allow-incomplete-restore`). The check fires BEFORE
the transaction begins, so the partial state is never written.
This is an optimisation of AC #14's per-row check for the
"every row will fail anyway" case; the actionable wording is
identical.

**AC #14ter — `--allow-incomplete-restore` bypass works as
specified on BOTH failure modes.** With the explicit bypass,
both the pre-flight (AC #14bis) and the per-row sentinel-
mismatch (AC #14) paths proceed: each unresolvable sentinel
clears the affected field, the resulting BoltDB carries the
per-section counts in the `config_restored` audit event with
`allow_incomplete_restore: true`, the next boot prints a
startup WARN listing every row that needs a secret re-saved
(cross-reference §1.6 J.4 boot WARN pattern). The bypass is
opt-in on every code path; default behaviour stays loud-fail
on every code path. "Never silent" = "always actionable" on
every failure mode.

**AC #15 — Restore rejects empty-users export.** Restoring a
backup with zero users is rejected by default. The
`--allow-empty-users` opt-in proceeds + re-triggers the
boot-time setup-token flow on next boot. Distinct from the
disaster-recovery pre-flight (AC #14bis): a non-empty target
+ an empty-users import can still hit this path.

**AC #15bis — Restore emits the full audit event.** A
successful restore emits `config_restored` carrying:
`source_sha256` of the file, `schema_version`,
`secrets_included_in_source`, `allow_incomplete_restore`,
per-section import counts, and sentinel-resolution counts
(`sentinels_inherited_total`,
`sentinels_unresolved_total`). A rejected restore emits
`config_restored_rejected` with the failure reason. Auditing
on the failure path matches the export's audit-on-success
discipline.

**AC #16 — Frontend tests pass.** `npm run check` clean and
`npm test` green.

**AC #17 — Backend tests pass.** `go test ./...` green across
all packages.

**AC #18 — Lint / vet / format clean.** `gofmt`, `go vet`,
`staticcheck` on Step K surface, and the frontend linter
report no issues.

**AC #19 — Bundle budget.** `npm run build` completes within
the Step J §1 bundle budget (30 kB gz topology page +
no new pathological size on the Settings or Routes pages).

---

## 3. Architecture impact

### 3.1 Domain model deltas

**Route struct** (`internal/storage/routes.go`):

Replace the current dual `BasicAuthEnabled bool + BasicAuthUsername
string + BasicAuthPasswordHash string` triplet with an explicit
`AuthMode` enum + a nested `ForwardAuth ForwardAuthRouteConfig`
struct that only carries the per-route reference to a provider
(provider names live at instance level, see below).

```go
// AuthMode enum (K.1).
const (
    RouteAuthNone        = "none"
    RouteAuthBasic       = "basic"
    RouteAuthForwardAuth = "forward_auth"
)

type Route struct {
    // ... existing fields ...
    AuthMode    string                 `json:"auth_mode"`
    BasicAuth   BasicAuthRouteConfig   `json:"basic_auth"`
    ForwardAuth ForwardAuthRouteConfig `json:"forward_auth"`
    // Removed: BasicAuthEnabled / BasicAuthUsername /
    //          BasicAuthPasswordHash (replaced by the structs).
}

// BasicAuthRouteConfig keeps the Step I.5 fields, grouped.
// Validation rules: when r.AuthMode == "basic", BasicAuth.
// Username + PasswordHash must both be non-empty.
type BasicAuthRouteConfig struct {
    Username     string `json:"username"`
    PasswordHash string `json:"password_hash"` // argon2id PHC — never echoed
}

// ForwardAuthRouteConfig is the per-route reference to one of
// the instance-level providers. Validation: when r.AuthMode ==
// "forward_auth", ProviderName must reference an existing
// instance-level provider config (looked up at edit time, same
// pattern as J.4 DNS-01 provider check).
type ForwardAuthRouteConfig struct {
    ProviderName string `json:"provider_name"` // e.g. "authelia-prod"
}
```

**ForwardAuthProvider** (new struct, new BoltDB bucket):

```go
type ForwardAuthProvider struct {
    Name           string   `json:"name"`            // unique key, slug-shaped
    Kind           string   `json:"kind"`            // "authelia"|"authentik"|"keycloak"|"generic"
    VerifyURL      string   `json:"verify_url"`      // e.g. "http://authelia:9091"
    AuthRequestURI string   `json:"auth_request_uri"`// e.g. "/api/authz/forward-auth"
    CopyHeaders    []string `json:"copy_headers"`    // e.g. ["Remote-User","Remote-Email"]
    ClientSecret   string   `json:"client_secret"`   // SECRET — never echoed (Step J.4 pattern)
    CreatedAt      time.Time `json:"created_at"`
    UpdatedAt      time.Time `json:"updated_at"`
}
```

Stored in a new bucket `forward_auth_providers`, keyed by `Name`.

**OIDCConfig** (new struct, new BoltDB bucket, single instance):

```go
type OIDCConfig struct {
    Enabled           bool                  `json:"enabled"`
    IssuerURL         string                `json:"issuer_url"`         // discovery: <issuer>/.well-known/openid-configuration
    ClientID          string                `json:"client_id"`
    ClientSecret      string                `json:"client_secret"`      // SECRET — never echoed
    Scopes            []string              `json:"scopes"`             // default: ["openid","profile","email"]
    RedirectURL       string                `json:"redirect_url"`       // e.g. "https://arenet.example.com/api/v1/auth/oidc/callback"
    AllowedIdentities []OIDCAllowedIdentity `json:"allowed_identities"` // see below — email + sub
    CreatedAt         time.Time             `json:"created_at"`
    UpdatedAt         time.Time             `json:"updated_at"`
}

// OIDCAllowedIdentity is one entry in the allowlist (§1.3 decision 13).
// The operator adds entries by email at create time; Arenet
// canonicalises Sub on the user's first successful login.
type OIDCAllowedIdentity struct {
    Email       string    `json:"email"`        // operator-supplied, required, unique within the list
    DisplayName string    `json:"display_name"` // operator-supplied, optional
    Sub         string    `json:"sub"`          // OIDC subject, set at first login, empty before
    AddedAt     time.Time `json:"added_at"`
    FirstLoginAt time.Time `json:"first_login_at,omitempty"` // canonicalisation timestamp
}
```

Stored in a new bucket `oidc_config`, single row keyed `"default"`
(future-proof for multi-IdP if needed; today only `"default"`).

**User struct** (`internal/auth/types.go`):

Add three fields: `AuthSource` (distinguishes locally-managed
from OIDC-mapped), `OIDCSub` (the OIDC subject when applicable),
and `Role` (viewer vs admin, §1.3 decision 12):

```go
const (
    UserAuthSourceLocal = "local" // username + PasswordHash, Step D
    UserAuthSourceOIDC  = "oidc"  // OIDC sub mapped to this user

    UserRoleViewer = "viewer" // read-only admin UI access
    UserRoleAdmin  = "admin"  // full CRUD on routes / settings / users
)

type User struct {
    // ... existing fields ...
    AuthSource string `json:"auth_source"`        // "local" | "oidc"
    OIDCSub    string `json:"oidc_sub,omitempty"` // OIDC subject if AuthSource == "oidc"
    Role       string `json:"role"`               // "viewer" | "admin"
}
```

OIDC-source users have no `PasswordHash` (the IdP is the
auth source). Local-source users have no `OIDCSub`. Mutual
exclusivity enforced by `UserStore` validation.

Role semantics:
- `viewer` — read access to /routes, /audit, /topology
  (GET-only endpoints). All POST/PUT/DELETE on /routes /
  /settings/* / /admin/users/* → 403. Theme toggle + password
  change on the user's own row remain allowed (UX
  unaffected).
- `admin` — today's behaviour. Full CRUD access everywhere.

Role enforcement is by middleware: a new `RequireRole(admin)`
wrapper sits inside the existing `HardAuthMiddleware` chain
for the relevant business endpoints. The wrapper reads the
session's user, checks `user.Role`, returns 403 with
`{"error": "admin role required"}` if mismatch. Self-edit
endpoints (password / theme) bypass the role check.

Role transitions are explicit: a viewer can never elevate
itself; only an `admin` can call
`POST /api/v1/admin/users/{id}/role` to elevate or demote
another user. The endpoint guards against the last admin
demoting themselves (would lock the instance out of admin
access) — rejected with 400 "cannot demote the last admin".

### 3.2 Generator (caddymgr) deltas

**K.1** — `buildConfigJSON` route loop emits the auth chain based
on `route.AuthMode`:

- `AuthMode == "none"`: no auth handler emitted.
- `AuthMode == "basic"`: emit the existing `authentication` handler
  with `http_basic` provider (Step I.5 shape, unchanged).
- `AuthMode == "forward_auth"`: emit the Caddy `subroute` block
  with `handle_response` per the Caddy Caddyfile-adapt sample
  (verified empirically against caddy v2.11.3, see
  `caddytest/integration/caddyfile_adapt/forward_auth_authelia.
  caddyfiletest`). The block is parameterised by the provider's
  VerifyURL + AuthRequestURI + CopyHeaders.

Handler chain order (preserved from Step I.7 Finding #9 + Step
J.4): `[metrics, auth, waf, headers, proxy]`. The new
`forward_auth` block sits in the same slot as the current
`authentication` block.

**K.2 and K.3** do not touch caddymgr.

### 3.3 API surface deltas

K.1 endpoints (new):

- `GET /api/v1/settings/forward-auth/providers` — list configured
  providers (secrets redacted).
- `POST /api/v1/settings/forward-auth/providers` — create a new
  provider.
- `PUT /api/v1/settings/forward-auth/providers/{name}` — update
  (preserve-on-edit secret semantics, Step J.4 pattern).
- `DELETE /api/v1/settings/forward-auth/providers/{name}` —
  rejected when at least one route references the provider
  (returns 409 with the offending route IDs).

K.2 endpoints (new):

- `GET /api/v1/settings/oidc` — read config (client secret
  redacted).
- `PUT /api/v1/settings/oidc` — update config (preserve-on-edit
  secret semantics).
- `GET /api/v1/auth/oidc/login` — initiate OIDC flow (sets state +
  nonce cookies, 302 to IdP `authorization_endpoint`).
- `GET /api/v1/auth/oidc/callback` — validate state + nonce + ID
  token, lookup `sub` in allowlist, create local session, redirect
  to the admin UI.
- `GET /api/v1/settings/oidc/allowlist` — list allowed
  identities. Each entry surfaces `email`, `display_name`,
  `sub` (empty if pending first login), `added_at`,
  `first_login_at` (zero-value if pending).
- `POST /api/v1/settings/oidc/allowlist` — add an identity by
  email. Body: `{"email": "...", "display_name": "..."}`. Email
  must be unique within the list; case-insensitive comparison
  for the uniqueness check, stored as the operator typed.
- `DELETE /api/v1/settings/oidc/allowlist/{email}` — remove
  by email. Key is the URL-encoded email (operator-known
  identifier); the corresponding Arenet user row, if any,
  is NOT auto-deleted — that's a separate admin Users UI
  gesture per §1.3 decision 13.
- `GET /api/v1/admin/users` — list users (admin role required).
  Includes `role`, `auth_source`, `last_login_at` per row;
  excludes `password_hash`.
- `POST /api/v1/admin/users/{id}/role` — elevate or demote
  another user's role (admin role required). Body:
  `{"role": "viewer"|"admin"}`. Last-admin-demote guard
  rejects with 400. Audit event: `user_role_changed` with
  before/after.

K.3 endpoints (new):

- `GET /api/v1/admin/backup?include-secrets=false` — stream the
  export JSON as the response body (Content-Type
  `application/json`, Content-Disposition `attachment;
  filename="arenet-config-YYYY-MM-DD.json"`).
- `POST /api/v1/admin/restore` — accept the JSON body, validate,
  apply. Response: redirect to `/routes` (UI) or 200 (CLI).
- The CLI equivalents (`arenet --export /path` and `arenet
  --restore /path`) are flag handlers in `cmd/arenet/main.go` and
  reuse the same export/restore engine as the API endpoints.

### 3.4 Frontend surface deltas

**Routes page** (`/routes`):

- Replace the existing `Checkbox "Require Basic Auth"` with a
  radio group: None / Basic auth / Forward auth (IdP).
- When "Basic auth" is selected: show the Step I.5 fields
  (Username + Password) — unchanged.
- When "Forward auth (IdP)" is selected: show a single `<select>`
  whose options are the names of the configured providers (loaded
  from `/settings/forward-auth/providers`); show a hint with a
  link to the Settings page when no provider is configured (same
  pattern as J.4's DNS-01 selector).

**Settings page** (`/settings`):

- New section: "Forward-auth providers" — table of configured
  providers + "Add provider" button. Each provider edit modal:
  Name (slug), Kind (radio: Authelia / Authentik / Keycloak /
  Generic), Verify URL, Auth-request URI, Copy headers
  (repeater of strings), Client secret (password input with
  `••• set (leave blank to keep)` placeholder).
- New section: "Admin login (OIDC SSO)" — Configured / Not
  configured badge, form with IdP issuer URL, Client ID, Client
  secret (preserve-on-edit), Scopes (repeater), Redirect URL,
  Enabled toggle. Below the form: "Authorized OIDC identities"
  sub-section with an allowlist editor — table of entries with
  columns "Email", "Display name", "Status" (`Pending first
  login` while `Sub == ""`, `Active` once canonicalised — with
  the date of first login on hover), and "Remove" action. The
  "Add identity" form takes only `email` (required) and
  `display_name` (optional); the `sub` is resolved server-side
  on the user's first login per §1.3 decision 13.
- New section: "Backup & restore" — "Export configuration" button
  (with `include secrets` checkbox), "Import configuration"
  button (file upload + confirm-twice modal).

**Login page** (`/login`):

- When OIDC is configured + enabled: show a "Continue with SSO"
  button above the username/password form. The button links to
  `/api/v1/auth/oidc/login`.
- Local username/password form is **always visible** (break-glass
  invariant). No "OIDC only" toggle.

### 3.5 Migrations

Step K introduces two BoltDB migrations:

- **`migrateBasicAuthToAuthMode`** (K.1): for every route row,
  derive `AuthMode` from the legacy `BasicAuthEnabled` field
  (true → `"basic"`, false → `"none"`); move `BasicAuthUsername`
  + `BasicAuthPasswordHash` into the new nested `BasicAuth`
  struct. Pattern: passthrough-map (per the Step J.1 / I.4
  lesson on full-Route round-trip fragility recorded in the
  backlog). Idempotent via shape sentinel: `AuthMode` non-empty
  ⇒ already migrated.

- **`migrateUsersAuthSource`** (K.2): for every user row, set
  `AuthSource = "local"` when the field is empty (i.e. every
  pre-K user, since `AuthSource` did not exist). Pattern:
  passthrough-map. Idempotent: `AuthSource` non-empty ⇒ already
  migrated.

The new buckets (`forward_auth_providers`, `oidc_config`) are
created on first boot — they are empty until the operator
populates them, no migration needed (Step J.4 pattern).

The OIDC allowlist `AllowedIdentities` (§3.1) lives inside the
single `OIDCConfig` row (not a separate bucket) — simpler than
a bucket per allowlist entry.

---

## 4. Sub-tasks (ordered)

The order minimizes blast radius. K.1 is least risky (per-route
auth choice, additive to the route shape). K.2 is most risky
(touches the admin login path + introduces the role model — a
bug locks the operator out; the break-glass invariant explicitly
mitigates this). K.3 is medium risk (touches export/import;
restore-failure cases need care).

Implementation order:

1. **K.1** — per-route auth (backend) + the Routes page UI changes.
   Single commit.
2. **K.2** — OIDC SSO admin auth + viewer/admin role model
   (backend) + Settings page OIDC section + Login page SSO
   button + admin Users management UI. Single commit.
3. **K.3** — backup/restore engine (backend + CLI flags) + Settings
   page backup/restore section. Single commit.
4. **K.4** — live smoke test + tag `v0.7.0-step-k`. Mandatory by
   project discipline (mirror Step J §J.7). Smoke doc lands as
   `docs/smoke-test-step-k.md`, single commit; the tag follows
   the smoke verdict PASS.

---

## 5. Per-sub-task design

### 5.1 K.1 — Per-route forward-auth

**Component & decomposition.** Three layers:

- Storage: new `ForwardAuthProvider` struct + bucket; `Route`
  struct gains `AuthMode` + `BasicAuth` + `ForwardAuth` fields
  (Step I.5 fields moved into the nested `BasicAuth`); validation
  + migration `migrateBasicAuthToAuthMode`.
- API: 4 endpoints for the provider CRUD; route create/update
  validates `AuthMode` enum + cross-rule "ProviderName references
  an existing provider when AuthMode == forward_auth".
- Generator: route loop emits the auth chain branch per
  `AuthMode`. The `forward_auth` JSON shape is the Caddy-
  documented `subroute + handle_response` pattern, parameterised
  by the provider's URL + path + headers.

**Domain model — Route.AuthMode.** Enum of three string values,
materialised at the API layer:
- POST with empty `authMode` → normalised to `"none"`.
- PUT with empty `authMode` → preserve previous (same UX as J.4
  ACMEChallenge).
- Other values rejected with a 400.

**Domain model — ForwardAuthProvider lifecycle.** Same shape as
J.4 DNSProviderConfig:
- Create via POST (first write).
- Read via GET (list / single, secrets redacted).
- Update via PUT (preserve-on-edit for ClientSecret).
- **Delete via DELETE — REJECTED with 409 if any route's
  ForwardAuth.ProviderName references this provider.** The 409
  body lists the route IDs so the operator knows what to fix
  first. (Different from J.4's "no delete" decision — here we
  do have a delete, but it's reference-guarded.)

**Secrets.** Same pattern as J.4: API GET response sets
`ClientSecret: ""` + a `secretSet: bool` flag; audit
`forward_auth_provider_updated` emits scrubbed before/after;
BoltDB at-rest cleartext (boundary = file permissions).

**Generator emission.** For a route with `AuthMode ==
"forward_auth"` referencing provider `authelia-prod`:

```json
{
  "handler": "subroute",
  "routes": [{
    "handle": [
      {
        "handler": "reverse_proxy",
        "rewrite": {
          "method": "GET",
          "uri": "/api/authz/forward-auth"
        },
        "upstreams": [{"dial": "authelia:9091"}],
        "headers": {
          "request": {
            "set": {
              "X-Forwarded-Method": ["{http.request.method}"],
              "X-Forwarded-Uri": ["{http.request.uri}"]
            }
          }
        },
        "handle_response": [{
          "match": {"status_code": [2]},
          "routes": [
            { "handle": [{"handler": "vars"}] },
            // Per-header copy block, repeated for each header in
            // provider.CopyHeaders (see the Caddy reference sample).
            ...
          ]
        }]
      },
      { "handler": "reverse_proxy", "upstreams": [...] }
    ]
  }]
}
```

The per-header copy block is verbatim from the Caddy reference
sample. Arenet emits one such block per header in
`provider.CopyHeaders`.

**Failure mode — provider unreachable at the IdP layer.** Caddy
returns 401 / 403 from the IdP forward call → propagated to the
end user. Arenet logs the failure via Caddy's structured logger
but does not take additional action (no fallback to Basic Auth,
no auto-disable: §1.3 decision 1 + Δ1).

**API validation rules.**

On `POST/PUT /routes`:
- `AuthMode` must be `"none"` / `"basic"` / `"forward_auth"` (or
  `""` on PUT → preserve previous).
- When `AuthMode == "basic"`: `BasicAuth.Username` required;
  `BasicAuth.Password` required on POST + on PUT when no existing
  hash; preserve-on-edit semantics (Step I.5 pattern).
- When `AuthMode == "forward_auth"`: `ForwardAuth.ProviderName`
  required; the provider must exist (cross-rule, looked up at
  request time).
- Mutual exclusivity (AC #5): the request must not set BOTH
  `BasicAuth.Password != ""` AND `ForwardAuth.ProviderName !=
  ""`. Rejected as 400 "auth_mode and field shape disagree —
  ensure exactly one auth method is configured".

On `POST/PUT /settings/forward-auth/providers`:
- `Name` required, slug shape (`^[a-z0-9-]{1,32}$`).
- `Kind` must be `"authelia"` / `"authentik"` / `"keycloak"` /
  `"generic"`.
- `VerifyURL` must parse as `http://` or `https://` URL.
- `AuthRequestURI` must start with `"/"`.
- `CopyHeaders` each element must be an HTTP token (RFC 7230).
- `ClientSecret`: preserve-on-edit (empty preserves previous).

On `DELETE /settings/forward-auth/providers/{name}`:
- Check no route references this provider → 409 with the offending
  route IDs.

**Tests.**
- Storage validate: enum check + cross-rule (basic vs forward_auth
  fields mutex).
- API: each AC #1–#5 surface tested via httptest, including the
  mutex rejection (AC #5).
- Generator: a route with each `AuthMode` value emits the right
  shape; `TestBuildConfigJSON_LoadsCleanly` extended with a
  forward-auth route + a fixture ForwardAuthProvider (the Caddy
  modules involved are all in `standard`, no new blank import).
- Migration: a pre-K route row with `BasicAuthEnabled: true`
  decodes into `AuthMode: "basic"` + `BasicAuth.Username` /
  `PasswordHash` populated.

### 5.2 K.2 — OIDC SSO on admin login

**Component & decomposition.**

- Storage: new `OIDCConfig` struct + bucket; `User` gains
  `AuthSource` + `OIDCSub`.
- New `internal/auth/oidc/` package: discovery doc cache, state +
  nonce generation, ID-token verification, allowlist check.
  Built on `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`.
- API: new OIDC endpoints (`/auth/oidc/login`, `/auth/oidc/
  callback`); new Settings endpoints (`/settings/oidc`, `/settings/
  oidc/allowlist`).
- Middleware: NO CHANGE to SoftAuth / HardAuth middlewares
  (decision §1.3 #5 — local login does NOT depend on OIDC). The
  OIDC handlers issue the same `arenet_session` cookie that
  `POST /auth/login` issues; downstream middlewares are
  identity-source-agnostic.

**Break-glass invariant — preserve local login path verbatim.**
The existing `POST /api/v1/auth/login` is touched only to:
- Read the OIDC config to know whether OIDC has ever been
  configured (for the `login_break_glass` audit emission only).
- The actual auth logic is unchanged: lookup user by username,
  compare password, issue session, audit.

Concretely, the OIDC config lookup at the login handler MUST be
non-fatal: if reading the OIDC config fails (storage error,
deleted bucket, malformed row), the login proceeds anyway. The
break-glass audit emission is skipped in that case (with a warn
log).

**OIDC config lifecycle.**
- Initial state: bucket empty. UI shows "Not configured" badge.
- On PUT with a fresh config: Arenet validates the issuer URL by
  attempting the discovery doc fetch with a 10-second timeout.
  Failure → 400 "could not fetch OIDC discovery doc from issuer".
  Success → store + cache the discovery doc + emit
  `oidc_configured` audit event.
- On PUT with the `enabled: false` toggle: store + cache, but
  the `/auth/oidc/login` endpoint returns 503 "OIDC SSO disabled"
  and the Login page no longer renders the SSO button (frontend
  reads the `enabled` flag).
- `ClientSecret` preserve-on-edit pattern (Step J.4).

**Discovery doc cache.** In-memory, refreshed at intervals
(default 1 h, configurable per the OIDCConfig). On refresh
failure, the cache is kept (do not invalidate on transient
failures). On a config update, the cache is forcibly refreshed.

**State + nonce.**
- State: 32-byte cryptographically-random opaque value, stored
  in a short-lived (`5 min`) cookie `arenet_oidc_state`. The
  callback validates state == cookie value AND state hasn't
  been used before (single-use, stored in the session store
  with a 5-min TTL).
- Nonce: 32-byte cryptographically-random opaque value, embedded
  in the auth request, validated against the ID token's `nonce`
  claim.

**ID token verification.**
- Signature: against the JWKs from the discovery doc.
- Issuer: matches the configured issuer.
- Audience: includes the configured client ID.
- Expiry: in the future.
- `nonce`: matches the cookie nonce.
- All validated via `go-oidc/v3`'s `IDTokenVerifier`.

**Allowlist check + canonicalisation (per §1.3 decision 13).**

The validated ID token carries both `sub` (stable identifier)
and `email` (operator-known identifier). The callback resolves
the match in this order:

1. **First-pass: match by `Sub`.** Iterate
   `OIDCConfig.AllowedIdentities`. If any entry has
   `Sub == token.sub` (non-empty), the entry is the match.
   This is the steady-state path (post-canonicalisation).
2. **Second-pass: match by `Email`** (case-insensitive,
   trimmed). REQUIRES the ID token's `email_verified` claim
   to be present AND `true`. If the claim is absent or
   `false`, the second-pass match is SKIPPED entirely — the
   match falls through to (3) and the login is rejected.
   Rationale: matching on an unverified email allows an
   IdP-side malicious account to canonicalise into someone
   else's pending invite (invite hijack). The standard OIDC
   guard for this exact attack surface costs one claim
   check; a frozen auth spec must carry it.
   If `email_verified == true` AND any entry has
   `strings.EqualFold(strings.TrimSpace(entry.Email), strings.TrimSpace(token.email))`
   AND `Sub == ""`, the entry is the match AND the entry's
   `Sub` is updated to `token.sub` in storage (the
   canonicalisation). `FirstLoginAt` is set to `time.Now().UTC()`.
   The steady-state pass (1) is NOT affected — `sub` is not
   user-controllable IdP-side, so the verified-email guard
   does not apply there.
3. **No match** (both passes empty): reject with
   `oidc_login_rejected` audit event (records the rejected
   `sub` and the rejected `email` for trace), redirect to
   `/login?error=not_authorized`.

**Why the order matters:** match-by-Sub first ensures
stable lookup once canonicalised; match-by-Email is the
bootstrap path that fires at most once per identity (the
post-canonicalisation `Sub` then takes over). An IdP that
recycles a `sub` for a different email — pathological but
possible — would mismatch on the Sub-pass and could
spuriously canonicalise a different email's entry on the
Email-pass; mitigation: the Email-pass requires `Sub == ""`,
which a canonicalised entry no longer has. So the order is
safe even under pathological IdP behaviour.

**User row resolution after a match:**
- If the canonicalised `Sub` matches an Arenet user row
  (`OIDCSub == sub`), issue a session for that user.
- Otherwise auto-create a user row: `AuthSource: "oidc"`,
  `OIDCSub: token.sub`, `Username` derived from
  `token.preferred_username` (or `token.email`'s local part if
  missing), `DisplayName` from `token.name` (or
  `entry.DisplayName` if the IdP omitted the claim),
  `PasswordHash: ""` (OIDC users have no local password),
  `Role: "viewer"` (§1.3 decision 12 default).

**Session model.** OIDC-source users get the SAME `arenet_session`
cookie as local-source users (same SessionStore, same TTL, same
sliding renewal). The session row stores the user ID;
downstream middlewares don't know or care about the auth source.

**Local-admin password rotation (AC #11).** The existing
`POST /api/v1/auth/me/password` handler:
- Always emits the Step D `password_changed` audit event
  (preserved).
- ADDITIONALLY emits `local_admin_password_rotated` when the
  acting user's `AuthSource == "local"` AND OIDC has been
  configured (read non-fatally; on read error, skip the
  additional emission, log warn).

**Failure modes.**
- IdP unreachable on discovery doc refresh: cached doc kept;
  warn log; subsequent logins proceed against cached doc.
- IdP unreachable on callback's token exchange: 502 to the user,
  redirect to `/login?error=idp_unreachable`. The local login
  path remains usable.
- State / nonce mismatch on callback: 400 + `oidc_callback_
  invalid_state` audit + redirect to `/login?error=invalid_
  state`.
- ID-token invalid signature: same shape as state mismatch.

**Tests.**
- Storage: OIDCConfig validate (issuer URL parse, scopes
  required, client ID required).
- OIDC package: state + nonce generation entropy, single-use
  state, discovery doc cache refresh + failure path, ID-token
  verification (mock JWKs + valid/expired/wrong-issuer fixtures).
- API: login endpoint redirects to issuer; callback validates +
  creates session OR rejects + audits.
- Allowlist enforcement + auto-create user on first allowed
  login.
- Break-glass: AC #9 + AC #10 + AC #11.

### 5.3 K.3 — Backup / restore

**Component & decomposition.**

- New `internal/backup/` package: exporter (build the JSON from
  the BoltDB), importer (apply a JSON to a BoltDB instance),
  redaction logic, secret-sentinel handling.
- API: 2 endpoints (`GET /admin/backup`, `POST /admin/restore`).
- CLI: 2 flags on `cmd/arenet/main.go` (`--export PATH`,
  `--restore PATH`).
- Frontend: Settings page "Backup & restore" section.

**Export JSON shape.**

```json
{
  "schema_version": "1.0.0",
  "exported_at": "2026-05-26T20:00:00Z",
  "secrets_included": false,
  "arenet_version": "v0.7.0-step-k",
  "routes": [ /* every Route row, secrets redacted by default */ ],
  "dns_providers": [ /* every DNSProviderConfig row, secrets redacted */ ],
  "forward_auth_providers": [ /* every ForwardAuthProvider, secrets redacted */ ],
  "oidc_config": { /* the single OIDCConfig row, ClientSecret redacted */ },
  "users": [ /* every User row, PasswordHash redacted */ ]
}
```

Redaction: every secret field is replaced by the literal string
`"$$ARENET_REDACTED$$"`. On `--include-secrets` opt-in,
`secrets_included: true` is set and the actual secret values
appear.

**Secret scope (B clarification).** The exhaustive list of fields
treated as secrets and subject to the `"$$ARENET_REDACTED$$"`
redaction in the default export:

| Source                            | Field                              | Why secret |
|-----------------------------------|------------------------------------|------------|
| `users[].password_hash`           | argon2id PHC string of local admin | Hash is still credential-equivalent to anyone who can verify against it |
| `routes[].basic_auth.password_hash` | argon2id PHC of route Basic Auth | Same as above |
| `dns_providers[].application_key` | OVH API application key            | Replayed verbatim to OVH at every cert renewal |
| `dns_providers[].application_secret` | OVH API application secret      | Same |
| `dns_providers[].consumer_key`    | OVH API consumer key               | Same |
| `forward_auth_providers[].client_secret` | IdP-issued client secret    | Replayed to the IdP on the forward_auth sub-request |
| `oidc_config.client_secret`       | Arenet's OIDC client secret at the IdP | Replayed to the IdP on every token exchange |

Every other field round-trips normally (route hosts, upstream
URLs, weights, LB policies, WAF modes, ACME challenges,
endpoint identifiers like OVH region or OIDC issuer URL).

**Operator-facing security warnings (B clarification).** Three
explicit surfaces:

1. **CLI `--include-secrets`** emits a warning to stderr
   BEFORE writing the file:
   ```
   WARNING: --include-secrets requested. The exported file will
   contain PLAINTEXT secrets (admin password hashes, OVH API
   keys, OIDC client secret, forward-auth provider client
   secrets, per-route Basic Auth hashes). Store the file with
   restricted permissions (chmod 600) and consider encrypting
   at rest (age / GPG / vault).
   ```
   The CLI then writes the file with `os.WriteFile(path,
   data, 0o600)` — the file-permission protection is enforced
   by Arenet at write time, not by trusting the operator.

2. **API `GET /admin/backup?include-secrets=true`** sets a
   response header `X-Arenet-Secrets-Included: true` and
   surfaces the same warning in the UI's "Export configuration"
   modal before the download starts. The UI modal also reminds
   the operator that the browser will save the file with its
   default permissions (typically 0o644 on Unix, ACL-inherited
   on Windows) — Arenet cannot enforce the file mode for an
   HTTP-downloaded file, so the wording explicitly says "save
   the downloaded file to a restricted location".

3. **Audit `config_exported`** records `secrets_included:
   bool` so a post-mortem can trace which export carried
   secrets. The actor user is recorded as always.

The export wire shape itself carries the top-level
`secrets_included: bool` so any consumer of the file (a future
restore tool, an inspector script) can read the flag without
parsing the body. This is the same flag the API + CLI emit;
single source of truth.

**Schema version compatibility rule (Q3 arbitration).** The
`schema_version` field is a semver-shaped string. The restore
implementation enforces ONE rule, written explicitly in the
code at the entry point of the importer:

> **The MAJOR version of the import file's `schema_version` MUST
> equal the MAJOR version that the running binary knows how to
> read.** A MINOR or PATCH mismatch is accepted with a warn log
> (forward-compat / backward-compat tolerance); a MAJOR mismatch
> is rejected with a clear error message naming both versions.

K.3 ships with binary-known schema MAJOR `"1"` (the file declares
`"1.0.0"`). A future K' that introduces a breaking change to the
shape (e.g. removing a field, restructuring a section) bumps to
`"2.0.0"`; a v(K) binary refuses to import a `"2.0.0"` file with
a clear error, and the operator either upgrades the binary or
downgrades the file via a side migrate tool. This explicit rule
removes the "version field as decoration" risk.

Forward-compat additions (e.g. K introduces field X, K+1
introduces field Y on a `"1.1.0"` schema): a v(K) binary reading
a `"1.1.0"` file silently ignores the unknown Y field (Go's
`json.Unmarshal` discards unknown fields by default unless
`DisallowUnknownFields` is set — restore does NOT set it for
this reason). A v(K+1) binary reading a `"1.0.0"` file fills the
missing Y with the zero value.

**Restore behaviour — live instance semantics (Q4
arbitration).** The restore path via the API endpoint
(`POST /api/v1/admin/restore`) is a **hot-apply**: after the
BoltDB transaction commits successfully, the handler calls
`caddymgr.ReloadFromStore` (the same path every route mutation
uses today). On reload failure, the storage is rolled back via
the same single-rollback pattern Step I uses for route
mutations (`store.UpdateRoute(previous)`), so a Caddy that
rejects the restored config does not leave the operator with a
broken BoltDB.

**OIDC reconfiguration via restore** is a special sub-case: if
the restored `OIDCConfig` is different from the live one
(different issuer, client ID, scopes, allowed_identities), Arenet
does NOT automatically invalidate active sessions. The operator
sees the change in the audit log and can manually revoke
sessions if they want (Settings → Sessions → Revoke); the
automatic invalidation would surprise the operator
mid-restore (e.g. the very session running the restore call
would die). Documented behaviour, not a bug.

**Restore via CLI** (`arenet --restore PATH`) runs at boot,
before Caddy starts. Same engine, no live-instance semantics
apply (Caddy starts fresh from the post-restore BoltDB).

**Sentinel handling on restore (the mirror of the export
redaction).** The export writes `"$$ARENET_REDACTED$$"` in every
secret field when secrets are excluded; the restore must define
what happens when it reads that sentinel back. Three options
considered, one chosen:

| Option | Behaviour | Verdict |
|--------|-----------|---------|
| (a) write the literal sentinel into the target field | Auth instantly broken (password_hash literally equals the sentinel; nobody can log in; OIDC client_secret literal value rejected by the IdP at token exchange) | **REJECTED** — silent footgun; the field is "set" so validators do not catch it; auth fails only at use time |
| (b) preserve the existing value in the target BoltDB | Matches the Step I.5 BasicAuth + Step J.4 DNS provider preserve-on-edit semantics: "redaction in transit, value preserved in place" | **CHOSEN** — single semantic across the codebase, no surprise |
| (c) clear the field (empty string) | Equivalent to (a) at validate time: most secret fields are required by the storage validators (Step I.5 `BasicAuthPasswordHash` required when enabled, Step J.4 DNS provider validate requires all 4 fields non-empty, etc.). The row would be rejected at insert. | **REJECTED** — looks safer than (a) but produces the same broken outcome via a different code path |

The chosen behaviour is **(b) preserve in place by ID-match**.
The detailed sentinel-handling rules below are non-negotiable:

1. **Match a sentinel only against a target row of the same
   logical identity.** Per entity:
   - Route: matched by `id` (UUID v7) — a restored route whose
     `id` already exists in the target gets the existing
     `basic_auth.password_hash` inherited for any sentinel
     occurrence.
   - User: matched by `id` (UUID v7) — same rule for
     `password_hash` and (when AuthSource is "oidc") for any
     OIDC token cache the user row carries.
   - DNS provider: matched by bucket key `"ovh"` (a single
     row, J.4 design) — sentinels inherit the existing OVH
     secrets.
   - Forward-auth provider: matched by `name` (slug-shaped
     identifier) — sentinel `client_secret` inherits the
     existing provider's `client_secret`.
   - OIDC config: matched by bucket key `"default"` (a single
     row) — sentinel `client_secret` inherits the existing
     OIDC config's `client_secret`.

2. **If the sentinel finds no matching target row, restore
   REJECTS the row** (unless the operator opted into
   `--allow-incomplete-restore`, see scope below) with a
   clear error message naming the field, the affected
   entity, AND the two recovery paths — the same two paths
   the disaster-recovery pre-flight surfaces:
   ```
   restore: cannot import row routes[3] (id=ab12...): field
   basic_auth.password_hash is the redaction sentinel and no
   route with this id exists in the target. The restored row
   would have no usable secret.

   Two paths forward:
    (a) Re-export the source instance with --include-secrets
        (mind the file-permission warning) and re-import.
    (b) Pass --allow-incomplete-restore to accept this row
        knowingly. The affected secret field will be cleared;
        the route's Basic Auth will need to be re-saved by
        hand before the route works again. The boot WARN at
        next start lists every such row.
   ```
   The transaction rolls back; no partial restore.

3. **All-or-nothing transaction.** If ANY row's sentinel
   resolution fails (rule 2) and the operator has not opted
   into `--allow-incomplete-restore`, the whole import is
   rejected and the BoltDB is left untouched (the
   transaction never commits).

4. **`--allow-incomplete-restore` scope (general, not
   pre-flight-only).** The bypass flag covers BOTH
   unresolvable-sentinel failure modes "never silent" must
   handle:
   - The disaster-recovery pre-flight case (fresh target +
     no-secrets import — every sentinel necessarily fails to
     resolve).
   - The partial-mismatch case (non-empty target + an import
     row's logical identity does not match a target row, e.g.
     a route the operator deleted between export and re-
     import). Same broken-secret outcome on the affected row,
     same operator recourse needed.

   With the flag set, sentinels that find no inheritable
   value clear the affected field to empty string, the row's
   storage validate is bypassed for those fields (the
   incomplete-restore code path, not the normal validators
   — fail-loud at the validator would defeat the operator's
   explicit choice), the import proceeds, and the next boot
   prints a startup WARN listing every row that needs a
   secret re-saved.

   Without the flag, every unresolvable sentinel — pre-flight
   blanket or per-row partial — produces the actionable
   reject-with-two-paths message above. "Never silent" =
   "always actionable" on every failure path.

**Disaster-recovery flag (fail-loud on bare instance restore).**
The 5% scenario `--include-secrets` exists for is "restore
the full Arenet config onto a fresh disaster-recovery instance".
Restoring a no-secrets export (the 95% default) onto a fresh
target tries to inherit secrets that do not exist → rule 2 fires
on every secret-bearing row → all-or-nothing rejection. **The
error message has to make the WHY obvious**, because rejecting
"all" rows on a fresh target without an explanation looks like
a generic restore failure.

The restore engine therefore runs a **pre-flight check** as the
very first step:

- Read the import file's top-level `secrets_included: bool`.
- If `secrets_included == false` AND the destination BoltDB has
  zero `users`, zero `dns_providers`, zero
  `forward_auth_providers`, zero `oidc_config` rows (i.e. a
  truly fresh instance), the engine aborts with the dedicated
  error message:

  ```
  restore: import file was exported WITHOUT --include-secrets
  (secrets_included: false) AND the target instance has no
  existing secrets to inherit. The restored configuration would
  have no admin password, no OIDC client secret, no OVH DNS
  credentials, no per-route Basic Auth passwords, and no
  forward-auth client secrets — the resulting instance would be
  inaccessible.

  Two paths forward:
   (a) Re-export the source instance with --include-secrets
       (mind the file-permission warning) and re-import.
   (b) Pass --allow-incomplete-restore to accept this state
       knowingly. The restored instance will have a working
       admin user (via re-run of the boot-time setup token) but
       every per-route Basic Auth, OVH DNS, forward-auth, and
       OIDC field will need to be re-saved by hand before the
       corresponding routes work again.
  ```

- With `--allow-incomplete-restore` (CLI flag) or the equivalent
  UI confirm-twice toggle, the engine proceeds: each sentinel
  with no inheritable value clears the field to empty string,
  the row's storage validate is bypassed for the affected
  fields (a dedicated "incomplete restore" code path, not the
  normal validators — fail-loud at the validator would defeat
  the operator's explicit choice), and the resulting BoltDB
  carries every secret-bearing row in a "needs re-saved"
  state. The next boot prints a startup WARN listing the
  affected rows (cross-reference §1.6 J.4 boot WARN pattern).

  An incomplete restore is NEVER the default. The flag must be
  explicit. The pre-flight error message above is the only
  path to discovering the flag exists — the documentation
  surface for the flag is the error message itself, by design.

- If the destination instance has at least one secret-bearing
  row already, the pre-flight skips this check (the operator
  is restoring onto an existing instance, secrets-by-ID match
  will work).

**Per-section restore steps** (after the pre-flight passes):
- Validate the top-level schema_version per the MAJOR-equal rule
  above.
- For each section, build the new BoltDB state in a transaction:
  - Routes: clear the bucket, re-insert all from the JSON. For
    each route whose `basic_auth.password_hash ==
    "$$ARENET_REDACTED$$"` AND whose ID matches an existing
    route in the current state, inherit the existing hash. Per
    rules 1-2 above.
  - DNS providers, forward-auth providers, OIDC config: same
    sentinel rules.
  - Users: same sentinel rules. Empty-users edge case per
    AC #15 + Δ5.
- All-or-nothing semantics: if any row fails validation OR any
  unresolved sentinel exists, no row is applied (rollback
  inside the transaction).

**Emergency lock-out path** (AC #15 + Δ5): the importer counts the
users in the destination state post-restore; if zero AND
`--allow-empty-users` is not set, reject with a clear error.
Note this is a separate check from the disaster-recovery
pre-flight: a non-empty target can still produce zero post-
restore users if the import file's users array is empty.

**Audit events.**

The restore is significantly more destructive than the export.
Both must be audited; the restore audit is richer.

- `config_exported` — emitted on successful export. Records
  `secrets_included: bool` (so a post-mortem can tell whether a
  given export carried secrets — see §5.3 export warnings).
- `config_restored` — emitted on successful restore. Records
  the following metadata in the audit message:
  - `source_sha256`: SHA-256 of the imported file (trace
    "which file landed").
  - `schema_version`: version string from the import file.
  - `secrets_included_in_source`: bool, from the file.
  - `allow_incomplete_restore`: bool, whether the operator
    used the dedicated bypass flag.
  - Per-section counts: `routes_imported`, `users_imported`,
    `dns_providers_imported`,
    `forward_auth_providers_imported`,
    `oidc_config_imported` (bool — single row).
  - Sentinel resolution counts (operationally useful for
    post-mortem): `sentinels_inherited_total` (sentinels that
    found a target match), `sentinels_unresolved_total`
    (sentinels that landed in an incomplete-restore bypass).
- `config_restored_rejected` — emitted on a REJECTED restore
  attempt. Records the failure reason (schema_version
  mismatch, sentinel-without-match, empty-users without flag,
  Caddy reload failure post-restore, etc.). Always audit-able
  even on failure: a rejected restore is the kind of event an
  operator wants to trace ("did someone try to take over my
  instance?").

**Tests.**
- Round-trip export → import on a fresh empty store **with
  --include-secrets**: produces the same state as the source
  byte-for-byte (modulo timestamps + IDs).
- Redaction: secrets are `$$ARENET_REDACTED$$` in the default
  export; cleartext when opted in.
- Sentinel inheritance: restore onto an existing target with
  matching IDs preserves the target's secrets for every
  sentinel-bearing row.
- Sentinel rejection: restore onto a target where the route ID
  doesn't exist + the import has a sentinel → rejected with
  the specific error message (rule 2).
- Disaster-recovery pre-flight: restore a no-secrets export onto
  a truly fresh target → aborts with the dedicated pre-flight
  error message; same restore with `--allow-incomplete-restore`
  proceeds and the resulting BoltDB has the secrets cleared on
  the affected rows.
- Restore rejects empty-users by default; accepts with
  `--allow-empty-users`.
- Audit emission: `config_exported` on every export,
  `config_restored` on every successful restore with the full
  metadata payload, `config_restored_rejected` on every failed
  attempt.

---

## 6. Migration strategy

Two BoltDB migrations, both shape-based + idempotent. The
passthrough-map choice differs between them based on the J.1 /
I.4 lesson recorded in the backlog ("any step that REMOVES a
field from Route MUST write its migration in the passthrough-map
pattern; full-Route round-trip is only safe for steps that
exclusively add fields"):

- **K.1** REMOVES the legacy keys `basic_auth_enabled`,
  `basic_auth_username`, `basic_auth_password_hash` from each
  route row (they are subsumed by the new `AuthMode` + nested
  `BasicAuth` struct). The backlog rule therefore directly
  applies: K.1 uses **passthrough-map** (set new keys, delete
  legacy keys, re-marshal). Full-Route round-trip would silently
  drop any other key that a hypothetical later step might add
  without K.1 knowing — exactly the I.4 trap.

- **K.2** ADDS the field `auth_source` (and `oidc_sub`) to each
  user row, without removing anything. The full-Route round-trip
  pattern is therefore safe by the backlog rule, but K.2 uses
  **passthrough-map anyway** as a defence-in-depth choice: it
  preserves forward-compat for a future binary downgrade
  scenario (a v(K+1) admin runs the v(K) binary briefly — a
  full-Route round-trip on v(K) would drop any v(K+1) field on
  re-write). At the K.2 cost (one extra helper function), the
  posture protects the wider lifecycle.

### 6.1 K.1: migrateBasicAuthToAuthMode

For every row in the `routes` bucket:

- Read as `map[string]any`.
- If `auth_mode` key is present (non-empty string) → already
  migrated, skip.
- Else, derive `auth_mode`:
  - If `basic_auth_enabled` (legacy bool) is `true` → `"basic"`.
  - Else → `"none"`.
- Build the new `basic_auth` nested struct from
  `basic_auth_username` + `basic_auth_password_hash` (legacy keys).
- Initialise `forward_auth` as `{"provider_name": ""}`.
- Remove the legacy keys (`basic_auth_enabled`,
  `basic_auth_username`, `basic_auth_password_hash`).
- Re-marshal + write.

Sentinel: `auth_mode` non-empty ⇒ already migrated.

Ordering: must run BEFORE `migrateUpstreamURLToPool` is consulted
in case future migrations add fields adjacent. Currently no
ordering conflict since `migrateBasicAuthToAuthMode` only
restructures the Step I.5 auth keys.

### 6.2 K.2: migrateUsersAuthSourceAndRole

For every row in the `users` bucket:

- Read as `map[string]any`.
- If `auth_source` key is present (non-empty string) AND `role`
  key is present (non-empty string) → already migrated, skip.
- Else, set the missing fields:
  - `auth_source = "local"` if absent (every pre-K user is
    local-source).
  - `role = "admin"` if absent (every pre-K user was admin per
    Step D phase 1; §1.3 decision 12 preserves their privilege).
  - `oidc_sub = ""` (zero-value, no OIDC mapping on pre-K rows).
- Re-marshal + write (passthrough-map per §6 intro: forward-compat
  defence).

Sentinel: both `auth_source` AND `role` non-empty ⇒ already
migrated. Compound sentinel guards against a partially-migrated
row landing in a downgraded-binary scenario — a single-key
sentinel would let a v(K) → v(K+1) → v(K) cycle leave `role`
empty if v(K+1) had only set `auth_source`.

### 6.3 New buckets (no migration needed)

`forward_auth_providers` (K.1), `oidc_config` (K.2): created on
first boot via `tx.CreateBucketIfNotExists` (Step J.4 pattern).
Empty until the operator configures.

### 6.4 §6.2 verbatim table — Step K migration reference

| Field                        | Pre-K row                              | Post-K row                                    |
|------------------------------|----------------------------------------|-----------------------------------------------|
| `Route.AuthMode`             | absent                                 | `"basic"` if BasicAuthEnabled was true; `"none"` otherwise |
| `Route.BasicAuth.Username`   | legacy `basic_auth_username`           | same value, nested                            |
| `Route.BasicAuth.PasswordHash` | legacy `basic_auth_password_hash`    | same value, nested                            |
| `Route.ForwardAuth.ProviderName` | absent                             | `""` (no provider referenced)                 |
| `User.AuthSource`            | absent                                 | `"local"` (every pre-K user)                  |
| `User.OIDCSub`               | absent                                 | `""` (cleared by zero-value decode)           |
| `User.Role`                  | absent                                 | `"admin"` (every pre-K user — they were admin before, they stay admin per §1.3 decision 12) |

---

## 7. Smoke test plan (skeleton, filled at K.4)

The Step K smoke doc (`docs/smoke-test-step-k.md`) is written during
K.4, following the Step J pattern. Phases:

- **0. Setup** — backend + frontend dev servers + browser; OIDC
  testing uses a local Authentik or Authelia in Docker (the
  smoke doc will pin which); forward-auth same.
- **Phase A — Regression Step J** — login + route CRUD + audit +
  /healthz + theme toggle + sidebar + topology + the Step J B.x
  features (LB policies, active HC, DNS-01) — none of these
  should regress. Plus the AC #1 path: pre-K routes with
  `BasicAuthEnabled` migrate at first boot to `AuthMode:
  "basic"`.
- **Phase B — New Step K features**:
  - **B.1 (K.1)** — configure a forward-auth provider via the
    Settings UI; create a route protected by it; verify
    unauthenticated request flows through to the IdP login;
    verify successful auth round-trips to the upstream with the
    copied headers. Use a local Authelia or Authentik. Plus the
    mutex rejection (AC #5).
  - **B.2 (K.2)** — configure OIDC against a local IdP; verify
    the SSO login round-trip; verify allowlist enforcement
    (rejected sub).
  - **B.3 (K.2 break-glass)** — with OIDC configured, stop the
    IdP, attempt local login → verifies AC #9. Verify
    `login_break_glass` audit emission (AC #10). Verify local
    admin password rotation emits `local_admin_password_rotated`
    (AC #11).
  - **B.4 (K.3)** — export config via UI + CLI, verify the JSON
    shape and the redaction (AC #13). Re-import on a fresh
    instance, verify byte-for-byte round-trip (AC #12). Test the
    empty-users rejection (AC #15).
  - **B.5 (K.3 restore secrets)** — restore with redacted
    sentinels onto a current state that has the secrets — verify
    secrets carry forward (AC #14).
- **Phase C — AC validation matrix** — one row per AC in §2.
- **Phase D — Migration validation** — boot a Step K binary
  against a pre-Step-K snapshot (`v0.6.0-step-j`); verify routes
  migrate per §6.4 table; idempotent re-boot.

---

## 8. Tag plan

Mirrors Step J §8.

1. Spec freeze: `v0.7.0-step-k-spec` (this document, after
   Ludo review + freeze).
2. Implementation commits: one per sub-task per §4 ordering.
3. Smoke doc: `docs/smoke-test-step-k.md` written during K.4.
4. Release tag: `v0.7.0-step-k` after the smoke verdict PASS.

---

## 9. Implementation notes

- New Go deps to add (verified existing in go.sum where
  noted): `github.com/coreos/go-oidc/v3` (not yet in go.sum
  — add at K.2 implementation), `golang.org/x/oauth2` (already
  in go.sum transitively via Caddy, verify version pin at
  K.2 time).
- `caddy-dns/ovh` blank import (Step J.4) stays. No new blank
  imports needed for K.1 — `forward_auth` uses standard
  modules.
- The K.1 generator emission is verbose (the per-header copy
  block is ~50 LoC per header in Caddyfile-adapt). Recommend
  factoring into a `buildForwardAuthHandler(p ForwardAuthProvider)
  map[string]any` helper, akin to the Step I helpers
  (`buildWAFHandler`, `buildHeadersHandler`).
- The `subroute` handler is the wrap for the forward_auth
  subroutine pattern. Verified empirically in
  `caddy/caddytest/integration/caddyfile_adapt/forward_auth_
  authelia.caddyfiletest`. Caddy v2.11.3 supports it natively.
- AGPL header convention (per CLAUDE.md) applies to every new
  Go / Svelte file in the step.

---

## 10. Review history

The seven open questions of the initial DRAFT were arbitrated by
Ludo in the review pass on 2026-05-26. Resolutions:

- **Q1** Basic Auth stays single-credential. Multi-user Basic
  Auth backlog entry is DECLINED — superseded by K.1
  forward_auth (recorded in `docs/backlog-step-j.md`).
- **Q2** OIDC auto-create + role model. Auto-create stays.
  Default role for an auto-created OIDC user is `viewer`;
  elevation to `admin` is an explicit, separate operator
  gesture (§1.3 decision 12, §5.2). Allowlist granularity is
  `sub`-only (§1.3 decision 13); domain-wide or group-wide
  allowlists rejected as too permissive (§1.4).
- **Q3** Schema version is semver-shaped string with an
  explicit compat rule: MAJOR must match the binary's known
  schema MAJOR; MINOR / PATCH mismatch tolerated with a warn
  log (§5.3 schema version compatibility rule).
- **Q4** Restore via API + CLI both retained. API restore is
  hot-apply (BoltDB transaction + `caddymgr.ReloadFromStore`
  with single-rollback on reload failure). OIDC reconfigured
  by restore does NOT auto-invalidate sessions — the operator
  manually revokes if needed (§5.3 restore behaviour).
- **Q5** ForwardAuthProvider DELETE 409-on-reference is
  kept. The asymmetry vs J.4 DNSProviderConfig "no delete" is
  justified in §1.3 decision 14 — different referential model
  (N routes → 1 provider for forward_auth vs no per-route
  reference for OVH).
- **Q6** Sub-task order K.1 → K.2 → K.3 confirmed.
- **Q7** Placeholder sub-tasks K.4 (refinements) and K.6
  (frontend) removed from the plan. The smoke is promoted from
  the placeholder K.7 to **K.4 as a proper numbered sub-task**
  (mandatory by project discipline, mirrors Step J §J.7).

The first pass also added three resolutions not in the
original question list:

- **A** Migrations clarification: K.1 IS a remove-fields
  migration (drops legacy `basic_auth_*` keys when nesting),
  so passthrough-map is required by the backlog rule. K.2 is
  pure-additions but uses passthrough-map anyway for
  forward-compat / defence-in-depth (§6 intro).
- **B** Export secret scope made exhaustive (the table in
  §5.3), CLI / API / audit warnings clarified, file-perm 0o600
  enforced by Arenet at CLI write time (§5.3 operator-facing
  security warnings).
- **C** Two new ACs added for explicit redaction coverage:
  AC #2bis (forward_auth client secret) and AC #8bis (OIDC
  client secret), mirroring the AC #10 pattern from Step J.
  AC #8ter pins the default-viewer behaviour of OIDC
  auto-create (§1.3 decision 12).

**Second-pass review (2026-05-26)** addressed two gaps in the
first-pass draft:

- **B-restore mirror** — the first-pass §5.3 covered export
  redaction in full but left restore-side sentinel handling
  underspecified. The second pass adds the explicit
  preserve-by-ID-match rules (option (b) chosen over the
  literal-write footgun (a) and the equivalent-broken-by-
  validator (c)), the disaster-recovery loud-fail pre-flight
  on bare-target restore (with the dedicated
  `--allow-incomplete-restore` bypass), and the enriched
  audit event (`config_restored` with sentinel-resolution
  counts + `config_restored_rejected` on failure). New ACs:
  #14, #14bis, #14ter, #15bis.
- **Q2 allowlist chicken-and-egg** — the first-pass
  "sub-only" decision was incomplete: an OIDC `sub` is opaque
  and unknowable before a user's first login, contradicting
  the operator-invites-by-email UX the mockup showed. The
  second pass rewrites §1.3 decision 13 to a two-step
  lifecycle: operator adds by email (case-insensitive,
  trimmed), the callback canonicalises `sub` on the first
  successful login. Per-identity granularity is preserved
  (no domain-wide or group-wide entries — §1.4 OIDC group
  sync stays deferred). §3.1 `OIDCConfig.AllowedIdentities`
  replaces the flat `AllowedSubs` slice; §5.2 callback logic
  spells out the match-by-sub-then-by-email order with the
  pathological IdP corner explained.

**Second-pass post-review adjustments (2026-05-26)**, integrated
on Ludo's approval before freeze:

- **`--allow-incomplete-restore` scope generalised**, no longer
  pre-flight-only. The flag now covers BOTH unresolvable-
  sentinel failure modes: the pre-flight blanket case
  (fresh target + no-secrets import) AND the per-row partial-
  mismatch case (non-empty target + a row whose identity
  doesn't match the target, e.g. a deleted-since-export
  route). The rule 2 rejection message in §5.3 surfaces the
  same two recovery paths (re-export with `--include-secrets`,
  or use the bypass flag). AC #14, AC #14ter updated to
  reflect the general scope. "Never silent" = "always
  actionable" on every failure mode, not just the pre-flight.
- **`email_verified == true` required for the email-pass
  canonicalisation** (§5.2 callback logic, AC #8). The
  standard OIDC guard against invite-hijack: an IdP-side
  malicious account claiming someone else's email cannot
  canonicalise into a pending invite if the token's
  `email_verified` claim is absent or `false`. New §1.6 Δ7
  records the threat surface and the mitigation; the
  steady-state pass (by `sub`) is not affected (the `sub`
  is not user-controllable IdP-side).

**Spec status:** FROZEN on 2026-05-26 after the second-pass
adjustments above. Tag: `v0.7.0-step-k-spec`.
