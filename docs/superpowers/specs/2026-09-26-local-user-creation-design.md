<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Creating local users — design

**Target version**: v2.48.0
**Date**: 2026-09-26
**Origin**: operator request, raised twice. Confirmed absent: Arenet can
list users, change a role, delete an account and create *service*
accounts — there is no way to create a **human local user**.

---

## Where we start

Verified in the code, not assumed:

- `auth.UserStore.Create(ctx, username, displayName, email, password)`
  already exists and does the right things: username regex and length,
  display-name length, password length bounds, argon2id, and
  `ErrUsernameTaken` on collision. It is used by the boot-time setup
  flow and by nothing else.
- `User.AuthSource` is `"local"` or `"oidc"`, and the store enforces
  mutual exclusion: an OIDC user has no password hash, a local user has
  no `OIDCSub`.
- `User.Role` is `viewer` or `admin`.
- HIBP fields exist (`HIBPCheckStatus`, `PasswordCompromised`) and
  `Create` leaves the status `pending`.
- `UserStore.UpdatePassword` exists and resets the HIBP status.
- The `Email` field's own doc comment reads *"Required on new local
  accounts (setup flow + future invites — Phase 1 of the users-page
  refactor)"*. This is that.

So the storage layer is largely ready. What is missing is an endpoint,
a UI, and a decision about the first password.

---

## The decision that matters: the first password

Three ways to get a password into a new account.

**The admin types one.** Simple, and the admin then knows the user's
password forever unless the user changes it.

**Arenet generates one and shows it once.** The admin never invents a
weak password; the value crosses exactly one screen. Same pattern the
product already uses for service-account tokens, so it is a shape
operators here have met.

**An invite link the user redeems.** Best practice in a SaaS, and the
wrong fit here: Arenet's admin API binds to `127.0.0.1` by default, so
a link handed to a colleague is very often unreachable from where they
are. It also needs a token store, an expiry policy and a public
endpoint — a new authentication surface for a homelab tool whose
operator population is usually one person.

| # | Decision | Rationale |
|---|---|---|
| D1 | **Generate by default, allow typing one** | The generated path is the default because it is the safe one. Typing is kept because handing over a chosen password out of band is a legitimate workflow, and refusing it would just push operators to "password123" via the generator-then-change dance. |
| D2 | **Both paths enforce the same policy**: length bounds, and the HIBP check the login flow already runs | A typed password gets no discount for having been typed. |
| D3 | **The password is shown once and never retrievable** | Mirrors service-account tokens. The response carries it; no endpoint returns it afterwards, and it is never written to the audit log. |
| D4 | **The account is flagged `MustChangePassword`** | Without it the admin knows the user's password indefinitely. With it the exposure is one login. This is the only new field on `User`. |
| D5 | **Admin role only** | Creating an account is a privilege change. Same posture as role editing and deletion. |
| D6 | **Role defaults to `viewer`; `admin` is an explicit choice** | The safe default, and it makes granting admin a deliberate act rather than a forgotten dropdown. |
| D7 | **Refuse a local account whose email is on the OIDC allowlist** | Otherwise that person gets two identities — one password-based, one SSO — and which one they land in depends on how they signed in. The refusal names the conflict. |
| D8 | **Every creation is audited**: actor, new username, role, auth source. No password material, generated or typed | An audit trail that carries credentials is a credential store. |

---

## What `MustChangePassword` costs

It is the expensive half of this feature, because it is not just a
field: the login flow has to surface it, and the UI has to refuse to
let the user anywhere else until they have changed it. The
change-password endpoint already exists, so the work is the gate, not
the mechanism.

**If the operator wants creation sooner**, D4 can ship as a second
step — the field lands now with the account created as
`MustChangePassword: true`, and the gate follows. The accounts are
then correct from the start and only the enforcement is late, which is
the right way round: retrofitting the flag onto accounts created
without it would need a migration and a judgement call about existing
users.

---

## Shape

`POST /api/v1/admin/users` (admin), next to the existing
`/admin/users/{id}/role` and the service-account endpoints.

```json
{"username": "alice", "displayName": "Alice", "email": "alice@example.org",
 "role": "viewer", "password": ""}
```

An empty or absent `password` means generate. The response carries the
account plus, once:

```json
{"user": {...}, "generatedPassword": "…"}
```

`generatedPassword` is present only when Arenet generated it. When the
admin typed one, they already have it and echoing it back would put it
in a place it does not need to be.

Refusals use the coded-error mechanism from v2.46, so they arrive in
the operator's language: `user_username_taken`,
`user_username_invalid`, `user_password_too_short`,
`user_email_on_oidc_allowlist`, `user_role_invalid`.

---

## Empirical validation gates

1. A created user can actually sign in with the returned password, and
   is then required to change it. Asserted against the real login
   handler, not a stubbed one.
2. The password appears in the creation response and **nowhere else** —
   not in `GET /admin/users`, not in the audit event. A test greps the
   audit payload for it.
3. `ErrUsernameTaken` surfaces as a 409 with a code, not a 500.
4. An email on the OIDC allowlist is refused, and the message says why.
5. A `viewer` calling the endpoint gets 403.

---

## Non-goals

**Invite links and email delivery.** Arenet can send mail — it has SMTP
for alerts — and sending a credential by email would be worse than
showing it once on a screen the admin is already looking at.

**Admin-initiated password reset.** The obvious next step, and cheap
once this exists (`UpdatePassword` is already there). Kept separate so
this change stays one decision.

**Groups, per-route permissions, more roles.** `viewer` and `admin`
have been enough so far; inventing a third before anyone needs it
would be inventing a permission model.
