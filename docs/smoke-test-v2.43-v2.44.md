<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke test — v2.43 / v2.44

Everything below came out of one afternoon of dogfooding a real mail
relay (Stalwart behind Arenet) on 2026-09-24. Each item names what to
do, what proves it, and — where there is one — the trap that made it
worth building.

Test host: arenet-test. Backend: Stalwart, another subnet, no NAT
between them (verified: Stalwart logs `remoteIp = 192.168.99.10` for
Arenet's own connections).

---

## 1. The layer-4 test sends a real PROXY header (v2.43)

**Do.** Open a TCP service configured with PROXY protocol v2 — `imaps`
is the one to use — and press **Test the backends**.

**Expect.** A verdict badge next to the backend: *header not refused*.
Not "accepted" — one connection cannot prove the far side parsed the
header, only that it did not hang up, and the wording says exactly
that.

**Then break it on purpose.** On the Stalwart listener, clear
"Override proxy networks" and restart Stalwart. Press the button
again: the verdict must become **header refused**, while the backend
line itself stays green — the dial succeeded, the backend is up, and
the two verdicts are separate on purpose.

Put the setting back afterwards.

**Why this matters.** Before v2.43 the button opened a connection and
closed it. On the morning of 2026-09-24 it reported green while every
real connection was being refused with a TLS decode error.

---

## 2. UDP is untestable, not broken (v2.43)

**Do.** Create a UDP service (the WireGuard preset will do), point it
anywhere, and press **Test the backends**.

**Expect.** *not testable*, with the reason: UDP is connectionless,
there is no handshake to attempt. **Not** a red cross.

**Why.** The previous version dialled TCP whatever the protocol said,
so a healthy UDP relay was reported broken. Delete the service
afterwards if you do not want it.

---

## 3. Layer-4 counters move on their own (v2.43)

**Do.** Open **Services TCP / UDP** and leave the page open. From the
Mac, hold an IMAP session open through Arenet:

```
openssl s_client -connect 192.168.99.10:993 -servername mail.worldgeekwide.fr
```

**Expect.** Within ~5 seconds and without touching the page: the
connection count rises, "open" shows 1, and **the bytes rise while the
session is still open**. Close the session; "open" drops back to 0.

**Why.** Bytes used to be reported only at close, so a phone's IMAP
session — hours long — left the column at 0 B for a relay that was
busy the whole time.

**Also check** the idle lock still works: leave the page open and
untouched for 15 minutes. It must still lock. The polling is tagged as
a background request precisely so it does not hold the session open.

---

## 4. The rollback names the health check (v2.43.1)

**Do.** On the Stalwart webadmin route, set the health check's
**expected body** to something the backend does not answer — `NOPE`
will do — and save. Wait for the probe to mark the backend down (with
`fails=3` and a 30 s interval, about 90 seconds). Now change anything
on the route and save again.

**Expect.** The refusal message names the **health check** and points
at its URI, expected status and expected body. It must **not** tell
you to check the upstream address.

**Then clear the expected body** and save to recover.

**Why.** The old message sent the operator to the one screen where
nothing was wrong. The real cause — a regex expecting `OK` against a
backend answering `{"detail":"OK",…}` — was three fields away.

**Restraint to verify too:** break a route by pointing it at a dead
upstream with **no** health check configured. The message must stay
the generic one. A confidently wrong accusation is the defect being
fixed, in the other direction.

---

## 5. The probe's verdict is in the form (v2.43.1)

**Do.** Open a route that has an active health check.

**Expect.** In the **Health check** section, a line with the current
state (`HEALTHY` / `DEGRADED` / `DOWN` / waiting for the first probe)
and the healthy-over-total count. When it is failing, a sentence
pointing at the URI, the expected status and the expected body.

**And the section badge follows the verdict**: it must not read "on"
in green while the backends are down.

**Creating** a route must show nothing there — no probe has run.

---

## 6. The redirect state (v2.44)

**Do.** Create a route for a spare name, choose the state
**Redirect**, target `https://arenet-test.<lan>` or any other host you
control, leave 301 and "keep the path" on, and save.

**Expect.**

```
curl -I https://<the-route-host>/some/path?x=1
```

answers `301` with `Location: https://<target>/some/path?x=1` — path
**and** query preserved. The certificate must still be valid: a
redirecting route still terminates TLS.

**The loop guard.** Try to set the target to the route's **own** host.
Arenet must refuse at save, name the host, and point at path rules as
the alternative. Try an alias of the same route: same refusal.

**The path trap.** With "keep the path" on, set a target that already
has a path (`https://example.com/app`). Refused, with the reason —
appending the visitor's path would silently produce `/app/a/b`.

**On the list**, a redirecting route shows its state as a badge rather
than the three-way control: switching to a redirect needs a target, so
it happens in the form.

---

## 7. Non-regression

- A route with no redirect and no health-check change must behave
  exactly as before — same certificate, same proxying, same counters.
- The Stalwart mail relays (25 / 465 / 993) must keep working
  throughout: PROXY v2 to Stalwart, real client IP in its logs.
- `arenet backup export` then re-import: a redirecting route must come
  back redirecting. (Routes are snapshotted as whole structs, so this
  is a check that nothing else broke, not that a mapping was added.)
