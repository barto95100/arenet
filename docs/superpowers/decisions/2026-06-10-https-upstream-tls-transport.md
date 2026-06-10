<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# HTTPS upstreams: honour `https://` scheme + route-level `insecureSkipVerify`

Date: 2026-06-10
Status: SHIPPED — commits `a69880d` (storage + Caddy config + wire layer), `37f38a5` (frontend), `f119116` (test-upstream endpoint)
Related tickets: `#R-PROXMOX-HTTPS-LOOP` (RESOLVED), `#F-UPSTREAM-TEST-ENDPOINT` (RESOLVED), `#R-API-PUT-ROUTE-GENERIC-400` (partial — sweep of remaining 16 sites OPEN)

## Context

Operator Day-8 review (2026-06-10) reproduced an infinite-redirect loop on
every route with an `https://` upstream pool. The symptomatic route was
`proxmox.worldgeekwide.fr → https://192.168.1.60:8006`; the browser saw an
endless 301 chain. The same shape would break Synology DSM (`:5001`), ESXi
(`:443`), UniFi controllers (`:8443`), and any other homelab service that
serves only HTTPS.

Empirical reproduction:

```text
# Live Caddy config dump (live admin :2019)
$ curl -s http://localhost:2019/config/apps/http/servers | jq \
    '.[].routes[] | select(.match[0].host[0]=="proxmox.worldgeekwide.fr")
     | .handle[0].routes[0].handle[]
     | select(.handler=="reverse_proxy")'
{
  "handler": "reverse_proxy",
  "upstreams": [ { "dial": "192.168.1.60:8006" } ]
}
```

No `transport` block. Caddy spoke plain HTTP toward the upstream, Proxmox
returned 301 to `https://`, Caddy faithfully re-proxied the redirect to
itself, browser saw infinite loop.

Root cause (audit of `internal/caddymgr/manager.go` upstream-dial path,
pre-fix lines 2453-2474): the `upstreamDial` helper parsed the URL's scheme
ONLY to compute the default port (`:443` for https, `:80` otherwise) but
then dropped the scheme. The `dial` field carried only `host:port`. No
`transport.tls` block was emitted. Caddy defaulted to HTTP transport.

## Decision

Five Q1–Q5 design decisions, validated by the operator before any code
was written:

### Q1: Same-scheme pool invariant (storage + API)

A route's upstream pool must be homogeneous — every URL shares either
`http://` or `https://`. Mixed pools are rejected at the storage validator
with a clear error message and pre-emptively at the frontend submit boundary
(`validateBeforeSubmit` surfaces the same invariant so the operator sees
the error without a backend round-trip).

**Why**: a heterogeneous pool would require either per-upstream `transport`
blocks (which Caddy's `reverse_proxy` does not support — `transport` is
per-handler) or a per-handler transport that lies about the scheme of at
least one element. Both options confuse the operator more than they help.
Forcing same-scheme makes the relationship "pool scheme → transport"
deterministic and audit-friendly.

**Alternative rejected**: emit two reverse_proxy handlers in a chain, one
for http upstreams and one for https. Too complex for v1; the homelab use
case is "Proxmox cluster nodes all on https" or "Docker app cluster all on
http", never mixed.

### Q2: Route-level `insecureSkipVerify` toggle, NOT global

The TLS verification posture is per-route, not a global Caddy setting. A
homelab operator who runs both a Let's Encrypt-protected reverse proxy AND
a self-signed Proxmox upstream must be able to verify the first strictly
and skip-verify the second.

**Why**: the global alternative would force a choice between "strict
everywhere" (breaks Proxmox) and "skip everywhere" (silently accepts a
MITM on a public upstream). The per-route grain matches the real
security model.

**Storage**: `Route.InsecureSkipVerify bool` with `omitempty`; default
false on create AND on pre-fix-row decode (the zero value is the
operator-safer default — strict).

**Wire**: `routeRequest.InsecureSkipVerify *bool` (preserve-on-omit on
PUT) + `routeResponse.InsecureSkipVerify bool` (always emitted). Same
preserve UX as `healthCheck` and `countryBlock`.

**HTTP-only self-heal** (silent normalisation, NOT rejection): if the
operator sets `insecureSkipVerify=true` on an http-only pool, the field
is meaningless (no `transport.tls` block emitted). Both create and
update silently coerce to false with a warn-log, mirror of the
`RedirectToHTTPS` self-heal at `routes.go:1273-1275` when `TLSEnabled`
flips false. The frontend mirrors the same self-heal in a `$effect` that
resets the form's toggle to false on every https→http scheme transition.

### Q3: Per-URL test endpoint with frontend parallelisation

The `POST /api/v1/routes/test-upstream` endpoint accepts ONE URL per call.
The frontend parallelises pool > 1 via `Promise.all` so the operator sees
every row chip update concurrently (wall-clock bounded by the slowest dial).

**Why**:
- Per-URL keeps the handler simple (one timeout, one transport, one
  shaped result).
- Per-URL failures surface independently in the UI: row 0 green ✓ 200,
  row 1 red ✗ refused. A batch endpoint would force a partial-failure
  result shape (`results: [...] | error: "..."`) that the UI would have
  to special-case.
- Wall-clock latency is identical: a batch endpoint with `errgroup` runs
  the same N goroutines.
- Per-URL is easier to test on both sides.

**Probe method**: `GET /` (not HEAD) because many homelab upstreams (Home
Assistant, some Spring Boot apps) return 405 on HEAD even when the service
is healthy — a HEAD-only probe would mislead the operator. The 4KB body
preview gives the operator a sight-recognition signal ("Proxmox login
page" vs "nginx default" vs misdirected service).

**Redirects are NOT followed**: a 301 to `https://` IS a legit data point —
exactly the symptom that started this work. Following would also mask
loops and could leak the request to an unintended service.

### Q4: `POST /api/v1/routes/test-upstream` endpoint, deferred to commit 3

The endpoint and UI button shipped in `f119116` rather than alongside the
storage + Caddy-config fix in `a69880d`. The fix itself is independent of
diagnostics and shipped to unblock the loop ASAP; the diagnostic surface
followed once the operator could already save working routes.

**Why split**: the loop was a P0 reproduction. The diagnostic UX is a P1
quality-of-life. Bundling them would have delayed the P0 fix for the
non-blocking work.

### Q5: Path warning preserves the input value (non-blocking)

When the operator pastes a full URL with a non-root path (e.g.
`https://pve.local:8006/api2/json`), the form surfaces an amber warning
under the URL input — "Le chemin `/api2/json` sera ignoré — Caddy
proxyfie uniquement vers `host:port`" — but does NOT strip the path
from the field, and does NOT block submit.

**Why non-blocking**: the operator may want to keep the path as a reminder
of where the API root sits (then configure path forwarding via request
headers in a future commit). Auto-stripping would erase the operator's
intent silently; blocking would frustrate a power user who knows what
they're doing.

## SSRF posture for `test-upstream` (explicit non-decision)

The endpoint accepts an arbitrary URL from an authenticated admin and
opens an outbound connection from the Arenet process to that URL. We
explicitly DO NOT block RFC 1918, loopback, link-local, or IPv6 ULA
ranges in the SSRF guard.

**Why**: the use case IS the homelab. Proxmox at `192.168.1.60`. HA at
`10.0.0.10`. Synology at `192.168.1.50`. Blocking would defeat the
feature. The trust model is "admin credentials = root-equivalent for
proxy targets" — an admin can already CONFIGURE a route to any internal
IP via `createRoute`; this endpoint adds no new capability, just a
faster diagnostic loop. Locking it down would force the operator to
save a probably-broken route and read Caddy logs to confirm — a worse
UX with the same security posture.

**What we DO guard**:
- Auth: admin-only (same `RequireAdminMiddleware` as `createRoute`).
- Scheme allowlist: `http` / `https` only. `file://`, `gopher://`,
  `ftp://`, `ldap://`, etc. → 400 at parse time.
- Max URL length: 2048 (RFC 7230 §3.1 recommendation).
- Hard 5s deadline.
- `DisallowUnknownFields` on the JSON decoder so a typo like
  `skipVerify` (instead of `insecureSkipVerify`) returns 400, not a
  silently-honoured-but-different request.

## Consequences

### Positive
- Proxmox, Synology DSM, ESXi, UniFi controllers all proxy correctly
  after a one-line operator action (toggle `insecureSkipVerify=true`
  in the form).
- `transport.tls` shape mirrors the existing `forward_auth` precedent
  at `manager.go:2298-2302`, so the same caddy.Validate coverage that
  protects `forward_auth` HTTPS VerifyURL fixtures also protects the
  route emission (see `manager_https_upstream_test.go` for the
  rationale — no duplicate caddy.Validate test was needed for the
  route path because the shape is byte-identical).
- Pre-fix rows decode safely: `InsecureSkipVerify omitempty` + Go's
  zero-value bool gives strict-default-on-read. No boot migration
  needed.
- Operator can probe an upstream before saving a route — fewer "save,
  refresh, check Caddy logs, repeat" loops.
- Smoke caught the wire-layer gap (`#R-API-PUT-ROUTE-GENERIC-400`) that
  would have silently broken PUT for every future field added to
  `storage.Route` without a matching `routeRequest` entry. Partial fix
  shipped (routes.go createRoute + updateRoute now surface the decoder
  error); the sweep across the other 16 handlers is open.

### Negative
- `insecureSkipVerify=true` is a footgun by definition — it disables
  cert validation. The frontend UX surfaces a discreet helper:
  > À cocher uniquement si l'upstream présente un certificat
  > auto-signé (homelab Proxmox, Synology DSM, ESXi, UniFi). En
  > production, préférez ajouter le CA à la trust store de l'hôte
  > Arenet.
  But there is no programmatic check that the operator read it.
- The route-form became measurably larger (453 frontend insertions in
  commit `37f38a5` + 1229 in commit `f119116`). Future feature
  additions in this area should consider whether the form is
  approaching its natural complexity ceiling.

### Neutral
- `test-upstream` outbound traffic appears in the upstream's access
  log under the User-Agent `Arenet-Upstream-Probe/1.0` (explicit so
  an operator inspecting the upstream's log can identify the probe).
- The per-route TLS posture (strict by default, opt-in to skip)
  matches Caddy's own default for `reverse_proxy.transport.tls`. Our
  storage zero-value lines up with Caddy's preferred default — no
  semantic drift between layers.

## Alternatives considered

### Global "trust all upstreams" mode (rejected)

Add a single `--insecure-skip-verify-all-upstreams` flag at boot. Trivial
to implement. Rejected because it forces a binary choice across the
operator's entire fleet — a homelab with both a Let's Encrypt-protected
upstream and a Proxmox cluster would either accept a MITM on the public
upstream or break the Proxmox routes.

### Per-route override via Caddy's `tls_trusted_ca_certs` (rejected)

Allow the operator to upload a custom CA PEM per route. Architecturally
cleaner ("don't disable verification, trust the right CA"). Rejected for
v1 because:
- Most homelab certs are self-signed leaf certs, NOT signed by a custom
  CA — there's no useful CA to upload.
- The storage layer would gain a per-route blob; the frontend would gain
  a file-upload form field; the Caddy config translation would gain a
  fingerprint-vs-CA branch.
- Operator workload: extracting a CA bundle from a Proxmox install is a
  much harder ask than ticking a checkbox.

May revisit in a future commit if operators report enterprise homelab
setups where the CA upload is the right shape (Step 2 mTLS work might
need this anyway).

### Caddy global TLS pool override (rejected)

Use Caddy's own `tls.automation` block to inject a custom default TLS
config that applies to all upstream dials. Rejected because Caddy's
automation block targets the SERVER side (cert issuance + serving), not
the CLIENT side (upstream dial). The right level for client-side TLS is
`reverse_proxy.transport.tls`, which is exactly what we emit.

## Lessons captured

The smoke loop on commit 1 → commit 1b caught a wire-layer gap that the
audit-time analysis missed. The original commit 1 shipped the storage
field but forgot the `routeRequest` wire struct; `updateRoute` uses
`dec.DisallowUnknownFields()`, so any PUT containing the new field
returned 400 "invalid JSON body" — including a pure GET→PUT roundtrip
from a future frontend.

**Mitigation pattern, codified for future schema extensions**:
storage struct ≠ wire struct. When extending a Route schema, verify
BOTH axes (`storage.Route` AND `routeRequest`/`routeResponse`) before
declaring the change shipped. `DisallowUnknownFields` turns a forgotten
wire-side field into a generic 400 that masks the root cause. The
operator-suggested "Lesson 5" addition to `ENGINEERING-PRACTICES.md`
captures this.

## References

- `internal/storage/routes.go` — `InsecureSkipVerify` field,
  `PoolUsesHTTPS()` helper, `validateSameSchemePool` invariant
- `internal/caddymgr/manager.go` — `buildConfigJSON` emits
  `transport.tls` when `r.PoolUsesHTTPS()`
- `internal/api/handler.go` — `routeRequest.InsecureSkipVerify *bool`
  (preserve-on-omit), `routeResponse.InsecureSkipVerify bool`
- `internal/api/routes.go` — createRoute / updateRoute mapping with
  self-heal
- `internal/api/routes_test_upstream.go` — POST
  `/api/v1/routes/test-upstream` handler + `probeUpstream` core
- `web/frontend/src/routes/routes/+page.svelte` — scheme-derived
  helpers, disclosure block, per-row probe button + chip
- `web/frontend/src/lib/api/client.ts` — `testUpstream` wrapper
- Caddy `reverse_proxy.transport.tls` reference:
  https://caddyserver.com/docs/json/apps/http/servers/routes/handle/reverse_proxy/transport/http/tls/
