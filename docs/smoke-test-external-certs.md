# Smoke test — External / uploaded certificates (manual live-serve)

**Why manual:** `caddy.Validate` (used in the unit tests) provisions the
Caddy modules but never opens a listener or serves a request. Per the
CLAUDE.md empirical-verification mandate, the serve-path behaviour of a
route backed by an **uploaded external certificate** — the actual TLS
handshake serving the uploaded cert, the absence of an ACME policy for
that host, the `skip_certificates` entry, restart persistence, and the
delete-while-referenced guard — must be confirmed against a running
binary. Modelled on `docs/smoke-test-maintenance.md`.

This procedure is the one that was **actually run** against the binary
(2026-07-19). Every command and expected output below is proven — nothing
here is invented.

## What this verifies

1. **Upload** an external cert → `201`, parsed metadata returned, **private key redacted** in the response.
2. A route with **Cert Source = Manual** referencing that cert → `201`.
3. The live Caddy config carries the cert in `tls.certificates.load_pem`, has **NO** ACME automation policy for the manual host (only `{module: internal}`), and lists the host in `automatic_https.skip_certificates`.
4. The **TLS handshake** serves the **uploaded cert** (matched by serial), and an HTTP request through it returns `200`.
5. **Maintenance + manual**: a manual route in maintenance still serves the manual cert at handshake AND returns `503` (handshake-before-503 ordering).
6. **Restart persistence**: after a restart on the same data-dir the manual cert is still served (serial unchanged), `200`, and **no ACME attempt** for the manual host in the log.
7. **Delete-while-referenced**: `DELETE` on a cert a route still references → `409` with the blocking route host(s).

## Setup

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET

# 1. Build the real binary (frontend embedded).
go build -o /tmp/arenet ./cmd/arenet

# 2. A working directory + a data-dir we reuse across the restart step.
WORK=$(mktemp -d)
DATA=$(mktemp -d)
cd "$WORK"

# 3. Generate a self-signed test cert that stands in for the external CA cert.
#    CN + SAN = manual.local, 30-day validity.
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 30 -nodes \
  -subj "/CN=manual.local" -addext "subjectAltName=DNS:manual.local"

# 4. Boot Arenet in dev mode (no ACME issuance; high ports so no root needed).
#    NOTE: there is NO --http-port / --https-port flag — the data-plane
#    ports are set via the ARENET_HTTP_PORT / ARENET_HTTPS_PORT env vars.
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  /tmp/arenet --dev --admin-port 127.0.0.1:8009 --data-dir "$DATA" >arenet.log 2>&1 &
ARENET_PID=$!
sleep 4

# 5. Bootstrap the admin from the setup token, keeping the session cookie.
#    The field is "setupToken" (not "token"); the password MUST be >= 15 chars.
TOKEN=$(grep "Setup token:" <arenet.log | tail -1 | sed 's/.*Setup token: //' | tr -d '"')
curl -s -c /tmp/cookies -X POST http://127.0.0.1:8009/api/v1/auth/setup \
  -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"SmokeTestPass123!\",\"email\":\"a@b.co\"}"
# Use `-b /tmp/cookies` on the admin-API curls below.
```

## Step 1 — Upload the external certificate (201 + redacted key)

```bash
# Build the JSON body from the two PEM files (chainPEM empty — the leaf is self-issued).
CERT=$(python3 -c 'import json,sys;print(json.dumps(open("cert.pem").read()))')
KEY=$(python3 -c 'import json,sys;print(json.dumps(open("key.pem").read()))')

curl -s -b /tmp/cookies -X POST http://127.0.0.1:8009/api/v1/certificates/external \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"manual-smoke\",\"certPEM\":$CERT,\"keyPEM\":$KEY,\"chainPEM\":\"\"}"
```

**Expected:** HTTP `201`. The response is the stored cert's parsed metadata —
`issuer` / `subject` / `serialNumber`, `keyAlgorithm: RSA`,
`signatureAlgorithm: SHA256-RSA`, a `notAfter` ~30 days out, and
`dnsNames: ["manual.local"]`. Crucially **`keyPEM` is `""` (redacted)** — the
private key is never echoed back.

```bash
# Capture the cert ID for the next steps.
CERT_ID=$(curl -s -b /tmp/cookies http://127.0.0.1:8009/api/v1/certificates/external \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
```

## Step 2 — Create a route with Cert Source = Manual (201)

```bash
curl -s -b /tmp/cookies -X POST http://127.0.0.1:8009/api/v1/routes \
  -H 'Content-Type: application/json' \
  -d "{
    \"host\":\"manual.local\",
    \"upstreams\":[{\"url\":\"http://127.0.0.1:8080\",\"weight\":1}],
    \"lbPolicy\":\"round_robin\",\"tlsEnabled\":true,
    \"cert_source\":\"manual\",\"cert_id\":\"$CERT_ID\"
  }"
```

**Expected:** HTTP `201`. **Note the wire fields are snake_case** —
`cert_source` and `cert_id` — matching the route request decoder.

## Step 3 — Inspect the live Caddy config (load_pem, no ACME policy, skip list)

```bash
# The manual cert + key are carried inline under load_pem.
curl -s http://127.0.0.1:2019/config/apps/tls | python3 -m json.tool | grep -A3 load_pem

# The TLS automation has ONLY the internal module — NO ACME policy for manual.local.
curl -s http://127.0.0.1:2019/config/apps/tls | python3 -m json.tool | grep -A2 policies

# auto_https skips certificate management for the manual host.
curl -s http://127.0.0.1:2019/config/apps/http/servers | python3 -m json.tool | grep -A2 skip_certificates
```

**Expected:**
- `certificates.load_pem` carries the uploaded cert **and** key.
- `automation.policies` contains **only** `{"module": "internal"}` — there is **no** ACME policy for `manual.local`.
- `arenet_https.automatic_https.skip_certificates` **includes `manual.local`** (so Caddy's `auto_https` will not try to ACME-issue it).

## Step 4 — TLS handshake serves the uploaded cert, HTTP 200

```bash
# The served leaf's subject + serial must be the uploaded cert's.
echo | openssl s_client -connect 127.0.0.1:8443 -servername manual.local 2>/dev/null \
  | openssl x509 -noout -subject -serial

# A request routed through the manual cert returns 200.
curl -sk --resolve manual.local:8443:127.0.0.1 https://manual.local:8443/ -o /dev/null -w '%{http_code}\n'
```

**Expected:**
- `subject= CN=manual.local` and the **serial equals the uploaded cert's serial** (the smoke run observed `serial=C72BB8D17D8BD359`). This proves the served cert is the uploaded one, not an internal fallback.
- The `curl` returns `200`.

## Step 5 — Maintenance + manual (handshake still serves the cert, HTTP 503)

```bash
# Put the manual route into maintenance.
RID=$(curl -s -b /tmp/cookies http://127.0.0.1:8009/api/v1/routes \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')
curl -s -b /tmp/cookies -X POST http://127.0.0.1:8009/api/v1/routes/$RID/maintenance
sleep 3

# Handshake still serves the manual cert...
echo | openssl s_client -connect 127.0.0.1:8443 -servername manual.local 2>/dev/null \
  | openssl x509 -noout -serial
# ...and the HTTP response is the 503 maintenance page.
curl -sk --resolve manual.local:8443:127.0.0.1 https://manual.local:8443/ -o /dev/null -w '%{http_code}\n'
```

**Expected:** the handshake still presents the **uploaded cert** (same serial),
AND the HTTP status is **`503`**. This proves the handshake happens **before**
the 503 handler runs — without the manual cert being served, there would be no
handshake and thus no 503 at all.

```bash
# Restore the route to Active for the restart step.
curl -s -b /tmp/cookies -X POST http://127.0.0.1:8009/api/v1/routes/$RID/maintenance/off
```

## Step 6 — Restart persistence (cert re-served, no ACME attempt)

```bash
# Restart on the SAME data-dir.
kill "$ARENET_PID"; sleep 1
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  /tmp/arenet --dev --admin-port 127.0.0.1:8009 --data-dir "$DATA" >arenet2.log 2>&1 &
ARENET_PID=$!
sleep 4

# Same cert still served after restart.
echo | openssl s_client -connect 127.0.0.1:8443 -servername manual.local 2>/dev/null \
  | openssl x509 -noout -serial
curl -sk --resolve manual.local:8443:127.0.0.1 https://manual.local:8443/ -o /dev/null -w '%{http_code}\n'

# No ACME issuance was attempted for the manual host.
grep -i "manual.local" arenet2.log | grep -i acme || echo "no ACME attempt for manual.local (expected)"
```

**Expected:** the manual cert is still served (serial **unchanged**), `curl`
returns `200`, and there is **no ACME attempt** for `manual.local` in the log.

## Step 7 — Delete while referenced (409 + blocking routes)

```bash
# Log back in if the cookie expired across the restart, then attempt the delete.
curl -s -b /tmp/cookies -X DELETE http://127.0.0.1:8009/api/v1/certificates/external/$CERT_ID
```

**Expected:** HTTP `409` with a body like
`{"blockingRoutes":["manual.local"],"error":"certificate is referenced by one or more routes"}`.
The cert cannot be deleted while a Manual route still references it — change or
remove that route first.

## Teardown

```bash
kill "$ARENET_PID" 2>/dev/null
rm -rf "$WORK" "$DATA"
```

## Result (2026-07-19)

All seven assertions **PASSED** against the real binary:
upload `201` + key redacted; manual route `201`; `load_pem` present with no
ACME policy and `manual.local` in `skip_certificates`; handshake served the
uploaded cert (serial `C72BB8D17D8BD359`) with HTTP `200`; maintenance kept the
handshake while returning `503`; the cert survived a restart with no ACME
attempt; and the delete was blocked `409` while a route referenced it.
