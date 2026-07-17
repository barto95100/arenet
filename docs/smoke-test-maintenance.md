# Smoke test — Maintenance mode (manual live-serve)

**Why manual:** `caddy.Validate` (used in the unit tests) provisions the
Caddy modules but never opens a listener or serves a request. Per the
CLAUDE.md empirical-verification mandate, the serve-path behaviour of a
maintenance route — the actual 503, the `Retry-After` header, the client_ip
bypass — must be confirmed against a running binary. Modelled on
`docs/smoke-test-step-i.md`.

## What this verifies

1. A route in **maintenance** serves **503 + the maintenance HTML + `Retry-After`** to a non-bypassed client.
2. A client whose IP is in the **bypass allow-list** reaches the **real upstream** (200), not the 503.
3. `:443` still handshakes for the maintenance host (the cert issues / survives — maintenance keeps the route emitted).
4. Priority: a **Disabled** route wins (404), even over maintenance.

## Setup

```bash
export PATH=/usr/bin:/bin:/usr/local/bin:$PATH
cd /Users/l.ramos/Documents/Projets/AreNET

# 1. Build the real binary (frontend embed optional for API-only smoke).
go build -o /tmp/arenet ./cmd/arenet

# 2. A throwaway upstream so the bypass path has something real to hit.
#    (any local HTTP server; python is fine)
python3 -m http.server 9099 --bind 127.0.0.1 &
UPSTREAM_PID=$!

# 3. Boot Arenet in dev mode (no ACME issuance; high ports so no root needed).
#    NOTE: there is NO --http-port / --https-port flag — the data-plane
#    ports are set via the ARENET_HTTP_PORT / ARENET_HTTPS_PORT env vars
#    (verified against the real binary — the only flags are admin-port,
#    data-dir, dev, config, export/restore, healthcheck, topology-tick-ms,
#    ui-origin, insert-test-route, include-secrets, allow-*).
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  /tmp/arenet --dev --admin-port 127.0.0.1:8001 --data-dir "$(mktemp -d)" &
ARENET_PID=$!
sleep 4

# Bootstrap the admin from the setup token, then keep the session cookie.
TOKEN=$(grep "Setup token:" <arenet.log | tail -1 | sed 's/.*Setup token: //' | tr -d '"')
curl -s -c /tmp/cookies -X POST http://127.0.0.1:8001/api/v1/auth/setup \
  -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"SmokeTestPass123!\",\"email\":\"a@b.co\"}"
# password MUST be >= 15 chars; the field is "setupToken" (not "token").
# Use `-b /tmp/cookies` on the admin-API curls below.
```

## Create a maintenance route with a bypass

```bash
# Create a route in maintenance, bypass = the loopback so THIS host reaches the upstream.
curl -s -b "$COOKIE" -X POST http://127.0.0.1:8001/api/v1/routes \
  -H 'Content-Type: application/json' -d '{
    "host":"maint.local",
    "upstreams":[{"url":"http://127.0.0.1:9099","weight":1}],
    "lbPolicy":"round_robin","tlsEnabled":false,"redirectToHttps":false,
    "aliases":[],"authMode":"none","requestHeaders":{},"responseHeaders":{},
    "wafMode":"off",
    "maintenanceConfig":{"retryAfterSeconds":300,"bypassIps":["127.0.0.1/32"]}
  }'
# (or create it Active, then POST /api/v1/routes/{id}/maintenance to toggle in.)
```

## Assertions

```bash
# A) Bypassed client (127.0.0.1 is in the allow-list) → real upstream, 200.
curl -s -o /dev/null -w "bypass: %{http_code}\n" \
  --resolve maint.local:8080:127.0.0.1 http://maint.local:8080/
# EXPECT: bypass: 200   (the python http.server directory listing)

# B) Non-bypassed client → 503 + Retry-After + maintenance HTML.
#    Simulate a different source IP. Easiest: set bypassIps to a bogus CIDR
#    (e.g. "10.99.0.0/16") via PUT /routes/{id}, reload, then curl from loopback:
curl -s -D - -o /tmp/maint-body.html -w "\nno-bypass: %{http_code}\n" \
  --resolve maint.local:8080:127.0.0.1 http://maint.local:8080/ | grep -iE "HTTP/|Retry-After|no-bypass"
# EXPECT: HTTP/1.1 503 Service Unavailable
#         Retry-After: 300
#         no-bypass: 503
grep -qi "maintenance" /tmp/maint-body.html && echo "body: maintenance page served" || echo "body: MISSING maintenance content"

# C) TLS host still handshakes (maintenance keeps :443). Enable TLS on the route
#    (tlsEnabled:true, internal CA in --dev), reload, then:
curl -sk -o /dev/null -w "tls: %{http_code}\n" \
  --resolve maint.local:8443:127.0.0.1 https://maint.local:8443/
# EXPECT: tls handshake succeeds (503 or 200 depending on bypass) — NOT a
#         connection-refused. The point is :443 is alive for the maintenance host.

# D) Priority: DISABLE the route (POST /routes/{id}/disable). It is filtered out
#    of Caddy entirely → the host hits the catch-all 404, not the 503.
curl -s -o /dev/null -w "disabled: %{http_code}\n" \
  --resolve maint.local:8080:127.0.0.1 http://maint.local:8080/
# EXPECT: disabled: 404   (Disabled wins over maintenance)
```

## Teardown

```bash
kill "$ARENET_PID" "$UPSTREAM_PID" 2>/dev/null
```

## Pass criteria

- (A) bypass → **200** from the real upstream.
- (B) non-bypass → **503** + `Retry-After: 300` + the maintenance HTML body.
- (C) TLS host → handshake succeeds (**:443 alive**), no connection-refused.
- (D) disabled → **404** (Disabled beats Maintenance).

All four must hold. If (B) returns 200 or (C) refuses the connection, the
emission branch is wrong — do not ship.
