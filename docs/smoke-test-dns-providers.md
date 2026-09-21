<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke test — Multi-type DNS providers (v2.26.0)

Spec: `docs/superpowers/specs/2026-09-21-dns-providers-multi-type-design.md`.

The maintainer only has an OVH account, so the evidence is split:

- **Part A — automated + dummy-credential smoke (done 2026-09-21).** Proves,
  for all 9 types, that the registry fields match the real Caddy modules, that
  each module provisions and reaches its provider's real API, and that no
  secret leaks. Does **not** prove a certificate can be issued.
- **Part B — real OVH smoke (operator, on the test host).** Proves the
  non-regression of the reference provider end to end, including issuance.

## Setup (Part A, local)

```bash
BIN=./arenet ; DATA=/tmp/dns-data ; rm -rf "$DATA"; mkdir -p "$DATA"
ARENET_HTTP_PORT=18080 ARENET_HTTPS_PORT=18443 \
  "$BIN" --dev --admin-port 127.0.0.1:18001 --data-dir "$DATA" >arenet.log 2>&1 &
TOKEN=$(grep -o 'Setup token: [0-9a-f]*' arenet.log | awk '{print $3}')
A=http://127.0.0.1:18001/api/v1
curl -s -X POST $A/auth/setup -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"displayName\":\"Admin\",\"password\":\"Smoke-test-Passw0rd-2026!x\"}"
curl -s -c ck -X POST $A/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Smoke-test-Passw0rd-2026!x"}'
```

Every dummy credential embeds the marker `SMOKESECRET` so any leak is
greppable in responses and in `arenet.log`.

## Part A — results (2026-09-21, macOS arm64, Caddy v2.11.4)

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| A1 | `caddy.Validate` with every registry field filled, one managed domain per type | PASS | `TestBuildConfigJSON_LoadsCleanly_AllDNSProviderTypes` (strict module decode — a drifted key fails with `unknown field`) |
| A2 | OVH provider block byte-identical to v2.25.1 | PASS | `TestBuildACMEPolicy_OVHProviderBlockUnchanged` |
| A3 | `GET /settings/dns-providers/types` lists the 9 types with their fields | PASS | ovh, cloudflare, digitalocean, gandi, hetzner, infomaniak, porkbun, route53, scaleway |
| A4 | Create one provider per type (dummy credentials) → 201, no secret echoed | PASS | 9 × 201, `SMOKESECRET` absent from every body |
| A5 | `POST /{id}/test` zone `example.com` → module reaches the real API, clean auth rejection, no leak | PASS | see table below |
| A6 | Cloudflare token of invalid format bound to a managed domain → reload fails, token redacted in API error and log | PASS | 500 `… API token '[REDACTED]' appears invalid …`; `grep -c SMOKESECRET arenet.log` = 0 |
| A7 | Backend CI gate | PASS | `go vet ./...` + `go test -race -count=1 ./...` all green |
| A8 | Frontend gate | PASS | `npm run check` 0 errors; `npm test` 1104/1104 (Node 24 as in CI; local Node 26 needs `NODE_OPTIONS=--no-experimental-webstorage` for two unrelated store suites) |
| A9 | Binary size | +11.1 MB | 103.7 MB → 114.8 MB (AWS SDK, Scaleway SDK, hcloud-go, godo) |

A5 detail — the provider's own answer to dummy credentials:

| Type | Result |
|------|--------|
| ovh | `OVHcloud API error (status code 403): Client::Forbidden: "This application key is invalid"` |
| cloudflare | `HTTP 403: Code 9109 Invalid access token` |
| digitalocean | `401 … Unable to authenticate you` |
| gandi | `LiveDNS returned a 403 (Access was denied to this resource.)` |
| hetzner | `the token you have provided is invalid (unauthorized)` |
| infomaniak | `HTTP 401: not_authorized` |
| porkbun | `Invalid API key. (001)` |
| route53 | `operation error Route 53: ListHostedZonesByName, https response error StatusCode: 403 … api error Inva…` (truncated in the capture) |
| scaleway | `invalid secret key format '[REDACTED]', expected a UUID` — the SDK echoes the secret; redaction caught it |

Finding: besides Cloudflare (known from the spec), the **Scaleway SDK also
echoes the secret key** in its error. Both are covered by
`storage.RedactDNSSecrets`.

## Part B — real OVH smoke (operator, test host)

Results column left blank — fill in during the live run.

| # | Gate | Result | Evidence |
|---|------|--------|----------|
| B1 | Upgrade an instance with an existing OVH provider: boot log shows `migrated DNS provider credentials to multi-type format count=1`; provider still `configured` | | |
| B2 | Existing OVH wildcard keeps being served; `journalctl -u arenet` shows no ACME error after the reload | | |
| B3 | ⚡ Test connection on the OVH provider (zone = your apex) → green, record count plausible | | |
| B4 | Edit the OVH provider label only (secrets blank) → still `configured`, B3 still green | | |
| B5 | Declare a new wildcard apex on the OVH provider → certificate issued (staging or prod) | | |
| B6 | Export a backup **without** secrets, restore it on the same instance → OVH credentials inherited, B3 still green | | |
| B7 | UI: add form switches fields with the type (e.g. Cloudflare shows API token + Zone token), docs link opens the provider page, FR/EN labels | | |
