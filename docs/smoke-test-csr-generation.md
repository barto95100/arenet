# Smoke test — External-certificate CSR generation (v2.20.0)

Live smoke run against a real `go build` binary (dev mode, no ACME issuance),
executed 2026-07-20 on the `feature/external-certs-csr` branch. All ten gates
PASS. This is the CLAUDE.md §Empirical-verification evidence for the CSR
workflow: generate key+CSR → download CSR → sign with a test CA → re-import →
serve over TLS → persist across restart.

## Setup

```bash
BIN=./arenet ; DATA=/tmp/smoke-data ; rm -rf "$DATA"; mkdir -p "$DATA"
ARENET_HTTP_PORT=:8080 ARENET_HTTPS_PORT=:8443 \
  "$BIN" --dev --admin-port 127.0.0.1:8009 --data-dir "$DATA" >arenet.log 2>&1 &
# Bootstrap admin from the setup token (password >= 15 chars):
TOKEN=$(grep "Setup token:" arenet.log | tail -1 | sed 's/.*Setup token: //' | tr -d '"')
curl -s -c ck -X POST http://127.0.0.1:8009/api/v1/auth/setup -H 'Content-Type: application/json' \
  -d "{\"setupToken\":\"$TOKEN\",\"username\":\"admin\",\"password\":\"SmokeTestPass123!\",\"email\":\"a@b.co\"}"
A=http://127.0.0.1:8009/api/v1
```

**Wire-field note (bit us during smoke, recorded for future doc/tests):** the
route-create payload mixes conventions — `host`, `upstreams`, `tlsEnabled` are
camelCase, but `cert_source` / `cert_id` are snake_case (inherited v2.19.0).
`DisallowUnknownFields` 400s on the wrong casing.

## Gates

### Gate 1 — Generate CSR (RSA 4096) — PASS
`POST /certificates/external/csr` with `keyAlgorithm: rsa_4096` →
`status=pending_csr`, `keyPEM` **redacted** (`""`), `csrPEM` present.

### Gate 2 — Generate CSR (ECDSA P-256) — PASS
Same, `keyAlgorithm: ecdsa_p256`. CSR verified via `openssl req -text`:
`Public Key Algorithm: id-ecPublicKey`, `ASN1 OID: prime256v1`, 256-bit.

### Gate 3 — Download CSR — PASS
`GET /certificates/external/{id}/csr` → `CERTIFICATE REQUEST` PEM, contains
**no** `PRIVATE KEY`. Subject `C=FR, O=Corp, CN=app.corp.local`, 4096-bit,
SANs `app.corp.local` + `www.corp.local` (CN auto-included).

### Gate 4 — Re-import signed cert → flip + warnings — PASS
Signed the downloaded CSR with an openssl test CA, dropping the `www` SAN.
`PUT /certificates/external/{id}` with the signed `certPEM` and empty `keyPEM`
(preserve-on-edit keeps the generated key) →
`status` cleared to active, `warnings=['sans_missing']` (the dropped SAN is
surfaced — the Q4 subject/SANs advisory).

### Gate 5 — Re-import a key-mismatched cert → 400, stays pending — PASS
`PUT` a cert from a different key onto the pending ECDSA row →
`400 {"error":"key_does_not_match_cert: tls: private key type does not match
public key type"}`; the row's `status` remains `pending_csr` (no flip on the
mandatory-gate failure).

### Gate 6 — TLS route serves the re-imported cert (handshake) — PASS
Created a manual TLS route (`tlsEnabled:true, cert_source:manual,
cert_id:<active id>`) → `201`. TLS handshake on :8443 with SNI
`app.corp.local` served `subject=CN=app.corp.local`, `issuer=CN=Smoke Test CA`
(our CA that signed the CSR). `curl --cacert ca.crt https://app.corp.local:8443/`
→ **200**. End-to-end: a cert obtained entirely through the CSR workflow is
served by Caddy.

### Gate 7 — Multiple pending CSRs for the same hostname — PASS
Two `POST .../csr` for `dup.corp.local` → both `201`, distinct IDs. No
uniqueness friction (Q6).

### Gate 8 — Delete a pending CSR → 200, no 409 — PASS
`DELETE /certificates/external/{pending-id}` → `200`. The SOCLE delete-guard
never blocks a pending row (it has no TLS route referencing it).

### Gate 9 — Restart persistence — PASS
Killed and relaunched the binary on the same data-dir. No setup token on
reboot (admin persisted). Cert counts identical across restart: total=5,
pending=4, active=1. The active cert is still served (`http=200`,
`subject=CN=app.corp.local`).

### Gate 10 — Pending cert not servable / config stays valid — PASS
Attempting a TLS route pointing at a **pending** cert is refused at the API:
`400 {"error":"host_not_covered_by_cert: the route host is not present in the
certificate SANs"}` — defense in front of the Task 7 emission skip. The
running Caddy config (`GET :2019/config/apps/tls`) shows exactly **one**
`load_pem` entry (the active `CN=app.corp.local` cert), **no** pending cert
emitted; `GET :2019/config/` returns `200` (config valid and loaded). The
active route still serves through the added pending route (no config break).

## Notes

- Smoke runs LOCAL: native `go build` + `curl --resolve` + an openssl test CA
  as the signing authority. No Docker/VM needed (same as the SOCLE Task 11 smoke).
- `staticcheck` is not installed in this environment; `go vet ./...` is clean.
  The full `go test ./...` and frontend `vitest` + `svelte-check` are green
  (see the task ledger).
- The re-import public-key gate is `tls.X509KeyPair` inside `ParseExternalCert`
  (existing SOCLE code) — Gate 5 confirms it fires before any status flip.
