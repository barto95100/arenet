<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Secrets at rest — PR 2 implementation plan

Spec: `docs/superpowers/specs/2026-09-21-secrets-at-rest-design.md` §PR 2.
Target: **v2.30.0**. Branch `feature/secrets-at-rest`.

## Architecture

- **`internal/secrets`** (new): `Keyring` (AES-256-GCM, stdlib),
  `Load` / `Create` (key file = base64 of 32 random bytes, created
  `O_EXCL` 0600), `Seal(plaintext, aad)` → `enc:v1:<base64(nonce‖ct)>`,
  `Open` (unprefixed values pass through), `Fingerprint()` (hex of the
  first 8 bytes of SHA-256(key)).
- **`storage` row codec** (`secret_codec.go`): one table
  bucket → secret fields; `sealRow` / `openRow` work on the raw JSON
  row, so every write goes through `encodeRow` (marshal + seal) and
  every read through `decodeRow` (open + unmarshal). `sealRow` skips
  values already sealed (idempotent). AAD = `bucket.field[.key]`.

  | Bucket | Fields |
  |---|---|
  | `dns_providers` | every `credentials` value (+ legacy flat OVH keys) |
  | `external_certificates` | `keyPEM` |
  | `crowdsec_config` | `api_key` |
  | `automation` | `password` (credentials row) |
  | `maxmind_config` | `license_key` |
  | `oidc_config` | `client_secret` |
  | `forward_auth_providers` | `client_secret` |
  | `alerting_channels` | whole `config` (sealed as a JSON string) |
  | `routes` | `request_headers` / `response_headers` values of sensitive names |

- `Store.EnableEncryption(ctx, kr)`: fingerprint guard (bucket `meta`,
  key `secrets_key_fingerprint`) → refuses a different key; then one
  `Update` transaction seals every plaintext secret and records the
  fingerprint. Without a keyring the store stays plaintext (tests), and
  reading a sealed value fails loudly (`ErrSecretsKeyRequired`).
- `RestoreSnapshot` seals rows before `resetAndFill`.
- `IsSensitiveHeader` moves to `storage` (backup keeps calling it).
- **Sessions**: bucket key = `hex(SHA-256(id))` (the *handle*). Store
  methods taking the cookie value hash it; `GetByHandle` /
  `DeleteByHandle` for the sessions API, which now lists and deletes by
  handle (the raw IDs of other browsers were returned and audited).
  `PurgeLegacySessions` deletes rows not keyed by a handle → one
  re-login after the upgrade.
- **cmd**: `openSecrets(store, dataDir)` shared by `main` and the backup
  CLI — `ARENET_SECRET_KEY_FILE` or `<data-dir>/arenet.key`; missing key
  + fingerprint recorded → refuse to start; missing key on a fresh /
  never-encrypted DB → create it + WARN to back it up. Runs after the
  DNS migrations.

## Tasks

1. `internal/secrets` + tests (round trip, AAD mismatch, tamper,
   passthrough, Create `O_EXCL`/0600, Load bad key).
2. Storage codec + `EnableEncryption` + migration + meta bucket; route
   every secret-bucket read/write through the funnels; restore seals.
   Tests: every public read returns plaintext, raw BoltDB file holds no
   seeded plaintext, idempotent migration, key mismatch refused,
   no-keyring read of sealed value fails.
3. Sessions hashing + API list/delete by handle + legacy purge.
4. cmd wiring (main + backup CLI), env var doc, boot WARN.
5. Docs (wiki Backup-Restore / Security / Installation EN+FR, env-vars),
   real-binary smoke: upgrade from a plaintext DB, restart, missing key,
   wrong key, backup CLI with key.
