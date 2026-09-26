<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke — secrets encrypted at rest (v2.30.0)

Date: 2026-09-21. Real binaries, macOS, `--dev`, fake CrowdSec LAPI on
`127.0.0.1:18090` logging the `X-Api-Key` it receives.

## Procedure

1. **v2.29 binary** (`origin/main` before this PR) on an empty data dir:
   setup + login, then create a Cloudflare DNS provider, CrowdSec
   settings, watcher credentials, a webhook channel (secret URL +
   `Authorization` header) and a route with an `Authorization` request
   header. Stop. `grep -a` finds all 6 seeded secrets in `arenet.db`.
2. **v2.30 binary**, same data dir.
3. Restart.
4. Move `arenet.key` away and start.
5. Put a random key in place and start.
6. Remove it; start with `ARENET_SECRET_KEY_FILE` pointing at the
   original key.
7. Stop; `--export --include-secrets` with the key.
8. Scan every bucket of the final `arenet.db` for the 6 secrets.

## Results

| Step | Expected | Observed |
|---|---|---|
| 2 | key generated, secrets sealed, file rewritten | WARN "generated a new secrets key… back it up" (0600); `rows=5` sealed; `events=2` audit events scrubbed; "rewrote arenet.db"; `sessions=2` pre-v2.30 sessions signed out |
| 2 | nothing in clear | 0 of 6 secrets in the file (step 8 scan: every bucket clean) |
| 2 | old cookie rejected, new login OK | `/auth/me` 401 with the v2.29 cookie; login 200 |
| 2 | runtime still gets plaintext | bouncer calls the LAPI with the decrypted key (2 calls); routes API shows the header; export with secrets holds all 6 |
| 2 | sessions listed by handle | `id` is 64-hex, not the cookie |
| 3 | no re-sealing | only "secrets encryption at rest enabled" |
| 4 | refuse, no new key | exit 1, "arenet.db is encrypted (key fingerprint …) but the key file … is missing"; no key file created |
| 5 | refuse | exit 1, "… is not the key arenet.db was encrypted with" |
| 6 | boots | OK, login 200 |
| 7 | decrypted export | exit 0, all 6 secrets in the JSON |

## Findings fixed during the smoke

- The first run found 2 secrets still in clear after sealing: the
  **audit log** kept the webhook URL and the route header (plus, by
  code reading, path-rule Basic Auth hashes). Fixed: redaction of new
  events + one-time scrub of old ones.
- A unit test found that bbolt keeps the pre-sealing plaintext in freed
  pages: `Store.Compact()` after any rewrite.

Verdict: **pass**.
