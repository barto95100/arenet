# Updating Arenet

**🌐 English** · [Français](Updates-FR)

Arenet ships as a single binary / container image. **Updating is a manual, operator-driven action** — Arenet never downloads or installs an update itself. The [opt-in update checker](DNS-Providers#stay-updated) (v2.12.3) only *notifies* you that a newer stable release exists; this page explains how to actually upgrade, safely.

> **Why no auto-update?** See [Security notes](#security-notes) below. In short: auto-updating a reverse proxy means giving a network-facing service the privilege to overwrite its own binary and restart itself — a large attack surface and a supply-chain risk. Like nginx, Traefik, Caddy and Postgres, Arenet leaves the upgrade decision (and timing) to you.

---

## 0. Before you start: check your current version

There is **no `--version` flag**. Read the running version from any of:

- **UI** — *Settings → Updates* shows the current version (and the latest available, if the checker is enabled).
- **API** — `GET /api/v1/system/version` (admin session) → `{"current": "vX.Y.Z", ...}`.
- **Logs** — `journalctl -u arenet | grep "Arenet starting" | tail -1` (systemd) or `docker logs arenet 2>&1 | grep "Arenet starting" | tail -1` (Docker). The last match shows the running version (`version=vX.Y.Z`).

Compare against the [latest release](https://github.com/barto95100/arenet/releases/latest).

**Golden rule:** take a backup before every upgrade. UI: *Backup → Export*. See [Backup & Restore](Backup-Restore).

---

## 1. Docker Compose (recommended)

If you deploy with the reference `docker-compose.yml` (image `ghcr.io/barto95100/arenet:latest`):

```bash
cd ~/arenet            # wherever your docker-compose.yml lives
docker compose pull    # fetch the newest :latest image
docker compose up -d   # recreate the container on the new image
docker compose logs -f arenet | grep "Arenet starting"   # confirm the new version
```

Your state lives in the named volume `arenet-data` (mounted at `/var/lib/arenet`), so it survives the container recreation. Nothing else to do.

**Pin a specific version** instead of `:latest` for reproducible upgrades:

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:vX.Y.Z   # pick a tag from the releases page
```
Replace `vX.Y.Z` with a tag from the [releases page](https://github.com/barto95100/arenet/releases), then `docker compose pull`, `docker compose up -d`. To move to a newer version later, bump the tag and repeat.

---

## 2. Docker image (standalone `docker run`)

```bash
docker pull ghcr.io/barto95100/arenet:latest
docker stop arenet && docker rm arenet
docker run -d --name arenet \
  --cap-add=NET_BIND_SERVICE \
  -p 80:80 -p 443:443 -p 443:443/udp -p 127.0.0.1:8001:8001 \
  -v arenet-data:/var/lib/arenet \
  ghcr.io/barto95100/arenet:latest
```

The `arenet-data` volume carries your data across the replace. Keep the **same `-v` volume name** and the **`/var/lib/arenet`** mount target — that's where the binary reads its state.

---

## 3. Native binary + systemd

Download the new release binary, verify its checksum, swap it in, restart:

```bash
ARCH=linux-amd64        # or linux-arm64

cd /tmp

# Download the LATEST stable binary + its checksums manifest. The
# /releases/latest/download/ URL always redirects to the newest stable
# release — no version number to keep up to date. The file is saved
# under its release name (arenet-linux-amd64) so it matches the entry
# in checksums.txt and `sha256sum -c` can find it.
curl -L -o "arenet-${ARCH}" "https://github.com/barto95100/arenet/releases/latest/download/arenet-${ARCH}"
curl -L -o checksums.txt "https://github.com/barto95100/arenet/releases/latest/download/checksums.txt"

# Verify integrity (the release publishes a sha256 manifest). Run this
# in the same dir as the downloaded file.
grep "arenet-${ARCH}\$" checksums.txt | sha256sum -c -
#   → "arenet-linux-amd64: OK"

# Swap the binary in (rename to the install path) and restart
sudo systemctl stop arenet
sudo mv "arenet-${ARCH}" /usr/local/bin/arenet
sudo chmod +x /usr/local/bin/arenet
sudo chown root:root /usr/local/bin/arenet
sudo systemctl start arenet
sudo systemctl status arenet          # Active: active (running)
sudo journalctl -u arenet | grep "Arenet starting" | tail -1
```

The data dir (`/var/lib/arenet` by default) is untouched by a binary swap.

---

## 4. Rollback

An upgrade is reversible as long as you didn't cross a schema MAJOR bump (see [§5](#5-migration-safety)).

**Docker Compose / run** — re-pin the previous image tag and recreate. Replace `vPREV` with the version you were on before the upgrade (find it in your shell history, or on the [releases page](https://github.com/barto95100/arenet/releases)):
```bash
docker pull ghcr.io/barto95100/arenet:vPREV
# edit the compose image tag back to :vPREV, or re-run docker run with :vPREV
docker compose up -d
```

**Binary** — keep the old binary before overwriting (`sudo cp /usr/local/bin/arenet /usr/local/bin/arenet.prev` before step 3), then:
```bash
sudo systemctl stop arenet
sudo mv /usr/local/bin/arenet.prev /usr/local/bin/arenet
sudo systemctl start arenet
```

If state was touched and won't load, restore the backup you took: [Backup & Restore → Restore](Backup-Restore).

---

## 5. Migration safety

- Arenet runs **idempotent boot migrations** on startup (e.g. the v2.12.0 DNS-provider migration). They're safe to re-run and require no action.
- **Backups carry a schema version** (`SchemaVersion`, MAJOR `1` today). Restore enforces **MAJOR-equal**: a backup from a different schema generation is rejected with a clear message rather than corrupting state. Within the same MAJOR, restore across minor/patch versions is fine.
- **Practical rule:** patch/minor upgrades are drop-in. Before a **MAJOR** upgrade, read that release's notes, take a backup, and be ready to roll back to the prior binary/image (a backup can only be restored on a same-MAJOR binary).
- **Upgrading to v2.15.1+ (data-dir permissions):** v2.15.1 tightens the data directory to `0700` (owner-only) because it holds secrets and TLS private keys. Fresh installs and standard upgrades get this automatically — the binary chmods the dir to `0700` on boot. **No action needed** in the common case; to confirm: `stat -c '%a' /var/lib/arenet` → `700`. If you run Arenet under a bind mount and boot fails on the data dir, see [Installation → Data directory setup](Installation#data-directory-setup-named-volume-vs-bind-mount).
- **Upgrading to v2.30.0+ (secrets encrypted at rest):** on first boot Arenet generates `arenet.key` in the data directory (mode `0600`) and encrypts every secret stored in `arenet.db` — DNS credentials, private keys of uploaded certificates, CrowdSec / MaxMind / OIDC / forward-auth secrets, alert channel credentials, sensitive route headers — then rewrites the file so no plaintext copy remains. Two visible effects: **everyone logs in once more** (session IDs are now stored hashed), and a WARN asks you to **back up `arenet.key` separately**. Without the key the secrets cannot be recovered, and Arenet refuses to start on an encrypted database whose key is missing or different. **Rollback below v2.30 needs the data directory backed up *before* the upgrade** — an older binary cannot read encrypted secrets.
- **Upgrading to v2.71.0+ (admin port binds loopback by default):** the admin API now listens on `127.0.0.1:8001` instead of every interface, which is what spec D6 decided and what this wiki, the hardening guide and the binary's own `--admin-port` help text have all said since v1.4 — the default simply never matched. **Docker is unaffected** (the image CMD passes `--admin-port=:8001`, and a flag beats the default; the compose file already restricts access with `127.0.0.1:8001:8001`). **A native/systemd install that reaches the admin UI over the LAN will lose that access.** Two ways forward: reach it through an Arenet route pointing at `127.0.0.1:8001` (loopback works — Caddy is embedded in the same process), or state the exposure explicitly with `ARENET_ADMIN_BIND=0.0.0.0:8001` in `/etc/arenet/arenet.env` and apply items 2 and 3 of the [hardening checklist](https://github.com/barto95100/arenet/blob/main/docs/operations/hardening.md). Test the new path **before** closing your SSH session.
- **Upgrading to v2.73.0+ (a security release: six behaviour changes worth reading first).** This release closes eighteen findings from a security review of the unauthenticated-reachable surface, three of them rated HIGH. Most are invisible to you, these are not:

  1. **The WAF now inspects a WebSocket handshake.** It used to skip Coraza entirely for any request carrying `Upgrade: websocket` and `Connection: upgrade` — two client-supplied headers, no method or `Sec-WebSocket-Key` check — so anyone could bypass the WAF on any route by adding them, with no event emitted. The handshake is inspected now and only the response phase is skipped. **Consequence:** a CRS false positive on a handshake can refuse a WebSocket that previously worked. The paths at risk are Home Assistant `/api/websocket`, Jellyfin, n8n, TeslaMate, Outline. **Put the route in `detect` mode, watch the activity log, then switch back to `block`.**
  2. **CRS blocking now applies under `/api/v1` on your own routes.** A management-plane CRS exemption was prepended to *every* route's engine and keyed on the request path, so any client could strip the anomaly-score evaluator by aiming at `/api/v1/...`. It is now scoped to the route that points at the admin listener. **Consequence:** an upstream that serves its own API under `/api/v1` — Gitea, n8n, many REST apps — is now actually inspected there. Same advice: `detect` first.
  3. **A path rule now gates its whole subtree.** A prefix ending in `/` produced a Caddy matcher that matched the exact path and nothing beneath it, so `/admin/` prompted for credentials and `/admin/users` was proxied in the clear. **In the other direction**, a path rule carrying `DisableRouteAuth` with a trailing slash now really exempts its subtree, where the broken matcher had been accidentally keeping the route's auth on. Check your path rules if you use that exemption.
  4. **A path prefix containing `*`, `?`, `[` or `]` is refused on save.** Caddy reads those as glob syntax, and a stored `/*` expanded to a match over the whole site — on a `DisableRouteAuth` rule, that turned the route's authentication off everywhere. An existing rule with such a prefix keeps working until you next edit the route, which will then refuse it with the reason.
  5. **A viewer no longer reads credential header values.** `GET /routes` returned upstream `Authorization`, `X-Api-Key` and health-check probe headers in cleartext to any authenticated identity, including the read-only role and a viewer-scoped service-account token. Header *names* still show; values are redacted for non-admins. **Consequence:** automation using a VIEWER token to read those values breaks. Give it an admin token, or stop reading secrets from the route list.
  6. **A live telemetry stream now closes when its session is revoked.** `/ws/geo-events`, `/ws/topology` and `/topology/stream` were authorized once at the upgrade and never again, so revoking a session, deleting the account or the 15-minute idle lock left the socket emitting every source IP hitting your proxy. They re-check every 30 s. **Consequence:** a dashboard tab left idle past the lock now has its socket closed and reconnects after you unlock.

  **One action, if it applies to you:** if you ever exported a backup while a **Discord** alert channel was configured, that webhook URL is in the file **in cleartext** — it was missing from the backup secret registry, so even the export labelled "no secrets" and the passphrase-encrypted one carried it. This release fixes future exports, not the files already on your NAS or in a ticket. **Regenerate the webhook** in Discord → Integrations → Webhooks.

  Also in this release: private vulnerability reporting is enabled on the repository and `SECURITY.md` describes the channel, the scope and the timelines.

- **Upgrading to v2.74.0+ (the rest of the security review: hardening, with a few behaviour changes).** This release closes the remaining findings from the same review — the MEDIUM and LOW ones — mostly invisible internal hardening (WAF event-sample memory and credential masking, request-body caps against OOM, rate-limiter and token-touch memory bounds, a geo-reader use-after-free and a bus send-on-closed race). These few you may feel:

  1. **Cookie-authenticated writes must be `Content-Type: application/json`.** A new CSRF guard on `/api/v1` refuses a state-changing request that carries the session cookie but a form/`text/plain` body (415), or whose browser labels it cross-site (403). The web UI and **bearer / API-token clients are unaffected** (a token is not attached cross-site). **Consequence:** a hand-written script that drives the admin API with the *session cookie* and a non-JSON body breaks — give it an API token, or send JSON.
  2. **A forced password change is now enforced by the server, not just the UI.** An admin-created account still on its one-time initial password is refused on every endpoint except changing that password (403 `password_change_required`). **Consequence:** if you point automation at such an account, it cannot act until the password is rotated. Rotate it, or use a service-account API token.
  3. **Removing an OIDC allowlist entry — or disabling OIDC — now ends that identity's live sessions.** Before, it only blocked future sign-ins while the open session kept working. **Consequence:** an offboarded SSO user is logged out immediately, as intended.
  4. **Login answers the same 401 for an OIDC/service account as for a bad password** (it used to answer 500 for an account with no local password) and now runs the key derivation on every failure. **Consequence:** a monitor that keyed on the old 500 sees 401; there is no behaviour to rely on there.
  5. **The Caddyfile import refuses `import <path>` and `{$ENV}`.** Caddy's parser would otherwise read files off *this* host and substitute *this* process's environment, and hand both back in the preview — an admin-only file-read. A snippet import (`import name` with `(name)` defined in the same text) still works; a file/glob import or an env placeholder is rejected. **Consequence:** inline those before importing a Caddyfile that used them.
  6. **Country blocking enforces from the first request after a restart.** There was a brief window at boot where a country-gated route accepted everything; it is closed. Certificate deletion also now accepts only a hostname or `*.domain`.
  7. **Forward-auth routes strip the full identity-header set before the IdP check.** Previously only the headers your provider was configured to copy (its "copy headers") were deleted from the incoming request; a conventional identity header your provider does *not* copy — `Remote-Groups`, `Remote-Name`, `X-Authentik-*`, `X-Forwarded-User` — reached the backend verbatim. Now the whole conventional set (plus your copy headers) is stripped on the gated path, so only the IdP's values reach the upstream. **Consequence:** a backend that trusted a client-supplied identity header your provider didn't copy no longer sees the client's value — it never should have. Affects forward-auth routes (e.g. an Authentik-fronted app); the IdP-set values are unchanged.
  8. **The session cookie is flagged `Secure` behind a trusted TLS proxy.** It used to get `Secure` only on a direct TLS connection (`r.TLS`), so reaching the admin UI through an HTTPS route that terminates TLS and forwards over plaintext loopback left the cookie without it. Arenet now flags it `Secure` when the request arrives over HTTPS through a trusted hop — loopback or a CIDR in `ARENET_TRUSTED_PROXIES` — that forwarded `X-Forwarded-Proto: https`; an untrusted caller's forwarded scheme is ignored. **Consequence:** none to act on — plaintext loopback admin (SSH tunnel, direct HTTP on 127.0.0.1) still works, and HTTPS access now yields a `Secure` cookie as it should.
  9. **Custom error / maintenance pages render the raw request placeholders literally.** `{http.request.uri}`, `{http.request.host}` and `{http.request.uri.path}` reflect the client's raw request into a page served as HTML — a reflected-XSS vector — so they are no longer expanded; they now print as literal text. The URL-escaped whole-URI form `{http.request.uri_escaped}` is safe and still expands. **Consequence:** if a custom page used one of the raw tokens, switch it to `{http.request.uri_escaped}`. The built-in default pages are unaffected (they already use the escaped form).

  **One action, if it applies to you:** rotate the password of any admin-created account still on its initial password that a script logs in with (item 2) — otherwise that account is now blocked from doing anything but changing it.

- **Upgrading to v2.74.1+ (two security hardenings, no behaviour you set out to use changes).** Both close a gap rather than alter a feature you drive:

  1. **The client IP behind a trusted proxy is read from the *right* of `X-Forwarded-For`.** If you front AreNET with a CDN and list its ranges in `ARENET_TRUSTED_PROXIES`, the source IP used for the country/ASN gate, the login rate-limiter and the audit rows is now the hop your own infrastructure vouched for — not the leftmost, client-supplied entry a visitor could forge. **Consequence:** relevant only to a CDN-fronted deployment; those geo / rate-limit / audit decisions now reflect the real client. AreNET at the edge with the default (loopback-only trust) is unchanged.
  2. **Alert channels can no longer reach cloud instance metadata.** The webhook and Discord senders — and the channel Test button — now refuse link-local / metadata addresses (`169.254.169.254`, `fd00:ec2::254`), the same guard the upstream and health-check probes already apply. Private and loopback webhooks stay reachable. **Consequence:** none, unless a channel was pointed at a metadata address (which should not exist).

  **No action required.**

- **Upgrading to v2.75.0+ (a new opt-in feature: route health notifications).** Nothing changes for an existing route — the feature is off until you turn it on. Each route now has a **Health notifications** section: enable it, pick an alert channel, and Arenet messages that channel when the route's upstreams go down and when they recover (with the outage duration), grouping routes that share a dead backend, with an optional reminder while it stays down. **Consequence:** none unless you enable it; an untouched route behaves exactly as before. To use it you need at least one alert channel configured (Settings → Alerting), then the toggle + channel on the route.

- **Upgrading to v2.75.1+ (a health-detection fix).** Before this release, a route's upstream that had been down since before the last reload could still show **healthy** in the UI — and route-health notifications would not fire — because Arenet re-primed every health-checked upstream optimistically on each reload, and the embedded Caddy (which keeps upstream health across a reload) had no state change left to announce. Health is now **reconciled** across a reload instead of reset-and-reprimed. **Consequence:** nothing to act on — the upgrade restarts Arenet, which re-establishes the true state on the first probe, and in-process reloads no longer flip a down upstream back to green. If you enabled route-health notifications on v2.75.0 and they seemed silent for a down backend, this is the fix.

- **Upgrading to v2.75.2+ (the other half of the health-detection fix).** v2.75.1 fixed the reload case; this fixes the rest: an upstream whose URL **omits the port** (e.g. `http://10.0.0.5` for a port-80 backend) was tracked without a port, while Caddy's health-check events always report the dial address **with** one (`10.0.0.5:80`). The down state recorded by the event never met the port-less lookup the badge and the notifier used, so the upstream stayed green. Addresses are now canonicalized to `host:port`. **Consequence:** none to act on — a down upstream whose URL omits the port is now correctly shown DOWN and fires route-health notifications. If notifications still looked silent on v2.75.1, this is why.

- **Upgrading to v2.75.3+ (an alert-channel test fix).** Pressing **Test** on an email channel whose SMTP server accepts the TCP connection but is slow to send its `220` greeting banner — a strict MTA running a reverse-DNS / SPF / DNSBL check on connect, a greeting delay, or greylisting — could hang the request indefinitely, with no HTTP response and no log line. `net/smtp` takes no timeout from the request context, and only the initial dial was bounded, so every subsequent read (the greeting, EHLO, STARTTLS, AUTH, MAIL/RCPT/DATA) could block forever. The whole SMTP conversation is now bounded by a connection deadline, and the outcome of a manual channel test (sent / failed, with the reason) is written to the server log on both code paths. **Consequence:** none to act on — a healthy channel tests exactly as before; a stalling SMTP server now returns a clear timeout error within seconds instead of hanging the admin UI, and a test always leaves a log line. If your email test seemed to do nothing with "rien dans les logs", this is the fix.

---

## 6. Automation (CLI-only)

If you want unattended upgrades, keep them **outside** Arenet — on your own schedule, with your own guardrails:

- **Docker — Watchtower** (or a cron `docker compose pull && up -d`): auto-pulls new images. Prefer a **pinned tag + manual bump** in production so an upgrade lands only when you decide.
- **Binary — systemd timer / cron**: a script that downloads the latest release, **verifies the checksum**, swaps the binary and restarts. Always back up first in the script.
- **Fleet — Ansible**: a role templating the binary/image version, gated behind a review of the release notes.

All of these run under *your* control and privileges — not the reverse proxy's.

---

## Security notes

- **Do NOT wire an "update now" button, plugin, or hack that lets the Arenet process replace its own binary.** That would require giving a network-exposed service write access to `/usr/local/bin` (or the container image) plus the ability to restart itself — a privilege-escalation and RCE amplifier if any download/parse path is ever exploited.
- **Verify integrity.** Binary releases ship a `checksums.txt` (sha256). Verify it (§3) before installing. Releases are **not** GPG/cosign-signed today, so the checksum + HTTPS from GitHub is your integrity check.
- **Supply chain.** Pin explicit versions in production; review release notes before bumping. A blind `:latest` on every host means a single bad release reaches everyone at once.
- **Back up before every upgrade.** It's the cheapest rollback you have. See [Backup & Restore](Backup-Restore).
- **Industry pattern.** nginx, Traefik, Caddy, Postgres — none auto-update via their own admin surface. Notification + manual, controlled upgrade is the norm for infrastructure that terminates your traffic.

---

_Related: [DNS Providers → Stay updated](DNS-Providers#stay-updated) · [Backup & Restore](Backup-Restore) · [Installation](Installation)_
