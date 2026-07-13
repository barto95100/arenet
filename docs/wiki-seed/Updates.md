# Updating Arenet

**🌐 English** · [Français](Updates-FR)

Arenet ships as a single binary / container image. **Updating is a manual, operator-driven action** — Arenet never downloads or installs an update itself. The [opt-in update checker](DNS-Providers#stay-updated) (v2.12.3) only *notifies* you that a newer stable release exists; this page explains how to actually upgrade, safely.

> **Why no auto-update?** See [Security notes](#security-notes) below. In short: auto-updating a reverse proxy means giving a network-facing service the privilege to overwrite its own binary and restart itself — a large attack surface and a supply-chain risk. Like nginx, Traefik, Caddy and Postgres, Arenet leaves the upgrade decision (and timing) to you.

---

## 0. Before you start: check your current version

There is **no `--version` flag**. Read the running version from any of:

- **UI** — *Settings → Updates* shows the current version (and the latest available, if the checker is enabled).
- **API** — `GET /api/v1/system/version` (admin session) → `{"current": "v2.12.3", ...}`.
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
    image: ghcr.io/barto95100/arenet:v2.12.3   # explicit tag
```
Then bump the tag, `docker compose pull`, `docker compose up -d`.

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
VERSION=v2.12.3
ARCH=linux-amd64        # or linux-arm64

cd /tmp

# Download the binary UNDER ITS RELEASE NAME + the checksums manifest.
# The name must match the entry in checksums.txt (arenet-linux-amd64)
# so `sha256sum -c` can find the file.
curl -L -o "arenet-${ARCH}" "https://github.com/barto95100/arenet/releases/download/${VERSION}/arenet-${ARCH}"
curl -L -o checksums.txt "https://github.com/barto95100/arenet/releases/download/${VERSION}/checksums.txt"

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

**Docker Compose / run** — re-pin the previous image tag and recreate:
```bash
docker pull ghcr.io/barto95100/arenet:v2.12.2   # the version you were on
# edit compose image tag back, or re-run docker run with :v2.12.2
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
