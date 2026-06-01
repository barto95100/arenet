# Hardening checklist

10 actionable items for an Arenet homelab install. Each has a
**verify** command. Read time: ~10 minutes. Apply time depends
on how many you already have right.

For each item: ✓ if applied, with the verify command's output
as evidence.

---

## 1. Admin port is loopback by default — keep it that way

The compose example binds admin to `127.0.0.1:8001` only.
Reach it from a workstation via SSH tunnel:

```bash
ssh -L 8001:localhost:8001 <homelab-host>
```

**Verify** (from a LAN machine — should fail):

```bash
curl -m 3 http://<homelab-LAN-IP>:8001/healthz
# expected: connection refused / timeout, NOT a 401
```

If you've intentionally opened admin to LAN (`ARENET_ADMIN_BIND=
0.0.0.0:8001`), apply items 2 + 3 below.

## 2. Put TLS in front of LAN-exposed admin

Admin runs plain HTTP. If you expose it on LAN, terminate TLS
with a reverse proxy in front (Caddy, Nginx, Cloudflare Tunnel).

**Verify**:

```bash
curl -I https://admin.<your-domain>/healthz
# expected: HTTP/2 200 with the proxy's cert
```

Recipe (Caddy in front):

```
admin.<your-domain> {
    reverse_proxy 127.0.0.1:8001
}
```

## 3. Rotate the admin TLS cert (advanced)

If you skip path 2 and use Arenet's direct-TLS option,
generate a cert and supply both:

```bash
ARENET_ADMIN_TLS_CERT=/etc/arenet/admin.crt
ARENET_ADMIN_TLS_KEY=/etc/arenet/admin.key
```

**Verify**:

```bash
echo | openssl s_client -connect <host>:8001 -servername admin 2>/dev/null \
    | openssl x509 -noout -dates
# expected: notAfter > 30 days from now
```

Rotate on a calendar reminder; Arenet doesn't ACME its own
admin cert (chicken-egg — auto-TLS for admin is on the
roadmap).

## 4. Confirm the rate-limit is active

Step Q rate-limit protects all `/api/v1/*` endpoints against
credential stuffing (Step S.4 lifted it from `/auth` only to
the whole admin tree).

**Verify** (don't run against a real install — block-out is
1 hour):

```bash
# Manually trigger 11 wrong logins from a test IP. The 11th
# should return 429 with Retry-After header.
for i in $(seq 1 11); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -X POST http://127.0.0.1:8001/api/v1/auth/login \
    -d '{"username":"wrong","password":"wrong"}' \
    -H "Content-Type: application/json"
done
# expected: 401×10 then 429
```

## 5. Secrets via env vars or Docker secrets — NOT in TOML

The config file at `/etc/arenet/config.toml` is fine for
non-secret tuning (ports, log levels). Anything sensitive
(`ARENET_CROWDSEC_API_KEY`, OVH DNS provider creds, etc.)
goes via:

- env vars (`/etc/arenet/arenet.env`, mode 0600, root-owned).
- Docker secrets (file at `/run/secrets/<name>`).

**Verify**:

```bash
sudo stat -c '%a %U:%G' /etc/arenet/arenet.env
# expected: 600 root:root
```

Never check secrets into git. Add `arenet.env` to your
deployment's `.gitignore`.

## 6. Run as non-root

The Docker image's USER is `nonroot` (uid 65532). The systemd
unit's User is `arenet`. Privileged ports (80/443) bind via
`CAP_NET_BIND_SERVICE`, not root.

**Verify (Docker)**:

```bash
docker inspect arenet --format '{{.Config.User}}'
# expected: nonroot:nonroot
```

**Verify (systemd)**:

```bash
sudo systemctl show arenet --property=User
# expected: User=arenet
```

## 7. Filesystem hardening on systemd

The unit ships `ProtectSystem=strict`, `ProtectHome=true`,
`PrivateTmp=true`, `NoNewPrivileges=true`,
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`. Only
`/var/lib/arenet` is writable; everything else is RO or
hidden.

**Verify**:

```bash
sudo systemctl show arenet --property=ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges
# expected: ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes, NoNewPrivileges=yes
```

## 8. Backup before every upgrade

Step S.D8 auto-migrates schemas forward on first boot of a
new version. Migrations are tested, but the operator owns the
backup.

```bash
# See docs/operations/backup.md for the exact commands.
```

**Verify**: a backup &lt; 7 days old exists in
`/var/backups/` (or wherever you snapshot to).

## 9. Restrict outbound network if you don't use CrowdSec / ACME

Arenet's outbound needs:

- ACME (Let's Encrypt: `:80` + `:443` to `acme-v02.api.
  letsencrypt.org`) — only if any route has TLS enabled.
- CrowdSec LAPI — only if `ARENET_CROWDSEC_API_KEY` is set.
- DNS provider (OVH `:443`) — only for DNS-01 wildcards.

If none of those apply, your firewall can deny outbound
entirely.

**Verify**:

```bash
sudo iptables -L OUTPUT -v -n | grep arenet
# (or your firewall's equivalent)
```

## 10. Disable dev mode in production

`--dev` enables verbose logging + skips TLS auto-issuance +
serves a dev landing page. Never set in production.

**Verify**:

```bash
sudo journalctl -u arenet --since "5 min ago" | grep -i "dev=true"
# expected: no matches
```

In compose, make sure your environment block does NOT contain
`ARENET_DEV=true`.

---

## Quick scorecard

After applying all 10, count your ✓s:

- 10 ✓: hardened production posture.
- 7–9 ✓: solid, with documented exceptions.
- &lt; 7 ✓: still in dev-mode territory — pick the lowest-
  hanging items and apply them first (1, 6, 8, 10 are the
  highest-impact / lowest-effort).
