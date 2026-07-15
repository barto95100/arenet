# Certificates

Arenet obtains and renews TLS certificates **automatically** through the embedded Caddy v2 / certmagic engine. A certificate is issued because a **route** (or a **wildcard managed-domain policy**) references its hostname — there is no separate "create a certificate" action, and there is no "delete a certificate" button either. This page explains why, and the exact manual procedure to remove a certificate (HTTP-01 or DNS-01) when you really need to.

---

## How certificates are managed

- Certificates are **auto-issued and auto-renewed** by certmagic. You never create them by hand: enable TLS on a route (challenge `http-01` or `dns-01`), or define a wildcard apex policy, and Arenet emits the matching Caddy config so ACME obtains the cert.
- The `/certs` page is **read-only** (a status/expiry dashboard with a drill-down into cert events). It has **no delete, revoke, or force-renew button** by design.
- There is **no `DELETE` API** for certificates. The only cert endpoint is `GET /api/certificates` (the dashboard's data source).
- Arenet keeps **no certificate record in its database**. The cert lifecycle lives entirely on disk under certmagic's store; Arenet only holds an in-memory view, rebuilt from disk at every boot.

**Consequence:** deleting a route (or a managed-domain policy) stops the certificate from being **served** (Caddy no longer references its hostname) and clears its row from `/certs` — but the certificate **files stay on disk**. To physically remove them you must delete them on the server and restart Arenet.

---

## Why there is no "delete certificate" button

This is a deliberate design choice, not an oversight:

- **Caddy v2 emits no cert-removal event**, so Arenet cannot reliably react to a deletion in-process.
- The "delete the files and let ACME re-obtain" approach introduces a **downtime window** at the next TLS handshake, and was explicitly rejected as an automated in-app action for that production-impact risk.

So certificate removal stays a **deliberate, manual, on-disk operation** — described below.

---

## Where certificates live on disk

certmagic stores certificates under Caddy's data directory, which resolves from the process `$HOME` (`$XDG_DATA_HOME/caddy` or `$HOME/.local/share/caddy`). On a standard Arenet install (`$HOME = /var/lib/arenet`), that is:

```
/var/lib/arenet/.local/share/caddy/certificates/
  <issuer>/                         e.g. acme-v02.api.letsencrypt.org-directory
    <domain>/                       e.g. app.example.com
      <domain>.crt                  leaf + chain
      <domain>.key                  private key
      <domain>.json                 certmagic metadata
```

Notes:
- **Wildcards** are stored as `wildcard_.example.com/` (for `*.example.com`).
- The `<issuer>` directory is the ACME directory host (Let's Encrypt production is `acme-v02.api.letsencrypt.org-directory`; staging and ZeroSSL have their own).
- The path is the **same for HTTP-01 and DNS-01** certificates — the challenge type does not change where the cert is stored, so the cleanup procedure is identical for both.

---

## Manual cleanup procedure

Do this only when you genuinely want the certificate gone (e.g. a decommissioned domain, or you want to force a clean re-issue). Two steps: stop serving it, then remove the files.

### Step 1 — stop serving the certificate (in the app)

Delete the object that references the hostname:
- a **route** → Sidebar → **Routes** → delete the route, **or**
- a **wildcard apex policy** → `/certs` page → "Politiques wildcard par apex" → delete the apex.

This removes the hostname from the emitted Caddy config (Caddy stops serving that cert) and clears its row from `/certs`. **The files are still on disk after this step.**

### Step 2 — remove the files on disk and restart

Pick your deployment.

**systemd / binary install** (`$HOME = /var/lib/arenet`):

```bash
# List what's there first — confirm the exact issuer + domain directory names.
sudo ls /var/lib/arenet/.local/share/caddy/certificates/*/

# Remove the domain's cert directory (adjust the issuer + domain).
sudo systemctl stop arenet
sudo rm -rf "/var/lib/arenet/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/app.example.com"
sudo systemctl start arenet

# For a wildcard *.example.com the directory is wildcard_.example.com:
# sudo rm -rf ".../certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.example.com"
```

**Docker** (container `arenet`, data volume `arenet-data` mounted at `/var/lib/arenet`):

The runtime image is **distroless — it has no shell**, so `docker exec arenet ls/rm …` does **not** work. Operate on the named volume through a throwaway `alpine` container instead:

```bash
# Inspect
docker run --rm -v arenet-data:/data alpine \
  ls /data/.local/share/caddy/certificates/

# Remove the domain's cert dir, then restart so Arenet re-reads the cleaned disk on boot
docker compose stop arenet
docker run --rm -v arenet-data:/data alpine \
  rm -rf "/data/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/app.example.com"
docker compose start arenet
```

On restart, Arenet's boot-time reconcile re-seeds the `/certs` dashboard from the now-cleaned store, so the removed certificate disappears from the UI.

> ⚠️ Delete only the **domain** directory you intend to remove. Do not delete the whole `certificates/` tree unless you want every certificate re-issued from scratch (that triggers fresh ACME requests for every served hostname on the next handshake — mind Let's Encrypt rate limits).

---

## "Orphaned" certificates

If you delete a route but skip Step 2, the certificate becomes an **orphan on disk**: harmless (Caddy no longer serves it, it no longer shows in `/certs`), but it still occupies space and keeps its ACME account references. Run Step 2 whenever you want to reclaim that state.

---

## See also

- [Routes](Routes) — enabling TLS + choosing the HTTP-01 / DNS-01 challenge
- [DNS Providers](DNS-Providers) — required for DNS-01 / wildcard certificates
- [Backup & Restore](Backup-Restore) — cert files are **not** in the JSON snapshot; they live in the certmagic store on disk
- [Troubleshooting](Troubleshooting) — diagnosing renewal / issuance failures
