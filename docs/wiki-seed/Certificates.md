# Certificates

Arenet obtains and renews TLS certificates **automatically** through the embedded Caddy v2 / certmagic engine. A certificate is issued because a **route** (or a **wildcard managed-domain policy**) references its hostname — there is no separate "create a certificate" action. Since **v2.16.0** the `/certs` page has a **Delete** button for removing a certificate you no longer need; this page explains how it works, and the manual on-disk procedure for the cases the button intentionally blocks.

---

## How certificates are managed

- Certificates are **auto-issued and auto-renewed** by certmagic. You never create them by hand: enable TLS on a route (challenge `http-01` or `dns-01`), or define a wildcard apex policy, and Arenet emits the matching Caddy config so ACME obtains the cert.
- The `/certs` page is a status/expiry dashboard with a drill-down into cert events, **plus a Delete action per row** (v2.16.0). There is no force-renew or revoke button.
- Certificate deletion is exposed as `DELETE /api/v1/certificates/{domain}` (admin only); `GET /api/certificates` remains the dashboard's data source.
- Arenet keeps **no certificate record in its database**. The cert lifecycle lives entirely on disk under certmagic's store; Arenet only holds an in-memory view, rebuilt from disk at every boot.

---

## Deleting a certificate from the UI

On the `/certs` page, each certificate row has a **Delete** button. Click it, confirm, and Arenet removes the certificate's on-disk material (`.crt`/`.key`/`.json`, across every issuer) and clears its row — no server access or restart needed.

**Orphans only.** A certificate can be deleted only when **nothing still references its domain**. If a route (host or alias — including a *disabled* route) or a wildcard managed-domain still uses the hostname, the delete is **blocked** and a dialog lists the route(s) in the way. Delete or disable those first, then delete the certificate.

Why block it? Deleting a certificate whose hostname is still served would just make Caddy **re-issue it** on the next reload (a fresh ACME request — and, if you are near Let's Encrypt's rate limit, a failure loop). Removing an *orphan* is safe: nothing serves it, so nothing re-requests it.

- **No revocation.** Deletion removes the local files only; it does **not** revoke the certificate at the CA (it stays technically valid until expiry). Revocation is not offered in-app.
- **Wildcards** are handled the same way — the `/certs` row for `*.example.com` deletes the `wildcard_.example.com` material, and is blocked while the managing wildcard apex policy is live.
- The removed certificate is evicted from Caddy's in-memory cache by the same reload, so it stops being served immediately.

If the certificate you want gone is **still referenced** (e.g. you want to force a clean re-issue for an *active* route without deleting the route), the button will block it — use the manual on-disk procedure below instead.

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

## Manual cleanup procedure (advanced / blocked cases)

The UI Delete button (above) is the normal path and covers orphan certificates. Use this manual procedure only for the cases the button intentionally blocks — chiefly **forcing a clean re-issue for a domain that is still served** (still referenced by an active route or a live wildcard policy). Two steps: stop serving it, then remove the files.

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

If you delete a route but keep its certificate, the certificate becomes an **orphan on disk**: harmless (Caddy no longer serves it), but it still occupies space and keeps its ACME account references. Its `/certs` row now offers the **Delete** button (it is an orphan, so deletion is allowed) — that's the one-click way to reclaim it. The manual Step 2 above remains available if you prefer operating on the store directly.

---

## See also

- [Routes](Routes) — enabling TLS + choosing the HTTP-01 / DNS-01 challenge
- [DNS Providers](DNS-Providers) — required for DNS-01 / wildcard certificates
- [Backup & Restore](Backup-Restore) — cert files are **not** in the JSON snapshot; they live in the certmagic store on disk
- [Troubleshooting](Troubleshooting) — diagnosing renewal / issuance failures
