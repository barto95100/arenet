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

## External / uploaded certificates (v2.19.0)

Everything above is about certificates Arenet **obtains and renews itself** via ACME. Since **v2.19.0** you can also **upload a certificate you already hold** — issued by an external CA (DigiCert, a corporate PKI, a non-ACME or air-gapped CA) — and serve it on a route **without ACME**. This is the SOCLE of the external-cert story: upload + serve + an expiry alert. There is no in-app CSR generation or auto-renewal yet.

### What it is

An **external certificate** is a leaf certificate + its chain + its private key, in PEM, that you paste into Arenet. Arenet parses the leaf at upload time to show its issuer, subject, serial, key/signature algorithm, validity window (`notBefore`/`notAfter`) and SAN list, then stores the material and serves it on any route you point at it. Unlike ACME certs (which live only in the certmagic on-disk store), external certs are a **record in Arenet's database** — the `/certs` page's **External certificates** card lists them.

### How to upload

1. Sidebar → **Certificates** (`/certs`) → **External certificates** card → **+ Upload certificate**
2. Give it a **name** (and optional description)
3. Paste the three PEM blocks:
   - **Certificate** — your domain's certificate, the "leaf" (e.g. `your_domain.crt` / `cert.pem` / `fullchain.pem`, public)
   - **Chain** — the CA's intermediate certificate(s) linking your leaf to a trusted root (e.g. `intermediate.crt` / `ca-bundle.crt` / `chain.pem`, public; optional if your leaf is directly issued)
   - **Private key** — the matching key generated with your CSR (e.g. `your_domain.key` / `privkey.pem`)
4. **Upload**

> **Fullchain shortcut (v2.19.1).** Many CAs (vendor-agnostic) hand you a single **"fullchain"** file with several `-----BEGIN CERTIFICATE-----` blocks — the leaf first, then the intermediates. Just paste the whole file into **Certificate** and leave **Chain** empty: Arenet splits the leaf from the intermediates automatically. Supplying a chain in **both** the Certificate field (as a fullchain) and the Chain field is rejected (`chain_specified_twice`) to avoid a duplicated chain.

Arenet validates the material before storing it. **Blocking** errors reject the upload: the leaf PEM does not parse, the chain PEM does not parse, or the **private key does not match the certificate**. **Non-blocking** warnings are surfaced but still let you save — the cert is already expired, not yet valid (you can stage a cert ahead of a cutover), signed with a weak algorithm (SHA-1 / MD5), or the chain looks incomplete. A CRLF PEM pasted from a Windows tool is normalized automatically.

> **The private key is write-only.** After upload it is **never shown again** — API responses redact it, and it is excluded from backup snapshots unless you explicitly `--include-secrets`. When you edit a cert, leaving the key field empty keeps the stored key; the only way to change the key is to paste a new one.

### Renewal is MANUAL

Arenet does **NOT** auto-renew an uploaded certificate — there is no ACME account behind it, so nothing renews on its own. **You** must re-upload a fresh cert before the old one expires.

To avoid being surprised, set up the **`cert_manual_expiring`** alerting rule:

1. **Settings → Alerting → + Rule**
2. Source: **`cert_manual_expiring`**
3. Threshold: warn **N days** before `notAfter` (default **30**)
4. Route it to your channel (Discord / webhook / email) like any other rule

The rule fires **once per transition** (edge-triggered) when an uploaded cert crosses inside the threshold — not on every poll. When your CA issues the renewed cert, **re-upload it**: edit the external cert and paste the new leaf (+ chain + key). Arenet re-parses and the new validity window takes effect on the next reload.

### Linking a certificate to a route

An uploaded cert is not served until a route references it:

1. Edit a route → **TLS / Cert Source** area → **Cert Source = Manual**
2. Pick the uploaded certificate from the list

Only certificates whose **SAN covers the route's host** are offered. The match is exact or a **one-label wildcard** (RFC 6125): a cert with SAN `*.example.com` covers `app.example.com` but **not** `sub.app.example.com` or the bare `example.com`. See [Routes](Routes#cert-source-acme--internal--manual) for the Cert Source picker.

### Wildcard external cert vs ACME wildcard

A wildcard **external** cert is just a cert whose SAN list contains `*.example.com`. Unlike an **ACME managed-domain apex** (which auto-covers every subdomain route under it), an external wildcard has **no auto-coverage**: each route that wants it must reference it **explicitly** via Cert Source = Manual. One external cert (wildcard or multi-SAN) can be referenced by as many routes as its SANs cover — there just is no "managed domain" magic; you wire each route yourself.

### Deleting an external certificate

Delete an external cert from its row on the **External certificates** card.

- **Referenced certs are blocked (409).** If any route in **Manual** mode still points at the cert, the delete is refused and the dialog lists the blocking route host(s). Change those routes' Cert Source (or remove them) first.
- **Delete ≠ revoke.** Removing the cert from Arenet only drops the stored material; it does **NOT** revoke it at the CA. If you need the certificate revoked (key compromise, mis-issuance), do that at your **CA's portal** — consistent with how ACME cert deletion also never revokes.

---

## See also

- [Routes](Routes) — enabling TLS + choosing the HTTP-01 / DNS-01 challenge, and the Manual Cert Source
- [DNS Providers](DNS-Providers) — required for DNS-01 / wildcard certificates
- [Backup & Restore](Backup-Restore) — cert files are **not** in the JSON snapshot; they live in the certmagic store on disk
- [Troubleshooting](Troubleshooting) — diagnosing renewal / issuance failures
