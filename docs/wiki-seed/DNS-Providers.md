# DNS Providers

**🌐 English** · [Français](DNS-Providers-FR)

Arenet issues **wildcard TLS certificates** (`*.example.com`) via the ACME **DNS-01 challenge**, which needs API access to your DNS zone. A *DNS provider* in Arenet is a saved set of credentials for that API. Since **v2.12.0** you can configure **several** providers — for example one OVH account for your personal domains and another for work — and point each wildcard at the one that owns its zone.

> **OVH is the only provider type in v1.** The design is forward-compatible with other types (Cloudflare, Route53) — see [V3 backlog](#v3-backlog).

---

## Why DNS-01 (and when you need a provider)

Per-route certificates use the **HTTP-01** challenge by default and need **no** DNS provider — Caddy answers the challenge on `:80`. You only need a DNS provider for **wildcard** certificates, because a wildcard can't be validated over HTTP-01; ACME requires DNS-01 for `*.example.com`.

| You want… | Challenge | DNS provider needed? |
| --------- | --------- | -------------------- |
| A cert for `app.example.com` (single host) | HTTP-01 (default) | No |
| A wildcard `*.example.com` (all subdomains) | DNS-01 | **Yes** |
| A single host on DNS-01 (e.g. behind a firewall with :80 closed) | DNS-01 | **Yes** |

---

## Multi-config (v2.12.0)

Each provider is an independent entry with:

| Field | Meaning |
| ----- | ------- |
| **Label** | A free-text name you choose (e.g. `OVH perso`, `OVH pro`). Shown in the wizard dropdown. |
| **Type** | `ovh` (the only type in v1). |
| **Endpoint** | The OVH region: `ovh-eu`, `ovh-ca`, `ovh-us`, `kimsufi-eu`, `kimsufi-ca`, `soyoustart-eu`, `soyoustart-ca`. |
| **Application key / Application secret / Consumer key** | The three OVH API credentials (kept secret; never shown again after saving). |

Two providers using different OVH accounts each carry their own credentials, so wildcards on zones owned by different accounts each validate through the right one.

---

## Setup, step by step

### 1. Create OVH API credentials

In the OVH API console (`https://api.ovh.com/createToken/` for `ovh-eu`), create a token with the DNS-zone rights certmagic needs:

- `GET /domain/zone/*`
- `PUT /domain/zone/*`
- `POST /domain/zone/*`
- `DELETE /domain/zone/*`

You get an **Application key**, **Application secret**, and **Consumer key**. Note them — they are the three secret fields below.

### 2. Add the provider in Arenet

Open **Settings → DNS Providers → + Add DNS provider**, then fill in:

- **Label** — a name that means something to you (`OVH perso`).
- **Endpoint** — your OVH region (`ovh-eu` for most European accounts).
- **Application key / Application secret / Consumer key** — from step 1.

Save. The row shows a `configured` badge. Add a second provider the same way if you manage a second account.

> Editing a provider later? Leave the secret fields **blank** to keep the stored values (only re-enter a secret if you're rotating it).

### 3. Create a wildcard certificate

Go to **Certificats → + Wildcard apex**. The wizard asks for:

- **Apex domain** — e.g. `example.com` (the wildcard `*.example.com` is implied).
- **DNS provider** — the dropdown lists your configured providers by label; pick the one that owns this zone.
- **Include bare apex in cert SAN** — also cover `example.com` itself, not just its subdomains.

Once declared, every route whose host matches `*.example.com` is served by that one wildcard certificate.

---

## Migration from the legacy single provider

Before v2.12.0 there was a single global OVH config. On the **first boot of v2.12.0+**, Arenet migrates it automatically:

- The old config becomes a provider labelled **"OVH (default)"** with a stable id.
- Every existing wildcard is re-pointed to it.

The migration is **transparent and idempotent** — no ACME downtime, nothing to do. A restore of a pre-v2.12 backup follows the same path on the next boot.

---

## Save-safety (v2.12.2)

Changing a provider now takes effect in the running Caddy config **immediately** (create, edit, and delete all reload Caddy). Two guards protect your certs:

- **Deleting a provider still used by a wildcard** is refused with a clear error naming the blocking wildcards — reassign or remove them first.
- **Deleting the last configured provider while DNS-01 routes depend on it** is refused too (they'd otherwise silently fall back to a self-signed cert). Deleting a *spare* provider while another configured one remains is allowed.

If a DNS-01 host ever ends up with no configured provider (e.g. via an inconsistent import), Arenet logs a loud warning naming the affected hosts instead of failing silently.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| Wildcard cert stuck / route serves a self-signed cert | No provider configured, or credentials wrong | Add/fix the provider in Settings; watch `journalctl -u arenet` for ACME errors |
| `acmeChallenge "dns-01" requires a configured DNS provider` (400 on route save) | Route set to DNS-01 with no provider | Configure a provider first, or use HTTP-01 for that route |
| Can't delete a provider (409) | It's still referenced by a wildcard or is the last one a DNS-01 route needs | Reassign/remove those wildcards or routes first |
| Credentials rejected by OVH | Token missing zone rights or wrong region | Recreate the token with the four `/domain/zone/*` rules; check the endpoint matches your account region |

More general help: [Troubleshooting](Troubleshooting).

---

## Stay updated

Arenet v2.12.3 added an **opt-in update checker**. Enable it in **Settings → Updates** to be notified (topbar badge + optional alerting rule) when a newer stable release ships — so a fix like the save-safety above reaches you promptly. Arenet never auto-updates; you stay in control of when to upgrade.

---

## V3 backlog

- **Test connection** — a button to validate a provider's OVH credentials without saving a cert.
- **More provider types** — Cloudflare, Route53. The `Type` field and the wizard's provider icon already prepare for this.

---

_Related: [Routes](Routes) · [Installation](Installation) · [Backup & Restore](Backup-Restore)_
