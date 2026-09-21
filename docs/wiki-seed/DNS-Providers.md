# DNS Providers

**🌐 English** · [Français](DNS-Providers-FR)

Arenet issues **wildcard TLS certificates** (`*.example.com`) via the ACME **DNS-01 challenge**, which needs API access to your DNS zone. A *DNS provider* in Arenet is a saved set of credentials for that API. Since **v2.12.0** you can configure **several** providers — for example one OVH account for your personal domains and another for work — and point each wildcard at the one that owns its zone.

> **Since v2.26.0, nine provider types are supported** — OVHcloud, Cloudflare, DigitalOcean, Gandi, Hetzner, Infomaniak, Porkbun, Amazon Route 53 and Scaleway. See [Supported providers](#supported-providers-v2260).

---

## Why DNS-01 (and when you need a provider)

Per-route certificates use the **HTTP-01** challenge by default and need **no** DNS provider — Caddy answers the challenge on `:80`. You only need a DNS provider for **wildcard** certificates, because a wildcard can't be validated over HTTP-01; ACME requires DNS-01 for `*.example.com`.

| You want… | Challenge | DNS provider needed? |
| --------- | --------- | -------------------- |
| A cert for `app.example.com` (single host) | HTTP-01 (default) | No |
| A wildcard `*.example.com` (all subdomains) | DNS-01 | **Yes** |
| A single host on DNS-01 (e.g. behind a firewall with :80 closed) | DNS-01 | **Yes** |

---

## Supported providers (v2.26.0)

| Type | Credentials | Rights the token needs |
| ---- | ----------- | ---------------------- |
| **OVHcloud** | Endpoint (region), Application key, Application secret, Consumer key | `GET/PUT/POST/DELETE /domain/zone/*` |
| **Cloudflare** | API token, optional Zone token | *Zone → DNS → Edit* on the zone(s). If the API token is scoped to specific zones, add a *Zone token* with *Zone → Zone → Read* on all zones |
| **DigitalOcean** | API token | Read + write (or the `domain` read/create/update/delete scopes) |
| **Gandi** | Personal access token | *Manage domain name technical configurations* (LiveDNS) on the domain |
| **Hetzner** | Hetzner **Cloud** API token | Read & Write on the project hosting the zone. Zones must live in the new Hetzner Console DNS — tokens of the legacy DNS Console (dns.hetzner.com) do not work |
| **Infomaniak** | API token | The *domain* scope |
| **Porkbun** | API key, Secret API key | *API Access* must be enabled on each domain in the Porkbun dashboard |
| **Amazon Route 53** | Region, Access key ID, Secret access key, optional Hosted zone ID | `route53:ListHostedZonesByName`, `ListResourceRecordSets`, `ChangeResourceRecordSets`, `GetChange` |
| **Scaleway** | Secret key (IAM API key), Organization ID | *DomainsDNSFullAccess* |

> **Testing status.** OVHcloud is the reference provider, live-tested by the maintainer. The eight others are **validated automatically** — every build checks that Arenet's credential fields match the real Caddy DNS module of each provider, and the v2.26.0 release smoke confirmed that each module reaches the provider's real API (rejecting dummy credentials cleanly) — but they are **not live-tested end to end by the maintainer** (no accounts there): no real certificate has been issued through them yet. Use the [Test connection](#test-connection-v2260) button to check your own credentials, and please report any issue.

Each provider form links to the page where that provider's credentials are created. Rights evolve on the providers' side — when in doubt, their own documentation wins.

---

## Multi-config (v2.12.0)

Each provider is an independent entry with:

| Field | Meaning |
| ----- | ------- |
| **Label** | A free-text name you choose (e.g. `OVH perso`, `Cloudflare pro`). Shown in the wizard dropdown. |
| **Type** | One of the [supported providers](#supported-providers-v2260). Chosen at creation; to switch type, delete and recreate the provider. |
| **Credentials** | The fields of that type (see the table above). Secret fields are never shown again after saving; non-secret ones (OVH endpoint, Route 53 region, Scaleway organization ID…) are displayed in the list. |

Two providers — of the same type with different accounts, or of different types — each carry their own credentials, so wildcards on zones owned by different accounts or providers each validate through the right one.

---

## Setup, step by step

### 1. Create the API credentials

Create a token with the rights listed in [Supported providers](#supported-providers-v2260) (the Arenet form links to the right page for each type). Example for **OVHcloud**: in the OVH API console (`https://api.ovh.com/createToken/` for `ovh-eu`), create a token with the DNS-zone rights certmagic needs:

- `GET /domain/zone/*`
- `PUT /domain/zone/*`
- `POST /domain/zone/*`
- `DELETE /domain/zone/*`

You get an **Application key**, **Application secret**, and **Consumer key**. Note them — they are the three secret fields below.

For **Cloudflare**: *My Profile → API Tokens → Create Token*, template *Edit zone DNS*, restricted to your zone.

### 2. Add the provider in Arenet

Open **Settings → DNS Providers → + Add DNS provider**, then fill in:

- **Label** — a name that means something to you (`OVH perso`).
- **Type** — your DNS provider. The credential fields below adapt to it (required ones are marked `*`).
- **Credentials** — from step 1 (for OVH: the endpoint, e.g. `ovh-eu` for most European accounts, and the three keys).

Save. The row shows a `configured` badge. Click **⚡ Test connection** on the row to check the credentials right away. Add more providers the same way for other accounts.

> Editing a provider later? Leave the secret fields **blank** to keep the stored values (only re-enter a secret if you're rotating it).

### 3. Create a wildcard certificate

Go to **Certificats → + Wildcard apex**. The wizard asks for:

- **Apex domain** — e.g. `example.com` (the wildcard `*.example.com` is implied).
- **DNS provider** — the dropdown lists your configured providers by label; pick the one that owns this zone.
- **Include bare apex in cert SAN** — also cover `example.com` itself, not just its subdomains.

Once declared, every route whose host matches `*.example.com` is served by that one wildcard certificate.

---

## Test connection (v2.26.0)

The **⚡** button on a configured provider opens *Test connection*. Arenet lists the records of a zone through the provider's API with the stored credentials — the same code path ACME DNS-01 uses — and shows the number of records found, or the provider's error message.

- **Zone** — prefilled with the first wildcard apex bound to the provider; type any zone the account manages otherwise (e.g. `example.com`).
- **Read-only** — nothing is created or changed in your zone.
- A green result proves authentication and **read** access. Write access is only exercised at certificate issuance, so if a wildcard still fails, check the token's write rights.
- Secrets are never included in the result: provider error messages that echo a credential are scrubbed (`[REDACTED]`).

---

## Migration from the legacy single provider

Before v2.12.0 there was a single global OVH config. On the **first boot of v2.12.0+**, Arenet migrates it automatically:

- The old config becomes a provider labelled **"OVH (default)"** with a stable id.
- Every existing wildcard is re-pointed to it.

The migration is **transparent and idempotent** — no ACME downtime, nothing to do. A restore of a pre-v2.12 backup follows the same path on the next boot.

v2.26.0 changes the storage format of provider credentials (to support several types). Existing OVH providers are converted automatically at boot, and backups taken with earlier versions restore as before. The emitted Caddy configuration of an OVH provider is unchanged.

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
| *Test connection* fails with 401 / 403 / "invalid token" | Wrong credential, or token without rights on this zone | Recreate the token with the rights in [Supported providers](#supported-providers-v2260); check the zone belongs to this account |
| *Test connection* OK but the wildcard is not issued | The token can read the zone but not write TXT records | Grant write (edit) rights on DNS records; watch `journalctl -u arenet` for the ACME error |
| Hetzner: "the token you have provided is invalid" | Legacy DNS Console token, or zone not yet migrated | Use a Hetzner **Cloud** API token and a zone hosted in the Hetzner Console |

More general help: [Troubleshooting](Troubleshooting).

---

## Stay updated

Arenet v2.12.3 added an **opt-in update checker**. Enable it in **Settings → Updates** to be notified (topbar badge + optional alerting rule) when a newer stable release ships — so a fix like the save-safety above reaches you promptly. Arenet never auto-updates; you stay in control of when to upgrade.

The **enable switch is UI-only** (there is no env toggle — the check stays off until you opt in). Once enabled, the check runs ~30s after boot then every **24h**; a manual "Check now" button bypasses the cadence. To change the cadence, set **`ARENET_UPDATE_CHECK_INTERVAL`** (a Go duration such as `12h`; default `24h`, minimum `1h` — lower or invalid values fall back to `24h`). See how to upgrade once notified in [Updating Arenet](Updates).

---

## Backlog

- **More provider types** — adding one is now a small change (registry entry + Caddy module); open an issue with the provider you need.
- **Per-route provider selection** for single-host DNS-01 routes (managed domains already pick their provider).
- **DNS-01 propagation settings** (custom resolvers, propagation timeout) for split-horizon setups.

---

_Related: [Routes](Routes) · [Installation](Installation) · [Backup & Restore](Backup-Restore)_
