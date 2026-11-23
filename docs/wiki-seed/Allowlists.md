# Allowlists

**🌐 English** · [Français](Allowlists-FR)

**Since v2.85.0.** AreNET allowlists exempt trusted IPs/CIDRs from the bans that
**AreNET Security Automation** issues (decisions with origin `arenet`). Use them
for uptime probes, office egress ranges or internal scanners — anything that may
trip a WAF / throttle / auth rule but must never be auto-banned.

---

## Where

**Sidebar → Sécurité → Allowlists** (`/security/allowlists`). Admin role is
required to create, edit or delete; viewers can read.

## What an allowlist holds

- **Name** + optional description (a stable slug is derived from the name).
- **Entries** — one IP or CIDR per line. A bare IP becomes `/32` (IPv4) or
  `/128` (IPv6). An optional note may follow the address after a space.
- **Scope** — three checkboxes, all on by default:
  - **Block** — exempts from WAF bans (`arenet/waf-*`).
  - **Throttle** — exempts from throttle bans (`arenet/throttle-tier*`).
  - **Audit** — exempts from auth-burst bans (`arenet/auth-*`).
- **Active** — an inactive allowlist exempts nobody (kept, not deleted).

When an allowlisted IP would otherwise be auto-banned, AreNET logs at INFO:

```
automation: ban skipped (allowlisted) src_ip=198.51.100.10 scenario=arenet/waf-rce
```

Changes take effect immediately — no restart.

## ⚠️ Limitation — origin=arenet only

AreNET Allowlist covers **only** the bans issued by AreNET Security Automation
(`origin=arenet`). It does **not** affect native CrowdSec decisions, the
Community Blocklist, or bans added with `cscli`. To exempt an IP from those, use
`cscli allowlist` on the CrowdSec side.

This is by design: AreNET enforces the exemption inside its own trigger, before
pushing to the LAPI. CrowdSec has no released allowlist **write** API, so a
"CrowdSec source-of-truth" design is not buildable today.

## Storage & backup

Allowlists live in a dedicated SQLite file, `data/security.db`, separate from
the retention-pruned `metrics.db`. If it can't be opened at boot, AreNET is
**fail-closed**: no exemptions apply (automation keeps banning) and a WARN is
logged.
