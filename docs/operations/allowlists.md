<!-- Arenet operations doc — AreNET Allowlists (#364). AGPL-3.0. © 2026 The Arenet Authors. -->

# AreNET Allowlists

**Since v2.85.0.** AreNET allowlists exempt trusted IPs/CIDRs from the bans that
**AreNET Security Automation** issues (origin `arenet`). Use them for uptime
probes, office egress ranges, internal scanners — anything that may trip a WAF /
throttle / auth rule but must never be auto-banned.

## Using the UI

**Sidebar → Sécurité → Allowlists** (`/security/allowlists`). Admin role is
required to create, edit or delete; viewers can read.

Each allowlist has:

- **Name** + optional description (a stable slug is derived from the name).
- **Entries** — one IP or CIDR per line. A bare IP is stored as `/32` (IPv4) or
  `/128` (IPv6). An optional note may follow the address after a space.
- **Scope** — three checkboxes, all on by default:
  - **Block** — exempts from WAF bans (`arenet/waf-*`: RCE, SQLi, XSS, LFI,
    Protocol, Other).
  - **Throttle** — exempts from throttle bans (`arenet/throttle-tier*`).
  - **Audit** — exempts from auth-burst bans (`arenet/auth-*`).
- **Active** — an inactive allowlist exempts nobody (kept for later, not
  deleted).

When an allowlisted IP would otherwise be auto-banned, AreNET logs at INFO:

```
automation: ban skipped (allowlisted) src_ip=198.51.100.10 scenario=arenet/waf-rce
```

Changes take effect immediately on the running engine — no restart.

## Important limitation (origin=arenet only)

> **AreNET Allowlist covers only the bans issued by AreNET Security Automation
> (`origin=arenet`).** It does NOT affect native CrowdSec decisions, the
> CrowdSec Community Blocklist, or bans added with `cscli`. To exempt an IP from
> those, use `cscli allowlist` on the CrowdSec side.

This is by design: AreNET enforces the exemption inside its own trigger, before
pushing to the LAPI. CrowdSec has no released write API for allowlists, so a
"CrowdSec source-of-truth" design is not buildable today.

## Storage & backup

Allowlists live in a dedicated SQLite file, `data/security.db`, kept separate
from the retention-pruned `metrics.db` so this operator config is never pruned.
If the file can't be opened at boot, AreNET is **fail-closed**: no exemptions
apply (the automation keeps banning normally) and a WARN is logged.
