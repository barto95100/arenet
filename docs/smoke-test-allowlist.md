<!-- Arenet smoke test — AreNET Allowlist UI (#364). AGPL-3.0. © 2026 The Arenet Authors. -->

# Smoke test — AreNET Allowlist UI (#364)

Target: v2.85.0. Run on AreNET-test before the operator GO.

Prereq: Security Automation configured and pushing bans (origin=arenet), as
validated during the v2.84.5 dogfood (burst RCE from ns1 → `arenet/waf-rce`
ban). A second source IP you control to use as the "allowlisted" vector.

## 1. UI — CRUD

1. Sidebar → **Sécurité → Allowlists** (`/security/allowlists`). The page loads
   with the origin=arenet limitation note visible.
2. Empty state shows when no allowlist exists.
3. **New allowlist** → name `office`, description, entries (one per line):
   ```
   198.51.100.10        # test vector
   10.0.0.0/24 LAN
   ```
   Toggle scope: leave **block** on, turn **throttle/audit** off. Save.
4. The row shows: name + description, entry count + preview, **Block** badge
   only, **Enabled** badge, last-edited timestamp.
5. Edit → add an invalid line `not-an-ip` → the textarea flags the line live and
   the save is refused with the invalid-line message. Remove it, save OK.
6. As a **viewer** (non-admin) user: the New/Edit/Delete actions are hidden; the
   list is still readable.

## 2. Enforcement — the point of the feature

With `office` active (scope **block**, entry `198.51.100.10`):

1. From **198.51.100.10**, trigger a WAF RCE burst (≥ threshold, as in the
   v2.84.5 dogfood). Expect: **no** `arenet/waf-rce` decision pushed for that IP.
   Log line (INFO): `automation: ban skipped (allowlisted) src_ip=198.51.100.10
   scenario=arenet/waf-rce`.
2. From a **different, non-allowlisted** IP, the same burst → ban pushed as
   normal (non-regression of the v2.84.5 pipeline).
3. **Scope check:** trigger a throttle-tier burst from 198.51.100.10 → ban IS
   pushed (`arenet/throttle-tier*`), because `office` is scoped to block only.
4. **Inactive check:** toggle `office` off, repeat the RCE burst → ban pushed
   (an inactive allowlist exempts nobody).
5. **CIDR check:** add `10.0.0.0/24`, re-enable, burst from `10.0.0.42` →
   skipped (covered by the CIDR, not just an exact IP).

## 3. Independence from CrowdSec

- The allowlist skip must NOT affect a CrowdSec-native decision. Add a `cscli
  decisions add --ip 198.51.100.10` (origin=crowdsec) and confirm the AreNET
  allowlist does NOT lift it — the bouncer still blocks. This is the documented
  limitation (origin=arenet only).

## 4. Persistence / degraded

1. Restart AreNET → allowlists survive (stored in `data/security.db`). The boot
   log shows `allowlist storage opened path=.../security.db`.
2. (Optional) Make `security.db` unreadable and restart → boot WARN
   `allowlist: security DB unavailable — allowlist disabled, automation bans
   normally (fail-closed)`; the automation still bans (fail-closed), the UI
   endpoints answer 503.

## Verdict

- [ ] CRUD + live validation OK
- [ ] block skip + INFO log OK
- [ ] non-allowlisted IP still banned (non-regression)
- [ ] scope honoured (throttle not skipped)
- [ ] inactive exempts nobody
- [ ] CIDR match OK
- [ ] CrowdSec-native decision unaffected (limitation holds)
- [ ] survives restart; fail-closed on DB loss
