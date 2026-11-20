<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Smoke test — Security Automation pre-LRU volume (v2.83.1)

Spec: `docs/superpowers/specs/2026-11-20-automation-prelru-volume-design.md`.
Fixes the "auto-ban never fires from a single vector" bug: the WAF/throttle
60 s LRU dedup ran before the event tables, so the trigger's per-`(srcIP,
source)` row count capped at 1 per 60 s and `Threshold >= 2` was unreachable.
The trigger now reads an in-memory **pre-LRU** volume tracker instead of the
deduplicated tables (the LRUs and the tables are unchanged).

## Automated guards (CI)

```
go test -race -count=1 ./internal/automation/... ./cmd/arenet/...
```

- `TestVolumeTracker_NoDedup` — a 4-event burst is retained as 4, not 1.
- `TestVolumeTracker_PerKeyCap` / `_GlobalCap` / `_PruneRetention` — bounds (§A).
- `TestVolumeTrigger_WafBurst_BansOnce` (**G1**) — 4 identical RCE, threshold 2
  → exactly one intent. **Reinjection proof:** collapsing the tracker read to
  one row per `(srcIP, source)` in `readWaf` (the old LRU-deduped table
  behaviour) makes this and `TestVolumeTrigger_CrossTick_BansOnce` fail with
  `alertCount=0` — restore with `cp`, never `git checkout`.
- `TestVolumeTrigger_ThrottleBurst_BansOnce` (**G2**).
- `TestVolumeTrigger_CrossTick_BansOnce` (**G3**) — events in different ticks
  accumulate over the window and ban exactly once (D8 re-emit guard).
- `TestGeoForwardingWafSink_FeedsVolumeBlockOnly` — detect-mode events are NOT
  counted (the v2.58.4 invariant, now enforced at the forwarder gate).

## Manual dogfood gate (G5) — AreNET-test

Preconditions: WAF·RCE rule **Enabled**, `threshold=2`, `window=1m`, route
`whatsapp` in **Block** mode, writer healthy (badge Active). Attacker from a
public IP (e.g. ns1 / srv2009298).

```bash
# Burst of 4 identical RCE requests — the exact scenario that produced no ban.
for i in 1 2 3 4; do curl -s -o /dev/null -w "%{http_code}\n" \
  "https://whatsapp.worldgeekwide.fr/?cmd=;cat%20/etc/passwd" & done; wait
# → 4× 403

# Within ~10s (engine ticks every 5s), confirm exactly one arenet decision:
cscli decisions list -o human | grep arenet
# or filter in the UI: Posture › CrowdSec › Live LAPI, origin=arenet
```

**Pass:** exactly one `arenet/waf-rce` decision for the attacker IP, scope Ip.
**Fail:** no decision (regression) or more than one (re-emit guard broken).

Cross-check the tracker is healthy via `/metrics` (service-account token):

```
arenet_automation_memcounter_keys_total          # small; climbs only under broad attack
arenet_automation_memcounter_dropped_capglobal_total  # 0 unless > 4096 distinct (IP,source)
```

## Notes

- The in-memory tracker is empty on restart; a burst straddling a restart may
  undercount. The forensic rows persist in `waf_event` / the throttle table.
- Distributed/volumetric attacks (many srcIPs) are out of scope — the bouncer
  and rate-limit own that layer.
- D11 (in-UI `totalBansIssued24h` + a deep-link to Live LAPI filtered on
  `origin=arenet`) is a deferred v2.84.0 follow-up; `LastPushAt` already answers
  "did a ban just fire?" in the health block.
