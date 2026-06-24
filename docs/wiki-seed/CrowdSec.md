# CrowdSec

[CrowdSec](https://www.crowdsec.net) is a community-powered IP reputation service : a collaborative IDS that lets your hosts share threat intelligence. Arenet ships a native [CrowdSec bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) that blocks requests from IPs the CrowdSec community has flagged.

**The CrowdSec agent itself runs separately** (typically as a Docker container or systemd service on the same host). Arenet only embeds the *bouncer* — the component that queries the agent's Local API (LAPI) and enforces decisions.

---

## Architecture

```
┌─────────────────┐       ┌─────────────────┐       ┌──────────────────┐
│  Arenet         │ ────▶ │  CrowdSec       │ ◀──── │  CrowdSec Hub    │
│  (bouncer)      │ LAPI  │  agent          │       │  (community      │
│                 │ poll  │  (your host)    │       │   blocklists)    │
└─────────────────┘       └─────────────────┘       └──────────────────┘
   │                          │
   │ if IP in decision        │ scenarios trigger
   │ → reject with 403        │ on parsed log lines
   ▼                          ▼
   Client                     Local decisions
                              (banned IPs)
```

The agent parses your local logs (auth, web server, etc.), triggers on scenarios (brute-force, scanning, exploitation), and creates **decisions** (ban X for Y minutes). The bouncer polls the agent every N seconds and enforces.

You also get **community decisions** for free : the agent fetches the CrowdSec hub's curated blocklist of IPs currently abusive in the global community. Effectively a real-time blocklist updated by thousands of operators worldwide.

---

## Quick start

### 1. Install + run the CrowdSec agent

Run the agent on the same host as Arenet (or a reachable LAN host). Docker is easiest :

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 8080:8080 \
  crowdsecurity/crowdsec
```

The agent's LAPI is now on `http://<host>:8080`.

### 2. Register the Arenet bouncer

```bash
docker exec crowdsec cscli bouncers add arenet
```

The command prints an API key — copy it.

### 3. Configure Arenet

1. Sidebar → **Settings** → **CrowdSec** section
2. **LAPI URL** : `http://127.0.0.1:8080` (or your agent's address)
3. **API key** : paste the key from step 2
4. **Bouncer name** : `arenet` (matches the cscli registration)
5. **Timeout** : `5s` (default ; how long the bouncer waits for LAPI response)
6. **Test connection** → should return ✅
7. **Save**

Within ~30 seconds the bouncer is active. Any inbound request whose source IP is in CrowdSec's current decision list returns **403 Forbidden** before reaching the WAF / route handlers.

---

## What gets blocked

The bouncer enforces **whatever decisions the agent has**. Default scenarios (after `cscli scenarios install crowdsecurity/http-cve` etc.) include :

- Brute-force on SSH / web auth pages
- Scanning (nmap, masscan, web vuln scanners)
- Known exploit attempts (CVE-tagged scenarios)
- Community blocklist : IPs currently abusive across the CrowdSec network

You can extend with custom scenarios — see [CrowdSec docs](https://docs.crowdsec.net/docs/scenarios/intro).

---

## Observability

Every CrowdSec block emits a `decision_event` row in the SQLite `decision_event` table :

- `ts` — timestamp
- `src_ip` — banned IP
- `reason` — scenario name (e.g. `crowdsecurity/http-bf`)
- `duration` — ban length
- `origin` — `local` (your agent's scenarios) or `crowdsec` (community blocklist)

The `/security/decisions` page renders these with filter by origin + scenario + time. The unified `/logs` shows them alongside WAF / auth / rate-limit events.

---

## Verifying the integration is live

```bash
# Find a currently-banned IP in your agent's decision list
docker exec crowdsec cscli decisions list

# Pick an IP from the output, then try to hit any of your routes from it
# (or, easier, run from a VM with that IP)
# Expected : the route returns 403 before reaching the WAF
```

You can also manually ban your own IP for a minute as a smoke test :

```bash
docker exec crowdsec cscli decisions add --ip "$(curl -s ifconfig.me)" --duration 60s
```

Try to hit any route from your home → 403. After 60s the ban expires, the route works again.

---

## Tuning : what to do when CrowdSec blocks legitimate users

CrowdSec is communal — sometimes an IP gets banned globally for behaviour your local users aren't doing. You have two safety valves :

### Whitelist a specific IP

```bash
docker exec crowdsec cscli decisions delete --ip <your-user-ip>
docker exec crowdsec cscli postoverflows install crowdsecurity/whitelists
# Then edit /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# to add your user's IP / CIDR
```

### Disable the bouncer per-route

Currently CrowdSec is **global** in Arenet (all routes or no routes). If you need to bypass it on a specific route, the workaround is to put that route on a different Arenet instance OR to whitelist the source IPs at the CrowdSec agent layer.

A per-route CrowdSec toggle is on the V3 backlog ; open an issue if you'd find it useful.

---

## Fallback behaviour (LAPI down)

When the agent is unreachable (network blip, agent crash, restart), the bouncer **fails open by default** — requests pass through as if CrowdSec was disabled. This is the AC #13 degraded-mode contract : Arenet's own LAPI client never blocks legitimate traffic because the agent is having a bad day.

The dashboard's CrowdSec card shows the agent status (✅ reachable / ⚠️ unreachable + last-success timestamp). Wire an [Alerting](Alerting) rule on `system_health == degraded` to get a Discord/email ping when the agent drops.

---

## See also

- [WAF](WAF) — layered defense ; WAF catches what CrowdSec doesn't
- [Country Block](Country-Block) — geo-fence layer above CrowdSec
- [Alerting](Alerting) — pager when the agent is down
- [CrowdSec official docs](https://docs.crowdsec.net) — agent install, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — the Caddy module Arenet uses
- `internal/crowdsec/` — Arenet's wrapping (sink, observability adapter)
