# CrowdSec

**🌐 English** · [Français](CrowdSec-FR)

[CrowdSec](https://www.crowdsec.net) is a community-powered IP reputation service : a collaborative IDS that lets your hosts share threat intelligence. Arenet ships a native [CrowdSec bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) that blocks requests from IPs the CrowdSec community has flagged.

**The CrowdSec agent itself runs separately** — as a Linux service installed from the CrowdSec repository, or as a Docker container. Both are covered below. Arenet only embeds the *bouncer* — the component that queries the agent's Local API (LAPI) and enforces decisions.

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

The agent runs on the same host as Arenet, or on any host Arenet can
reach. Pick the path that matches how Arenet itself is installed.

#### Linux package — systemd or bare-binary Arenet

```bash
curl -s https://install.crowdsec.net | sudo sh   # add the CrowdSec repository
sudo apt install crowdsec                        # Debian / Ubuntu
# sudo yum install crowdsec                      # RHEL / CentOS / Fedora
sudo systemctl enable --now crowdsec
```

The package starts the agent and its Local API. Check it is listening :

```bash
ss -tlnp | grep 8080
# tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("crowdsec",pid=…))
```

Configuration lives in `/etc/crowdsec/`, the database in
`/var/lib/crowdsec/data/`. Agent logs : `sudo journalctl -u crowdsec -f`.

See the [official Linux install guide](https://docs.crowdsec.net/u/getting_started/installation/linux/)
for other distributions.

#### Docker — containerised Arenet

```bash
docker run -d --name crowdsec \
  -e GID="$(getent group docker | cut -d: -f3)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v /var/log:/var/log:ro \
  -v crowdsec-db:/var/lib/crowdsec/data \
  -v crowdsec-config:/etc/crowdsec \
  -p 127.0.0.1:8080:8080 \
  crowdsecurity/crowdsec
```

Either way, the agent's LAPI is now on `http://127.0.0.1:8080`.

> **Every `cscli` command below is written for the package install.**
> With the Docker agent, prefix it with `docker exec crowdsec` —
> `sudo cscli decisions list` becomes
> `docker exec crowdsec cscli decisions list`.

### 2. Register the Arenet bouncer

```bash
sudo cscli bouncers add arenet
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

Since **v2.26.0**, blocked visitors get Arenet's **branded error page** instead of an empty response: a `ban` decision serves the route's **403** page, a `throttle` decision its **429** page (with a `Retry-After` header matching the decision duration). The page is the one selected for the route in its error-page settings, or the Arenet default — the same pages as the IP filter and upstream errors (see [Custom error pages](Custom-Error-Pages)).

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
sudo cscli decisions list

# Pick an IP from the output, then try to hit any of your routes from it
# (or, easier, run from a VM with that IP)
# Expected : the route returns 403 before reaching the WAF
```

You can also manually ban your own IP for a minute as a smoke test :

```bash
sudo cscli decisions add --ip "$(curl -s ifconfig.me)" --duration 60s
```

Try to hit any route from your home → 403. After 60s the ban expires, the route works again.

---

## Tuning : what to do when CrowdSec blocks legitimate users

CrowdSec is communal — sometimes an IP gets banned globally for behaviour your local users aren't doing. You have two safety valves :

### Whitelist a specific IP

```bash
sudo cscli decisions delete --ip <your-user-ip>
sudo cscli postoverflows install crowdsecurity/whitelists
# Then edit /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
# to add your user's IP / CIDR.
# Docker : that file is inside the crowdsec-config volume, so edit it with
#   docker exec -it crowdsec vi /etc/crowdsec/postoverflows/s01-whitelist/whitelists.yaml
```

### Disable the bouncer per-route

Currently CrowdSec is **global** in Arenet (all routes or no routes). If you need to bypass it on a specific route, the workaround is to put that route on a different Arenet instance OR to whitelist the source IPs at the CrowdSec agent layer.

A per-route CrowdSec toggle is on the V3 backlog ; open an issue if you'd find it useful.

---

## Fallback behaviour (LAPI down)

When the agent is unreachable — network blip, crash, restart — the bouncer **fails open by default** : requests pass through as if CrowdSec were disabled. That is deliberate (`enable_hard_fails: false`) : legitimate traffic should not go down because the agent is having a bad day.

The dashboard's CrowdSec card shows the agent status (✅ reachable / ⚠️ unreachable + last-success timestamp). Wire an [Alerting](Alerting) rule on `system_health == degraded` to get a Discord/email ping when the agent drops.

---

## See also

- [WAF](WAF) — layered defense ; WAF catches what CrowdSec doesn't
- [Country Block](Country-Block) — geo-fence layer above CrowdSec
- [Alerting](Alerting) — pager when the agent is down
- [CrowdSec official docs](https://docs.crowdsec.net) — agent install, scenarios, hub
- [hslatman/caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer) — the Caddy module Arenet uses
- `internal/crowdsec/` — Arenet's wrapping (sink, observability adapter)
