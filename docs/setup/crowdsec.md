<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# CrowdSec — Setup guide for Arenet

> Configure the CrowdSec bouncer that ships embedded in Arenet
> (Step CS.1). Arenet is **deployment-agnostic**: it talks to
> any reachable LAPI HTTP endpoint. The doc below walks through
> the three common topologies, the bouncer-key generation, and
> a tiered list of recommended scenarios.

## What Arenet does with CrowdSec

Arenet embeds the `caddy-crowdsec-bouncer` module
(`github.com/hslatman/caddy-crowdsec-bouncer v0.12.1`) and wires
it into the Caddy request chain at **position #2**, between the
metrics counter (#1) and the country-block gate (#3, when
enabled). The full pre-WAF chain order is:

```
metrics  →  country_block  →  crowdsec  →  WAF / auth / route
```

**Important implication**: if you configure both country-block
and CrowdSec on the same route, the country-block decision
fires FIRST. An IP from a blocked country is rejected before
the CrowdSec bouncer ever sees the request. This is intentional
— geo lookups are local (cheap, deterministic); LAPI calls cross
a process boundary (expensive, fail-open if LAPI is down). The
trade-off: you'll see fewer CrowdSec decisions on routes with
country-block enabled, because country-block already filtered
those sources upstream. For full CrowdSec visibility, leave
country-block off on at least one observability-target route.

The bouncer's decisions feed Arenet's GeoEvent sink and land in
`/observability/logs` alongside WAF + country-block events, with
the existing geo enricher attaching country / city / lat / lon.

## A — Deployment options

Arenet does not assume any deployment topology. The LAPI URL
field accepts any `http(s)` URL the Arenet process can reach.

### Option A.1 — apt install on the same host

Recommended when Arenet runs as a systemd service or directly
as a binary on a Linux host.

```bash
curl -s https://install.crowdsec.net | sudo sh
sudo apt install crowdsec
sudo systemctl enable --now crowdsec
```

Verify the engine is listening on the default LAPI port:

```bash
ss -tlnp | grep 8080
# tcp  LISTEN  0  4096  127.0.0.1:8080  0.0.0.0:*  users:(("crowdsec",pid=...,fd=...))
```

LAPI URL to use in Arenet Settings → CrowdSec bouncer:
`http://127.0.0.1:8080`

### Option A.2 — Docker container with ports mapping

Recommended for homelab Docker deployments where Arenet runs on
the host and CrowdSec runs in a container with port 8080 mapped
back to the host.

```yaml
# docker-compose.yml
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
      - /var/log:/var/log:ro
    restart: unless-stopped

volumes:
  crowdsec-config:
  crowdsec-data:
```

LAPI URL to use: `http://127.0.0.1:8080` (same as Option A.1,
because the port is mapped to loopback).

### Option A.3 — Arenet + CrowdSec as sibling containers

Recommended when both Arenet and CrowdSec run as containers in
the same Docker compose network.

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:latest
    depends_on: [crowdsec]
    networks: [arenet-net]
    # ... other Arenet config

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    networks: [arenet-net]
    volumes:
      - crowdsec-config:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    restart: unless-stopped

networks:
  arenet-net:

volumes:
  crowdsec-config:
  crowdsec-data:
```

LAPI URL to use: `http://crowdsec:8080` (Docker DNS resolves
the `crowdsec` service name to the container IP within the
shared network).

## B — Generate a bouncer API key

The bouncer key is the credential Arenet uses to authenticate
against LAPI. Generated once via `cscli`; if lost, you must
delete the bouncer entry and create a new one (the secret is
displayed only at creation time).

```bash
# On the host running CrowdSec (or `docker exec` into the container)
sudo cscli bouncers add arenet
# Api key for 'arenet':
#
#    abc123def456ghi789jkl0123456789mnopqrstuvwxyz
#
# Please keep this key since you will not be able to retrieve it!
```

Paste the key into Arenet UI: **Settings → CrowdSec bouncer →
Bouncer API key**, save & apply. Click **Test connection** to
verify; the badge should turn green and show the LAPI version.

The bouncer name (default `arenet`) is cosmetic — LAPI
identifies the bouncer by its API key, not its name. The name
shows up in `cscli bouncers list`, useful for the operator
auditing which bouncer connected to LAPI.

## C — Verify connectivity from Arenet

If the **Test connection** button in the UI returns a failure,
verify the LAPI is reachable from the Arenet process:

### From the Arenet host (Option A.1, A.2):

```bash
curl -i \
  -H "X-Api-Key: <YOUR_BOUNCER_KEY>" \
  http://127.0.0.1:8080/v1/decisions
# HTTP/1.1 200 OK
# Content-Type: application/json
# [...]
# []   (or a non-empty array if there are active decisions)
```

### From the Arenet container (Option A.3):

```bash
docker exec arenet sh -c \
  'curl -sS -i -H "X-Api-Key: <YOUR_BOUNCER_KEY>" http://crowdsec:8080/v1/decisions'
```

Expected response shapes:
- **`200 OK`** with a JSON array body → success, bouncer
  authenticated correctly
- **`204 No Content`** → success, no active decisions in LAPI
  (also accepted as "connected" by Arenet)
- **`403 Forbidden`** → wrong API key
- **`Connection refused`** → LAPI not running or wrong port
- **`no such host`** → DNS resolution failed (in Option A.3,
  check the compose network names)

## D — Recommended scenarios

CrowdSec scenarios are the detection rules that produce ban
decisions. Without scenarios, the local LAPI only emits
decisions from the CAPI (the CrowdSec community consensus
blocklist). Bouncer-only deployments work fine — see the
**Bouncer-only mode** note below.

### Tier 1 — Essential (install on every deployment)

Detection rules every Arenet operator benefits from. These run
against incoming HTTP requests + auth log patterns + the host
firewall.

```bash
sudo cscli collections install crowdsecurity/http-cve
sudo cscli collections install crowdsecurity/base-http-scenarios
sudo cscli collections install crowdsecurity/iptables
```

- `http-cve` — known-CVE pattern detection (Log4Shell,
  Spring4Shell, etc.).
- `base-http-scenarios` — generic HTTP attack patterns
  (path traversal, scanner fingerprints, etc.).
- `iptables` — protects against host-level abuse (SSH brute
  force, port scans).

### Tier 2 — Strongly recommended

Higher-noise scenarios that catch broader attack classes.
Enable when the Tier 1 baseline is stable and you want deeper
coverage.

```bash
sudo cscli collections install crowdsecurity/http-generic-bf
sudo cscli collections install crowdsecurity/http-dos
```

- `http-generic-bf` — generic brute force (login pages,
  password-spray patterns).
- `http-dos` — HTTP-layer DoS attempts (rate-bound floods).

### Tier 3 — Per-application

Install only when the corresponding upstream service exists in
the routes you proxy. Each adds parsers + scenarios tuned to a
specific app's log format.

```bash
# Home Assistant
sudo cscli collections install crowdsecurity/home-assistant

# Jellyfin
sudo cscli collections install crowdsecurity/jellyfin

# Many more — browse the hub:
#   https://app.crowdsec.net/hub/
```

After installing a collection, reload the engine:

```bash
sudo systemctl reload crowdsec
# or, in Docker:
docker restart crowdsec
```

### Bouncer-only mode (no local scenarios)

If installing scenarios feels like too much for a first
deployment, the bouncer works fine on its own. Without local
scenarios:

- No locally-generated decisions (no `arenet` will see `0` on
  scenarios installed)
- Arenet still receives the **CAPI consensus blocklist** — a
  community-aggregated list of malicious IPs updated every
  few minutes
- Active decisions visible via the CS.2 decisions list will be
  `source: CAPI`, type `ban`

This gives you immediate value (community blocklist) without
the operational complexity of tuning scenarios. Add scenarios
incrementally as the deployment stabilises.

## E — Troubleshooting

### "Connection refused"

LAPI is not running on the configured URL. Common causes:

- The CrowdSec service isn't started: `sudo systemctl status crowdsec`
- The Docker container has crashed: `docker logs crowdsec | tail -50`
- The LAPI is bound to a different interface than expected. By
  default it binds to `127.0.0.1:8080`; check
  `/etc/crowdsec/config.yaml` → `api.server.listen_uri`. If you
  changed it, update the Arenet Settings field to match.

### "Authentication failed (invalid bouncer API key)"

The key Arenet has doesn't match what LAPI knows. Common causes:

- Wrong key pasted (e.g. captured a trailing whitespace, missed
  characters)
- Bouncer was deleted from LAPI (`cscli bouncers list` will not
  show `arenet`) — re-create with `cscli bouncers add arenet`
- The key was rotated on LAPI (no UI for this; would have
  required `cscli bouncers delete arenet && cscli bouncers add arenet`)

Generate a fresh key with `cscli bouncers add arenet-new` (or
just `arenet` after deleting the old entry) and paste into
Arenet Settings.

### "Timeout (LAPI did not respond in time)"

LAPI is reachable but slow. Common causes:

- LAPI engine is under heavy load (large bucket population, slow
  disk)
- Network path between Arenet and LAPI is congested (only
  possible in Option A.3 cross-network setups)

Mitigations:
- Increase the timeout field in Arenet Settings (max 60s)
- Check LAPI logs: `journalctl -u crowdsec` for slow-query
  warnings

### "No decisions visible in the UI"

Expected on a fresh deployment with no threats yet. The CS.2
decisions panel (shipped after CS.1) will show:

- Empty state when there are no active CAPI consensus decisions
  AND no local scenario fires have produced bans yet
- A growing list as the CAPI sync runs (~every 2-15 minutes
  depending on the LAPI's pull cadence)

To confirm the bouncer IS connected even when empty: the
**Configured** badge in Arenet Settings → CrowdSec bouncer will
be green, and clicking **Test connection** will show
"Connected to LAPI v1.6.x".

### "Scenarios actifs" panel is empty (after CS.2 ships)

The scenarios panel reads LAPI's `/v1/metrics` endpoint. By
default, LAPI exposes Prometheus metrics; the panel renders an
empty state if the endpoint is disabled. Check
`/etc/crowdsec/config.yaml`:

```yaml
prometheus:
  enabled: true
  level: full       # not "off" / "aggregated"
  listen_addr: 127.0.0.1
  listen_port: 6060
```

The empty state in the UI will hint: "Enable LAPI metrics in
config.yaml to see scenario activity."

## F — Settings precedence (env vs. UI)

Arenet reads CrowdSec config from two sources, with this
precedence:

1. **Stored row** (BoltDB, written via Settings UI) — highest
   priority. Once you save anything from the UI, the stored
   value is source of truth.
2. **Environment variables** — `ARENET_CROWDSEC_API_URL` and
   `ARENET_CROWDSEC_API_KEY` — used as bootstrap default for
   first-boot or as an emergency override when the operator
   cannot log in.

To revert to env-driven config: PUT an all-empty row from the
UI (or delete the BoltDB row directly), then restart Arenet
with the env vars set.

To rotate the key from env to UI: log in, paste the new key in
the Settings UI, click Save & apply. Remove the env vars on the
next deploy (they'll be ignored as long as a stored row exists,
but removing avoids accidental future regression).

## G — Audit trail

Every CrowdSec settings change emits an audit event:

- First PUT of a stored row → `crowdsec_configured`
- Subsequent PUTs → `crowdsec_updated`
- The audit payload carries the LAPI URL + bouncer name; the
  API key is **always blanked** before the audit write (secret
  scrubbing mirror of OIDC / DNS provider)

View audit entries at `/audit` or via `GET /api/v1/audit`.

## H — Useful references

- CrowdSec docs: https://docs.crowdsec.net/
- Scenario hub: https://app.crowdsec.net/hub/
- `cscli` reference: https://docs.crowdsec.net/u/user_guides/cscli/
- caddy-crowdsec-bouncer: https://github.com/hslatman/caddy-crowdsec-bouncer
