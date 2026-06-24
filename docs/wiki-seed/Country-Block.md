# Country Block

Per-route geographic filtering using the embedded **MaxMind GeoLite2-Country** database. Allow-list or deny-list any combination of ISO 3166 country codes for any route.

Use when : your homelab's intended audience is geographically bounded (e.g. France-only family services) and you want to drop traffic from outside the bubble before it ever reaches the WAF or your backend.

---

## Quick start

1. Sidebar → **Routes** → click your route → **Edit**
2. Expand the **Pays bloqués** (Country Block) section
3. Pick a mode :
   - **Désactivé** (off) — default, no filtering
   - **Allow** — only the listed countries can access
   - **Deny** — the listed countries are blocked, everyone else passes
4. Type a country name in the autocomplete (e.g. `France`, `Brazil`) — picks resolve to ISO codes (`FR`, `BR`)
5. Click each entry to add it to the chip list ; click the chip's ✕ to remove
6. **Save**

Within 5s the country filter is active. Requests from blocked countries get **403 Forbidden** with the route's branded error page (or the default Arenet error page).

---

## When to use Allow vs Deny

| Strategy | Best for |
| -------- | -------- |
| **Allow** (whitelist) | Personal / family services, home automation, internal admin tools — your audience IS geographically bounded |
| **Deny** (blacklist) | Public services with global audience but specific known-bad regions you want to drop |

Allow is safer (default-deny posture). Deny is more permissive but easier to maintain (no risk of accidentally locking yourself out when traveling — just add your transient country temporarily).

---

## How country resolution works

For each request :

1. Get the source IP (after X-Forwarded-For trust if configured)
2. Look up the IP in the embedded MaxMind GeoLite2-Country DB
3. Match the resolved country code against the route's allow/deny list
4. Decision : pass-through or 403

The MaxMind DB is bundled in the Arenet binary (~6 MB) and refreshed on each release. No external API call, no per-request network cost.

---

## What gets blocked

The block fires **before WAF and reverse-proxy handlers** in the chain. A blocked request :
- Returns 403 Forbidden
- Emits a `decision_event` row (visible in `/security/decisions`)
- Does NOT count against rate limits (it never reaches them)
- Does NOT show up in WAF events (it never reaches Coraza)

---

## Edge cases

### Unknown IP (private, reserved, CGNAT)

MaxMind's GeoLite2 doesn't cover private (RFC1918), reserved, or CGNAT IPs. For these, the country code resolves to `""` (empty).

**Allow mode** : empty country is **rejected** (the IP isn't in the allow list). Useful behaviour for public routes — private-range IPs reaching a public route is suspicious.

**Deny mode** : empty country is **passed through** (not in the deny list).

If your route is meant for LAN-only access AND you want to allow private ranges in Allow mode, the workaround is to bind that route to a specific listener on the LAN interface only (advanced, not UI-exposed). The standard pattern is to keep LAN-only routes off the public listener entirely.

### IPv6

Fully supported — MaxMind GeoLite2 covers IPv6 ranges.

### Anonymous proxies / VPNs

MaxMind's free GeoLite2 doesn't flag anonymous proxies. If you need this, the [paid MaxMind GeoIP2 Anonymous IP DB](https://www.maxmind.com/en/geoip2-anonymous-ip-database) integrates separately (not currently exposed in Arenet UI ; manual config required).

For most homelab use cases, layering Country Block + [CrowdSec](CrowdSec) (which DOES flag known VPN exit nodes via community scenarios) gives you ~90% of the value of a paid anonymous-IP DB.

---

## Observability

Every blocked request emits a `decision_event` with `origin=country_block`. The `/security/decisions` page filters these. The unified `/logs` shows them with the COUNTRY badge.

The dashboard's **GeoIP World Map** visualizes the live distribution of blocked-by-country traffic — useful for understanding what your routes are seeing without diving into individual events.

---

## API reference

```bash
# Update a route's country block via API
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{
    ...other route fields...,
    "countryBlock": {
      "mode": "allow",
      "countryList": ["FR", "BE", "CH", "LU"]
    }
  }' \
  http://localhost:8001/api/v1/routes/<route-id>
```

Available modes : `"off"` (or empty), `"allow"`, `"deny"`. Country codes are 2-letter ISO 3166-1 alpha-2, uppercase.

---

## Updating the GeoLite2 database

The database ships embedded in each Arenet release. To refresh between releases (e.g. a country's IP allocation shifted), upgrade to a newer Arenet build — the binary always carries the latest DB at build time.

No runtime "update the DB" hook is exposed in the UI ; the file isn't user-replaceable in the running binary.

---

## See also

- [Routes](Routes) — where to find the Country Block section in the UI
- [CrowdSec](CrowdSec) — community IP reputation, layered with country blocking
- [WAF](WAF) — layer 7 attack detection after country + CrowdSec pass-through
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) — the upstream database
- `internal/countryblock/` — Arenet's implementation
- `internal/geo/` — embedded MaxMind DB + IP lookup
