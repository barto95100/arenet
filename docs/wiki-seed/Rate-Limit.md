# Rate Limit

Per-route request throttling via the [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) module. Each route can declare its own rate-limit policy : `N events per time window keyed by X`.

Use when : protecting brute-force-prone endpoints (`/api/login`, `/admin`), throttling abusive scrapers, or enforcing per-API-key quotas on public APIs.

---

## Quick start

1. Sidebar → **Routes** → click your route → **Edit**
2. Expand the **Limitation de débit** (Rate Limit) section
3. Toggle **Activé** ✅
4. **Événements** : how many requests are allowed per window (e.g. `60`)
5. **Fenêtre** : the time window (e.g. `1m`, `30s`, `1h`) — Go duration format
6. **Clé** : the rate-limit key. Default `{http.request.remote.host}` = per-IP. Other useful keys :
   - `{http.request.remote.host}` — per source IP
   - `{http.request.header.X-API-Key}` — per API key (when clients send one)
   - `{http.request.header.Authorization}` — per JWT / Bearer token
   - `{http.request.cookie.session}` — per session
7. **Save**

Within 5s the rate limit is active. Test by hammering the route :

```bash
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" https://your-route.example.com/api/ping; done | sort | uniq -c
# Expected after the 60th request : 200 (60 times) then 429 (40 times)
```

---

## How it works

The `caddy-ratelimit` module maintains an in-memory counter per (zone, key) tuple. When the count exceeds `events` within `window`, subsequent requests get **429 Too Many Requests** with a `Retry-After` header.

The window slides continuously (not bucket-aligned). After the window passes, the counter naturally decays.

Counters are **in-process** — they don't persist across restarts and don't synchronize between Arenet instances (no multi-instance support yet).

---

## Anatomy of a rate limit emit

Caddy JSON config (simplified) :

```json
{
  "handler": "rate_limit",
  "rate_limits": {
    "route-<uuid>": {
      "match": [...],
      "key": "{http.request.remote.host}",
      "window": "1m",
      "max_events": 60
    }
  }
}
```

Arenet emits one zone per rate-limit-enabled route, keyed by route UUID. The zone name follows the convention `route-<uuid>` so the rate-limit event handler (Step Z) can map zones back to route IDs in the unified `/logs`.

---

## Observability

Every 429 emits a `rate_limit_event` row in SQLite :

- `ts` — timestamp
- `route_id` — which route (derived from the zone name)
- `zone` — the Caddy zone name
- `src_ip` — remote IP
- `wait_ms` — how long until the counter decays enough (Retry-After hint)

The `/logs` page renders these with the RATE-LIMIT badge (orange). The per-route observability page `/observability/<routeId>` shows the rate-limit timeseries alongside req/s + 4xx + 5xx.

The dashboard's **rate_limit_count** counter (per-route bucket) increments on every 429.

---

## Pattern catalog

### Login brute-force protection

```
Events: 5
Window: 5m
Key: {http.request.remote.host}
```

5 login attempts per 5 minutes per IP. After the 6th, 429 with Retry-After ≈ 5min. Combine with [CrowdSec](CrowdSec) scenarios that auto-ban after N 429s.

### Public API per-token quota

```
Events: 1000
Window: 1h
Key: {http.request.header.X-API-Key}
```

1k req/hour per API key. Easy to bump for paying tiers (different routes with different limits).

### Webhook receiver

```
Events: 30
Window: 1m
Key: {http.request.remote.host}
```

30 webhooks/min per source. Webhooks usually burst then idle ; this prevents a single misbehaving source from drowning your downstream.

### Anti-scraper for public content

```
Events: 300
Window: 1m
Key: {http.request.remote.host}
```

5 req/sec average per IP. Browsers stay well under ; aggressive scrapers hit the wall fast.

---

## Edge cases

### Behind a CDN / external reverse proxy

If Arenet is behind Cloudflare / nginx / a corporate proxy, `{http.request.remote.host}` resolves to the proxy's IP, not the real client. **Every client appears as the same IP** → rate limit triggers for everyone after N requests.

Fix : set the route's request header passthrough to include `X-Forwarded-For`, configure Caddy's `trusted_proxies` to recognise the front proxy's IP, and use `{http.request.header.X-Forwarded-For}` as the key (split-on-comma logic in Caddy handles the comma-joined chain).

A future Arenet release may expose a `trustedProxies` setting per-route ; currently only the listener-level config exists.

### Counter loss on restart

The in-memory counters reset on Arenet restart. An attacker who tracks Arenet uptime could time their brute-force attempts to coincide with restarts. **Mitigation** : combine rate-limit (short window) with CrowdSec (persistent decisions surviving restarts).

### IPv6 /64 sharing

Mobile carriers often share a /64 across many users. Keying by full IP works ; keying by IP prefix (`/64` block) currently isn't exposed — the Caddy module supports `key` placeholders but Arenet's UI ships the placeholder full-IP default.

---

## API reference

```bash
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{
    ...other route fields...,
    "rateLimit": {
      "events": 60,
      "window": "1m",
      "key": "{http.request.remote.host}"
    }
  }' \
  http://localhost:8001/api/v1/routes/<route-id>
```

Set `rateLimit: null` to disable.

---

## See also

- [Routes](Routes) — where to find the Rate Limit section in the UI
- [WAF](WAF) — layered defense ; rate limit catches abuse, WAF catches attack signatures
- [CrowdSec](CrowdSec) — auto-ban on persistent rate-limit hits via scenarios
- [Alerting](Alerting) — alert when rate-limit events spike
- [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit) — upstream module reference
- `internal/ratelimit/` — Arenet's emit + sink + handler
