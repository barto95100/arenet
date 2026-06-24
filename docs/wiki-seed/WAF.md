# WAF (Web Application Firewall)

Arenet embeds [Coraza v3.7](https://coraza.io) — a Go-native WAF engine compatible with the ModSecurity rule format — pre-loaded with **OWASP CRS v4.25** (Core Rule Set). Every route can opt into WAF protection at one of three levels :

| Mode | Behaviour |
| ---- | --------- |
| `off` | WAF handler not in the chain. Zero overhead. |
| `detect` | WAF evaluates every request, emits a `waf_event` to `/security` for each match, but **lets the request continue** to the upstream. Use for observation / triage. |
| `block` | WAF evaluates, emits the event, and **rejects** the request with `403 Forbidden` when the anomaly score exceeds the blocking threshold. |

---

## Quick start : enable WAF on a route

1. Sidebar → **Routes**
2. Click your route → **Edit**
3. **WAF mode** → pick `detect` (recommended for first deployment)
4. Save

Within 5 seconds the WAF is active. Send a probe to test :

```bash
curl "https://your-route.example.com/?id=1' OR '1'='1"
# In detect mode : the request reaches your backend AND a SQLi event lands in /security
# In block mode : 403 Forbidden, request doesn't reach backend
```

Open `/security` in the UI : you'll see the event listed with category `SQLi`, the matching CRS rule ID (942100 for libinjection), source IP + GeoIP, the matched payload sample.

---

## Anatomy of a WAF event

Each match emits one row in the SQLite `waf_event` table with :

- `ts` — timestamp
- `route_id` — which route triggered
- `rule_id` — CRS rule ID (e.g. `942100`, `920170`)
- `category` — Arenet classification (SQLi / XSS / RCE / LFI / RFI / PROTOCOL / METHOD / SCANNER / SESSION / DATA_LEAK / ...) — derived from rule ID range, see `internal/waf/category.go`
- `severity` — CRITICAL / ERROR / WARNING / NOTICE
- `src_ip` — remote IP
- `request_path` — `{method} {uri}`
- `payload_sample` — first 256 chars of the matched data
- `action` — `BLOCK` (block mode + score ≥ threshold) or `DETECT` (detect mode OR block mode + score < threshold)
- `status_code` — `403` for blocked, `200` for detect/observed

The `/security` page renders these with filter by route + category + level. The `/security/<routeId>` drilldown adds the CRS rule documentation links + a "Exclude this rule on this route" affordance for false-positive triage.

---

## Handling false positives

When the WAF blocks a legitimate request (a known false positive), you have **three escape hatches** to apply per-route, in increasing scope :

### Option (a) — Disable CRS entirely on the route

Use when : the route serves trusted internal traffic (admin tool on LAN), or the backend is so noisy that CRS produces 90% false positives.

1. Edit route → **WAF** section → **Disable OWASP CRS on this route** ✅
2. A confirmation dialog (ADR D4) warns about the security implications
3. Save

The WAF handler stays in the chain (the dashboard still counts events as 0), but the CRS includes are stripped. Zero CRS evaluation cost.

### Option (c) — Exclude specific CRS rule IDs

Use when : a precise rule (e.g. `942100` SQLi libinjection) fires on a legitimate payload.

1. Edit route → **WAF exclusions** → **Excluded rule IDs**
2. Comma-separated list : `942100, 920170, 911100`
3. Save

The rule is removed from this route's CRS evaluation set. Other rules in the same family still apply.

### Option (e) — Exclude entire CRS tag families

Use when : a whole rule family is noisy on this route. Example : `attack-protocol` (rule range 911-921) trips on legitimate WebDAV / non-standard HTTP method usage.

1. Edit route → **WAF exclusions** → **Excluded tags**
2. Pick from the autocomplete dropdown : `attack-protocol`, `attack-sqli`, `attack-rce`, `language-php`, `paranoia-level/3`, ...
3. Save

The whole tag family is excluded. Rules with that tag are removed from this route's CRS evaluation set. Cheaper to maintain than listing 15 rule IDs.

---

## CRS paranoia levels

OWASP CRS supports four paranoia levels (PL1–PL4) controlling the strictness :

- **PL1** (default) : rules with low false-positive rate, suitable for most public web apps
- **PL2** : adds rules that may trip on legitimate edge cases
- **PL3** : aggressive, expect FPs on rich-content apps
- **PL4** : maximum, for hardened endpoints only

Arenet currently emits **PL1 by default** for every route. Per-route paranoia level configuration is not exposed in the UI as of v2.9.3 ; if you need PL2+ on a specific route, the workaround is custom Coraza directives via the route's WAF config (advanced, not UI-exposed).

---

## Performance considerations

- The WAF handler runs **before** the reverse-proxy handler so a block-mode rejection never reaches the upstream
- WAF instances are pooled by their directives-string SHA — N routes with identical WAF config share **one Coraza WAF instance** in memory (see `internal/waf/module.go`'s pool key)
- Body inspection (multipart, XML, JSON) is the heaviest path. For routes that handle large uploads (file servers, Docker registry), enable **Upload streaming mode** on the route which skips body inspection and asks Caddy to flush bytes through without RAM buffering
- The Coraza engine itself is Go-native (not cgo), so no thread-overhead per request

---

## Common false-positive patterns + fixes

| Symptom | Likely cause | Fix |
| ------- | ------------ | --- |
| GET with body returns 403 on REST API | `920170` (attack-protocol) | Exclude rule 920170 or tag `attack-protocol` |
| PUT/DELETE returns 403 on admin API | `911100` (METHOD-ENFORCEMENT) | Exclude rule 911100 or tag `attack-protocol` |
| Anything containing `--` in URL returns 403 | `942100` (SQLi libinjection FP on UUIDs / version strings) | Exclude rule 942100 or, narrower, exclude only on the specific route |
| Multipart upload returns 403 | `922xxx` (multipart attacks) | Exclude tag `attack-multipart` or enable Upload Streaming Mode |
| Authentik / Keycloak `/api/v1/auth/oidc/callback` returns 403 | Multiple CRS rules trip on OAuth state/code params | Exclude tags `attack-protocol` + `attack-sqli` on the IdP route, OR set the IdP route's WAF to `off` |

---

## Monitoring : staying ahead of false positives

The recommended workflow when adding a new route :

1. Set WAF mode to **`detect`** first
2. Use the route normally for 24-48h (your real traffic exercises the CRS rule set)
3. Open `/security/<routeId>` → review the events generated
4. Identify FPs : events where the matched payload is legitimate user data, not an attack
5. Add exclusions (rule IDs or tags) for the FPs
6. Switch WAF mode to **`block`**
7. Wire an alert ([Alerting](Alerting)) on `waf_event_rate > 10 / 5min` so you catch unexpected spikes

---

## Cross-route observability

The dashboard `/dashboard` shows the **WAF detect/block rates** per top-N routes. The `/security` page aggregates events across all routes with filters. The unified `/logs` shows WAF events alongside auth + rate-limit + cert events for correlation ("did this IP try N WAF probes AND fail auth N times AND trip rate-limit ?").

---

## See also

- [Routes](Routes) — where to find the WAF settings in the UI
- [CrowdSec](CrowdSec) — bans the most egregious WAF-triggering IPs at the network layer (before they reach the WAF)
- [Alerting](Alerting) — alert on `waf_event_rate` spikes
- [Custom Error Pages](Custom-Error-Pages) — brand the 403 page WAF returns
- [OWASP CRS documentation](https://coreruleset.org/docs/) — rule reference + tag taxonomy
- [Coraza documentation](https://coraza.io/docs/) — WAF engine internals
- `internal/waf/category.go` — Arenet rule-ID → category mapping
- `internal/caddymgr/manager.go` (lines ~1400-2550) — WAF handler emit + per-route SecAction shape
