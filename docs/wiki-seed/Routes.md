# Routes

A **route** in Arenet maps an inbound `host` (FQDN) to one or more `upstreams` (backends). Every route also carries TLS, WAF, auth, rate-limit, country-block, and health-check configuration.

This page covers the route lifecycle : create, configure, alias, debug.

---

## Create your first route

1. Open the admin UI : `http://<your-host>:8001`
2. Sidebar → **Routes**
3. Click **+ Add route**
4. Fill in :
   - **Host** : the public hostname, e.g. `vault.example.com`
   - **Upstreams** : one or more backends. Click **+ Add upstream** to add. Format : `http://<lan-ip>:<port>` or `https://<host>:<port>` for HTTPS backends. Each upstream has a `weight` (used when LB policy is weighted-round-robin).
   - **LB Policy** : `round_robin` (default) or `weighted_round_robin`
   - **TLS** : check ✅ to enable HTTPS + auto-cert via ACME. Pick the **ACME challenge** : `http-01` (default, works for any domain pointing at your host) or `dns-01` (required for wildcard certs, needs DNS provider creds in Settings).
5. Click **Save**

Within ~5 seconds, Caddy reloads and the route is live :
- HTTP requests to `http://vault.example.com` redirect to `https://`
- HTTPS requests get an auto-issued Let's Encrypt cert (first request may take 5-15s while ACME completes)
- The request is reverse-proxied to your upstream

---

## Anatomy of a route

Every route stores the following fields (BoltDB `routes` bucket) :

| Field | Default | Purpose |
| ----- | ------- | ------- |
| `host` | — (required) | Primary FQDN matcher |
| `aliases` | `[]` | Additional FQDNs that match the same route |
| `upstreams[]` | — (required) | Backend pool (`url` + `weight`) |
| `lbPolicy` | `round_robin` | Load balancing policy |
| `tlsEnabled` | `false` | Auto-HTTPS via ACME |
| `redirectToHttps` | `false` | If TLS, force HTTP→HTTPS redirect |
| `acmeChallenge` | `http-01` | `http-01` / `dns-01` / `inherited` (from managed apex) |
| `useDedicatedCert` | `false` | Force a per-route cert vs the wildcard apex cert |
| `insecureSkipVerify` | `false` | Trust self-signed upstream certs |
| `uploadStreamingMode` | `false` | Don't buffer upload bodies (large file PUT, registry push) |
| `requestHeaders` | `{}` | Extra headers forwarded to upstream |
| `responseHeaders` | `{}` | Extra headers added to client response |
| `wafMode` | `off` | `off` / `detect` / `block` ([see WAF](WAF)) |
| `wafDisableCRS` | `false` | Don't load OWASP CRS on this route |
| `wafExcludeRules[]` | `[]` | CRS rule IDs to exclude |
| `wafExcludeTags[]` | `[]` | CRS tag families to exclude |
| `authMode` | `none` | `none` / `basic` / `forward` ([see OIDC-SSO](OIDC-SSO)) |
| `countryBlock` | `{mode:off}` | GeoIP allow/deny list |
| `rateLimit` | `null` | Per-route throttle |
| `healthCheck` | `{enabled:false}` | Active health checks (URI + status + body regex) |
| `errorPageTemplateId` | `""` | Custom error pages template |
| `errorPageOverrides` | `{}` | Per-status-code HTML overrides |

The full schema lives in `internal/storage/routes.go`.

---

## Aliases : one route, multiple hostnames

Use aliases when you have several FQDNs that should hit the same backend with the same config (WAF, auth, TLS).

Example : a single Traefik backend behind Arenet that serves 20 *arr-stack apps :
- **Host** : `traefik.example.com`
- **Aliases** : `sonarr.example.com`, `radarr.example.com`, `prowlarr.example.com`, ...

Caddy auto-acquires SAN certs covering all aliases. The `/topology` dashboard groups them visually as one container with N alias nodes.

---

## Wildcard certificates

For a route like `*.example.com`, you need a **managed apex** :

1. Sidebar → **Certificates** (`/certs`)
2. **Wildcard policies per apex** section → **+ Wildcard apex**
3. Apex : `example.com`
4. DNS provider : OVH (more providers planned) — paste your API keys
5. Save

Routes whose host falls under `*.example.com` (e.g. `vault.example.com`, `cloud.example.com`) will inherit the wildcard cert automatically. Set their `acmeChallenge` to `inherited` for explicit declaration, or leave default and Caddy will pick the wildcard cert via SNI matching at handshake.

---

## Health checks

Active health checks monitor each upstream and remove unhealthy ones from the pool. To enable :

1. Edit a route → **Health check** section
2. **Enabled** ✅
3. **URI** : the path Caddy will GET on the upstream, e.g. `/healthz` or `/api/health`
4. **Method** : default `GET`
5. **Interval** : default `30s`
6. **Timeout** : default `5s` (must be `<` interval)
7. **Expected status** : default `0` = "any 2xx is OK", or pin to e.g. `200`
8. **Expected body** (regex) : optional, e.g. `^\\{"status":"ok"\\}` for JSON healthz
9. **Passes** : consecutive checks needed to mark healthy (default `1`)
10. **Fails** : consecutive checks needed to mark unhealthy (default `1`)

Unhealthy upstreams are skipped by the load balancer ; the `/topology` dashboard shows them in dimmed state.

---

## Route states (Active / Maintenance / Disabled)

Every route has a **3-state lifecycle control**, shown as an icon-only segmented control on the `/routes` list — play (▶, green) = **Active**, wrench (🔧, amber) = **Maintenance**, power (⏻, red) = **Disabled**. Hover any segment for a tooltip with its name ; click a segment to switch state.

| State | Traffic | TLS / `:443` | Config |
| ----- | ------- | ------------- | ------ |
| **Active** | Normal reverse-proxy to the upstream pool | Kept if `tlsEnabled` | — |
| **Maintenance** | 503 + branded maintenance page + `Retry-After` header to everyone, except bypass IPs which reach the real upstream | **Kept** — host/TLS stay served | Upstreams/WAF/etc. untouched, just wrapped |
| **Disabled** | Route removed from Caddy entirely ; the host falls through to the catch-all (404) | Dropped ; disabling the **last** active HTTPS route removes the `:443` listener (a confirm dialog warns you first) | **Preserved** for one-click re-enable |

If a route somehow carries both a `disabled` flag and a `maintenanceConfig` at once, **Disabled wins** — it's the stronger "serves no traffic at all" state. Priority : **Disabled → 404** (wins) > **Maintenance → 503** > **Active**.

### Disabled (v2.15.0)

Disabling a route is for **maintenance windows where you don't want the app reachable at all**, or for parking a route you don't want to delete (its host/upstreams/TLS/WAF/aliases config is preserved in BoltDB — nothing is lost). A disabled route is filtered out before the Caddy config is built, so:

- The host stops resolving through Arenet — a request for it hits the **catch-all** (404, see [Custom Error Pages](Custom-Error-Pages#catch-all-host-not-configured)).
- If it was the **last route with `tlsEnabled` + active**, disabling it also removes the `:443` HTTPS listener — any other HTTPS URL served by Arenet will fail with connection refused until you re-enable a route or add a new HTTPS one. The UI detects this case and shows a dedicated warning dialog ("Disable the last HTTPS route?") before you confirm.
- Re-enabling is one click (or `POST /routes/{id}/enable`) — same upstreams, TLS, WAF, everything comes back exactly as configured.

### Maintenance (v2.17.0)

Maintenance mode is for **"I need to take the app down for a bit, but I still want to hit it myself to verify"**. Unlike Disabled, the route **stays served** — Caddy keeps the host + TLS cert alive — but every request gets:

- **HTTP 503**
- The **global maintenance page** (customized in Settings → Error Pages → Maintenance tab, see [Custom Error Pages](Custom-Error-Pages#maintenance-page))
- A **`Retry-After`** header (seconds, configurable per route)

...**except** requests from IPs/CIDRs on the route's **bypass allow-list**, which are forwarded straight to the real upstream as if the route were Active. This lets you validate the app is actually back up before flipping everyone else over.

Configure maintenance in the route's **edit form**, in the **Maintenance** section (shown for every route, not just ones currently in maintenance, so you can pre-fill it before switching the state control):

- **Retry-After (seconds)** — sent as the `Retry-After` response header and substituted into the maintenance page via the `{arenet.maintenance.retry_after}` placeholder. `0` omits the header. Defaults to `300` the first time a route enters maintenance.
- **Bypass IPs / CIDRs** — a repeater of bare IPs (`10.0.0.5`) or CIDR ranges (`192.168.1.0/24`). Add as many as you need.

The bypass check matches the **real client IP** (Caddy's `client_ip` matcher), not the `X-Forwarded-For` header — so it can't be spoofed by a request header the way an `X-Forwarded-For` check could.

Toggling the state control to/from Maintenance is idempotent and immediate — entering maintenance again on an already-in-maintenance route keeps your existing Retry-After/bypass config (it doesn't reset to defaults) ; exiting clears the maintenance config back to nil, so the next time you enter maintenance it starts fresh from the default `300`s.

### API reference (state control)

```bash
# Disable / re-enable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/disable
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/enable

# Enter / exit maintenance (config — retryAfter/bypassIps — is set via the normal PUT route update)
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance
curl -b /tmp/jar -X POST http://localhost:8001/api/v1/routes/<route-id>/maintenance/off
```

All four endpoints are idempotent : disabling an already-disabled route, or entering maintenance on a route already in maintenance, returns `200` without error.

---

## Per-route security knobs (cheat sheet)

The most common configuration combinations :

### Public read-only website

```
TLS: ✅ enabled, http-01
WAF: detect mode (observe attacks, don't block legit users)
Rate limit: 60 req/min per remote IP
Country block: off
Auth: none
```

### Internal admin tool (Vault, Proxmox, Grafana)

```
TLS: ✅ enabled, dns-01 wildcard
WAF: off (or detect with attack-protocol excluded if backend is REST-noisy)
Rate limit: off
Country block: allow [FR, BE, CH] (your home countries)
Auth: forward (Authelia / Authentik) OR OIDC SSO at the route level
```

### Public API endpoint

```
TLS: ✅ enabled
WAF: block mode
Rate limit: 100 req/min per API key
Country block: deny [CN, RU, ...] or allow [your-customer-countries]
Auth: forward (your API gateway) or basic
```

### Webhook receiver (low-trust source)

```
TLS: ✅ enabled
WAF: block mode + paranoia level 2
Rate limit: 10 req/min per remote IP
Country block: allow only the webhook source's country
upload streaming mode: ✅ (large payloads ; skip WAF body buffering)
```

---

## Upstream error interception

When an upstream returns a 4xx or 5xx response, Arenet automatically replaces the upstream's raw body with the route's configured error page (see [Custom Error Pages](Custom-Error-Pages)). This keeps the visual experience consistent — operators see the Arenet-branded 404 instead of e.g. nginx's default 404.

### Auto-passthrough on auth challenges

Two status codes are **intentionally NOT intercepted** : **401 Unauthorized** and **407 Proxy Authentication Required**. The upstream's full response — including the `WWW-Authenticate` / `Proxy-Authenticate` header carrying the challenge — flows through to the client untouched.

This is required for any auth flow where the client retries with credentials after reading the challenge header. Replacing the body with a generic HTML 401 would strip the challenge header and break the negotiation entirely.

If you want a branded 401 page for one of YOUR auth gates (BasicAuth, ForwardAuth, OIDC at the Arenet layer), those still serve the branded body — they raise their 401 BEFORE the request reaches the upstream, so the auto-passthrough isn't on the path. Only upstream-originated 401/407 traverse the passthrough.

### Codes intercepted

`400, 402, 403, 404, 405, 406, 408, 409, 410, 411, 412, 413, 414, 415, 416, 417, 418, 421, 422, 423, 424, 425, 426, 428, 429, 431, 451` (4xx without 401+407) and `500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511` (full 5xx range).

For each intercepted code, Arenet returns its own response built from the route's error-page template, the per-route override, or the Arenet built-in default (in that priority order).

---

## Hot-reload

Every route change applies in **< 5 seconds** without dropping in-flight connections. Caddy keeps the old config serving until the new one is fully provisioned, then swaps atomically.

If a config emit fails (e.g. malformed regex in `wafExcludeRules`), the API call returns 400 with the error, the route is NOT saved, and the live Caddy config is unchanged. Loud-fail.

---

## API reference

For automation (Ansible, Terraform, scripts), the same operations are available via REST :

```bash
# List
curl -b /tmp/jar http://localhost:8001/api/v1/routes

# Create
curl -b /tmp/jar -X POST -H "Content-Type: application/json" \
  -d '{"host":"vault.example.com","upstreams":[{"url":"http://192.168.1.50:8200","weight":1}],"lbPolicy":"round_robin","tlsEnabled":true}' \
  http://localhost:8001/api/v1/routes

# Update
curl -b /tmp/jar -X PUT -H "Content-Type: application/json" \
  -d '{...}' http://localhost:8001/api/v1/routes/<route-id>

# Delete
curl -b /tmp/jar -X DELETE http://localhost:8001/api/v1/routes/<route-id>
```

Auth : the cookie jar (`/tmp/jar`) must hold a session from `/api/v1/auth/login` (Content-Type `application/json`, body `{"username","password"}`).

---

## See also

- [Topology](Topology) — visualize your routes as a live graph
- [WAF](WAF) — protect your routes against OWASP attacks
- [Custom Error Pages](Custom-Error-Pages) — brand the 4xx/5xx pages per route ; also covers the global [Maintenance page](Custom-Error-Pages#maintenance-page)
- [Rate Limit](Rate-Limit) — throttle abusive clients
- [Country Block](Country-Block) — geo-fence per route
- [OIDC SSO](OIDC-SSO) — single sign-on for admin tools
