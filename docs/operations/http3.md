# HTTP/3 (QUIC)

Arenet serves HTTP/3 **automatically** on every HTTPS-enabled
route. There is no toggle to enable or disable it — Caddy v2 (the
embedded HTTP engine) ships with `[h1, h2, h3]` enabled by default
and Arenet does not override that.

This page tells you how to verify that HTTP/3 is actually live
and what to check if it isn't.

## What you need

Three things must line up for HTTP/3 to work end-to-end :

1. **Arenet binary** — already correct. No config required ;
   verified empirically against `caddyserver/caddy/v2@v2.11.3`
   `server.go:303` which declares the default
   `[]string{"h1", "h2", "h3"}` protocol list. Arenet's emitted
   `httpServer` JSON has no `protocols` field, so the Caddy
   default applies.

2. **Firewall : UDP/443 inbound open**. HTTP/3 runs over QUIC
   which is a UDP transport, distinct from HTTP/1+2 which run
   over TCP/443. Operators who only opened TCP/443 in their
   router / nftables / cloud security group will see HTTP/1+2
   working perfectly and HTTP/3 silently failing back to TCP.
   The browser experiences this as "first request takes a bit
   longer than expected" — no error visible to the user.

3. **Browser support** — Chrome 87+, Firefox 88+, Safari 16+ all
   speak HTTP/3 natively. Older browsers fall back to HTTP/2
   gracefully ; no configuration needed.

## How to verify HTTP/3 is live

### Quick check : `Alt-Svc` header

Hit any HTTPS route with `curl -I` and look at the response
headers. Caddy advertises HTTP/3 availability via the standard
`Alt-Svc` header :

```bash
curl -sI https://your-route.example.com | grep -i alt-svc
```

Expected output (the exact ma= value may differ across Caddy
versions) :

```
alt-svc: h3=":443"; ma=2592000
```

If the header is **present**, your Arenet is announcing HTTP/3
availability to browsers correctly.

If the header is **absent**, either :

- The route's `TLSEnabled` is false (HTTP/3 requires TLS) — check
  the route's "TLS" toggle in the UI.
- A reverse-proxy in front of Arenet is stripping the header
  (rare ; only happens if you've put nginx / haproxy / a CDN
  between the browser and Arenet).

### Direct check : `curl --http3`

Force curl to attempt HTTP/3 directly. Requires curl compiled
with HTTP/3 support (Homebrew `curl` on macOS does ; the
system `/usr/bin/curl` on macOS does NOT — install via
`brew install curl` and run `/opt/homebrew/opt/curl/bin/curl`).

```bash
curl --http3 -sI https://your-route.example.com
```

Expected response includes `HTTP/3` in the status line :

```
HTTP/3 200
content-type: application/json
...
```

If you get `curl: (6) Could not resolve host` or
`curl: (35) Failed to connect on UDP/443` the firewall is the
suspect — see the next section.

## Firewall checklist

If `Alt-Svc` is present but `curl --http3` fails to connect :

### Linux nftables / iptables

```bash
# Confirm UDP/443 is open
sudo nft list ruleset | grep "udp dport 443"
# Or with iptables :
sudo iptables -L INPUT -n -v | grep -E "dpt:443.*udp|udp.*dpt:443"
```

If no match : open UDP/443 inbound :

```bash
# nftables :
sudo nft add rule inet filter input udp dport 443 accept

# iptables (persisted via iptables-persistent or similar) :
sudo iptables -A INPUT -p udp --dport 443 -j ACCEPT
```

### Home router NAT forwarding

If Arenet runs behind a NAT (typical homelab), the router's
port-forwarding rule for `:443` must explicitly include UDP,
not just TCP. The default in most consumer routers is TCP-only.

In your router admin UI, find the port-forward rule for 443 and
ensure it covers **both protocols** (often shown as a
dropdown : "TCP", "UDP", "TCP+UDP").

### Cloud security groups (AWS / GCP / Hetzner / etc.)

Same logic : the security group inbound rule for 443 must
include UDP. Default templates often only include TCP.

## What you cannot configure

Arenet does **not** expose HTTP/3-specific tuning :

- **Disable HTTP/3 per route** — not exposed in the UI. If you
  ever need this (e.g. a back-end that breaks on HTTP/3
  request multiplexing), open an issue ; the underlying Caddy
  `protocols: ["h1", "h2"]` JSON is per-server, not per-route,
  so the feature would require an opt-out toggle in Settings.
- **0-RTT (early data)** — Caddy default is off ; Arenet does
  not override. 0-RTT trades a forward-secrecy property for a
  marginal latency win on resumed sessions ; the secure
  default is to leave it disabled.
- **QUIC port** — bound to the same port as the HTTPS listener
  (`:443` in production, `:8443` in dev mode). Cannot be
  separated.

These are all conscious design choices to keep the homelab UX
trivial : the operator opens UDP/443 in the firewall and gets
HTTP/3 for free.

## Cross-references

- Caddy upstream docs : <https://caddyserver.com/docs/json/apps/http/servers/protocols/>
- HTTP/3 protocol spec : <https://datatracker.ietf.org/doc/html/rfc9114>
- Alt-Svc header spec : <https://datatracker.ietf.org/doc/html/rfc7838>
