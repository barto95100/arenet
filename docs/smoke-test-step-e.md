# Step E — Manual smoke test

Run **before** tagging `v0.3.0-step-e`. Targets the local single-binary build with `--dev` mode (frontend served by Vite on `:5173`, admin API on `:8001`). Mirrors the Step D smoke pattern.

Each section is self-contained: copy/paste the block in a terminal. Stop on the first FAIL.

This smoke validates the 12 acceptance criteria of spec §10, the spec §11.5 / §3.5 / §4.3 invariants validated in code, and the §9.2 browser FPS budget.

---

## 0. Setup

```bash
# From repo root
cd web/frontend && npm install && npm run build && cd ../..
go build -o ./arenet ./cmd/arenet

# Reset state (CAUTION: destroys local data)
rm -rf ./data
mkdir -p ./data

# Run the binary in another terminal (keep it running for all sections)
./arenet --dev --admin-port :8001
```

Capture the setup token from the boot log:

```
INFO  Setup token: <token-hex>
INFO  metrics pipeline started tick_interval=1s ws_path=/api/v1/ws/topology
```

If the second line is missing, the build is older than Chunk 2 — rebuild.

Export for the rest of the session:

```bash
export ARENET_SETUP_TOKEN='<paste-here>'
export ARENET_USER='admin'
export ARENET_PASSWORD='ThisIsASecurePass!23'
export ARENET_BASE='http://localhost:8001/api/v1'
export COOKIES="$(mktemp -t arenet-cookies-e)"

# Bootstrap admin (idempotent if already done in a previous run).
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg t "$ARENET_SETUP_TOKEN" --arg u "$ARENET_USER" \
            --arg d "Admin" --arg p "$ARENET_PASSWORD" \
            '{setupToken:$t, username:$u, displayName:$d, password:$p}')" \
  "$ARENET_BASE/auth/setup" >/dev/null

# Re-login to be sure we have a fresh cookie.
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ARENET_USER" --arg p "$ARENET_PASSWORD" \
            '{username:$u, password:$p, rememberMe:false}')" \
  "$ARENET_BASE/auth/login" >/dev/null

export COOKIE_VAL=$(grep arenet_session "$COOKIES" | awk '{print $NF}')
echo "cookie ready (len=${#COOKIE_VAL})"
```

We also need a tiny upstream that returns either 200 or 503. Write it
to a file then launch — heredoc + `&` is shell-fragile.

```bash
cat > /tmp/upstream.py <<'PY'
import os, http.server
# ARENET_UPSTREAM_503 is read ONCE at process start, not per request.
# To flip from 200 to 503 (or back), kill this process and relaunch
# with the new env value. §4.b walks through that.
CODE = 503 if os.environ.get("ARENET_UPSTREAM_503") == "1" else 200
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(CODE)
        self.end_headers()
        self.wfile.write(b"ok\n" if CODE == 200 else b"down\n")
    def log_message(self, *a): pass
http.server.HTTPServer(("127.0.0.1", 9999), H).serve_forever()
PY

python3 /tmp/upstream.py &
export UPSTREAM_PID=$!
echo "upstream started PID=$UPSTREAM_PID (code=200)"
```

Stop it later with `kill $UPSTREAM_PID`.

---

## 1. Module registration (AC #1)

The Caddy module is registered at `init()` of the imported
`internal/metrics` package, so its presence is unconditional in
the binary. What this section verifies is the **JSON config**
produced by `caddymgr`: every persisted user route must have
`arenet_routemetrics` as the FIRST handler in its `handle` chain
(spec §11.5). With zero user routes, only the catch-all route
exists (no metrics handler in it) — so we create one first to
make the check meaningful.

```bash
# Create a smoke route so the handler chain is non-trivial.
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -H 'Content-Type: application/json' \
  -d '{"host":"smoke.localhost","upstreamUrl":"http://127.0.0.1:9999","tlsEnabled":false,"wafEnabled":false}' \
  "$ARENET_BASE/routes" >/tmp/arenet-route.json

export ROUTE_ID="$(jq -r '.id' < /tmp/arenet-route.json)"
echo "route_id=$ROUTE_ID"

# Caddy's loaded config: inspect the first route (= the user route;
# the catch-all is the LAST entry in the array). Its handle[0] must
# be arenet_routemetrics.
curl -sS http://127.0.0.1:2019/config/apps/http/servers/arenet_http/routes \
  | jq '.[0].handle[0]'
```

**Expect** the first handler at index 0 to be:

```json
{ "handler": "arenet_routemetrics", "route_id": "<UUID>" }
```

The string MUST be exactly `arenet_routemetrics` (no dot, no `http.handlers.` prefix). If you see `reverse_proxy` at index 0 → FAIL (spec §11.5 violation, see Bug-1-like regression).

---

## 2. WebSocket handshake auth (AC #4)

Three cases, all observed at the **handshake level** (no upgrade on
auth failure).

Note: `Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==` is the fixed test
nonce from RFC 6455 § 1.2. The server (gorilla/websocket) only
checks header presence + version, not the nonce value, so reusing
the same literal across calls is safe.

### 2.a — Without cookie → 401

```bash
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  "$ARENET_BASE/ws/topology"
```
**Expect:** `HTTP 401`.

### 2.b — With valid cookie → 101 Switching Protocols

curl can hang holding the upgraded connection open waiting for
server bytes. Cap the call with `--max-time 3` and dump the
status line with `-sSi` so we observe `HTTP/1.1 101` without
waiting for tick payload.

```bash
curl --max-time 3 -sSi \
  --cookie "arenet_session=$COOKIE_VAL" \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  "$ARENET_BASE/ws/topology" | head -1
```
**Expect:** the first line printed is `HTTP/1.1 101 Switching Protocols`.

The curl drops the TCP connection immediately after observing the
upgrade response. On the next tick (within ~1 s) the server's
write loop attempts to send the snapshot, fails, and logs a
`ws topology: write failed` debug line. That log line is
**expected** and not a bug — see spec §5.6 (write error → close
the connection silently). We don't observe frames here — see §5
for actual streaming.

### 2.c — Locked session → 403

This sub-test needs the `smokebackdate` helper Go program. The
helper is intentionally **not committed to the repo** (chore
cleanup after v0.2.0-step-d), so save the snippet below as
`/tmp/smokebackdate.go`. It rewrites every session's
`last_activity` to 16 minutes ago (just past the 15-min idle
threshold).

```go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"go.etcd.io/bbolt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: smokebackdate <path/to/arenet.db>")
		os.Exit(2)
	}
	db, err := bbolt.Open(os.Args[1], 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil { panic(err) }
	defer db.Close()
	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte("sessions"))
		if b == nil { return fmt.Errorf("no sessions bucket") }
		return b.ForEach(func(k, v []byte) error {
			var s map[string]any
			if err := json.Unmarshal(v, &s); err != nil { return err }
			s["last_activity"] = time.Now().UTC().Add(-16 * time.Minute).Format(time.RFC3339Nano)
			out, _ := json.Marshal(s)
			return b.Put(k, out)
		})
	})
	if err != nil { panic(err) }
	fmt.Println("backdated all sessions by 16 min")
}
```

`go run /tmp/smokebackdate.go` will auto-resolve `go.etcd.io/bbolt`
because the file imports it directly (the Go toolchain will fetch
it into the module cache on first run).

Then, **with arenet stopped** (it holds an exclusive BoltDB lock):

```bash
# In the arenet terminal: Ctrl-C.
go run /tmp/smokebackdate.go ./data/arenet.db
# In the arenet terminal: ./arenet --dev --admin-port :8001
# COOKIE_VAL still points to the now-idle session (same jar, same value).

curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  --cookie "arenet_session=$COOKIE_VAL" \
  -H 'Upgrade: websocket' \
  -H 'Connection: Upgrade' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  -H 'Sec-WebSocket-Version: 13' \
  "$ARENET_BASE/ws/topology"
```
**Expect:** `HTTP 403`.

Then unlock by re-logging in (POST /auth/login) and re-export
`COOKIE_VAL` from the cookie jar.

---

## 3. Reload preservation (AC #6)

A new route via `POST /routes` should appear in the next WS tick
within ≤ 2 s, and a deleted route should disappear within ≤ 2 s.

**About the wsmoke probe**: each `/tmp/wsmoke-bin` invocation opens
a **fresh** WebSocket subscription, drains up to 3 ticks (or fails
on the 5-second read deadline), then exits. It does NOT keep a
persistent connection across calls. Consequence: running wsmoke
right after a `curl POST /routes` reliably observes the new route
because the WS subscription is created **after** the
`caddymgr.syncRegistry` post-reload. If wsmoke's 5 s deadline
fires before 3 ticks arrive, something is wrong with the server's
ticker — investigate.

Build a tiny Go probe `wsmoke` (same helper from Chunk 3 review):

```bash
mkdir -p /tmp/wsmoke
cat > /tmp/wsmoke/main.go <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
)

type RouteFrame struct {
	ID   string `json:"id"`
	Host string `json:"host"`
}
type Frame struct {
	T      string       `json:"t"`
	Routes []RouteFrame `json:"routes"`
}

func main() {
	hdr := http.Header{"Cookie": []string{"arenet_session=" + os.Args[2]}}
	conn, _, err := websocket.DefaultDialer.Dial(os.Args[1], hdr)
	if err != nil { panic(err) }
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 3; i++ {
		_, msg, err := conn.ReadMessage()
		if err != nil { return }
		var f Frame
		if err := json.Unmarshal(msg, &f); err != nil {
			fmt.Fprintf(os.Stderr, "unmarshal err: %v (msg=%q)\n", err, msg)
			continue
		}
		fmt.Printf("TICK t=%s routes=%d hosts=%v\n", f.T, len(f.Routes), hostsOf(f))
	}
}
func hostsOf(f Frame) []string {
	out := make([]string, 0, len(f.Routes))
	for _, r := range f.Routes { out = append(out, r.Host) }
	return out
}
GO

# Build in a subshell so the outer working directory is preserved.
(
  cd /tmp/wsmoke
  go mod init wsmoke 2>/dev/null || true   # already-initialized is fine
  go get github.com/gorilla/websocket
  go build -o /tmp/wsmoke-bin .
)
```

Now exercise the create/delete flow:

```bash
# Print 3 ticks. smoke.localhost should be in every list.
/tmp/wsmoke-bin "ws://localhost:8001/api/v1/ws/topology" "$COOKIE_VAL"

# Add a second route.
curl -sS -c "$COOKIES" -b "$COOKIES" -H 'Content-Type: application/json' \
  -d '{"host":"second.localhost","upstreamUrl":"http://127.0.0.1:9999","tlsEnabled":false,"wafEnabled":false}' \
  "$ARENET_BASE/routes" > /tmp/route2.json
export ROUTE2_ID="$(jq -r '.id' < /tmp/route2.json)"

# Next 3 ticks should include both hosts.
/tmp/wsmoke-bin "ws://localhost:8001/api/v1/ws/topology" "$COOKIE_VAL"

# Delete the second route.
curl -sS -c "$COOKIES" -b "$COOKIES" -X DELETE "$ARENET_BASE/routes/$ROUTE2_ID"

# Next 3 ticks should be back to one route.
/tmp/wsmoke-bin "ws://localhost:8001/api/v1/ws/topology" "$COOKIE_VAL"
```

**Expect:** the route set in the WS frames matches the storage state within one tick (≤ 2 s) of each mutation.

---

## 4. Counter accuracy & 5xx classification (AC #2 + AC #3)

### 4.a — Counter accuracy (1000 reqs, ≤ 1 lost)

Spec §10 AC #2 mandates the test be **serial** (no overlapping
requests).

The §0 upstream is already running on code 200 (the env var is
read once at process start). If you tweaked it earlier, restart
clean:

```bash
kill $UPSTREAM_PID 2>/dev/null
unset ARENET_UPSTREAM_503
python3 /tmp/upstream.py &
export UPSTREAM_PID=$!
```

The wsmoke Go probe only prints `hosts=...` (no per-route reqs
counter), so we use a small Python probe to sum `reqs` across
ticks. It requires `websocket-client` (NOT the stdlib
`websockets` asyncio package).

On macOS with system Python (or Homebrew Python ≥ 3.11), `pip
install --user` is blocked by PEP 668. Use a one-shot venv:

```bash
python3 -m venv /tmp/wsvenv
/tmp/wsvenv/bin/pip install websocket-client >/dev/null
```

(On Linux or with `pipx`, `pip install --user websocket-client`
also works.)

Race-safe execution: the WS subscription MUST be live BEFORE the
1000-request burst, otherwise the first tick (with the bulk of
the counter) arrives before the Python script connects and is
missed. Spawn the drain loop in the background, let it settle for
1.5 s, then fire the burst:

```bash
# Subscriber first, in the background. It connects, then drains
# 12 ticks while the burst runs in parallel.
/tmp/wsvenv/bin/python3 - "$COOKIE_VAL" > /tmp/drain.log 2>&1 <<'PY' &
import sys, json
from websocket import create_connection
# `origin=` is a websocket-client kwarg (NOT a custom HTTP header):
# spec §5.1 / §7.1 — the dev-mode Upgrader allows
# http://localhost:5173 explicitly.
ws = create_connection(
    "ws://localhost:8001/api/v1/ws/topology",
    header=["Cookie: arenet_session=" + sys.argv[1]],
    origin="http://localhost:5173",
)
total = 0
for _ in range(12):
    msg = ws.recv()
    f = json.loads(msg)
    for r in f["routes"]:
        if r["host"] == "smoke.localhost":
            total += r["reqs"]
print(f"TOTAL_REQS={total}")
PY
DRAIN_PID=$!

# Let the subscription settle.
sleep 1.5

# Fire 1000 serial requests against smoke.localhost (routed by
# Caddy to the python upstream on 9999).
for i in $(seq 1 1000); do
  curl -sS -o /dev/null -H "Host: smoke.localhost" "http://127.0.0.1:8080/"
done

# Wait for the subscriber to finish draining its 12 ticks.
wait $DRAIN_PID
cat /tmp/drain.log
```

**Expect:** `TOTAL_REQS` = 999 or 1000 (spec §10 AC #2 tolerance).

If `< 999` → audit the metrics pipeline. If `> 1000` → there's a
bug in counter accumulation (impossible by design but worth
flagging).

### 4.b — 5xx classification (sustained server errors)

Spec §10 AC #3 specifies "50/100 → errRate ≈ 0.5". We run a
stronger version here: 100/100 sustained → expected errRate ≈ 1.0.
A passing 100/100 also covers the 50/100 case by linearity.

Note on the kill+restart gap: between the moment we kill the
upstream and the moment the new one binds, requests routed through
Caddy will receive **502 Bad Gateway** (no upstream to connect to)
rather than 503. This is fine for the test — Step E classifies
**any** `status >= 500` as an err (spec §1.3 + §4.1 Inc), so 502s
and 503s both bump `Errs` identically. The sleep below is sized
generously to let the new upstream bind before we fire load.

```bash
# Kill the current 200-upstream and restart it on 503. During the
# gap (~0.5–1 s) Caddy proxies to a closed port → 502 Bad Gateway,
# which still classifies as a 5xx err. The sleep below ensures
# the new upstream is ready before we hit it.
kill $UPSTREAM_PID
ARENET_UPSTREAM_503=1 python3 /tmp/upstream.py &
export UPSTREAM_PID=$!
sleep 2

# 100 serial requests, all → 503 (or a few 502 if the upstream
# wasn't quite ready — same effect on the err counter).
for i in $(seq 1 100); do
  curl -sS -o /dev/null -H "Host: smoke.localhost" "http://127.0.0.1:8080/"
done

# Observe the next 3 ticks. errRate5xx should be ~1.0 over the
# active window.
/tmp/wsmoke-bin "ws://localhost:8001/api/v1/ws/topology" "$COOKIE_VAL"
```

**Expect:** the `errRate5xx` field in the WS frame is ≥ 0.99 for
`smoke.localhost`, indicating 5xx classification works.

Then restore the upstream to 200:

```bash
kill $UPSTREAM_PID
unset ARENET_UPSTREAM_503
python3 /tmp/upstream.py &
export UPSTREAM_PID=$!
```

---

## 5. Frontend smoke (AC #5 + AC #7)

Open the SvelteKit Vite dev server at **`http://localhost:5173/`** (NOT `:8001` — that's the admin API).

Login via the UI with the credentials you exported in §0:
- **Username**: value of `$ARENET_USER` (default `admin`)
- **Password**: value of `$ARENET_PASSWORD` (default `ThisIsASecurePass!23`)

Then navigate to **Topology** in the sidebar.

### 5.a — Page loads, connection indicator

**Expect:**
- Header `Topology` + subtitle.
- Right side: small green dot + `connected`.
- Layout: three columns — Clients pillar (left, full height) + Routes column (center, one box per route) + Upstreams column (right, one box per unique upstream URL).
- The Clients pillar shows `<N> req/s total` updating live.

### 5.b — Particles flow under load

Fire load against `smoke.localhost` for a sustained period:

```bash
# ~20 req/s (sleep 0.05) — enough to see particles without flooding
# arenet's INFO log. Bump to sleep 0.02 (~50 req/s) to saturate the
# particle density cap.
while true; do curl -sS -o /dev/null -H "Host: smoke.localhost" "http://127.0.0.1:8080/"; sleep 0.05; done
```

**Expect:**
- Cyan particles emerge from the Clients pillar, travel along the Client→Route bezier to the route node, then along the Route→Upstream bezier to the upstream.
- Particle density visibly increases with the rate (~50/s capped per edge).
- The route node has a **cyan stroke** in the active state.

Note: the spec §6.5 active-state description says only "full
opacity, normal border" — the code went one step further and ties
the active border to `--accent-cyan` for visual distinction from
idle (whose border falls back to `--border-default`). Cosmetic
divergence, intentional, documented here.

Stop the loop (Ctrl-C).

### 5.c — Idle transition after 60 s

Stop the curl loop. Wait 60 s.

**Expect:**
- Particles stop emerging.
- The route node fades to ~40% opacity with a dashed border (idle state).

### 5.d — Error spike under 503

In the terminal: flip the upstream to 503 (see §4.b: kill + restart
the python upstream with `ARENET_UPSTREAM_503=1`), then start the
load loop again. Switch back to the browser within a few seconds
to observe the transition. After **~10 s** — the `spikeWindow`
constant of spec §8 is exactly 10 s, so the sliding-window
detection (`isErrorSpike`) starts firing around then:

**Expect:**
- Particles change to red (`--status-down`).
- The route node gets a red border + subtle pulse animation.

Restore the upstream to 200 and stop the loop.

### 5.e — Detail panel (AC #7)

Spec §6.9 mandates three independent close paths. Test each.

**Open**: click on a route node.

**Expect on open:**
- A 360 px wide panel slides in from the right.
- Top: route host + upstream URL.
- Middle: two big numbers (`req/s`, `5xx %`) updating live.
- Two sparklines (req/s + 5xx) of the last ~60 s.
- A `Edit route ↗` link bottom of panel.

**Close path 1 — Escape**: open the panel, press `Escape`. The
panel must close.

**Close path 2 — overlay click**: open the panel, click anywhere
in the dimmed background (NOT inside the panel itself). The
panel must close.

**Close path 3 — second click of same node**: open the panel,
click the same node again. The panel must close.

(Clicking a *different* node should keep the panel open and just
switch its content to the new route — verify this too.)

### 5.f — Empty state

If you delete the smoke route via the UI (`Routes` page), the
topology page should show an empty-state message linking back to
`/routes`.

**Important**: re-create the smoke route via the UI (or by
re-running the `POST /routes` of §1) before moving to §7 — the
FPS test needs traffic against a real route.

---

## 6. Reduced motion (AC #8)

In Chrome / Edge DevTools, open the **Rendering** panel:
`⋮ menu (top-right) → More tools → Rendering`. Scroll to
"**Emulate CSS media feature prefers-reduced-motion**" and pick
`reduce`.

(Firefox: about:config → `ui.prefersReducedMotion` → 1.)

**Expect (within ~1 s):**
- Particles stop animating.
- Each edge displays a numeric `<N> req/s` text label near the midpoint.
- Route nodes keep their state color but the spike pulse animation is suppressed.
- Detail panel still works; sparklines still render.

Toggle back to `no-preference` and confirm particles resume
**without refreshing the page**. The page mounts a `matchMedia`
change listener in `onMount` (see `routes/topology/+page.svelte`),
so the transition is live. If a refresh is needed → that's a bug
in the listener wiring.

---

## 7. FPS budget (AC §9.2)

**Pre-req**: if you deleted the smoke route during §5.f, re-create
it via §1 before starting this section.

Open DevTools → **Performance** tab → click the circle Record
button. Generate load:

```bash
# ~20 req/s (sleep 0.05) — enough to see particles without flooding
# arenet's INFO log. Bump to sleep 0.02 (~50 req/s) to saturate the
# particle density cap.
while true; do curl -sS -o /dev/null -H "Host: smoke.localhost" "http://127.0.0.1:8080/"; sleep 0.05; done
```

Let it run 10 s. Stop recording.

**Reading the FPS**: in the recording's bottom panel, find the
**Frames** lane (just below the Timing lane). Hover over its
green/red bars — the tooltip shows the FPS at that instant.
Inspect the 10 s window for the **mean** (eyeball the green
density) and **min** values.

**Particle count check**: while load is running, open the DevTools
Console and run:

```js
document.querySelectorAll('svg circle.particle').length
```

(The class `particle` is scoped by Svelte to a hash suffix in
production builds; the selector above matches both forms. Validate
on a `npm run dev` session if needed.)

**Expect:**
- Mean FPS over the 10 s window ≥ **55**.
- No "Long task" (red triangle in the Performance Main lane) > 50 ms.
- Particle count snapshot returns a non-zero value (typically a few
  dozen to a few hundred under sustained 20 req/s load).

If FPS drops below 55 → investigate whether the particle density
cap (`PARTICLE_DENSITY_CAP = 50`) is being respected, or whether
SVG layout is thrashing. The page MUST stay focused for accurate
FPS — a background tab is intentionally closed by the WS client
(spec §5.5), so FPS = 0 there is expected, not a bug.

---

## 8. Reconnect lifecycle (AC #9 + spec §5.5)

With the browser open on `/topology`:

**Pre-req for 8.a / 8.b**: have load running (the §5.b loop) so
you can observe particles starting/stopping. If no load is
running, only the connection indicator changes — the rest of the
page stays empty of particles either way.

### 8.a — Server killed → "reconnecting…"

Send SIGINT to the arenet binary:
```bash
# In the arenet terminal, Ctrl-C
```

**Expect (within ~5 s):**
- The connection indicator switches to amber + `reconnecting…`.
- Particles stop emerging (if load was running).

The 5 s window covers TCP close detection + the client's status
transition.

### 8.b — Server restarted → "connected"

Restart arenet:
```bash
./arenet --dev --admin-port :8001
```

**Expect:**
- The connection indicator switches back to green + `connected`.
  Typically 1–2 s after the server is back; bounded by the
  exponential backoff cap of 30 s (spec §5.5 `reconnectMaxMs`).
- If load was running, particles resume on the next tick (~1 s
  after `connected`).

### 8.c — Tab hidden / visible (spec §5.5)

Switch to a different tab for **~5 s**, then switch back. Spec §5.5
mandates the client actively closes the WS on
`visibilitychange → hidden` and reopens immediately on `→ visible`.

**Method of observation** — open DevTools → **Network** tab,
click the **WS** filter chip, then locate the topology WS row
(URL ends with `/api/v1/ws/topology`).

**Expect:**
- When you switch away (tab hidden), the row's Status column
  transitions from `101` to `Finished` (greyed out) within ~1 s.
- When you switch back (tab visible), a new WS row appears with
  status `101` immediately (no backoff delay — spec §5.5).
- Particles resume within ~1 s of returning to the tab (if load
  was running).

---

## Checklist summary

| # | Step | Pass criterion |
|---|---|---|
| 1 | Module registration | `arenet_routemetrics` at index 0 of every route's handle chain (Caddy admin API) |
| 2.a | WS handshake no cookie | HTTP 401 |
| 2.b | WS handshake valid cookie | HTTP 101 |
| 2.c | WS handshake locked session | HTTP 403 |
| 3 | Reload preservation | new/deleted routes reflected in WS frames within ≤ 2 s |
| 4.a | Counter accuracy | 1000 serial reqs → 999 or 1000 reported |
| 4.b | 5xx classification | errRate5xx ≥ 0.99 under sustained 503 |
| 5.a | Page renders | connection indicator green, three columns visible |
| 5.b | Particles flow | cyan particles under load, density ∝ rate |
| 5.c | Idle transition | route fades to dashed/40% after 60 s of zero traffic |
| 5.d | Error spike | red particles + red node border + pulse under 503 |
| 5.e | Detail panel | open on click, sparklines render, close on Escape/overlay/2nd-click |
| 5.f | Empty state | message when no routes |
| 6 | Reduced motion | particles disabled, labels visible, pulse suppressed |
| 7 | FPS budget | mean FPS ≥ 55, no long task > 50 ms |
| 8.a | Reconnect on server kill | "reconnecting…" within ~5 s |
| 8.b | Reconnect on server restart | "connected" within 1–2 s typical, 30 s max (exp backoff cap) |
| 8.c | visibilitychange | DevTools Network WS row: 101 → Finished on hidden, new 101 on visible |

All green → tag `v0.3.0-step-e`. Any FAIL → file a bug before tagging.

---

## Cleanup

```bash
kill $UPSTREAM_PID 2>/dev/null
rm -f "$COOKIES" /tmp/route2.json /tmp/arenet-route.json /tmp/wsmoke-bin /tmp/upstream.py /tmp/smokebackdate.go /tmp/drain.log
rm -rf /tmp/wsmoke /tmp/wsvenv
# Stop arenet via Ctrl-C in its terminal.
```
