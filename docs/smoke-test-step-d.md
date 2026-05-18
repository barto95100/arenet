# Step D — Manual smoke test

Run **before** tagging `v0.2.0-step-d`. Targets the local single-binary build with `--dev` mode so cookies omit `Secure` (HTTP-only) and the frontend is served by Vite, while the API runs on `:8001`.

Each section is self-contained: copy/paste the block in a terminal. Stop on the first FAIL.

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
```

Export it for the rest of the session:

```bash
export ARENET_SETUP_TOKEN='<paste-here>'
export ARENET_USER='admin'
export ARENET_DISPLAY='Admin'
# 15+ chars, not in top-10k, and ideally not in HIBP (dev throwaway is fine)
export ARENET_PASSWORD='ThisIsASecurePass!23'
export ARENET_BASE='http://localhost:8001/api/v1'

# Cookie jar shared by all curl calls
export COOKIES="$(mktemp -t arenet-cookies)"
echo "cookies → $COOKIES"
```

All curl commands below use:
- `-c "$COOKIES" -b "$COOKIES"` → read/write the shared cookie jar (`arenet_session`)
- `-w '\nHTTP %{http_code}\n'` → print the status code on the last line
- `-s` → quiet, `-S` → keep error messages
- Expected status codes are listed; mismatch = FAIL

---

## 1. Bootstrap (setup admin) — expect 201

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg t "$ARENET_SETUP_TOKEN" \
            --arg u "$ARENET_USER" \
            --arg d "$ARENET_DISPLAY" \
            --arg p "$ARENET_PASSWORD" \
            '{setupToken:$t, username:$u, displayName:$d, password:$p}')" \
  "$ARENET_BASE/auth/setup"
```

**Expect:** `HTTP 201` + body `{"id":"...","username":"admin","displayName":"Admin","createdAt":"..."}`.
**Sanity:** cookie jar should now contain `arenet_session`.

```bash
grep arenet_session "$COOKIES" && echo OK_SESSION || echo FAIL_NO_COOKIE
```

**Second call must 404** (single-use bootstrap):

```bash
curl -sS -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg t "$ARENET_SETUP_TOKEN" \
            --arg u "$ARENET_USER" \
            --arg d "$ARENET_DISPLAY" \
            --arg p "$ARENET_PASSWORD" \
            '{setupToken:$t, username:$u, displayName:$d, password:$p}')" \
  "$ARENET_BASE/auth/setup"
```
**Expect:** `HTTP 404` body `setup unavailable: an admin already exists`.

---

## 2. Login — expect 200 + Set-Cookie + /me ok

`/setup` already set a session, but we exercise the explicit login flow.

```bash
# Clear the cookie jar so we start logged-out
: > "$COOKIES"

curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ARENET_USER" --arg p "$ARENET_PASSWORD" \
            '{username:$u, password:$p, rememberMe:false}')" \
  "$ARENET_BASE/auth/login"
```
**Expect:** `HTTP 200` + body `{"id":"...","username":"admin","displayName":"Admin"}`.

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  "$ARENET_BASE/auth/me"
```
**Expect:** `HTTP 200` + body contains `"username":"admin"` and `"locked":false`.

**Wrong password must 401:**

```bash
curl -sS -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ARENET_USER" '{username:$u, password:"wrong-pass", rememberMe:false}')" \
  "$ARENET_BASE/auth/login"
```
**Expect:** `HTTP 401` body `invalid credentials`.

---

## 3. Create route + Caddy reload — expect 201

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d '{"host":"smoke.localhost","upstreamUrl":"http://127.0.0.1:9999","tlsEnabled":false,"wafEnabled":false}' \
  "$ARENET_BASE/routes" | tee /tmp/arenet-route.json
```
**Expect:** `HTTP 201` + body with a `"id"` field. Note the id:

```bash
export ROUTE_ID="$(jq -r '.id' < /tmp/arenet-route.json)"
echo "route_id=$ROUTE_ID"
```

**Sanity — Caddy reload happened** (no error in logs, route reachable via Host header):

```bash
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' \
  -H 'Host: smoke.localhost' http://127.0.0.1:8080
```
**Expect:** `HTTP 502` (no upstream listening) — the **502 itself proves Caddy routed the host**. If you get `HTTP 404`, Caddy didn't reload → FAIL.

---

## 4. Audit log shows setup_admin_created + login_success + route_created

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  "$ARENET_BASE/audit?limit=50" | jq '.events[].action'
```
**Expect:** the output contains, in some order:
- `"audit_viewed"` (this very call)
- `"route_created"`
- `"login_success"`
- `"setup_admin_created"`

Quick assertion one-liner:

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" "$ARENET_BASE/audit?limit=50" \
  | jq -r '[.events[].action] | unique | inside(["setup_admin_created","login_success","route_created","audit_viewed"]) | not' \
  | grep -q false && echo OK_AUDIT || echo FAIL_AUDIT
```
The expression `inside(...) | not` returns `false` when our target set is a subset of observed actions → we want `false` → grep prints `OK_AUDIT`.

**Verify each event has its timestamp populated** (the wire field is `timestamp`, not `createdAt` — the latter is only on user/route responses):

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" "$ARENET_BASE/audit?limit=50" \
  | jq '.events[] | {action, timestamp}'
```
**Expect:** every event shows an RFC3339 timestamp (`"2026-..."`). A `null` or empty `timestamp` → FAIL.

---

## 5. Idle lock: backdate LastActivity by 16 min — expect 403 on /heartbeat

This needs **direct BoltDB access**. The `bbolt` CLI was considered but
its `put` subcommand does not exist in the current release, so we use
a small Go helper instead.

Save the snippet below as `cmd/smokebackdate/main.go` (temp file, not
committed — delete after the smoke session) and run it with arenet
stopped (BoltDB takes an exclusive lock):

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

```bash
go run ./cmd/smokebackdate ./data/arenet.db
./arenet --dev --admin-port :8001 &
```

### Verify lock

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' -X POST \
  "$ARENET_BASE/auth/heartbeat"
```
**Expect:** `HTTP 403`. The hard-auth middleware detected `now - last_activity > 15 min` and returned the lock signal **without** touching `last_activity`.

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' "$ARENET_BASE/auth/me"
```
**Expect:** `HTTP 200` body with `"locked":true` (soft-auth allows /me; the page can show the LockScreen).

### Verify in the browser

Open the SvelteKit Vite dev server at **`http://localhost:5173/`**
(the URL printed at `--dev` boot). `:8001` only serves the admin API;
the SPA itself is hosted by Vite in dev mode and proxies fetches to
`:8001` with `credentials:'include'`.

Sign in (or refresh if already signed in) and wait ~5 s for the next
heartbeat tick. The `LockScreen` overlay (full-screen, backdrop-blur)
should mount automatically once the heartbeat returns 403.

---

## 6. Unlock — expect 200, lock cleared

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg p "$ARENET_PASSWORD" '{password:$p}')" \
  "$ARENET_BASE/auth/unlock"
```
**Expect:** `HTTP 200` body `{"unlocked":true}`.

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' -X POST \
  "$ARENET_BASE/auth/heartbeat"
```
**Expect:** `HTTP 204` (lock cleared).

In the browser the LockScreen overlay should disappear once the unlock POST returns.

---

## 7. Change password — other sessions revoked

Create a second session (simulating another device) by logging in with a fresh cookie jar:

```bash
export COOKIES_B="$(mktemp -t arenet-cookies-b)"

curl -sS -c "$COOKIES_B" -b "$COOKIES_B" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ARENET_USER" --arg p "$ARENET_PASSWORD" \
            '{username:$u, password:$p, rememberMe:false}')" \
  "$ARENET_BASE/auth/login"
```
**Expect:** `HTTP 200`. The two jars now hold two distinct sessions.

Change the password from session A:

```bash
export ARENET_NEW_PASSWORD='AnotherStrongPass!42'

curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg c "$ARENET_PASSWORD" --arg n "$ARENET_NEW_PASSWORD" \
            '{currentPassword:$c, newPassword:$n}')" \
  "$ARENET_BASE/auth/me/password"
```
**Expect:** `HTTP 204`.

**Session B must now be revoked** — its cookie is no longer in `sessions`:

```bash
curl -sS -c "$COOKIES_B" -b "$COOKIES_B" \
  -w '\nHTTP %{http_code}\n' "$ARENET_BASE/auth/me"
```
**Expect:** `HTTP 401`.

**Session A is preserved** (current request's cookie):

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' "$ARENET_BASE/auth/me"
```
**Expect:** `HTTP 200`.

Update the exported password so the rest of the script uses the new one:

```bash
export ARENET_PASSWORD="$ARENET_NEW_PASSWORD"
```

Audit should now contain `password_changed`:

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" "$ARENET_BASE/audit?action=password_changed" \
  | jq '.events | length'
```
**Expect:** `>= 1`.

---

## 8. Logout

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' -X POST \
  "$ARENET_BASE/auth/logout"
```
**Expect:** `HTTP 204`. Cookie jar's `arenet_session` should be cleared (`Max-Age=0`).

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' "$ARENET_BASE/auth/me"
```
**Expect:** `HTTP 401`.

```bash
curl -sS -c "$COOKIES" -b "$COOKIES" \
  -w '\nHTTP %{http_code}\n' "$ARENET_BASE/routes"
```
**Expect:** `HTTP 401`.

Final audit shows the closing event:

```bash
# Re-login briefly so we can query /audit (hard-auth gated).
curl -sS -c "$COOKIES" -b "$COOKIES" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ARENET_USER" --arg p "$ARENET_PASSWORD" \
            '{username:$u, password:$p, rememberMe:false}')" \
  "$ARENET_BASE/auth/login" >/dev/null

curl -sS -c "$COOKIES" -b "$COOKIES" "$ARENET_BASE/audit?action=logout" \
  | jq '.events | length'
```
**Expect:** `>= 1`.

---

## Checklist summary

| # | Step | Pass criterion |
|---|---|---|
| 1 | Setup admin | 201 + cookie issued; 2nd call 404 |
| 2 | Login + /me | 200 / 200; wrong pwd 401 |
| 3 | Create route | 201; Caddy returns 502 (host routed, no upstream) |
| 4 | /audit content | events ⊇ {setup_admin_created, login_success, route_created, audit_viewed} |
| 5 | Idle 16 min → /heartbeat | 403; /me → `locked:true` |
| 6 | Unlock | 200; /heartbeat → 204 |
| 7 | Change password | 204; session B → 401; session A → 200; audit has `password_changed` |
| 8 | Logout | 204; /me → 401; audit has `logout` |

All green → tag `v0.2.0-step-d`. Any FAIL → file a bug before tagging.
