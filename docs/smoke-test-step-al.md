<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
-->

# Step AL — Alerting smoke test

Manual smoke pass for Step AL.1.b alerting (WebhookSender +
EmailSender + Channel CRUD + Dispatcher + `/test` endpoint).

The unit tests under `internal/alerting/` and `internal/api/`
cover protocol-level correctness. This document covers the
operator-facing wire path: real HTTP receivers, a real local
SMTP relay, and the `/test` button as it will be invoked
from the Settings UI.

## Pre-flight

- arenet built and running with admin credentials known.
- `curl` + `jq` available.
- Set environment for convenience:
  ```sh
  export A="https://arenet.local/api/v1"
  export COOKIE="-b /tmp/arenet-cookie.txt -c /tmp/arenet-cookie.txt"
  # login first so subsequent calls carry the session cookie
  curl -sS $COOKIE "$A/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"<your-admin-password>"}'
  ```

## 1. Webhook channel

### 1.1 Stand up a receiver

In a separate terminal, run a one-shot listener that prints
every POST it receives:

```sh
# https://github.com/cortesi/devd or any equivalent — for a
# zero-deps version, netcat works:
while true; do { echo -e 'HTTP/1.1 200 OK\r\n\r\nok'; } | nc -l 9999 | head -20; echo "---"; done
```

The receiver listens on `127.0.0.1:9999`.

### 1.2 Create a webhook channel

```sh
curl -sS $COOKIE "$A/settings/alerting/channels" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "smoke-webhook",
    "kind": "webhook",
    "enabled": true,
    "minSeverity": 0,
    "config": {
      "url": "http://127.0.0.1:9999/hook",
      "method": "POST",
      "timeoutSeconds": 5,
      "headers": {
        "Authorization": "Bearer smoke-test-token"
      }
    }
  }' | jq .
```

Expected: HTTP 201 with the created channel. Capture the `id`:

```sh
WEBHOOK_ID=$(curl -sS $COOKIE "$A/settings/alerting/channels" | jq -r '.[] | select(.name=="smoke-webhook") | .id')
echo "WEBHOOK_ID=$WEBHOOK_ID"
```

### 1.3 Secret redaction (GET path)

```sh
curl -sS $COOKIE "$A/settings/alerting/channels/$WEBHOOK_ID" | jq .config.headers
```

**Expected:** header VALUE is `[redacted]`, header KEY
(`Authorization`) is still visible. Operator can audit which
headers were configured without seeing their secret values.

### 1.4 Fire the `/test` synthetic event

```sh
curl -sS $COOKIE -X POST "$A/settings/alerting/channels/$WEBHOOK_ID/test" | jq .
```

**Expected:** `{"ok": true}`. The receiver terminal prints the
incoming POST. The body is the marshalled `AlertEvent` with
`subject` matching `"Arenet alerting test — channel \"smoke-webhook\""`.
The `Authorization: Bearer smoke-test-token` header is present
on the receiver side.

### 1.5 Verify last-sent timestamp

```sh
curl -sS $COOKIE "$A/settings/alerting/channels/$WEBHOOK_ID" \
  | jq '{name, lastSentAt, lastError}'
```

**Expected:** `lastSentAt` is set to the recent timestamp,
`lastError` is absent.

### 1.6 Trigger a failure to see error recording

Stop the receiver. Then `/test` again:

```sh
curl -sS $COOKIE -X POST "$A/settings/alerting/channels/$WEBHOOK_ID/test" | jq .
```

**Expected:** `{"ok": false, "error": "webhook: send: ..."}`.
Re-check the channel — `lastSentAt` is preserved (still the
prior success), `lastError` + `lastErrorAt` are populated.

## 2. Email channel via local maildev

### 2.1 Run maildev

[maildev](https://github.com/maildev/maildev) gives a one-shot
SMTP listener (port 1025) + web UI (port 1080) for inspecting
captured messages.

```sh
docker run --rm -p 1080:1080 -p 1025:1025 maildev/maildev
```

Web UI: <http://localhost:1080>.

### 2.2 Create an email channel

```sh
curl -sS $COOKIE "$A/settings/alerting/channels" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "smoke-email",
    "kind": "email",
    "enabled": true,
    "minSeverity": 0,
    "config": {
      "smtpHost": "localhost",
      "smtpPort": 1025,
      "smtpUsername": "",
      "smtpPassword": "",
      "from": "alerts@arenet.local",
      "to": ["ops@arenet.local"],
      "cc": ["audit@arenet.local"],
      "useTLS": false,
      "useStartTLS": false
    }
  }' | jq .
```

```sh
EMAIL_ID=$(curl -sS $COOKIE "$A/settings/alerting/channels" | jq -r '.[] | select(.name=="smoke-email") | .id')
```

Note: maildev accepts empty AUTH; in production with a real
relay the operator supplies `smtpUsername` + `smtpPassword`.

### 2.3 Fire the `/test`

```sh
curl -sS $COOKIE -X POST "$A/settings/alerting/channels/$EMAIL_ID/test" | jq .
```

**Expected:** `{"ok": true}`. The maildev web UI shows the
message with:
- Subject: `[info] Arenet alerting test — channel "smoke-email"`
- From: `alerts@arenet.local`
- To: `ops@arenet.local`, Cc: `audit@arenet.local`
- Body: the synthetic-test plain-text payload.

### 2.4 Password preservation on PUT

Update the channel with `smtpPassword: ""` and confirm the
stored password is preserved:

```sh
# First, give the channel a non-empty password
curl -sS $COOKIE -X PUT "$A/settings/alerting/channels/$EMAIL_ID" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"smoke-email","kind":"email","enabled":true,"minSeverity":0,
    "config":{"smtpHost":"localhost","smtpPort":1025,"smtpUsername":"alice","smtpPassword":"keep-me","from":"alerts@arenet.local","to":["ops@arenet.local"],"useTLS":false,"useStartTLS":false}
  }'

# Now PUT with empty password — the previous value must persist
curl -sS $COOKIE -X PUT "$A/settings/alerting/channels/$EMAIL_ID" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"smoke-email","kind":"email","enabled":true,"minSeverity":1,
    "config":{"smtpHost":"localhost","smtpPort":1025,"smtpUsername":"alice","smtpPassword":"","from":"alerts@arenet.local","to":["ops@arenet.local"],"useTLS":false,"useStartTLS":false}
  }'
```

The minSeverity moved from 0 → 1 to prove the PUT landed.
No direct way to read the stored password from the API (by
design), but a follow-up `/test` should still succeed.

## 3. Audit verification

After all the above, query the audit log:

```sh
curl -sS $COOKIE "$A/audit?action=alert_channel_created,alert_channel_updated,alert_channel_deleted" | jq .
```

**Expected entries:**
- `alert_channel_created` × 2 (webhook + email)
- `alert_channel_updated` × 2 (the two email PUTs in §2.4)

**Critical redaction check** — the `before_json` /
`after_json` fields of every event MUST be free of the
following strings:
- `super-secret-token` (webhook Authorization value)
- `keep-me` (the stored SMTP password)
- Any real secret value the operator submitted

Header VALUES inside the audit blob appear as `[redacted]`.
SMTP password fields appear as empty string.

```sh
# One-shot grep for the sentinel
curl -sS $COOKIE "$A/audit?action=alert_channel_updated" \
  | jq -r '.[].afterJson' \
  | grep -E 'keep-me|super-secret-token' \
  && echo "FAIL: secret leaked in audit" \
  || echo "PASS: no secrets in audit"
```

## 4. Rules (AL.3b + AL.2.b watcher integration)

### 4.1 Create a threshold rule against `system_health`

This is the rule used in the watcher smoke below.

```sh
RULE_BODY='{
  "name": "smoke-crowdsec-degraded",
  "enabled": true,
  "kind": "state",
  "severity": 2,
  "category": "system",
  "source": "system_health",
  "sourceParams": {"component": "crowdsec"},
  "evalParams": {"expected": "degraded"},
  "channels": ["'$WEBHOOK_ID'"],
  "cooldownSecs": 300
}'

curl -sS $COOKIE "$A/settings/alerting/rules" \
  -H 'Content-Type: application/json' \
  -d "$RULE_BODY" | jq .
```

Capture the rule ID:

```sh
RULE_ID=$(curl -sS $COOKIE "$A/settings/alerting/rules" \
  | jq -r '.[] | select(.name=="smoke-crowdsec-degraded") | .id')
echo "RULE_ID=$RULE_ID"
```

### 4.2 Force-fire via the rule /test endpoint

```sh
curl -sS $COOKIE -X POST "$A/settings/alerting/rules/$RULE_ID/test" | jq .
```

**Expected:** `{"sent": true, "channelsFired": ["<webhook_id>"]}`.
The webhook receiver sees a POST with subject prefix
`[TEST] Arenet alerting rule "smoke-crowdsec-degraded"
force-fired by operator`. The /test endpoint bypasses
cooldown AND `rule.Enabled` (operator pressed Test
deliberately).

### 4.3 Observe a real watcher fire

This step requires producing the actual condition the
rule watches. For the `system_health` rule above:

```sh
# Stop CrowdSec (the watcher will see component=degraded
# on its next 30s tick — `crowdsec_unreachable` → degraded
# via the AL.3a checker)
sudo systemctl stop crowdsec     # or docker stop crowdsec-container

# Wait for one watcher tick (30s default + boot-time
# initial tick). Give it 35s to be safe.
sleep 35

# The webhook receiver should now have received the live
# alert. Verify:
curl -sS $COOKIE "$A/observability/alert-events?limit=5" \
  | jq '.events[] | {ruleName, severity, subject, channelsFired}'

# Re-trigger by waiting another cooldownSecs (300s by
# default for this rule); the cooldown will prevent any
# repeat within the window.

# Restart CrowdSec; on next tick the watcher will record
# a clean evaluation (LastEvalAt updates; LastFiredAt
# stays).
sudo systemctl start crowdsec
```

**Expected timeline:**

| t (s) | State | Watcher | Webhook receiver |
|---|---|---|---|
| 0 | crowdsec up | tick OK, no fire | — |
| 0 | crowdsec stopped | — | — |
| 0-30 | crowdsec down | sleeping until next tick | — |
| ~30 | watcher tick | source=`degraded`, fire ✓ | 1 POST received |
| 30-330 | crowdsec down | every tick fires, but cooldown LRU suppresses every one of them | no new POST (silenced) |
| ~330 | crowdsec down | cooldown expired, re-fires | 2nd POST received |

### 4.4 Verify SQLite persistence

```sh
# Default path; adjust if your arenet uses a non-default
# data dir.
DB=/var/lib/arenet/metrics.db
# (or /tmp/arenet-*-data/metrics.db for dev mode)

sqlite3 "$DB" \
  "SELECT ts, rule_name, severity, channels_fired_json, channels_failed_json
   FROM alert_event
   WHERE rule_name = 'smoke-crowdsec-degraded'
   ORDER BY ts DESC LIMIT 5;"
```

**Expected:** rows with `severity = 2`, `channels_fired_json =
'["<webhook_id>"]'`, `channels_failed_json = ''`. The Test
fires from §4.2 are also there (look for the `[TEST]`
substring in the subject column).

## 5. UI verification (browser)

After §3 + §4 above, the operator-facing checks:

- Sidebar contains a **Alerting** entry (bell icon) in the
  Sécurité section.
- Clicking it loads `/alerting` with **Canaux** as the
  default active tab.
- URL hash deep-link works:
  - `/alerting#channels` → Canaux active
  - `/alerting#rules` → Règles active
  - `/alerting#history` → Historique active
- **Canaux** tab shows the seeded webhook + email
  channels with **État: Actif**, **Sévérité min**
  badge with hover tooltip explaining the level.
- The **Dernier envoi** column shows a relative time
  (`il y a 2 min`) for channels recently tested.
- Edit button on a channel row opens the modal pre-
  populated; the kind selector is **disabled** in edit
  mode; SMTP password field shows `[défini]` placeholder
  with a "Modifier le mot de passe" checkbox.
- Test button shows a success toast on a healthy
  channel; the channel row's `Dernier envoi` updates
  after the page refreshes.
- **Règles** tab shows the seeded rule with the right
  source / severity / channels count.
- Edit on a rule opens the modal with `kind` radio
  **disabled**, source dropdown and source-specific
  sub-form pre-populated.
- The source dropdown swaps the SourceParams sub-form
  when changed (try all 3: waf_event_rate →
  cert_expiry → system_health).
- The kind radio (create mode only) swaps the
  EvalParams form when changed (Threshold → State).
- Test button on a rule shows a toast (success or
  partial) and the History tab populates with a new
  `[TEST]` event.
- **Historique** tab lists every dispatched event.
  Filters trigger refetch after 300ms debounce
  (date range, severity, rule, category).
- Sévérité badges have hover tooltips explaining the
  level mapping (Info=0, Avertissement=1, Critique=2,
  Urgence=3).

## 6. Cleanup

```sh
# Remove the rule first (otherwise the channel deletion
# may be blocked by a reference check in V2 — V1 doesn't
# enforce this server-side but it's the right ordering).
curl -sS $COOKIE -X DELETE "$A/settings/alerting/rules/$RULE_ID"

curl -sS $COOKIE -X DELETE "$A/settings/alerting/channels/$WEBHOOK_ID"
curl -sS $COOKIE -X DELETE "$A/settings/alerting/channels/$EMAIL_ID"

docker stop $(docker ps -q --filter ancestor=maildev/maildev)  # stop maildev
```

## 7. Boot log checklist

The arenet boot log (journalctl or stdout) MUST contain:

```
INFO msg="alerting watcher started" interval=30s sources="[cert_expiry system_health waf_event_rate]"
```

On SIGTERM, the matching shutdown line:

```
INFO msg="alerting watcher stopped"
```

If the watcher line is absent, the alerting subsystem
won't fire any rule (the /test endpoints still work via
the dispatcher). Common causes:

- `obsStore` boot failure → check earlier `observability
  storage` log lines.
- A registry registration error → search the boot log
  for `alerting: register .* source failed`.

## 8. Expected outcomes vs failure modes

| Step | Pass | Common failure mode |
|---|---|---|
| §1.4 webhook /test | Toast green, receiver POST | URL unreachable → "webhook: send: ..." in `lastError`. Closed port → connection refused. |
| §2.3 email /test | Toast green, maildev shows message | Auth fail → `email: auth: 535`. RCPT reject → `email: RCPT TO: 550`. STARTTLS unsupported on port → switch to TLS=465 or none. |
| §4.2 rule /test | `sent:true` + receiver POST | Channel disabled → `skipped` non-empty in response. minSeverity gate → also `skipped`. |
| §4.3 watcher fire | 1 POST after ~30s | No watcher boot log → §7. Source not registered → `lastError` on rule. |
| §4.4 SQLite row | `channels_fired_json` populated | `degraded:true` in `/alert-events` response → obsStore unwired (check boot log). |
| §5 UI checks | All 3 tabs interactive | SPA not built (`/alerting` returns 404) → run `cd web/frontend && npm run build` before `go build`. |

## 9. Known limitations (V1)

See `docs/alerting.md#limitations-v1` for the full list.
The most operator-facing :

- **Cooldown reset on restart**. A mid-incident arenet
  restart will re-fire every active condition on the
  first watcher tick.
- **No retry on dispatch failure**. A flaky webhook
  receiver loses the alert; the `lastError` is the
  only trace.
- **No native Slack / Discord**. Use webhook with a
  template body in the receiver's expected JSON shape
  (examples in `docs/alerting.md`).
