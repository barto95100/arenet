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

## 4. Cleanup

```sh
curl -sS $COOKIE -X DELETE "$A/settings/alerting/channels/$WEBHOOK_ID"
curl -sS $COOKIE -X DELETE "$A/settings/alerting/channels/$EMAIL_ID"
docker stop $(docker ps -q --filter ancestor=maildev/maildev)  # stop maildev
```

## 5. Known gaps (Step AL.1.b ships with these — followed in AL.2)

- No retry on send failure (D1 ADR — V1 KISS). A single
  receiver hiccup loses the alert.
- Webhook supports POST only; PUT/PATCH deferred to V2.
- No dispatcher hooked to a rule engine yet — the `/test`
  endpoint is the only way to fire a channel in AL.1.b.
  AL.2 ships the rule engine + watcher that calls
  `Dispatcher.Dispatch` on rule fires.
- No frontend Settings card yet — channel CRUD is API-only
  in this commit. UI lands in AL.4.
