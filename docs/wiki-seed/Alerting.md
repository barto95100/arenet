# Alerting

Step AL — Arenet's native alerting subsystem. Configure **rules** that watch a **source** (e.g. WAF event rate, cert expiry, cert renewal failures, system health) ; when the rule's evaluator trips, an alert is dispatched to one or more **channels** (Discord webhook, generic webhook, SMTP email).

A 30-second polling watcher evaluates every rule and respects per-rule cooldowns to prevent alert storms.

---

## Quick start

### 1. Wire a channel

1. Sidebar → **Alerting** → **Channels** tab → **+ Add channel**
2. Pick kind : `discord_webhook` / `webhook_generic` / `email_smtp`
3. Fill in the kind-specific config :

**Discord webhook** :
- Webhook URL : `https://discord.com/api/webhooks/<id>/<token>` (Server Settings → Integrations → Webhooks)
- Username (optional) : the bot's display name in the channel
- Avatar URL (optional)

**Generic webhook** :
- URL : your endpoint
- Method : `POST` (default) / `PUT`
- Headers : key-value list (e.g. `Authorization: Bearer xxx`)
- Body template : optional Go template ; default sends a JSON envelope `{ ts, rule, value, message }`

**Email SMTP** :
- SMTP host + port (e.g. `smtp.gmail.com:587`)
- Username + password (app password if 2FA on Gmail)
- From + To addresses
- TLS mode (`starttls` typical, `implicit` for port 465)

4. **Enabled** ✅
5. **Test channel** button : fires a synthetic alert through the channel to validate the wiring. Watch for the test message in Discord / inbox.
6. **Save**

### 2. Wire a rule

1. Sidebar → **Alerting** → **Rules** tab → **+ Add rule**
2. **Name** : kebab-case slug, e.g. `cert-failed-vault`
3. **Severity** : 1 (low) → 5 (critical)
4. **Source** : pick from the dropdown :
   - `waf_event_rate` — count WAF events over a window
   - `cert_expiry` — days-until-NotAfter for a domain (or earliest)
   - `cert_renewal_failed` — count cert_failed events over a window
   - `system_health` — current health status of an Arenet subsystem
5. **Source params** : kind-specific (per-source fields appear)
6. **Eval kind** :
   - `threshold` : numeric comparison (`>`, `<`, `>=`, `<=`, `==`, `!=`) + value
   - `state` : exact match on a string value (used with `system_health`)
7. **Channels** : multi-select from your wired channels
8. **Cooldown** : seconds between successive alerts for this rule (default 300s = 5min)
9. **Subject template** (optional) + **Body template** (optional) : Go template strings with access to `{{.Rule.Name}}`, `{{.Value}}`, `{{.Labels}}`, `{{.At}}`
10. **Test rule** button : evaluates the rule once with the current source value, optionally dispatches if it would trip
11. **Save**

The watcher picks up the new rule within 30s and starts evaluating.

---

## Available sources

### `waf_event_rate`

Counts `waf_event` rows in a sliding window. Use to alert on attack volume spikes.

Params :
- `routeId` (optional) : limit to one route ; empty = all routes
- `category` (optional) : limit to one OWASP category (e.g. `SQLi`, `attack-protocol`)
- `action` (optional) : `BLOCK` / `DETECT` / `""`
- `windowSecs` : `60`-`86400`, default `300` (5min)

Returns count as Float.

Example rule : "Alert when > 50 WAF events in 5 minutes on any route" → threshold `>` `50`.

### `cert_expiry`

Returns days until NotAfter for a cert.

Params :
- `host` (optional) : the cert's primary subject ; empty = the earliest-expiring cert across all tracked certs

Returns days remaining as Float (negative = already expired).

Example rules :
- "Warn 30d before expiry" : threshold `<` `30`, severity 2
- "Critical 7d before expiry" : threshold `<` `7`, severity 4
- "Alert on expired" : threshold `<` `0`, severity 5

Wire all three with different channels (e.g. severity 4+5 also goes to email) for tiered escalation.

### `cert_renewal_failed`

Counts `cert_event` rows of type `cert_failed` in a sliding window. Use to alert on ACME renewal failures.

Params :
- `domain` (optional) : limit to one domain ; empty = all
- `windowSecs` : `60`-`604800`, default `86400` (24h ; matches Let's Encrypt retry cadence)

Returns count as Float. Typical threshold : `>` `0` (any failure).

### `system_health`

Returns the current health status of Arenet subsystems.

Params :
- `component` (optional) : `crowdsec_agent`, `dns_provider_ovh`, `caddy`, ... ; empty = global aggregated status

Returns string : `healthy` / `degraded` / `down`. Use with `state` eval kind :

```
eval: state
expected: "degraded"
```

Trips when the component goes from healthy to degraded.

---

## Eval kinds

### Threshold (numeric)

```
operator: > / < / >= / <= / == / !=
value: <number>
```

The source's returned Float is compared. Trips on true.

### State (string)

```
expected: <string>
```

The source's returned String is compared by exact equality. Trips on match.

State eval is used for `system_health` ; future sources may add more.

---

## Cooldown behaviour

Each rule has a `cooldownSecs` (default 300s). After an alert fires, the rule is muted for that duration even if the condition stays trip.

The watcher tracks last-fire timestamps per-rule in BoltDB (`alert_rules_eval_state` bucket). Cooldowns survive Arenet restarts.

Pick cooldowns matched to the scenario :
- **Cert expiry** : `86400` (24h) — once a day until you fix it
- **WAF event rate spike** : `1800` (30min) — frequent enough to notice trend, not pager-noisy
- **System health degraded** : `300` (5min) — quick re-notification when status changes

---

## Templates

Subject + body templates use Go's `text/template` with the following context :

```
.Rule.Name        — rule slug
.Rule.Severity    — 1-5
.Value.Float      — source's float return (when Threshold)
.Value.String     — source's string return (when State)
.Value.Labels     — map of attributes the source attached (e.g. {host, issuer, route_id})
.At               — time.Time of the evaluation
.Operator         — comparison operator (e.g. ">", "==")
.Threshold        — the rule's configured threshold (Float or String depending on kind)
```

Default subject : `[Arenet][SEV{{.Rule.Severity}}] {{.Rule.Name}} triggered`
Default body : depends on channel kind ; Discord uses an embed, generic webhook sends JSON, email plain text.

Example custom Discord body for `cert_renewal_failed` :

```
🚨 Cert renewal failed for {{index .Value.Labels "domain"}} ({{.Value.Float}} failures in last 24h)

Open https://arenet.example.com/certs to investigate
```

---

## Alert history

Sidebar → **Alerting** → **History** tab — chronological list of every alert fired, with rule name, severity, source value at fire-time, channels notified, and delivery status (success per channel).

Filter by rule / severity / channel / time range.

Useful for :
- Confirming a Discord channel really received the alert (`delivery_status=ok`)
- Post-mortem : "what alerts did the cert outage trigger ?"
- Cooldown debugging : if a rule fires once then nothing, check the cooldown timestamp

---

## Test mode

Every channel + every rule has a **Test** button. Channels send a synthetic envelope ("This is an Arenet test alert..."), rules evaluate the current source value and optionally dispatch.

Use after every config change to validate end-to-end without waiting for a real condition to trip.

---

## Common patterns

### Cert expiry tiered alerts

| Rule | Source | Threshold | Severity | Channels |
| ---- | ------ | --------- | -------- | -------- |
| `cert-expiry-30d` | `cert_expiry` | `<` `30` | 2 | Discord |
| `cert-expiry-7d` | `cert_expiry` | `<` `7` | 4 | Discord + Email |
| `cert-expiry-1d` | `cert_expiry` | `<` `1` | 5 | Discord + Email + Webhook (to your phone) |

### WAF attack volume

| Rule | Source | Window | Threshold |
| ---- | ------ | ------ | --------- |
| `waf-spike-5min` | `waf_event_rate` (all routes) | 300s | `>` `100` |
| `waf-spike-blocked` | `waf_event_rate` (action=BLOCK) | 300s | `>` `10` |

The second rule is the genuinely alarming one (block-mode actively rejecting).

### Cert ACME failures

| Rule | Source | Window | Threshold |
| ---- | ------ | ------ | --------- |
| `cert-renewal-fail-24h` | `cert_renewal_failed` (all domains) | 86400s | `>` `0` |

Combined with `cert-expiry-7d`, you have full coverage : the alert fires immediately on the renewal attempt failure AND again 7 days before expiry if nothing was done.

### System health

| Rule | Source | Eval | Cooldown |
| ---- | ------ | ---- | -------- |
| `crowdsec-down` | `system_health` (component=crowdsec_agent) | state == "degraded" | 300s |
| `dns-provider-down` | `system_health` (component=dns_provider_ovh) | state == "degraded" | 300s |

---

## API reference

```bash
# Create a channel
curl -b /tmp/jar -X POST -H "Content-Type: application/json" -d '{
  "kind": "discord_webhook",
  "name": "ops-discord",
  "enabled": true,
  "config": {
    "webhookUrl": "https://discord.com/api/webhooks/...",
    "username": "Arenet"
  }
}' http://localhost:8001/api/v1/alerting/channels

# Create a rule
curl -b /tmp/jar -X POST -H "Content-Type: application/json" -d '{
  "name": "cert-expiry-7d",
  "enabled": true,
  "kind": "threshold",
  "severity": 4,
  "source": "cert_expiry",
  "sourceParams": {},
  "evalParams": {"operator": "<", "value": 7},
  "channels": ["<channel-id>"],
  "cooldownSecs": 86400
}' http://localhost:8001/api/v1/alerting/rules
```

The full Step AL spec lives in `internal/alerting/`.

---

## See also

- [docs/alerting.md](https://github.com/barto95100/arenet/blob/main/docs/alerting.md) — Step AL operator reference + smoke procedure
- `internal/alerting/source.go` — Source interface
- `internal/alerting/source_cert_expiry.go`, `source_cert_renewal_failed.go`, `source_waf_event_rate.go`, `source_system_health.go` — built-in sources
- `internal/alerting/sender_email.go`, `sender_webhook.go` — channel implementations
- [Troubleshooting](Troubleshooting) — channel delivery debugging
