# Alerting

[English](Alerting) · **🌐 Français**

Step AL — le sous-système d'alerting natif d'Arenet. Configure des **rules** qui watch une **source** (ex. taux d'événements WAF, expiration de cert, échecs de renouvellement cert, santé système) ; quand l'evaluator de la rule trip, une alerte est dispatchée vers un ou plusieurs **channels** (webhook Discord, webhook générique, email SMTP).

Un watcher polling 30-seconds évalue chaque rule et respecte les cooldowns par rule pour prévenir les tempêtes d'alertes.

---

## Quick start

### 1. Câble un channel

1. Sidebar → **Alerting** → onglet **Channels** → **+ Add channel**
2. Choisis le kind : `discord_webhook` / `webhook_generic` / `email_smtp`
3. Remplis la config kind-specific :

**Discord webhook** :
- Webhook URL : `https://discord.com/api/webhooks/<id>/<token>` (Server Settings → Integrations → Webhooks)
- Username (optionnel) : le display name du bot dans le channel
- Avatar URL (optionnel)

**Generic webhook** :
- URL : ton endpoint
- Method : `POST` (défaut) / `PUT`
- Headers : liste key-value (ex. `Authorization: Bearer xxx`)
- Body template : template Go optionnel ; le défaut envoie une enveloppe JSON `{ ts, rule, value, message }`

**Email SMTP** :
- SMTP host + port (ex. `smtp.gmail.com:587`)
- Username + password (app password si 2FA sur Gmail)
- From + To addresses
- TLS mode (`starttls` typique, `implicit` pour port 465)

4. **Enabled** ✅
5. Bouton **Test channel** : déclenche une alerte synthétique à travers le channel pour valider le câblage. Watch pour le message de test dans Discord / inbox.
6. **Save**

### 2. Câble une rule

1. Sidebar → **Alerting** → onglet **Rules** → **+ Add rule**
2. **Name** : slug kebab-case, ex. `cert-failed-vault`
3. **Severity** : 1 (low) → 5 (critical) — labels Info/Warning/Critical/Emergency restent EN
4. **Source** : choisis depuis le dropdown :
   - `waf_event_rate` — count des événements WAF sur une fenêtre
   - `cert_expiry` — jours-jusqu'à-NotAfter pour un domaine (ou le plus tôt)
   - `cert_renewal_failed` — count des événements cert_failed sur une fenêtre
   - `system_health` — status de santé actuel d'un sous-système Arenet
5. **Source params** : kind-specific (les champs par-source apparaissent)
6. **Eval kind** :
   - `threshold` : comparaison numérique (`>`, `<`, `>=`, `<=`, `==`, `!=`) + value
   - `state` : match exact sur une string value (utilisé avec `system_health`)
7. **Channels** : multi-select depuis tes channels câblés
8. **Cooldown** : secondes entre alertes successives pour cette rule (défaut 300s = 5min)
9. **Subject template** (optionnel) + **Body template** (optionnel) : strings de template Go avec accès à `{{.Rule.Name}}`, `{{.Value}}`, `{{.Labels}}`, `{{.At}}`
10. Bouton **Test rule** : évalue la rule une fois avec la valeur courante de la source, dispatch optionnellement si elle triperait
11. **Save**

Le watcher pick up la nouvelle rule en 30s et commence à évaluer.

---

## Sources disponibles

### `waf_event_rate`

Count des lignes `waf_event` dans une fenêtre slidingue. À utiliser pour alerter sur les spikes de volume d'attaque.

Params :
- `routeId` (optionnel) : limite à une route ; vide = toutes les routes
- `category` (optionnel) : limite à une catégorie OWASP (ex. `SQLi`, `attack-protocol`)
- `action` (optionnel) : `BLOCK` / `DETECT` / `""`
- `windowSecs` : `60`-`86400`, défaut `300` (5min)

Retourne count comme Float.

Exemple rule : "Alert when > 50 WAF events in 5 minutes on any route" → threshold `>` `50`.

### `cert_expiry`

Retourne les jours jusqu'à NotAfter pour un cert.

Params :
- `host` (optionnel) : le subject primaire du cert ; vide = le cert expirant le plus tôt parmi tous les certs tracked

Retourne jours restants comme Float (négatif = déjà expiré).

Exemples de rules :
- "Warn 30d before expiry" : threshold `<` `30`, severity 2
- "Critical 7d before expiry" : threshold `<` `7`, severity 4
- "Alert on expired" : threshold `<` `0`, severity 5

Câble les trois avec des channels différents (ex. severity 4+5 va aussi à email) pour escalation tiered.

### `cert_renewal_failed`

Count des lignes `cert_event` de type `cert_failed` dans une fenêtre slidingue. À utiliser pour alerter sur les échecs de renouvellement ACME.

Params :
- `domain` (optionnel) : limite à un domaine ; vide = tous
- `windowSecs` : `60`-`604800`, défaut `86400` (24h ; match la cadence de retry Let's Encrypt)

Retourne count comme Float. Threshold typique : `>` `0` (any failure).

### `system_health`

Retourne le status de santé actuel des sous-systèmes Arenet.

Params :
- `component` (optionnel) : `crowdsec_agent`, `dns_provider_ovh`, `caddy`, ... ; vide = status global agrégé

Retourne string : `healthy` / `degraded` / `down`. À utiliser avec le `state` eval kind :

```
eval: state
expected: "degraded"
```

Trip quand le composant passe de healthy à degraded.

---

## Eval kinds

### Threshold (numérique)

```
operator: > / < / >= / <= / == / !=
value: <number>
```

Le Float retourné par la source est comparé. Trip sur true.

### State (string)

```
expected: <string>
```

La String retournée par la source est comparée par égalité exacte. Trip sur match.

L'eval state est utilisé pour `system_health` ; les futures sources pourraient en ajouter plus.

---

## Comportement de cooldown

Chaque rule a un `cooldownSecs` (défaut 300s). Après qu'une alerte fire, la rule est muted pour cette durée même si la condition reste trip.

Le watcher track les timestamps last-fire par rule dans BoltDB (bucket `alert_rules_eval_state`). Les cooldowns survivent aux restarts Arenet.

Choisis les cooldowns adaptés au scénario :
- **Cert expiry** : `86400` (24h) — une fois par jour jusqu'à ce que tu fixes
- **Spike de taux d'événements WAF** : `1800` (30min) — assez fréquent pour notice la tendance, pas pager-noisy
- **System health degraded** : `300` (5min) — re-notification rapide quand le status change

---

## Templates

Subject + body templates utilisent le `text/template` de Go avec le contexte suivant :

```
.Rule.Name        — slug de la rule
.Rule.Severity    — 1-5
.Value.Float      — return float de la source (quand Threshold)
.Value.String     — return string de la source (quand State)
.Value.Labels     — map d'attributs que la source a attachés (ex. {host, issuer, route_id})
.At               — time.Time de l'évaluation
.Operator         — opérateur de comparaison (ex. ">", "==")
.Threshold        — le threshold configuré de la rule (Float ou String selon kind)
```

Default subject : `[Arenet][SEV{{.Rule.Severity}}] {{.Rule.Name}} triggered`
Default body : dépend du kind de channel ; Discord utilise un embed, generic webhook envoie du JSON, email plain text.

Exemple body Discord custom pour `cert_renewal_failed` :

```
🚨 Cert renewal failed for {{index .Value.Labels "domain"}} ({{.Value.Float}} failures in last 24h)

Open https://arenet.example.com/certs to investigate
```

---

## Historique des alertes

Sidebar → **Alerting** → onglet **History** — liste chronologique de chaque alerte fired, avec nom de rule, severity, valeur source au fire-time, channels notifiés, et delivery status (succès par channel).

Filter par rule / severity / channel / range de temps.

Utile pour :
- Confirmer qu'un channel Discord a vraiment reçu l'alerte (`delivery_status=ok`)
- Post-mortem : "quelles alertes l'outage cert a triggered ?"
- Debug de cooldown : si une rule fire une fois puis plus rien, check le timestamp de cooldown

---

## Mode test

Chaque channel + chaque rule a un bouton **Test**. Les channels envoient une enveloppe synthétique ("This is an Arenet test alert..."), les rules évaluent la valeur source courante et dispatch optionnellement.

À utiliser après chaque changement de config pour valider end-to-end sans attendre une vraie condition qui trip.

---

## Patterns communs

### Alertes tiered d'expiration cert

| Rule | Source | Threshold | Severity | Channels |
| ---- | ------ | --------- | -------- | -------- |
| `cert-expiry-30d` | `cert_expiry` | `<` `30` | 2 | Discord |
| `cert-expiry-7d` | `cert_expiry` | `<` `7` | 4 | Discord + Email |
| `cert-expiry-1d` | `cert_expiry` | `<` `1` | 5 | Discord + Email + Webhook (vers ton téléphone) |

### Volume d'attaque WAF

| Rule | Source | Window | Threshold |
| ---- | ------ | ------ | --------- |
| `waf-spike-5min` | `waf_event_rate` (toutes routes) | 300s | `>` `100` |
| `waf-spike-blocked` | `waf_event_rate` (action=BLOCK) | 300s | `>` `10` |

La seconde rule est la genuinely alarming (block-mode rejette activement).

### Échecs cert ACME

| Rule | Source | Window | Threshold |
| ---- | ------ | ------ | --------- |
| `cert-renewal-fail-24h` | `cert_renewal_failed` (tous domaines) | 86400s | `>` `0` |

Combiné avec `cert-expiry-7d`, tu as une couverture full : l'alerte fire immédiatement sur l'échec de tentative de renouvellement ET de nouveau 7 jours avant expiry si rien n'a été fait.

### Santé système

| Rule | Source | Eval | Cooldown |
| ---- | ------ | ---- | -------- |
| `crowdsec-down` | `system_health` (component=crowdsec_agent) | state == "degraded" | 300s |
| `dns-provider-down` | `system_health` (component=dns_provider_ovh) | state == "degraded" | 300s |

---

## Référence API

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

La spec Step AL complète vit dans `internal/alerting/`.

---

## See also

- [docs/alerting.md](https://github.com/barto95100/arenet/blob/main/docs/alerting.md) — référence opérateur Step AL + procédure de smoke
- `internal/alerting/source.go` — interface Source
- `internal/alerting/source_cert_expiry.go`, `source_cert_renewal_failed.go`, `source_waf_event_rate.go`, `source_system_health.go` — sources built-in
- `internal/alerting/sender_email.go`, `sender_webhook.go` — implémentations de channels
- [Troubleshooting](Troubleshooting) — debug de delivery de channel
