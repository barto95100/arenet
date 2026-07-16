# Installation

[English](Installation) · **🌐 Français**

Deux chemins d'installation supportés : **Docker** (recommandé pour la plupart des homelabs) et **systemd natif** sur Linux. Choisis-en un — les deux finissent au même endroit : une instance Arenet qui tourne avec l'UI d'admin accessible sur `:8001` et le listener public sur `:80` + `:443`.

Cette page est le guide condensé. Pour les détails par OS, voir le dossier [docs/install/](https://github.com/barto95100/arenet/tree/main/docs/install) dans le repo principal.

---

## Prérequis

| Requirement | Pourquoi |
| ----------- | -------- |
| Host Linux (amd64 ou arm64) | Cible binaire native ; l'image Docker est multi-arch |
| DNS public pointant sur le host | Pour que le challenge ACME HTTP-01 fonctionne pour l'auto-HTTPS |
| TCP/80 + TCP/443 ouverts en inbound | Redirect HTTP-to-HTTPS + serving HTTPS |
| **UDP/443 ouvert en inbound** | HTTP/3 sur QUIC ([voir doc HTTP/3](https://github.com/barto95100/arenet/blob/main/docs/operations/http3.md)) |
| Optionnel : creds API DNS provider | Challenge DNS-01 pour les certs wildcard — configure un ou plusieurs comptes OVH, voir [DNS Providers](DNS-Providers-FR) |

Cible hardware : 2 vCPU + 1 Go RAM est confortable pour 50 routes. Le WAF Coraza est le plus gros consommateur — désactive-le par route sur les hosts low-resource si nécessaire (voir [WAF](WAF-FR)).

---

## Chemin 1 : Docker (recommandé)

### 1. Récupère le fichier compose

```bash
mkdir -p ~/arenet && cd ~/arenet
curl -O https://raw.githubusercontent.com/barto95100/arenet/main/docker-compose.yml
```

### 2. Pull + start

```bash
docker compose pull
docker compose up -d
```

Un volume nommé `arenet-data` contient l'état BoltDB + SQLite + les certs Caddy. Backup tout le volume (ou utilise l'[UI Backup](Backup-Restore-FR)) pour la disaster recovery.

### 3. Récupère le setup token

Au premier boot, Arenet génère un setup token one-time pour bootstrapper le compte admin. Trouve-le dans les logs :

```bash
docker compose logs arenet | grep "setup token"
```

Tu verras une ligne comme : `setup token : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`

### 4. Ouvre le wizard

Ouvre `http://<your-host>:8001` dans un navigateur. Le wizard de setup demande :
- Le setup token (de l'étape 3)
- Un username + password admin (hashé en Argon2id)
- Un email admin (pour alerting + recovery)

Clique **Submit** → tu es dedans. Le setup token est consommé (usage one-time), le compte admin est créé avec le rôle `admin`, et le wizard de setup disparaît aux visites suivantes.

### Bind mount au lieu d'un volume nommé ?

Si tu préfères un bind mount host-path (plus facile à backup avec `tar`), crée le directory d'abord avec le bon ownership :

```bash
mkdir -p ./data
sudo chown -R 65532:65532 ./data  # UID distroless 'nonroot'
```

Puis édite `docker-compose.yml` pour utiliser `./data:/var/lib/arenet` au lieu du volume nommé.

---

## Chemin 2 : Linux natif + systemd

Pour les opérateurs qui ne veulent pas Docker, ou qui veulent intégrer Arenet avec le graphe d'unit systemd existant du host (ex. `WantedBy` ta stack de monitoring).

### 1. Exécute le script d'install

```bash
curl -fsSL https://raw.githubusercontent.com/barto95100/arenet/main/packaging/systemd/install.sh \
  | sudo bash
```

Le script :
- Télécharge le dernier binaire release (multi-arch) depuis les GitHub releases
- Crée l'utilisateur système `arenet` (pas de shell, password locké)
- Installe le binaire à `/usr/local/bin/arenet`
- Installe l'unit systemd à `/etc/systemd/system/arenet.service`
- Crée `/var/lib/arenet/` pour l'état BoltDB + SQLite
- Reload systemd (`systemctl daemon-reload`)

### 2. Démarre le service

```bash
sudo systemctl enable --now arenet
```

### 3. Récupère le setup token

```bash
sudo journalctl -u arenet --since "1 min ago" | grep "setup token"
```

### 4. Ouvre le wizard

Pareil que l'étape 4 du chemin Docker — `http://<your-host>:8001`, colle le token, crée le compte admin.

---

## Post-install : exposer l'UI d'admin

Par défaut l'UI d'admin bind sur `127.0.0.1:8001` (loopback uniquement) par sécurité. Pour y accéder depuis ton LAN :

**Docker** : le `docker-compose.yml` publie déjà `8001:8001` donc c'est reachable sur `http://<docker-host>:8001` depuis ton LAN. Restreins via des policies Docker network ou ton firewall.

**systemd** : édite `/etc/systemd/system/arenet.service` et set la variable d'env :

```ini
[Service]
Environment="ARENET_ADMIN_BIND=0.0.0.0:8001"
```

Puis `systemctl daemon-reload && systemctl restart arenet`.

⚠️ **N'expose pas l'UI d'admin publiquement**. Utilise [SSO OIDC](OIDC-SSO-FR) + une route qui cible `127.0.0.1:8001` pour que l'admin soit derrière ta chaîne d'auth.

---

## Variables d'environnement (optionnel)

Toutes optionnelles — définis-les via `environment:` dans `docker-compose.yml` ou `Environment="..."` dans l'unit systemd.

| Variable | Défaut | Rôle |
| -------- | ------ | ---- |
| `ARENET_ADMIN_BIND` | `127.0.0.1:8001` | Adresse de bind de l'UI/API d'admin. Mets `0.0.0.0:8001` pour un accès LAN (voir ci-dessus). |
| `ARENET_DATA_DIR` | `/var/lib/arenet` | Où le binaire stocke son état BoltDB/SQLite. |
| `ARENET_UPDATE_CHECK_INTERVAL` | `24h` | Cadence du vérificateur de mises à jour opt-in (durée Go, min `1h`). Le check doit tout de même être **activé dans Réglages → Mises à jour** — pas de toggle env pour ça. Voir [DNS Providers → Rester à jour](DNS-Providers-FR#rester-à-jour). |
| `ARENET_ACME_EMAIL` | _(aucun)_ | Email de contact passé à l'émetteur ACME pour les notices Let's Encrypt. |

D'autres variables opérationnelles (`ARENET_CROWDSEC_*`, `ARENET_UI_ORIGIN`, …) sont documentées dans les pages de feature correspondantes.

---

## Vérifier l'install

```bash
# Endpoint Healthz
curl http://localhost:8001/healthz

# Output attendu : {"status":"ok"}
```

Si tu vois `{"status":"ok"}`, Arenet tourne et le Caddy embarqué + BoltDB + Coraza + bouncer CrowdSec ont tous booté proprement. Sinon, voir [Troubleshooting](Troubleshooting-FR).

---

## See also

- [Routes](Routes-FR) — câble ton premier host proxifié
- [Backup & Restore](Backup-Restore-FR) — sauve ta config avant/après les upgrades
- [Troubleshooting](Troubleshooting-FR) — pièges communs d'install + décodage des logs
- [`docs/install/docker-quickstart.md`](https://github.com/barto95100/arenet/blob/main/docs/install/docker-quickstart.md) — guide Docker étendu avec troubleshooting
- [`docs/install/systemd-native.md`](https://github.com/barto95100/arenet/blob/main/docs/install/systemd-native.md) — guide systemd étendu
