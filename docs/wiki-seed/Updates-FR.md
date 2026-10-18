# Mettre à jour Arenet

[English](Updates) · **🌐 Français**

Arenet est livré comme un binaire / image de conteneur unique. **La mise à jour est une action manuelle, pilotée par l'opérateur** — Arenet ne télécharge ni n'installe jamais une mise à jour tout seul. Le [vérificateur de mises à jour opt-in](DNS-Providers-FR#rester-à-jour) (v2.12.3) ne fait que te *notifier* qu'une version stable plus récente existe ; cette page explique comment effectuer la mise à niveau, en toute sécurité.

> **Pourquoi pas d'auto-update ?** Voir [Notes de sécurité](#notes-de-sécurité) ci-dessous. En bref : auto-mettre à jour un reverse proxy revient à donner à un service exposé au réseau le privilège d'écraser son propre binaire et de se redémarrer — une grande surface d'attaque et un risque supply-chain. Comme nginx, Traefik, Caddy et Postgres, Arenet te laisse la décision (et le timing) de la mise à niveau.

---

## 0. Avant de commencer : vérifie ta version actuelle

Il n'y a **pas de flag `--version`**. Lis la version en cours via l'un de :

- **UI** — *Réglages → Mises à jour* affiche la version actuelle (et la dernière disponible, si le checker est activé).
- **API** — `GET /api/v1/system/version` (session admin) → `{"current": "vX.Y.Z", ...}`.
- **Logs** — `journalctl -u arenet | grep "Arenet starting" | tail -1` (systemd) ou `docker logs arenet 2>&1 | grep "Arenet starting" | tail -1` (Docker). La dernière ligne montre la version en cours (`version=vX.Y.Z`).

Compare avec la [dernière release](https://github.com/barto95100/arenet/releases/latest).

**Règle d'or :** fais un backup avant chaque mise à niveau. UI : *Backup → Exporter*. Voir [Backup & Restore](Backup-Restore-FR).

---

## 1. Docker Compose (recommandé)

Si tu déploies avec le `docker-compose.yml` de référence (image `ghcr.io/barto95100/arenet:latest`) :

```bash
cd ~/arenet            # là où vit ton docker-compose.yml
docker compose pull    # récupère la nouvelle image :latest
docker compose up -d   # recrée le conteneur sur la nouvelle image
docker compose logs -f arenet | grep "Arenet starting"   # confirme la nouvelle version
```

Ton état vit dans le volume nommé `arenet-data` (monté sur `/var/lib/arenet`), il survit donc à la recréation du conteneur. Rien d'autre à faire.

**Épingle une version précise** au lieu de `:latest` pour des mises à niveau reproductibles :

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:vX.Y.Z   # choisis un tag sur la page des releases
```
Remplace `vX.Y.Z` par un tag de la [page des releases](https://github.com/barto95100/arenet/releases), puis `docker compose pull`, `docker compose up -d`. Pour passer à une version plus récente ensuite, bump le tag et recommence.

---

## 2. Image Docker (`docker run` standalone)

```bash
docker pull ghcr.io/barto95100/arenet:latest
docker stop arenet && docker rm arenet
docker run -d --name arenet \
  --cap-add=NET_BIND_SERVICE \
  -p 80:80 -p 443:443 -p 443:443/udp -p 127.0.0.1:8001:8001 \
  -v arenet-data:/var/lib/arenet \
  ghcr.io/barto95100/arenet:latest
```

Le volume `arenet-data` porte tes données à travers le remplacement. Garde le **même nom de volume `-v`** et la **cible de montage `/var/lib/arenet`** — c'est là que le binaire lit son état.

---

## 3. Binaire natif + systemd

Télécharge le nouveau binaire de release, vérifie son checksum, remplace-le, redémarre :

```bash
ARCH=linux-amd64        # ou linux-arm64

cd /tmp

# Télécharge le DERNIER binaire stable + son manifeste de checksums.
# L'URL /releases/latest/download/ redirige toujours vers la release
# stable la plus récente — aucun numéro de version à maintenir. Le
# fichier est enregistré sous son nom de release (arenet-linux-amd64)
# pour correspondre à l'entrée dans checksums.txt et que `sha256sum -c`
# le retrouve.
curl -L -o "arenet-${ARCH}" "https://github.com/barto95100/arenet/releases/latest/download/arenet-${ARCH}"
curl -L -o checksums.txt "https://github.com/barto95100/arenet/releases/latest/download/checksums.txt"

# Vérifie l'intégrité (la release publie un manifeste sha256). À lancer
# dans le même dossier que le fichier téléchargé.
grep "arenet-${ARCH}\$" checksums.txt | sha256sum -c -
#   → "arenet-linux-amd64: OK"

# Remplace le binaire (renomme vers le chemin d'install) et redémarre
sudo systemctl stop arenet
sudo mv "arenet-${ARCH}" /usr/local/bin/arenet
sudo chmod +x /usr/local/bin/arenet
sudo chown root:root /usr/local/bin/arenet
sudo systemctl start arenet
sudo systemctl status arenet          # Active: active (running)
sudo journalctl -u arenet | grep "Arenet starting" | tail -1
```

Le dossier de données (`/var/lib/arenet` par défaut) n'est pas touché par un remplacement de binaire.

---

## 4. Rollback

Une mise à niveau est réversible tant que tu n'as pas franchi un bump MAJOR de schéma (voir [§5](#5-sûreté-de-migration)).

**Docker Compose / run** — ré-épingle le tag d'image précédent et recrée. Remplace `vPREV` par la version où tu étais avant la mise à niveau (dans ton historique shell, ou sur la [page des releases](https://github.com/barto95100/arenet/releases)) :
```bash
docker pull ghcr.io/barto95100/arenet:vPREV
# remets le tag d'image du compose à :vPREV, ou relance docker run avec :vPREV
docker compose up -d
```

**Binaire** — garde l'ancien binaire avant d'écraser (`sudo cp /usr/local/bin/arenet /usr/local/bin/arenet.prev` avant l'étape 3), puis :
```bash
sudo systemctl stop arenet
sudo mv /usr/local/bin/arenet.prev /usr/local/bin/arenet
sudo systemctl start arenet
```

Si l'état a été touché et ne charge plus, restaure le backup que tu as pris : [Backup & Restore → Restaurer](Backup-Restore-FR).

---

## 5. Sûreté de migration

- Arenet exécute des **migrations de boot idempotentes** au démarrage (ex. la migration DNS-provider de v2.12.0). Elles sont sûres à ré-exécuter et ne demandent aucune action.
- **Les backups portent une version de schéma** (`SchemaVersion`, MAJOR `1` aujourd'hui). La restauration impose **MAJOR-égal** : un backup d'une génération de schéma différente est rejeté avec un message clair plutôt que de corrompre l'état. À l'intérieur du même MAJOR, restaurer entre versions minor/patch est OK.
- **Règle pratique :** les mises à niveau patch/minor sont drop-in. Avant une mise à niveau **MAJOR**, lis les notes de cette release, prends un backup, et sois prêt à revenir au binaire/image précédent (un backup ne peut être restauré que sur un binaire de même MAJOR).
- **Mise à niveau vers v2.15.1+ (permissions du répertoire de données) :** v2.15.1 resserre le répertoire de données en `0700` (owner-only) car il contient des secrets et des clés privées TLS. Les installs neuves et les mises à niveau standard l'ont automatiquement — le binaire chmod le dir en `0700` au boot. **Aucune action nécessaire** dans le cas courant ; pour confirmer : `stat -c '%a' /var/lib/arenet` → `700`. Si tu tournes Arenet sous un bind mount et que le boot échoue sur le répertoire de données, vois [Installation → Setup du répertoire de données](Installation-FR#setup-du-répertoire-de-données-volume-nommé-vs-bind-mount).
- **Mise à niveau vers v2.30.0+ (secrets chiffrés au repos) :** au premier démarrage, Arenet génère `arenet.key` dans le répertoire de données (mode `0600`) et chiffre tous les secrets stockés dans `arenet.db` — identifiants DNS, clés privées des certificats importés, secrets CrowdSec / MaxMind / OIDC / forward-auth, identifiants des canaux d'alerte, en-têtes de route sensibles — puis réécrit le fichier pour qu'aucune copie en clair ne subsiste. Deux effets visibles : **tout le monde se reconnecte une fois** (les identifiants de session sont désormais stockés hachés), et un WARN demande de **sauvegarder `arenet.key` à part**. Sans la clé les secrets sont irrécupérables, et Arenet refuse de démarrer sur une base chiffrée dont la clé manque ou diffère. **Revenir sous v2.30 exige la sauvegarde du répertoire de données faite *avant* la mise à niveau** — un binaire plus ancien ne sait pas lire les secrets chiffrés.

- **Mise à jour vers v2.71.0+ (le port admin bind sur loopback par défaut) :** l'API d'admin écoute désormais sur `127.0.0.1:8001` au lieu de toutes les interfaces, ce qu'avait décidé la spec D6 et ce qu'affirmaient déjà ce wiki, le guide de durcissement et l'aide du flag `--admin-port` du binaire depuis la v1.4 — c'est le défaut qui ne correspondait pas. **Docker n'est pas concerné** (le CMD de l'image passe `--admin-port=:8001`, et un flag bat le défaut ; le compose restreint déjà l'accès avec `127.0.0.1:8001:8001`). **Une installation native/systemd qui atteint l'UI d'admin depuis le LAN va perdre cet accès.** Deux options : y accéder via une route Arenet pointant sur `127.0.0.1:8001` (le loopback fonctionne — Caddy est embarqué dans le même processus), ou déclarer l'exposition explicitement avec `ARENET_ADMIN_BIND=0.0.0.0:8001` dans `/etc/arenet/arenet.env` puis appliquer les points 2 et 3 de la [checklist de durcissement](https://github.com/barto95100/arenet/blob/main/docs/operations/hardening.md). Testez le nouveau chemin **avant** de fermer votre session SSH.
- **Mise à jour vers v2.73.0+ (version de sécurité : six changements de comportement à lire d'abord).** Cette version ferme dix-huit findings issus d'une revue de sécurité de la surface atteignable sans authentification, dont trois classés HIGH. La plupart sont invisibles pour vous, ceux-ci non :

  1. **Le WAF inspecte désormais la poignée de main WebSocket.** Il sautait Coraza entièrement pour toute requête portant `Upgrade: websocket` et `Connection: upgrade` — deux en-têtes fournis par le client, sans contrôle de méthode ni de `Sec-WebSocket-Key` — donc n'importe qui pouvait contourner le WAF sur n'importe quelle route en les ajoutant, sans qu'aucun événement soit émis. La poignée de main est inspectée, et seule la phase de réponse est sautée. **Conséquence :** un faux positif CRS sur une poignée de main peut refuser un WebSocket qui marchait. Les chemins concernés sont Home Assistant `/api/websocket`, Jellyfin, n8n, TeslaMate, Outline. **Passez la route en mode `detect`, regardez le journal d'activité, puis rebasculez en `block`.**
  2. **Le blocage CRS s'applique maintenant sous `/api/v1` sur vos propres routes.** Une exemption CRS destinée au plan d'administration était préfixée au moteur de *chaque* route et indexée sur le chemin de la requête : n'importe quel client pouvait retirer l'évaluateur de score d'anomalie en visant `/api/v1/...`. Elle est désormais limitée à la route qui pointe sur le listener d'admin. **Conséquence :** un upstream qui sert sa propre API sous `/api/v1` — Gitea, n8n, beaucoup d'applis REST — y est réellement inspecté. Même conseil : `detect` d'abord.
  3. **Une règle de chemin garde enfin tout son sous-arbre.** Un préfixe finissant par `/` produisait un matcher Caddy qui ne matchait que le chemin exact : `/admin/` demandait le mot de passe et `/admin/users` passait en clair. **Dans l'autre sens**, une règle portant `DisableRouteAuth` avec un slash final exempte maintenant vraiment son sous-arbre, là où le matcher cassé maintenait l'auth active par accident. Vérifiez vos règles de chemin si vous utilisez cette exemption.
  4. **Un préfixe de chemin contenant `*`, `?`, `[` ou `]` est refusé à l'enregistrement.** Caddy les lit comme de la syntaxe glob, et un `/*` stocké s'étendait à tout le site — sur une règle `DisableRouteAuth`, ça coupait l'authentification de la route partout. Une règle existante avec un tel préfixe continue de fonctionner jusqu'à votre prochaine édition de la route, qui la refusera en expliquant pourquoi.
  5. **Un compte viewer ne lit plus les valeurs des en-têtes de credentials.** `GET /routes` renvoyait les `Authorization`, `X-Api-Key` et en-têtes de sonde de health-check en clair à toute identité authentifiée, y compris le rôle en lecture seule et un token de compte de service en viewer. Les *noms* d'en-têtes restent visibles ; les valeurs sont rédigées pour les non-admins. **Conséquence :** une automatisation qui lit ces valeurs avec un token VIEWER casse. Donnez-lui un token admin, ou arrêtez de lire des secrets depuis la liste des routes.
  6. **Un flux de télémétrie se ferme désormais quand sa session est révoquée.** `/ws/geo-events`, `/ws/topology` et `/topology/stream` étaient autorisés une seule fois à l'upgrade et jamais ensuite : révoquer une session, supprimer le compte ou le verrou inactif de 15 minutes laissaient le socket émettre chaque IP source atteignant votre proxy. Ils revérifient toutes les 30 s. **Conséquence :** un onglet de dashboard laissé inactif au-delà du verrou voit son socket fermé et se reconnecte après déverrouillage.

  **Une action, si elle vous concerne :** si vous avez déjà exporté une sauvegarde alors qu'un canal d'alerte **Discord** était configuré, cette URL de webhook est dans le fichier **en clair** — elle manquait au registre des secrets de sauvegarde, donc même l'export étiqueté « sans secrets » et celui chiffré par passphrase la contenaient. Cette version corrige les exports futurs, pas les fichiers déjà sur votre NAS ou dans un ticket. **Régénérez le webhook** dans Discord → Intégrations → Webhooks.

  Également dans cette version : le signalement privé de vulnérabilités est activé sur le dépôt, et `SECURITY.md` décrit le canal, le périmètre et les délais.

- **Mise à jour vers v2.74.0+ (le reste de la revue de sécurité : durcissement, avec quelques changements de comportement).** Cette version ferme les findings restants de la même revue — les MEDIUM et LOW — surtout du durcissement interne invisible (mémoire et masquage d'identifiants de l'échantillon WAF, bornes de corps de requête contre l'OOM, bornes mémoire du limiteur et du touch de token, un use-after-free du reader geo et une course send-on-closed du bus). Ceux-ci, vous pourriez les sentir :

  1. **Une écriture authentifiée par cookie doit être `Content-Type: application/json`.** Un nouveau garde CSRF sur `/api/v1` refuse une requête mutante qui porte le cookie de session mais un corps `form`/`text/plain` (415), ou que le navigateur étiquette cross-site (403). L'UI web et **les clients bearer / token d'API ne sont pas affectés** (un token n'est pas attaché cross-site). **Conséquence :** un script maison qui pilote l'API admin avec le *cookie de session* et un corps non-JSON casse — donnez-lui un token d'API, ou envoyez du JSON.
  2. **Le changement de mot de passe forcé est désormais imposé par le serveur, pas seulement l'UI.** Un compte créé par un admin encore sur son mot de passe initial est refusé sur tout endpoint sauf le changement de ce mot de passe (403 `password_change_required`). **Conséquence :** si vous pointez une automatisation sur un tel compte, il ne peut rien faire tant que le mot de passe n'est pas changé. Changez-le, ou utilisez un token de compte de service.
  3. **Retirer une entrée de l'allowlist OIDC — ou désactiver OIDC — met fin aux sessions vivantes de cette identité.** Avant, seules les futures connexions étaient bloquées tandis que la session ouverte continuait. **Conséquence :** un utilisateur SSO retiré est déconnecté immédiatement, comme attendu.
  4. **Le login renvoie le même 401 pour un compte OIDC/service que pour un mauvais mot de passe** (il renvoyait 500 pour un compte sans mot de passe local) et exécute désormais la dérivation de clé à chaque échec. **Conséquence :** un monitor qui se basait sur l'ancien 500 verra 401 ; il n'y a rien à exploiter là.
  5. **L'import Caddyfile refuse `import <chemin>` et `{$ENV}`.** Sinon le parseur de Caddy lirait des fichiers de *cet* hôte et substituerait l'environnement de *ce* process, et renverrait les deux dans l'aperçu — une lecture de fichier réservée aux admins. Un import de snippet (`import nom` avec `(nom)` défini dans le même texte) marche toujours ; un import de fichier/glob ou un placeholder d'env est rejeté. **Conséquence :** inlinez-les avant d'importer un Caddyfile qui les utilisait.
  6. **Le blocage par pays s'applique dès la première requête après un redémarrage.** Il y avait une courte fenêtre au boot où une route gatée par pays acceptait tout ; elle est fermée. La suppression de certificat n'accepte désormais qu'un hostname ou `*.domaine`.
  7. **Les routes forward-auth retirent tout le jeu d'en-têtes d'identité avant la vérification IdP.** Avant, seuls les en-têtes que votre provider était configuré pour copier (ses « copy headers ») étaient supprimés de la requête entrante ; un en-tête d'identité conventionnel que votre provider ne copie *pas* — `Remote-Groups`, `Remote-Name`, `X-Authentik-*`, `X-Forwarded-User` — atteignait le backend tel quel. Désormais tout le jeu conventionnel (plus vos copy headers) est retiré sur le chemin gaté, donc seules les valeurs de l'IdP atteignent l'upstream. **Conséquence :** un backend qui faisait confiance à un en-tête d'identité fourni par le client que votre provider ne copiait pas ne voit plus la valeur du client — il n'aurait jamais dû. Concerne les routes forward-auth (p. ex. une app derrière Authentik) ; les valeurs posées par l'IdP sont inchangées.
  8. **Le cookie de session est marqué `Secure` derrière un proxy TLS de confiance.** Il n'obtenait `Secure` que sur une connexion TLS directe (`r.TLS`) ; atteindre l'UI admin via une route HTTPS qui termine le TLS et relaie en clair sur la loopback laissait donc le cookie sans. Arenet le marque maintenant `Secure` quand la requête arrive en HTTPS via un hop de confiance — loopback ou un CIDR dans `ARENET_TRUSTED_PROXIES` — qui a relayé `X-Forwarded-Proto: https` ; le schéma relayé par un appelant non fiable est ignoré. **Conséquence :** rien à faire — l'admin en loopback clair (tunnel SSH, HTTP direct sur 127.0.0.1) marche toujours, et l'accès HTTPS donne désormais un cookie `Secure` comme il se doit.
  9. **Les pages d'erreur / maintenance personnalisées rendent les placeholders de requête bruts littéralement.** `{http.request.uri}`, `{http.request.host}` et `{http.request.uri.path}` reflètent la requête brute du client dans une page servie en HTML — un vecteur de XSS réfléchie — donc ils ne sont plus expansés ; ils s'affichent en texte littéral. La forme URL-échappée de l'URI complète `{http.request.uri_escaped}` est sûre et s'expanse toujours. **Conséquence :** si une page personnalisée utilisait un des jetons bruts, remplacez-le par `{http.request.uri_escaped}`. Les pages par défaut intégrées ne sont pas affectées (elles utilisent déjà la forme échappée).

  **Une action, si elle s'applique à vous :** changez le mot de passe de tout compte créé par un admin encore sur son mot de passe initial utilisé par un script (point 2) — sinon ce compte est maintenant bloqué pour tout sauf le changer.

- **Mise à jour vers v2.74.1+ (deux durcissements de sécurité, aucun comportement que vous utilisez ne change).** Les deux ferment un trou plutôt que de modifier une fonctionnalité :

  1. **L'IP client derrière un proxy de confiance est lue depuis la *droite* de `X-Forwarded-For`.** Si vous mettez AreNET derrière un CDN et listez ses plages dans `ARENET_TRUSTED_PROXIES`, l'IP source utilisée pour le filtre pays/ASN, le limiteur de login et les lignes d'audit est désormais le hop attesté par votre propre infrastructure — pas l'entrée la plus à gauche, fournie par le client, qu'un visiteur pouvait forger. **Conséquence :** concerne uniquement un déploiement derrière CDN ; ces décisions géo / rate-limit / audit reflètent maintenant le vrai client. AreNET en bordure avec le défaut (confiance loopback seule) est inchangé.
  2. **Les canaux d'alerte ne peuvent plus joindre les métadonnées d'instance cloud.** Les senders webhook et Discord — et le bouton Tester — refusent désormais les adresses lien-local / métadonnées (`169.254.169.254`, `fd00:ec2::254`), le même garde-fou que les sondes upstream et health-check. Les webhooks privés et loopback restent joignables. **Conséquence :** aucune, sauf si un canal pointait vers une adresse de métadonnées (ce qui ne devrait pas exister).

  **Aucune action requise.**

- **Mise à jour vers v2.75.0+ (une nouvelle fonctionnalité opt-in : notifications de santé des routes).** Rien ne change pour une route existante — la fonctionnalité est désactivée tant que vous ne l'activez pas. Chaque route a désormais une section **Notifications de santé** : activez-la, choisissez un canal d'alerte, et Arenet prévient ce canal quand les upstreams de la route tombent et quand ils reviennent (avec la durée de la panne), en regroupant les routes qui partagent un même backend en panne, avec un rappel optionnel tant qu'elle reste hors service. **Conséquence :** aucune tant que vous ne l'activez pas ; une route non modifiée se comporte exactement comme avant. Pour l'utiliser il faut au moins un canal d'alerte configuré (Réglages → Alertes), puis le toggle + le canal sur la route.

- **Mise à jour vers v2.75.1+ (correctif de détection de santé).** Avant cette version, un upstream tombé avant le dernier reload pouvait rester affiché **sain** dans l'UI — et les notifications de santé ne partaient pas — car Arenet re-primait chaque upstream health-checké en sain à chaque reload, et le Caddy embarqué (qui conserve la santé des upstreams à travers un reload) n'avait plus de changement d'état à annoncer. La santé est désormais **réconciliée** au reload au lieu d'être resettée-puis-reprimée. **Conséquence :** rien à faire — la mise à jour redémarre Arenet, ce qui rétablit l'état réel dès la première sonde, et les reloads en cours de route ne re-basculent plus un upstream down en vert. Si vous aviez activé les notifications de santé en v2.75.0 et qu'elles semblaient muettes pour un backend down, c'est le correctif.

- **Mise à jour vers v2.75.2+ (l'autre moitié du correctif de détection).** v2.75.1 corrigeait le cas du reload ; ceci corrige le reste : un upstream dont l'URL **omet le port** (ex. `http://10.0.0.5` pour un backend sur le port 80) était suivi sans port, alors que les événements de health-check de Caddy portent toujours l'adresse de dial **avec** le port (`10.0.0.5:80`). L'état down enregistré par l'événement ne rencontrait jamais la clé sans port utilisée par le badge et le notifieur, donc l'upstream restait vert. Les adresses sont désormais canonicalisées en `host:port`. **Conséquence :** rien à faire — un upstream down dont l'URL omet le port est maintenant correctement affiché DOWN et déclenche les notifications de santé. Si les notifications semblaient encore muettes en v2.75.1, c'est pour ça.
---

## 6. Automatisation (CLI-only)

Si tu veux des mises à niveau non-attendues, garde-les **en dehors** d'Arenet — sur ton propre planning, avec tes propres garde-fous :

- **Docker — Watchtower** (ou un cron `docker compose pull && up -d`) : auto-pull des nouvelles images. Préfère un **tag épinglé + bump manuel** en production pour qu'une mise à niveau n'arrive que quand tu le décides.
- **Binaire — timer systemd / cron** : un script qui télécharge la dernière release, **vérifie le checksum**, remplace le binaire et redémarre. Toujours backup d'abord dans le script.
- **Flotte — Ansible** : un rôle templatant la version binaire/image, derrière une revue des notes de release.

Tout ceci tourne sous *ton* contrôle et tes privilèges — pas ceux du reverse proxy.

---

## Notes de sécurité

- **Ne câble PAS un bouton « mettre à jour maintenant », plugin ou hack qui laisserait le process Arenet remplacer son propre binaire.** Cela nécessiterait de donner à un service exposé au réseau un accès en écriture à `/usr/local/bin` (ou à l'image du conteneur) plus la capacité de se redémarrer — un amplificateur d'escalade de privilèges et de RCE si un chemin de download/parse est un jour exploité.
- **Vérifie l'intégrité.** Les releases binaires livrent un `checksums.txt` (sha256). Vérifie-le (§3) avant d'installer. Les releases ne sont **pas** signées GPG/cosign aujourd'hui, donc le checksum + HTTPS depuis GitHub est ton contrôle d'intégrité.
- **Supply chain.** Épingle des versions explicites en production ; relis les notes de release avant de bumper. Un `:latest` aveugle sur chaque host signifie qu'une seule mauvaise release atteint tout le monde d'un coup.
- **Backup avant chaque mise à niveau.** C'est le rollback le moins cher que tu aies. Voir [Backup & Restore](Backup-Restore-FR).
- **Pattern industriel.** nginx, Traefik, Caddy, Postgres — aucun ne s'auto-met à jour via sa propre surface d'admin. Notification + mise à niveau manuelle et contrôlée est la norme pour de l'infrastructure qui termine ton trafic.

---

_Voir aussi : [DNS Providers → Rester à jour](DNS-Providers-FR#rester-à-jour) · [Backup & Restore](Backup-Restore-FR) · [Installation](Installation-FR)_
