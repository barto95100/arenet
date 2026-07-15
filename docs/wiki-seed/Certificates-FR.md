# Certificats

Arenet obtient et renouvelle les certificats TLS **automatiquement** via le moteur Caddy v2 / certmagic embarqué. Un certificat est émis parce qu'une **route** (ou une **politique wildcard par apex**) référence son nom d'hôte — il n'y a donc pas d'action « créer un certificat », ni de bouton « supprimer un certificat ». Cette page explique pourquoi, et donne la procédure manuelle exacte pour supprimer un certificat (HTTP-01 ou DNS-01) quand c'est réellement nécessaire.

---

## Comment les certificats sont gérés

- Les certificats sont **émis et renouvelés automatiquement** par certmagic. Tu ne les crées jamais à la main : active TLS sur une route (challenge `http-01` ou `dns-01`), ou définis une politique wildcard par apex, et Arenet génère la config Caddy correspondante pour qu'ACME obtienne le certificat.
- La page `/certs` est en **lecture seule** (tableau de bord état/expiration avec un drill-down dans les événements cert). Elle n'a **ni bouton supprimer, ni révoquer, ni forcer le renouvellement** — c'est voulu.
- Il n'existe **aucune API `DELETE`** pour les certificats. Le seul endpoint cert est `GET /api/certificates` (la source de données du tableau de bord).
- Arenet ne conserve **aucun enregistrement de certificat dans sa base**. Le cycle de vie des certs vit entièrement sur disque dans le store certmagic ; Arenet n'en garde qu'une vue en mémoire, reconstruite depuis le disque à chaque démarrage.

**Conséquence :** supprimer une route (ou une politique par apex) arrête de **servir** le certificat (Caddy ne référence plus son nom d'hôte) et retire sa ligne de `/certs` — mais les **fichiers du certificat restent sur le disque**. Pour les supprimer physiquement, tu dois les effacer sur le serveur puis redémarrer Arenet.

---

## Pourquoi il n'y a pas de bouton « supprimer un certificat »

C'est un choix de conception délibéré, pas un oubli :

- **Caddy v2 n'émet aucun événement de suppression de certificat**, donc Arenet ne peut pas réagir de façon fiable à une suppression dans le processus.
- L'approche « supprimer les fichiers et laisser ACME ré-obtenir » introduit une **fenêtre de coupure** au prochain handshake TLS, et a été explicitement rejetée comme action automatisée dans l'app à cause de ce risque en production.

La suppression d'un certificat reste donc une **opération manuelle, délibérée, sur le disque** — décrite ci-dessous.

---

## Où vivent les certificats sur le disque

certmagic stocke les certificats dans le répertoire de données de Caddy, résolu depuis le `$HOME` du processus (`$XDG_DATA_HOME/caddy` ou `$HOME/.local/share/caddy`). Sur une install Arenet standard (`$HOME = /var/lib/arenet`), c'est :

```
/var/lib/arenet/.local/share/caddy/certificates/
  <émetteur>/                       ex. acme-v02.api.letsencrypt.org-directory
    <domaine>/                      ex. app.example.com
      <domaine>.crt                 leaf + chaîne
      <domaine>.key                 clé privée
      <domaine>.json                métadonnées certmagic
```

À noter :
- Les **wildcards** sont stockés sous `wildcard_.example.com/` (pour `*.example.com`).
- Le répertoire `<émetteur>` est l'hôte du répertoire ACME (Let's Encrypt production = `acme-v02.api.letsencrypt.org-directory` ; staging et ZeroSSL ont les leurs).
- Le chemin est **identique pour HTTP-01 et DNS-01** — le type de challenge ne change pas l'emplacement de stockage, donc la procédure de nettoyage est la même pour les deux.

---

## Procédure de nettoyage manuel

À faire uniquement quand tu veux réellement supprimer le certificat (ex. domaine décommissionné, ou tu veux forcer une ré-émission propre). Deux étapes : arrêter de le servir, puis supprimer les fichiers.

### Étape 1 — arrêter de servir le certificat (dans l'app)

Supprime l'objet qui référence le nom d'hôte :
- une **route** → Sidebar → **Routes** → supprime la route, **ou**
- une **politique wildcard par apex** → page `/certs` → « Politiques wildcard par apex » → supprime l'apex.

Ça retire le nom d'hôte de la config Caddy émise (Caddy arrête de servir ce cert) et efface sa ligne de `/certs`. **Les fichiers sont toujours sur le disque après cette étape.**

### Étape 2 — supprimer les fichiers sur le disque et redémarrer

Choisis selon ton déploiement.

**Install systemd / binaire** (`$HOME = /var/lib/arenet`) :

```bash
# Liste d'abord ce qui est présent — confirme les noms exacts émetteur + domaine.
sudo ls /var/lib/arenet/.local/share/caddy/certificates/*/

# Supprime le répertoire du domaine (adapte l'émetteur + le domaine).
sudo systemctl stop arenet
sudo rm -rf "/var/lib/arenet/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/app.example.com"
sudo systemctl start arenet

# Pour un wildcard *.example.com, le répertoire est wildcard_.example.com :
# sudo rm -rf ".../certificates/acme-v02.api.letsencrypt.org-directory/wildcard_.example.com"
```

**Docker** (conteneur `arenet`, volume nommé `arenet-data` monté sur `/var/lib/arenet`) :

L'image runtime est **distroless — elle n'a pas de shell**, donc `docker exec arenet ls/rm …` ne **fonctionne pas**. Opérez sur le volume nommé via un conteneur `alpine` jetable :

```bash
# Inspecte
docker run --rm -v arenet-data:/data alpine \
  ls /data/.local/share/caddy/certificates/

# Supprime le dossier du domaine, puis redémarre pour qu'Arenet relise le disque nettoyé au boot
docker compose stop arenet
docker run --rm -v arenet-data:/data alpine \
  rm -rf "/data/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/app.example.com"
docker compose start arenet
```

Au redémarrage, la reconciliation au boot d'Arenet reconstruit le tableau de bord `/certs` depuis le store (maintenant nettoyé), donc le certificat supprimé disparaît de l'UI.

> ⚠️ Ne supprime que le répertoire du **domaine** que tu veux retirer. Ne supprime pas tout l'arbre `certificates/` sauf si tu veux ré-émettre **tous** les certificats depuis zéro (ça déclenche de nouvelles requêtes ACME pour chaque nom d'hôte servi au prochain handshake — attention aux limites de débit Let's Encrypt).

---

## Certificats « orphelins »

Si tu supprimes une route mais sautes l'Étape 2, le certificat devient un **orphelin sur le disque** : inoffensif (Caddy ne le sert plus, il n'apparaît plus dans `/certs`), mais il occupe toujours de l'espace et garde ses références de compte ACME. Fais l'Étape 2 quand tu veux récupérer cet état.

---

## Voir aussi

- [Routes](Routes-FR) — activer TLS + choisir le challenge HTTP-01 / DNS-01
- [DNS Providers](DNS-Providers-FR) — requis pour les certificats DNS-01 / wildcard
- [Backup & Restore](Backup-Restore-FR) — les fichiers cert ne sont **pas** dans le snapshot JSON ; ils vivent dans le store certmagic sur disque
- [Troubleshooting](Troubleshooting-FR) — diagnostiquer les échecs de renouvellement / d'émission
