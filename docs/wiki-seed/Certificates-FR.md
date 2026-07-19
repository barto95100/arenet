# Certificats

Arenet obtient et renouvelle les certificats TLS **automatiquement** via le moteur Caddy v2 / certmagic embarqué. Un certificat est émis parce qu'une **route** (ou une **politique wildcard par apex**) référence son nom d'hôte — il n'y a donc pas d'action « créer un certificat ». Depuis la **v2.16.0**, la page `/certs` a un bouton **Supprimer** pour retirer un certificat dont tu n'as plus besoin ; cette page explique comment il fonctionne, et la procédure manuelle sur disque pour les cas que le bouton bloque volontairement.

---

## Comment les certificats sont gérés

- Les certificats sont **émis et renouvelés automatiquement** par certmagic. Tu ne les crées jamais à la main : active TLS sur une route (challenge `http-01` ou `dns-01`), ou définis une politique wildcard par apex, et Arenet génère la config Caddy correspondante pour qu'ACME obtienne le certificat.
- La page `/certs` est un tableau de bord état/expiration avec un drill-down dans les événements cert, **plus une action Supprimer par ligne** (v2.16.0). Il n'y a pas de bouton forcer-le-renouvellement ni révoquer.
- La suppression de certificat est exposée via `DELETE /api/v1/certificates/{domain}` (admin uniquement) ; `GET /api/certificates` reste la source de données du tableau de bord.
- Arenet ne conserve **aucun enregistrement de certificat dans sa base**. Le cycle de vie des certs vit entièrement sur disque dans le store certmagic ; Arenet n'en garde qu'une vue en mémoire, reconstruite depuis le disque à chaque démarrage.

---

## Supprimer un certificat depuis l'UI

Sur la page `/certs`, chaque ligne de certificat a un bouton **Supprimer**. Clique dessus, confirme, et Arenet retire les fichiers du certificat sur disque (`.crt`/`.key`/`.json`, pour tous les émetteurs) et efface sa ligne — sans accès serveur ni redémarrage.

**Orphelins uniquement.** Un certificat ne peut être supprimé que si **plus rien ne référence son domaine**. Si une route (host ou alias — y compris une route *désactivée*) ou un wildcard managed-domain utilise encore le nom d'hôte, la suppression est **bloquée** et un dialogue liste la/les route(s) qui gênent. Supprime ou désactive-les d'abord, puis supprime le certificat.

Pourquoi bloquer ? Supprimer un certificat dont le nom d'hôte est encore servi ferait juste **ré-émettre** le cert par Caddy au prochain reload (une nouvelle requête ACME — et, si tu es proche de la limite Let's Encrypt, une boucle d'échec). Retirer un *orphelin* est sûr : rien ne le sert, donc rien ne le redemande.

- **Pas de révocation.** La suppression retire uniquement les fichiers locaux ; elle ne **révoque pas** le certificat auprès du CA (il reste techniquement valide jusqu'à expiration). La révocation n'est pas proposée dans l'app.
- Les **wildcards** sont traités pareil — la ligne `/certs` de `*.example.com` supprime le matériel `wildcard_.example.com`, et est bloquée tant que la politique wildcard par apex qui la gère est active.
- Le certificat supprimé est évincé du cache mémoire de Caddy par le même reload, donc il cesse d'être servi immédiatement.

Si le certificat que tu veux supprimer est **encore référencé** (ex. tu veux forcer une ré-émission propre pour une route *active* sans supprimer la route), le bouton le bloquera — utilise la procédure manuelle sur disque ci-dessous.

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

## Procédure de nettoyage manuel (cas avancés / bloqués)

Le bouton Supprimer de l'UI (ci-dessus) est le chemin normal et couvre les certificats orphelins. N'utilise cette procédure manuelle que pour les cas que le bouton bloque volontairement — principalement **forcer une ré-émission propre pour un domaine encore servi** (encore référencé par une route active ou une politique wildcard active). Deux étapes : arrêter de le servir, puis supprimer les fichiers.

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

Si tu supprimes une route mais gardes son certificat, le certificat devient un **orphelin sur le disque** : inoffensif (Caddy ne le sert plus), mais il occupe toujours de l'espace et garde ses références de compte ACME. Sa ligne `/certs` propose maintenant le bouton **Supprimer** (c'est un orphelin, donc la suppression est autorisée) — c'est le moyen en un clic de le récupérer. L'Étape 2 manuelle ci-dessus reste disponible si tu préfères opérer directement sur le store.

---

## Certificats externes / uploadés (v2.19.0)

Tout ce qui précède concerne les certificats qu'Arenet **obtient et renouvelle lui-même** via ACME. Depuis la **v2.19.0**, tu peux aussi **uploader un certificat que tu possèdes déjà** — émis par un CA externe (DigiCert, une PKI d'entreprise, un CA non-ACME ou en air-gap) — et le servir sur une route **sans ACME**. C'est le SOCLE de l'histoire cert externe : upload + service + une alerte d'expiration. Il n'y a pas encore de génération de CSR intégrée ni de renouvellement automatique.

### Ce que c'est

Un **certificat externe** est un certificat leaf + sa chaîne + sa clé privée, en PEM, que tu colles dans Arenet. Arenet parse le leaf au moment de l'upload pour afficher son émetteur, son sujet, son numéro de série, ses algorithmes de clé/signature, sa fenêtre de validité (`notBefore`/`notAfter`) et sa liste de SAN, puis stocke le matériel et le sert sur n'importe quelle route que tu pointes dessus. Contrairement aux certs ACME (qui vivent seulement dans le store certmagic sur disque), les certs externes sont un **enregistrement dans la base d'Arenet** — la carte **Certificats externes** de la page `/certs` les liste.

### Comment uploader

1. Barre latérale → **Certificates** (`/certs`) → carte **Certificats externes** → **+ Uploader un certificat**
2. Donne-lui un **nom** (et une description optionnelle)
3. Colle les trois blocs PEM :
   - **Certificat** — le certificat de ton domaine, le « leaf » (ex. `your_domain.crt` / `cert.pem` / `fullchain.pem`, public)
   - **Chaîne** — le/les certificat(s) intermédiaire(s) du CA reliant ton leaf à une racine de confiance (ex. `intermediate.crt` / `ca-bundle.crt` / `chain.pem`, public ; optionnel si ton leaf est émis directement)
   - **Clé privée** — la clé correspondante générée avec ton CSR (ex. `your_domain.key` / `privkey.pem`)
4. **Uploader**

> **Raccourci fullchain (v2.19.1).** Beaucoup de CA (quel que soit le fournisseur) te donnent un seul fichier **« fullchain »** avec plusieurs blocs `-----BEGIN CERTIFICATE-----` — le leaf en premier, puis les intermédiaires. Colle simplement tout le fichier dans **Certificat** et laisse **Chaîne** vide : Arenet sépare automatiquement le leaf des intermédiaires. Fournir une chaîne à la fois dans le champ Certificat (en fullchain) ET dans le champ Chaîne est rejeté (`chain_specified_twice`) pour éviter une chaîne dupliquée.

Arenet valide le matériel avant de le stocker. Les erreurs **bloquantes** rejettent l'upload : le PEM du leaf ne parse pas, le PEM de la chaîne ne parse pas, ou la **clé privée ne correspond pas au certificat**. Les avertissements **non bloquants** sont remontés mais laissent quand même sauvegarder — le cert est déjà expiré, pas encore valide (tu peux préparer un cert en avance d'une bascule), signé avec un algorithme faible (SHA-1 / MD5), ou la chaîne semble incomplète. Un PEM en CRLF collé depuis un outil Windows est normalisé automatiquement.

> **La clé privée est en écriture seule.** Après l'upload, elle n'est **plus jamais affichée** — les réponses API la masquent, et elle est exclue des snapshots de backup sauf `--include-secrets` explicite. Quand tu édites un cert, laisser le champ clé vide conserve la clé stockée ; le seul moyen de changer la clé est d'en coller une nouvelle.

### Le renouvellement est MANUEL

Arenet ne renouvelle **PAS** automatiquement un certificat uploadé — il n'y a pas de compte ACME derrière, donc rien ne se renouvelle tout seul. C'est **à toi** de ré-uploader un cert frais avant que l'ancien expire.

Pour ne pas être pris de court, configure la règle d'alerting **`cert_manual_expiring`** :

1. **Settings → Alerting → + Règle**
2. Source : **`cert_manual_expiring`**
3. Seuil : alerter **N jours** avant `notAfter` (défaut **30**)
4. Route-la vers ton canal (Discord / webhook / email) comme n'importe quelle règle

La règle se déclenche **une fois par transition** (edge-triggered) quand un cert uploadé passe sous le seuil — pas à chaque poll. Quand ton CA émet le cert renouvelé, **ré-uploade-le** : édite le cert externe et colle le nouveau leaf (+ chaîne + clé). Arenet le re-parse et la nouvelle fenêtre de validité prend effet au reload suivant.

### Lier un certificat à une route

Un cert uploadé n'est servi que si une route le référence :

1. Édite une route → zone **TLS / Cert Source** → **Cert Source = Manual**
2. Choisis le certificat uploadé dans la liste

Seuls les certificats dont le **SAN couvre le host de la route** sont proposés. Le match est exact ou **wildcard à un label** (RFC 6125) : un cert avec le SAN `*.example.com` couvre `app.example.com` mais **pas** `sub.app.example.com` ni le `example.com` nu. Voir [Routes](Routes-FR#cert-source-acme--internal--manual) pour le sélecteur Cert Source.

### Cert externe wildcard vs wildcard ACME

Un cert **externe** wildcard est juste un cert dont la liste de SAN contient `*.example.com`. Contrairement à un **apex managé ACME** (qui couvre automatiquement chaque route sous-domaine dessous), un wildcard externe n'a **aucune couverture automatique** : chaque route qui le veut doit le référencer **explicitement** via Cert Source = Manual. Un même cert externe (wildcard ou multi-SAN) peut être référencé par autant de routes que ses SAN en couvrent — il n'y a simplement pas de magie « managed domain » ; tu câbles chaque route toi-même.

### Supprimer un certificat externe

Supprime un cert externe depuis sa ligne sur la carte **Certificats externes**.

- **Les certs référencés sont bloqués (409).** Si une route en mode **Manual** pointe encore sur le cert, la suppression est refusée et le dialogue liste le/les host(s) de route qui bloquent. Change d'abord la Cert Source de ces routes (ou supprime-les).
- **Supprimer ≠ révoquer.** Retirer le cert d'Arenet ne fait que retirer le matériel stocké ; ça ne le **révoque PAS** auprès du CA. Si tu dois faire révoquer le certificat (compromission de clé, mauvaise émission), fais-le sur le **portail de ton CA** — cohérent avec la suppression de cert ACME qui, elle aussi, ne révoque jamais.

---

## Voir aussi

- [Routes](Routes-FR) — activer TLS + choisir le challenge HTTP-01 / DNS-01, et la Cert Source Manual
- [DNS Providers](DNS-Providers-FR) — requis pour les certificats DNS-01 / wildcard
- [Backup & Restore](Backup-Restore-FR) — les fichiers cert ne sont **pas** dans le snapshot JSON ; ils vivent dans le store certmagic sur disque
- [Troubleshooting](Troubleshooting-FR) — diagnostiquer les échecs de renouvellement / d'émission
