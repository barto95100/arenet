<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# API (OpenAPI)

Tout ce que fait l'interface web passe par l'API REST d'Arenet, et cette API est documentée : une description **OpenAPI 3.1** de toutes ses opérations est embarquée dans le binaire (depuis la v2.39).

## La consulter

- **Dans Arenet** : barre latérale → **Documentation API** (`/api-docs`). Les opérations sont regroupées par thème avec une recherche ; chacune montre son rôle, ses paramètres, le corps de la requête (champs, types, obligatoire / lecture seule / écriture seule, exemple) et les réponses.
- **En fichier** : `GET /api/v1/openapi.json` (tout utilisateur connecté), ou **Télécharger openapi.json** sur la page. Importable dans Postman, Insomnia, Bruno, ou un générateur de clients (`openapi-generator`, `oapi-codegen`…).

Le document correspond toujours au binaire qui tourne : un test de la CI d'Arenet échoue si un endpoint existe sans documentation, et il vérifie le rôle de chaque opération par rapport au vrai contrôle d'accès.

## L'appeler depuis un script

1. **Utilisateurs → + Créer un service account** : un nom, un rôle (`viewer` pour la lecture seule, `admin` pour modifier) et éventuellement une expiration. Le jeton (`arn_…`) n'est affiché **qu'une fois** — range-le dans ton gestionnaire de secrets.
2. Envoie-le en jeton « bearer » :

```bash
TOKEN=arn_xxxxxxxx
curl -s -H "Authorization: Bearer $TOKEN" https://arenet.example.com:8001/api/v1/routes | jq '.[].host'
```

Port de l'API d'administration : `8001` (sur `127.0.0.1` par défaut — voir [Installation](Installation-FR)). **Rotation** crée un nouveau jeton ; supprimer le compte de service le révoque.

À savoir :

- **Rôles** — chaque opération indique son rôle minimum : `public`, `viewer` ou `admin`. Un viewer qui appelle une opération admin reçoit `403 {"error":"admin role required"}`.
- **Erreurs** — `{"error": "...", "code"?: "...", "params"?: {...}}` ; `code` est stable quand il est présent (ex. `route_check_rolled_back`, `seclang_invalid`).
- **Les modifications rechargent Caddy** — une configuration refusée par Caddy est annulée et renvoyée en erreur.
- **`PUT /routes/{id}` remplace la route** : les champs omis ne sont pas tous conservés (`aliases`, en-têtes, règles par chemin, pages d'erreur…). Depuis la v2.39, `disabled` et `maintenanceConfig` sont conservés s'ils sont omis. La méthode sûre reste **GET → modifier → PUT** avec l'objet complet.
- **Limitation** sur `/auth/*` par IP : 5 échecs en 5 min bloquent 15 min.

## Essayer

Sur la page **Documentation API**, **Essayer** envoie la requête avec ta session et affiche le statut et la réponse JSON. Une requête qui modifie (POST, PUT, PATCH, DELETE) demande une confirmation : elle agit sur la configuration réelle.
