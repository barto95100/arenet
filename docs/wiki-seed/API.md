<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# API (OpenAPI)

Everything the web UI does goes through Arenet's REST API, and the API is documented: an **OpenAPI 3.1** description of all its operations ships inside the binary (since v2.39).

## Read it

- **In Arenet**: sidebar → **API docs** (`/api-docs`). Operations are grouped by theme with a search box; each one shows its role, parameters, request body (fields, types, required / read-only / write-only, example) and responses.
- **As a file**: `GET /api/v1/openapi.json` (any signed-in user), or **Download openapi.json** on the page. Import it into Postman, Insomnia, Bruno, or a client generator (`openapi-generator`, `oapi-codegen`…).

The document always matches the running binary: a test in Arenet's CI fails if an endpoint exists without documentation, and it checks each operation's role against the real access control.

## Call it from a script

1. **Users → + Create service account**: choose a name, a role (`viewer` for read-only, `admin` to change things) and optionally an expiry. The token (`arn_…`) is shown **once** — store it in your secret manager.
2. Send it as a bearer token:

```bash
TOKEN=arn_xxxxxxxx
curl -s -H "Authorization: Bearer $TOKEN" https://arenet.example.com:8001/api/v1/routes | jq '.[].host'
```

Admin API port: `8001` (on `127.0.0.1` by default — see [Installation](Installation)). Rotate a token with **Rotate**; deleting the service account revokes it.

Good to know:

- **Roles** — each operation shows its minimum role: `public`, `viewer` or `admin`. A viewer calling an admin operation gets `403 {"error":"admin role required"}`.
- **Errors** — `{"error": "...", "code"?: "...", "params"?: {...}}`; `code` is stable when present (e.g. `route_check_rolled_back`, `seclang_invalid`).
- **Changes reload Caddy** — a configuration Caddy refuses is rolled back and returned as an error.
- **`PUT /routes/{id}` replaces the route**: fields you omit are not all kept (`aliases`, headers, path rules, error pages…). Since v2.39, `disabled` and `maintenanceConfig` are kept when omitted. The safe pattern stays **GET → change → PUT** with the whole object.
- **Rate limit** on `/auth/*` per client IP: 5 failures in 5 min block 15 min.

## Try it

On the **API docs** page, **Try it** sends the request with your current session and shows the status and the JSON response. A request that changes something (POST, PUT, PATCH, DELETE) asks for confirmation first: it acts on the real configuration.
