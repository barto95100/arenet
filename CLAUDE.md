# Arenet — Project Context for Claude Code

## What is Arenet

Arenet is a **homelab-friendly reverse proxy with integrated security**, built on **Caddy v2 embedded as a library**. It combines Caddy's production-grade HTTP engine with a homelab-friendly admin UI (in the spirit of Zoraxy / NGINX Proxy Manager) and native security integrations (WAF, IP reputation, country blocking, rate limiting, SSO) usually found only in commercial products.

**Status**: in production use, single-developer project. Current line is **v2.x** (see `git tag --sort=-v:refname | head`). v1.0.0 was the first production release (2026-06-02), v2.0.0 added the alerting subsystem (2026-06-16).

**License**: AGPL-3.0. Every Go and TypeScript source file MUST include the AGPL header (see below).

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  Arenet (single Go binary, ~100 MB)                        │
├────────────────────────────────────────────────────────────┤
│  Web UI — SvelteKit 5 static build, embedded (web/embed.go)│
│   routes, certs, topology (@xyflow/svelte), logs, map (D3),│
│   WAF, security/CrowdSec, alerting, audit, users, settings │
│                       │                                    │
│  REST API + WebSocket — chi/v5 router, gorilla/websocket   │
│   (internal/api, admin on :8001, 127.0.0.1 by default)     │
│                       │                                    │
│  Services: auth (local + OIDC, RBAC, service accounts),    │
│   audit, alerting watcher, automation, backup, certinfo,   │
│   observability, geoipupdate, systemhealth, updatecheck    │
│                       │                                    │
│  Storage — BoltDB (go.etcd.io/bbolt), boot migrations      │
│                       │                                    │
│  Caddy Manager (internal/caddymgr) — routes → Caddy JSON,  │
│   graceful reload via caddy.Load()                         │
│                       │                                    │
│  Caddy v2 (embedded) + coraza-caddy/CRS v4 (WAF)           │
│   + caddy-crowdsec-bouncer + caddy-ratelimit               │
│   + caddy-dns/ovh (DNS-01) + Arenet custom modules         │
│   (metrics, countryblock, waf sink, caddyhc)               │
└────────────────────────────────────────────────────────────┘
```

## Tech Stack

### Backend (Go 1.25+)

- **HTTP engine**: Caddy v2 (`github.com/caddyserver/caddy/v2`) embedded as library, NEVER as an external process
- **WAF**: `github.com/corazawaf/coraza-caddy/v2` + `coraza-coreruleset/v4` (OWASP CRS v4)
- **CrowdSec**: `github.com/hslatman/caddy-crowdsec-bouncer` + `go-cs-bouncer` (LAPI)
- **Rate limiting**: `github.com/mholt/caddy-ratelimit`
- **DNS-01**: `github.com/caddy-dns/ovh`
- **GeoIP**: MaxMind GeoLite2 (`github.com/maxmind/geoipupdate/v8` for auto-update)
- **SSO**: `github.com/coreos/go-oidc/v3`; password hashing `alexedwards/argon2id`
- **Storage**: BoltDB (`go.etcd.io/bbolt`)
- **HTTP router (admin API)**: `github.com/go-chi/chi/v5`
- **WebSocket**: `github.com/gorilla/websocket`
- **Logging**: `log/slog`
- **Config**: flags + `ARENET_*` env vars (documented in `docs/operations/env-vars.md`)

### Frontend

- **Framework**: SvelteKit (Svelte 5 runes) + TypeScript strict
- **Build**: `@sveltejs/adapter-static`, embedded in the Go binary via `embed.FS`
- **Styling**: Tailwind CSS (OKLCH tokens, dark + light themes)
- **Topology graph**: `@xyflow/svelte` (custom nodes/edges in `routes/topology/_components/`)
- **Threat map / charts**: D3.js + topojson
- **HTML editor** (error templates): CodeMirror 6
- **i18n**: FR + EN in `lib/i18n/locales/`; the parity test (`lib/i18n/index.test.ts`) must pass — every new key goes into BOTH locales
- **Tests**: Vitest + `@testing-library/svelte` + jsdom
- **State**: Svelte stores / `.svelte.ts` rune stores in `lib/stores/`

## Project Structure

```
arenet/
├── cmd/arenet/            # main.go + wiring adapters, CLI subcommands (backup, healthcheck)
├── internal/
│   ├── caddymgr/          # Caddy lifecycle + config translation (manager.go = core)
│   ├── api/               # REST handlers (+ api/topology snapshot)
│   ├── storage/           # BoltDB CRUD + migrations (routes.go, migrate.go)
│   ├── auth/              # users, sessions, OIDC, RBAC, login rate limit
│   ├── audit/             # config-change audit log
│   ├── alerting/          # rules, channels (webhook/email/discord), watcher
│   ├── automation/        # CrowdSec auto-classify loop
│   ├── backup/            # export/import with secret sentinels
│   ├── caddyhc/           # health-check status tracker
│   ├── certinfo/          # cert lifecycle tracking + events
│   ├── countryblock/      # Caddy module: per-route GeoIP gate
│   ├── crowdsec/          # LAPI client + bouncer integration
│   ├── geo/ geoipupdate/  # MaxMind reader (hot-swappable) + updater
│   ├── metrics/           # per-route counters, Caddy middleware
│   ├── observability/     # WAF / rate-limit / auth / cert event store
│   ├── ratelimit/ throttle/ waf/ systemhealth/ updatecheck/ config/
├── web/
│   ├── embed.go           # embeds web/frontend/build
│   └── frontend/src/{routes,lib/{api,components,stores,i18n,ws,utils}}
├── packaging/systemd/     # install.sh + unit
├── Dockerfile, docker-compose.yml
├── docs/                  # see "Documentation map" below
├── .github/workflows/     # ci.yml, release.yml, wiki-sync.yml
└── Makefile
```

## Coding Conventions

### Go

- **Format**: `gofmt -s` clean, must pass `go vet ./...`; should pass `staticcheck ./...`
- **Tests**: `go test -race -count=1 ./...` is the CI gate (race detector mandatory). Test files alongside sources.
- **Errors**: wrap with `fmt.Errorf("context: %w", err)`; never `panic` outside `main`
- **Logging**: `slog` everywhere, never `fmt.Println` for runtime logs
- **No magic numbers**: well-named package-level constants
- **Context propagation**: I/O functions take `ctx context.Context` first
- **No global state**: dependencies passed via constructors / setters on the manager
- **Schema changes**: a new `storage.Route` field must be handled on BOTH axes — storage (JSON tag, migration if needed, backup/restore) AND API/UI (wire shape, validation, frontend types). See ENGINEERING-PRACTICES Lesson 8.

### Frontend

- TypeScript strict; components in PascalCase (`RouteList.svelte`)
- Stores in `lib/stores/`; API calls centralized in `lib/api/` (`client.ts` + one module per domain)
- No CSS framework beyond Tailwind; all interactive elements carry ARIA labels
- UI strings go through i18n (FR + EN), never hard-coded

### Git

- **Branches**: `feature/short-description`, `fix/short-description`
- **Commits**: conventional prefix + imperative mood, ≤72-char subject (`feat(topology): …`, `fix(ip-filter): …`, `docs(…): …`)
- **Versioning**: semver tags `vX.Y.Z` on `main` after the PR merges (minor = feature, patch = fix)
- **Co-author**: when Claude Code makes substantial contributions, include it in the commit footer

## Development workflow

Non-trivial work follows this cycle (look at recent history for examples):

1. **Brainstorm** with the operator → decisions locked.
2. **Spec**: `docs/superpowers/specs/YYYY-MM-DD-<topic>-design.md` (decisions table, non-goals, empirical validation gates, target version).
3. **Plan**: `docs/superpowers/plans/YYYY-MM-DD-<topic>.md` (task-by-task).
4. **Implementation** commits, then a **docs/smoke** commit (`docs/smoke-test-*.md`, wiki-seed if user-facing).
5. PR → merge → tag. The operator dogfoods on the test host; visual changes often iterate (e.g. topology v2.24.0 → v2.24.1 → v2.25.0).

Before any root-cause claim or non-trivial fix, read **`docs/ENGINEERING-PRACTICES.md`** (triangulate from 3+ sources, timestamp test actions, read library source, empirical probes over speculation).

## AGPLv3 Header

**EVERY Go source file** must start with this header (replace year as needed):

```go
// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.
```

For TypeScript/JavaScript files, use the equivalent `//` comment block. Markdown docs use a short HTML-comment header.

## What Claude Code Should Do

1. **Always include the AGPL header** on every Go and TypeScript file
2. **Respect the project structure** above; justify any new directory
3. **Generate working, compilable code** — no pseudo-code, no stubs, no non-compiling `// TODO`
4. **Verify often**: `go build ./... && go vet ./...`, `go test -race ./<pkg>/...`; frontend `npm run check && npm test`
5. **Write tests** for non-trivial logic
6. **Doc-comment every exported identifier**
7. **Match Caddy's actual API**: emit valid Caddy JSON (https://caddyserver.com/docs/json/); runtime behaviour per §Empirical verification
8. **Be conservative with deps**: stdlib first, then well-known libs; AGPL-compatible licenses only
9. **Preserve non-regression**: a route without the new feature must produce byte-identical Caddy config / identical UI (tests usually assert this)

## What Claude Code Should NOT Do

- Launch Caddy as a subprocess — it is embedded
- Use `panic()` in non-test code outside `main`
- Copy code from Zoraxy (different license/architecture)
- Introduce React, Vue or other frontend frameworks
- Suggest non-AGPL-compatible deps
- Fabricate API endpoints or library functions — verify they exist in the actual lib

## Empirical verification of external dependencies

Any claim about the runtime behaviour of an external dependency (Caddy, Coraza, CRS, certmagic, @xyflow/svelte, etc.) must be verified empirically before it is treated as settled — either by reading upstream source with an explicit `file:line` citation, or by a targeted test harness demonstrating the invariant. An unverified "I assume X does Y" is a latent finding until proven.

Background: the Step I.7 smoke caught five bugs (Findings #2, #4, #6, #7, #8) that all stemmed from audit-time inferences about Caddy or Coraza behaviour that proved wrong against a real binary. See `docs/smoke-test-step-i.md` §3 and `docs/backlog-step-j.md` §1.

Mitigation pattern: `caddy.Validate()` on emitted JSON (`TestBuildConfigJSON_LoadsCleanly*` in `internal/caddymgr/manager_test.go`) + handler-ID resolvability (`TestBuildConfigJSON_HandlersAllResolvable`). Extend this pattern to any new Caddy-facing config.

## Build & Run

```bash
# Full build (frontend + backend)
make build            # → bin/arenet
make run              # dev mode, data in ./data

# Manually
cd web/frontend && npm ci && npm run build
cd ../.. && go build -o arenet ./cmd/arenet

# Frontend dev server (alongside `make run`)
make dev-frontend     # Vite on :5173

# Tests
make test                               # go test -race -count=1 ./...
cd web/frontend && npm run check && npm test
```

## Documentation map

- `docs/roadmap.md` — shipped history + open backlog
- `docs/ENGINEERING-PRACTICES.md` — diagnostic lessons (load-bearing)
- `docs/superpowers/{specs,plans,decisions}/` — design specs, implementation plans, decision records
- `docs/smoke-test-*.md` — per-feature smoke procedures and verdicts
- `docs/backlog-*.md` — historical per-step backlogs
- `docs/install/`, `docs/operations/` — operator docs (Docker, systemd, env vars, hardening, HTTP/3)
- `docs/wiki-seed/` — GitHub wiki source (EN + FR), synced by `wiki-sync.yml`
- `docs/api/topology.md` — topology snapshot contract

## Useful Links

- Caddy library docs: https://pkg.go.dev/github.com/caddyserver/caddy/v2
- Caddy JSON config schema: https://caddyserver.com/docs/json/
- Coraza Caddy: https://github.com/corazawaf/coraza-caddy
- CrowdSec Caddy bouncer: https://github.com/hslatman/caddy-crowdsec-bouncer
- SvelteKit static adapter: https://kit.svelte.dev/docs/adapter-static
- Svelte Flow: https://svelteflow.dev
