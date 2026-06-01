# Step S — Production deployment (Docker + systemd + hardening)

**Status**: FROZEN 2026-06-01 — 9 decisions arbitrated (D1=A, D2=A, D3=A, D4=A, D5=A, D6=A, D7=A, D8=A, D9=A). Rationale-of-record locked. Two binding side-exigences from arbitrage: AC #2 binary-size radar (see §3 AC #2 amendment) + D6 quickstart inline LAN-override copy (see §4.6 + §3 AC #11 amendment).
**Author**: Ludo + Claude.
**Predecessor**: Step R (OKLCH visual migration, tagged `v1.4.0-step-r`).
**Goal directional**: ship Arenet as a deployable artefact so the operator can install it on a homelab and come back with real operational feedback.

---

## 1. Goal & scope

### 1.1 Goal

Up to and including Step R, Arenet has been a developer-machine project: `go build && ./arenet` is the only install path. Step S makes Arenet **installable on a real homelab** — Docker for the majority case (multi-arch, compose stack with persistent volumes) + systemd unit for native-Linux preference + documentation operators can actually follow + a hardening baseline so the admin surface isn't a soft target on day one.

The deliverable is **artefacts + doc**, not new product features. The functional surface of Arenet doesn't change in Step S; what changes is what an operator types to get it running.

The implicit goal: **enable real operational feedback**. After Step S ships, the operator deploys Arenet on a homelab, runs it against actual traffic, and the next step's scope is driven by what's surfaced — not by speculative roadmap features. Step S is the bridge between dev prototyping and operator reality.

### 1.2 Scope (5 sub-tasks — mirror M/Q/N/O/P/R cadence)

| Sub | Surface | What it produces |
|-----|---------|------------------|
| S.1 | Docker image | Multi-arch (linux/amd64 + linux/arm64) `Dockerfile` producing a single binary image. Build via `docker buildx`. CI workflow to publish on tag. Base image = distroless or Alpine — see D2. |
| S.2 | Compose + systemd | `docker-compose.yml` reference stack: arenet container + named volumes for `arenet.db` / `metrics.db` / `audit.db` / `certmagic/` + port mapping (80/443 data plane + 9994 admin). Plus `packaging/systemd/arenet.service` for native-Linux installs. |
| S.3 | Config + init | Config loading: env vars + optional `--config` file (TOML/YAML — D5). First-boot wizard via `/setup` (Step K-era) handles admin creation; no CLI init command needed unless D7 says otherwise. Data dir layout per D4. |
| S.4 | Hardening + doc | Admin TLS (D6 — Caddy self-cert vs reverse-proxy vs HTTP-only). Rate-limit on `/api/*` admin endpoints (Step Q already has the pieces — wire a default global limit). Secrets handling (env-only / file / Docker secrets — D5). README + `docs/install/` quickstart (Docker 5-min + native systemd) + `docs/operations/` (backup, upgrade, hardening checklist). |
| S.5 | Smoke + verdict | Real homelab install on the operator's machine. AC matrix: container builds for both archs, compose stack boots, /setup completes, admin endpoint reachable, data persists across container restart, schema migration runs cleanly on upgrade from v1.4.0-step-r-built binary. Verdict doc at `docs/smoke-test-step-s.md`. |

### 1.3 What this step DOES NOT do

- **HA / multi-host**: state is BoltDB + SQLite on local disk; no distributed-storage abstraction, no leader election. Future big-refactor step (Step T or later).
- **Automated TLS for admin port 9994**: ACME chicken-egg (Arenet needs to be running to provision its own cert; admin port needs the cert to be running). Worked around in D6 with operator-side options (self-signed default, reverse-proxy-in-front recipe, or HTTP-localhost-only). Real auto-TLS for admin is a follow-up.
- **Kubernetes manifests**: future. Helm chart + k8s Service/Deployment YAML can be done once compose works and we have operator feedback on what defaults make sense.
- **Distro packages (.deb / .rpm)**: future. systemd unit is the bridge; package wrappers can come if/when operator demand surfaces.
- **CI test matrix expansion**: existing `go test ./...` + `npm test` coverage carries over. Step S doesn't add new test surfaces beyond the docker-build smoke.
- **Telemetry / phone-home**: out of scope unless operator explicitly opts in. The Step L "anonymous usage" toggle exists; Step S doesn't change its semantics.

---

## 2. Decisions (arbitrated)

All 9 decisions arbitrated 2026-06-01. Each entry: Outcome → rationale-of-record. Two binding side-exigences captured inline at the relevant decisions (D2 → AC #2 radar; D6 → quickstart inline copy).

### D1 — Binary scope: single-binary ✓ (Outcome: A)

**Outcome**: one `arenet` binary serves both data plane (:80 / :443) and admin plane (:9994).

**Rationale-of-record**: matches the CLAUDE.md architecture diagram + the codebase as-built. Admin state (auth, audit, idle timer) and data plane (route config, observability counters, WAF event sink) share too much state to split cleanly without a massive refactor. The homelab audience values "one binary, one process, one systemd unit" simplicity. Same-process risk (an admin-plane bug affecting data plane) is mitigated by existing test coverage; if a real incident surfaces the need to split, it becomes a focused future step.

### D2 — Docker base image: distroless ✓ (Outcome: A)

**Outcome**: `gcr.io/distroless/static-debian12:nonroot` (or `base-debian12` if cgo is needed — TBD during S.1 against the actual build).

**Rationale-of-record**: smallest attack surface, no shell / no package manager / no debug tooling. Static Go binary (CGO_ENABLED=0) fits cleanly. Lack of shell for ops debug is operationally correct — `docker exec` into a prod container is itself a posture mistake; `docker logs` / `docker inspect` / `docker stats` cover the legitimate ops surface.

**Binding side-exigence — AC #2 radar (mandatory check at S.1 first build)**: the existing Go binary measures ~92 MB stripped (cited from prior step notes). Distroless base (~2 MB) + 92 MB binary = ≥ ~94 MB compressed-ish image, **OVER the AC #2 ≤ 50 MB ceiling**. AC #2 may need amendment, BUT the decision is deferred to **first measurement at S.1** — not speculative now.

When the S.1 build measures the image:
- **Path A (amend)**: if ≥ 50 MB, amend AC #2 ceiling to a measured-realistic value (likely 100 MB). Rationale-of-record: binary embeds frontend SvelteKit + all Caddy modules + WAF/CrowdSec/automation deps; the monolithic single-binary approach (D1) makes this inherent. Compare against reference images (Caddy official ~50 MB, Traefik ~120 MB) to justify the new ceiling.
- **Path B (compress)**: examine UPX compression (Go binaries shrink ~3× with UPX but startup time penalty + AV false-positives on some platforms), splitting the frontend out of the binary (serve from a sidecar nginx — increases compose complexity), or more aggressive linker flags (`-s -w` is already there; `-trimpath` doesn't change size).

S.1 commit message + spec amendment document the verdict path taken. NO speculative compression work before measurement lands.

### D3 — Default port mapping ✓ (Outcome: A)

**Outcome**: `80:80 443:443` on the host; admin `127.0.0.1:9994:9994` loopback-only by default.

**Rationale-of-record**: matches operator mental model ("a reverse proxy listens on :80/:443"). Loopback-only admin binding makes LAN exposure an explicit operator override (D6), not an accident. Privileged port bind on Linux is handled transparently by Docker; the systemd unit ships `AmbientCapabilities=CAP_NET_BIND_SERVICE` so the binary runs as the non-root `arenet` user with bind permission.

### D4 — Data dir layout ✓ (Outcome: A)

**Outcome**: `/var/lib/arenet/` canonical default, overridable via `--data-dir` flag or `ARENET_DATA_DIR` env var. Subdirs: `data/` (3 DBs) + `certmagic/` + `logs/` (optional). Docker volume mount-point matches.

**Rationale-of-record**: `/var/lib/<service>/` is FHS-canonical for service state. `/etc/arenet/` reserved for the optional config file (D5). Requires `useradd -r arenet` + `mkdir -p /var/lib/arenet && chown arenet:arenet` in the systemd `install.sh`; Docker handles equivalent via volume mount.

### D5 — Config delivery: env + TOML 12-factor ✓ (Outcome: A)

**Outcome**: env vars (primary) + optional `/etc/arenet/config.toml` file (secondary). Precedence: **flag > env > file > default**. Admin-creation flow stays at `/setup` (Step K-era); no CLI init wizard.

**Rationale-of-record**: 12-factor pattern. Env vars handle the "flip one knob" case ergonomically; TOML file handles "20 settings with inline comments". Secrets via env OR Docker secrets (file at `/run/secrets/<name>`) — never in the config file. Precedence rules documented in `docs/operations/config.md` + shown in `arenet --help`.

### D6 — Admin port TLS: loopback default ✓ (Outcome: A)

**Outcome**: admin port :9994 binds `127.0.0.1` by default. Three operator paths documented:
1. **Default (loopback only)**: accessed via SSH tunnel from workstation. Zero TLS bootstrap.
2. **Reverse-proxy-in-front**: operator runs an HTTPS terminator (Caddy / Nginx / Cloudflare Tunnel) in front. Recipe in `docs/operations/hardening.md`.
3. **Self-signed (advanced)**: optional `ARENET_ADMIN_TLS_CERT` + `ARENET_ADMIN_TLS_KEY` env vars; if both set, admin binds HTTPS with the supplied cert. Operator manages cert lifecycle.

Auto-TLS for admin port = OUT OF SCOPE (chicken-egg; future work).

**Rationale-of-record**: loopback-by-default makes LAN exposure an explicit operator decision, not an accident. The plaintext-over-LAN risk only materialises if the operator overrides the default AND skips the SSH-tunnel / reverse-proxy hardening — that's an active mistake, not a default-trap.

**Binding side-exigence — quickstart MUST show the LAN-override copy inline (mandatory in `docs/install/docker-quickstart.md`)**: the loopback default creates friction on first-day operator workflow. To avoid "SSH-tunnel by default = bad first impression", the 5-min quickstart includes EXPLICITLY (not in a separate hardening doc):

```
By default Arenet admin binds to loopback (127.0.0.1) for
security — your data plane (:80/:443) IS LAN-accessible, only
the admin UI is loopback-restricted. To access the admin from
a workstation on your LAN, choose one of:

  Option 1 — SSH tunnel (recommended, no config change):
    ssh -L 9994:localhost:9994 <homelab-host>
    open http://localhost:9994 in your browser

  Option 2 — Bind admin to LAN (less secure, plaintext):
    Set ARENET_ADMIN_BIND=0.0.0.0:9994 in your compose env or
    /etc/arenet/arenet.env, then restart. Anyone on your LAN
    can now reach the admin port over plain HTTP — put a TLS
    terminator in front before relying on this for anything
    sensitive.
```

This paragraph lands in the quickstart MAIN BODY, not in a "production hardening" sidebar. The override friction = one env var, not a separate section. AC #11 5-min path includes the LAN-override copy as a verified deliverable.

### D7 — Docker entrypoint: auto-init ✓ (Outcome: A)

**Outcome**: `docker run arenet:latest` on a fresh data dir auto-initialises (BoltDB + SQLite files + schema) and starts. `/setup` wizard handles admin user creation on first browser visit. No CLI init step.

**Rationale-of-record**: 5-min quickstart cadence preserved. The "mis-mounted volume looks like data loss" risk is mitigated by a clear `INFO` log line at first boot ("Initialised new database at <path>") — operators who see it when they didn't expect it can investigate before clicking through `/setup`.

### D8 — Upgrade path: auto-migrate ✓ (Outcome: A)

**Outcome**: when a newer binary starts against an older data dir, schema migrations auto-apply forward, with a startup log line showing each step (`migrating bolt schema v1 → v2…`). Backup before upgrade IS the operator's responsibility (documented in `docs/operations/backup.md`).

**Rationale-of-record**: existing migrations are idempotent + unit-tested in their originating steps (M / N / O / P / R). Manual-confirm adds friction without safety (the operator who runs `arenet migrate` without backup has the same risk as auto-migrate). A future buggy migration is caught by the per-step test discipline before release.

### D9 — Numbering scheme: pure semver from v1.0.0 ✓ (Outcome: A)

**Outcome**: tag scheme switches to pure semver starting with Step S. The freeze tag for this spec is `v1.0.0-step-s-spec` (transitional — keeps the step-letter narrative in the tag for ONE last cycle, marking the pivot point). The ship tag after S.5 smoke is `v1.0.0`. Subsequent steps tag `v1.1.0`, `v1.2.0`, etc. — no more step-letter in tags.

**Rationale-of-record**: step-letter scheme served the dev-prototyping phase where each step was a coherent chunk delivered to a single operator (the dev). Post-S we ship operator-visible releases; semver communicates intent better to outside readers ("v1.1.0 = backwards-compatible features; v2.0.0 = breaking change"). Internal narrative (Step T, Step U, …) stays in spec filenames + commit messages + the spec `h1` titles for traceability; tags are pure semver. The git-history-reader friction of jumping `v1.4 → v1.0` is addressed by a single paragraph in the v1.0.0 release notes explaining the convention reset.

---

## 3. Acceptance criteria

| # | AC | How to verify |
|---|----|---|
| 1 | Docker image builds for linux/amd64 + linux/arm64 | `docker buildx build --platform linux/amd64,linux/arm64 -t arenet:test .` succeeds; image inspected with `docker manifest inspect` shows both arch entries. |
| 2 | Image size ≤ 50 MB compressed — **PROVISIONAL ceiling, radar at S.1 first build** | `docker images arenet:test` size check on a fresh build. Existing binary is ~92 MB stripped (cited from prior step notes); distroless + 92 MB binary likely ≥ ~94 MB compressed-ish image, **OVER the 50 MB ceiling**. Per D2 binding side-exigence: measure at S.1, then choose Path A (amend ceiling to a measured-realistic value, likely 100 MB, rationale: monolithic binary inherent to D1) OR Path B (UPX / sidecar / aggressive linker). NO speculative compression before measurement. The S.1 commit message + a spec amendment document the verdict path. |
| 3 | Compose stack boots cleanly | `docker compose up -d` against the reference `docker-compose.yml` brings arenet up; healthcheck on `/api/v1/healthz` returns 200 within 10s. |
| 4 | Data persists across container restart | Stop + remove arenet container, recreate with same volumes; existing routes / users / audit log still present. |
| 5 | systemd unit installs + starts | `systemctl daemon-reload && systemctl start arenet` on a Linux box starts the binary as the `arenet` user with `CAP_NET_BIND_SERVICE`; `systemctl status` shows active (running). |
| 6 | First-boot setup completes | Fresh data dir + browser to admin port → `/setup` wizard creates admin user; subsequent browser visit to `/login` accepts the new credentials. |
| 7 | Schema migration runs on upgrade | v1.4.0-step-r binary started against v1.4 data dir → no-op (schema is current). Future migrations: documented contract that v1.X+1 against v1.X data is auto-migrate + log. Pinned by re-running existing M/N/O/P/R migration test suites against the packaged binary. |
| 8 | Admin port loopback default | Fresh install: `curl http://127.0.0.1:9994/api/v1/healthz` works from inside the box; `curl http://<LAN-IP>:9994/api/v1/healthz` from another machine fails (connection refused, not 401). |
| 9 | Hardening checklist documented + verified | `docs/operations/hardening.md` exists, lists: admin TLS options (D6 three paths), `/api/*` rate limiting (Step Q wired in), default-deny network posture, secret storage. Each item has a "verify" command. |
| 10 | Backup + restore documented + verified | `docs/operations/backup.md` shows a working backup script (stop arenet → tar the data dir → restart) and the inverse restore. Verified by: snapshot before a config mutation → restore → mutation gone. |
| 11 | Quickstart 5-min path actually 5 min — **MUST include inline LAN-override copy per D6 binding side-exigence** | `docs/install/docker-quickstart.md` followed end-to-end on a fresh VM produces a running, browser-accessible Arenet in ≤ 5 minutes wall-clock. Timed by the operator during S.5 smoke. The quickstart MUST show the SSH-tunnel + `ARENET_ADMIN_BIND=0.0.0.0:9994` LAN-override paragraph in the main body (verbatim per D6) — NOT in a separate hardening doc. Smoke verifies the paragraph is present + readable as a first-time-operator. |
| 12 | Standard lint/test gates | `go vet ./...`, `go test ./...`, `npm run check`, `npm run build` all green on the tip. |
| 13 | Image is non-root + minimal capabilities | `docker inspect arenet:test` shows USER set to a non-root UID; CAP_NET_BIND_SERVICE is the only capability granted in the compose example. |
| 14 | CI workflow publishes on tag | `.github/workflows/release.yml` triggers on `v*` tag push, runs buildx for amd64+arm64, pushes to a configured registry (ghcr.io default). Dry-run verified before live publish. |

---

## 4. Architecture

### 4.1 Single-binary boundary

Per D1, one `arenet` binary serves :80 / :443 (data plane) + :9994 (admin plane). All code lives in the existing repo structure; Step S adds **packaging + config glue**, not new internal/ packages (except possibly `internal/config/` if the env+file precedence logic earns its own package — TBD during S.3).

### 4.2 Docker artefact

Two-stage Dockerfile per D2:

```Dockerfile
# Stage 1 — frontend build
FROM node:20-alpine AS frontend
WORKDIR /src/web/frontend
COPY web/frontend/package*.json ./
RUN npm ci
COPY web/frontend ./
RUN npm run build

# Stage 2 — Go build
FROM golang:1.25-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend /src/web/build /src/web/build
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/arenet ./cmd/arenet

# Stage 3 — runtime
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=backend /out/arenet /usr/local/bin/arenet
USER nonroot:nonroot
EXPOSE 80 443 9994
ENTRYPOINT ["/usr/local/bin/arenet"]
```

Build via `docker buildx build --platform linux/amd64,linux/arm64 ...`. CI workflow at `.github/workflows/release.yml` triggers on `v*` tag push.

### 4.3 Reference compose

```yaml
# docker-compose.yml
services:
  arenet:
    image: ghcr.io/barto95100/arenet:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      # Admin port — LOOPBACK ONLY by default. To expose on LAN,
      # put a TLS-terminating reverse proxy in front (see
      # docs/operations/hardening.md). Uncomment ONLY if you
      # understand the implications.
      - "127.0.0.1:9994:9994"
    volumes:
      - arenet-data:/var/lib/arenet
    environment:
      ARENET_DATA_DIR: /var/lib/arenet
      ARENET_LOG_LEVEL: info
    cap_add:
      - NET_BIND_SERVICE
    healthcheck:
      test: ["CMD", "/usr/local/bin/arenet", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  arenet-data:
```

Note: a `arenet healthcheck` subcommand is needed because distroless has no curl/wget. Simple HTTP client subcommand against `127.0.0.1:9994/api/v1/healthz`.

### 4.4 systemd unit

```ini
# packaging/systemd/arenet.service
[Unit]
Description=Arenet — homelab reverse proxy with integrated security
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=arenet
Group=arenet
ExecStart=/usr/local/bin/arenet
EnvironmentFile=-/etc/arenet/arenet.env
WorkingDirectory=/var/lib/arenet
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/arenet
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

`packaging/systemd/install.sh` handles user creation (`useradd -r -s /usr/sbin/nologin arenet`), data dir setup, file placement.

### 4.5 Config loading (D5)

`internal/config/config.go` (new package) — precedence: flag > env > file > default. TOML format for the optional file. Single struct `Config` populated by a `Load()` function called from `cmd/arenet/main.go`.

Keys:
- `ARENET_DATA_DIR` (default `/var/lib/arenet`)
- `ARENET_ADMIN_BIND` (default `127.0.0.1:9994`)
- `ARENET_DATA_BIND_HTTP` (default `:80`)
- `ARENET_DATA_BIND_HTTPS` (default `:443`)
- `ARENET_LOG_LEVEL` (default `info`)
- `ARENET_LOG_FORMAT` (default `text`, opt `json`)
- `ARENET_ADMIN_TLS_CERT`, `ARENET_ADMIN_TLS_KEY` (D6 advanced path)

### 4.6 Documentation tree

```
docs/
├── install/
│   ├── docker-quickstart.md      ← AC #11: 5-min path
│   │                                MUST include LAN-override
│   │                                paragraph inline per D6
│   ├── docker-compose.md         ← reference + customisation
│   ├── systemd-native.md         ← Linux package install
│   └── upgrade.md                ← v1.X → v1.X+1 procedure
├── operations/
│   ├── backup.md                 ← AC #10
│   ├── hardening.md              ← AC #9 (3 admin TLS paths)
│   ├── config.md                 ← env + file precedence
│   └── troubleshooting.md        ← log levels, common issues
└── README.md (existing, refreshed with quickstart link)
```

The D6 quickstart LAN-override paragraph (verbatim text in the D6 decision body above) lands in `docs/install/docker-quickstart.md` MAIN BODY — not in a sidebar / not in the hardening doc. The 5-min path SHOWS the loopback default + the override options BEFORE the operator hits the friction. S.5 smoke verifies a first-time reader finds the LAN-override copy without scrolling past several sections.

---

## 5. Risks & mitigations

| Risk | Mitigation |
|------|------|
| **Multi-arch CI matrix** complexity (buildx + qemu emulation slow on amd64 CI runner for arm64 build) | GitHub Actions has native arm64 runners since 2024; CI workflow targets `ubuntu-latest-arm64` runner for the arm64 leg + standard `ubuntu-latest` for amd64. Estimated 5-10 min for both legs. |
| **Distroless lacks shell** for ops debug | Documented in `docs/operations/troubleshooting.md`: use `docker logs`, `docker inspect`, `docker stats`. The `arenet healthcheck` subcommand covers the most common "is it alive" check. |
| **Loopback-only admin** confuses operators expecting LAN-accessible default | Compose example has clear comment explaining the loopback default + the hardening doc shows the 3 paths (SSH tunnel, reverse-proxy-in-front, self-signed TLS). README quickstart includes the SSH tunnel command verbatim. |
| **Schema migration** runs on first upgrade across many existing operators (post-S releases) | Migration unit-tests already exist per step (M/N/O/P/R). Each future step adds its migration tests; the S smoke verifies the v1.0.0 → v1.0.1 migration shape is intact before publishing the next release. |
| **`arenet:latest` tag drift** — operators pulling `latest` get whatever was most recently published, even if it's a pre-release | CI workflow publishes BOTH `vX.Y.Z` tag AND `latest` only on stable tags (no -rc / -beta on `latest`). Docs recommend pinning to a specific version. |
| **Backup story relies on operator discipline** (cold-stop, tar, restart) — a running snapshot via BoltDB's `Tx.WriteTo` would be safer but isn't implemented | Document the cold-snapshot procedure clearly in `docs/operations/backup.md`. Add a `arenet backup` subcommand in a future step that wraps a `bbolt.Tx.WriteTo` snapshot — out of scope for S, tracked in S backlog. |
| **Numbering reset (D9)** confuses git history readers | Single-paragraph note in v1.0.0 release notes; the spec filename `2026-06-01-step-s-...` keeps the step-letter trail; commit messages keep referencing Step S internally. |

---

## 6. Out of scope (rationale-of-record)

- **HA / multi-host clustering**. State is local-disk BoltDB + SQLite; distributing it requires a new storage abstraction (Postgres? embedded etcd? consensus?) + leader election + replication strategy + split-brain handling. That's a big-refactor step in its own right and there's no operator demand yet. Run a single Arenet instance per homelab; failover via a separate HA layer (keepalived, etc.) if needed.
- **Automated TLS for admin port 9994**. Caddy can self-cert against an internal CA, but the bootstrap is chicken-egg: Arenet needs to be up to issue the cert; the cert is needed to expose the admin port. Solvable (use a self-signed cert at boot, rotate later) but operationally awkward + adds error paths. Defer until operator feedback says the loopback-only / reverse-proxy-in-front paths are inadequate.
- **Kubernetes Helm chart / manifests**. The homelab audience for v1.0 is single-node docker-compose or systemd. K8s deployment is a different operator profile (multi-node clusters, GitOps pipelines); the manifests should be designed against operator feedback, not speculation. Future step once compose ships.
- **Distro packages (.deb / .rpm)**. systemd unit + tarball install is the bridge for native Linux. Packaging adds release infrastructure (signing keys, repository hosting, distro-specific build matrices) without solving an unsolved problem — operators who want native install can run the systemd unit today. Defer until packaging demand is concrete.
- **CI test matrix expansion**. Existing `go test ./...` + `npm test` coverage carries forward; Step S adds the docker-build smoke as a new CI surface but doesn't expand the test matrix beyond it. Coverage gaps in M/N/O/P/R remain backlog items in their respective steps.
- **Telemetry / phone-home**. Step L's anonymous usage toggle exists but defaults OFF; Step S doesn't change defaults. The homelab audience values privacy; phoning home would damage trust.
- **Windows / macOS native binaries**. Go cross-compiles trivially but the deployment story for those targets is different (Docker Desktop is the natural path on those OSes); native daemons aren't the homelab pattern there. Cross-compile artefacts MAY ship as a side-benefit of the build pipeline but aren't tested / documented in S.

---

## 7. Appendix — references

- Predecessor specs:
  - L: `docs/superpowers/specs/2026-05-28-step-l-observability.md`
  - M: `docs/superpowers/specs/2026-05-28-step-m-security.md`
  - Q: `docs/superpowers/specs/2026-05-29-step-q-rate-limit-auth-events.md`
  - N: `docs/superpowers/specs/2026-05-29-step-n-crowdsec.md`
  - O: `docs/superpowers/specs/2026-05-30-step-o-wildcards.md`
  - P: `docs/superpowers/specs/2026-05-31-step-p-auto-classify.md`
  - R: `docs/superpowers/specs/2026-05-31-step-r-oklch-migration.md`
- Step R verdict (immediate predecessor): `docs/smoke-test-step-r.md`.
- CLAUDE.md architecture diagram: embedded Caddy + REST API + WebSocket + BoltDB in one process — drives D1 single-binary reco.
- Existing build / run instructions in CLAUDE.md §Build & Run: `cd cmd/arenet && go build -o ../../arenet` — Step S replaces this for operators with `docker compose up -d` OR `systemctl start arenet`.
- Reference Docker images for size comparison: Caddy official (~50 MB), Traefik (~120 MB), nginx (~40 MB). Distroless + static Go binary target = ≤ 50 MB compressed (AC #2).
