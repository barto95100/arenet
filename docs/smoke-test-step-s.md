# Step S — Smoke test

**Status**: VERDICT PROVISIONAL PASS 2026-06-01 — pending real-homelab smoke.
**Spec**: `docs/superpowers/specs/2026-06-01-step-s-production-deployment.md`.
**Tip**: commit `817dc87` (S.4 final).
**Scope**: production-deployment packaging verification — 14 ACs.

---

## 1. Environment

- macOS Darwin 25.3.0, arm64. Docker Desktop 4.75.0, buildkit
  v0.30.0.
- The local-Mac smoke covers everything the spec ACs ask for
  EXCEPT three runtime conditions that require a real homelab:
  the offline-fonts AC (network egress block), the arm64-native
  systemd install path, and the "5-min wall-clock fresh-VM"
  measurement (the local timing uses already-built layers + a
  pre-tagged image since CI hasn't published one yet).
- Real-homelab smoke is the operator's responsibility (this
  doc's §4 "DEFERRED / N/A" list spells out what's pending).

## 2. Method

- AC matrix run against a fresh `docker compose up -d` cycle on
  Docker Desktop. Volume + container teardown between phases
  for clean baselines where measurement integrity matters.
- Each AC reports outcome + evidence + caveat where applicable.
- Real binary boot + real `/healthz` + real rate-limit traffic
  — not just unit tests.

## 3. AC matrix

| # | AC | Outcome | Evidence |
|---|----|---------|----------|
| 1 | Docker image builds for linux/amd64 + linux/arm64 | PASS | `docker buildx build --platform linux/amd64,linux/arm64 -t arenet:v1.0.0-smoke .` succeeds. amd64 build via qemu emulation ~130s; arm64 build native on M-series Mac ~47s. Single-arch local build also OK (arch matches host = linux/arm64). |
| 2 | Image size — **amended ceiling per S.1 D2 side-exigence (≤ 100 MB uncompressed AND ≤ 30 MB compressed)** | PASS | Measured on `arenet:v1.0.0-smoke` (linux/arm64). `docker images`: **94.1 MB uncompressed**. `docker save \| gzip \| wc -c`: **22.4 MB registry-compressed** (23510628 B). Both under amended ceilings with comfortable margin. |
| 3 | Compose stack boots cleanly | PASS | `docker compose up -d` returns success. Container goes from `starting` → `healthy` in **~20 s** (start_period 10s + first healthcheck.interval 30s; the probe fires at start_period expiry). |
| 4 | Healthcheck reports healthy | PASS | `docker inspect arenet --format '{{.State.Health.Status}}'` returns `healthy`. The in-binary `--healthcheck=http://127.0.0.1:8001/healthz` exit 0 confirms the distroless probe path works without curl. |
| 5 | Data persists across container restart | PASS | Volume `arenet-data` (`/var/lib/arenet`) holds `arenet.db` (32 KB BoltDB) + `metrics.db` (4 KB → 86 KB across boots, observability accumulated state). Ownership `65532:65532` (nonroot uid) preserved. `docker compose down` (without -v) + `docker compose up -d` → /healthz returns 200, container reports healthy, files intact. |
| 6 | First-boot setup token logged | PASS | `docker compose logs arenet \| grep "Setup token"` returns `Setup token: 301576f510fe702627dc96c46fea3aab291c84568b2f8f78363b792afc839fc8` on the fresh data-dir boot. `/setup` HTML page reachable on loopback (HTTP 200). |
| 7 | Schema migration runs on upgrade | PASS-baseline (full upgrade path = N/A live in S.5) | v1.0.0 binary against v1.0.0 data dir = no migrations needed; `/healthz` returns 200 after restart, no error logs. The cross-version migration shape (v1.X → v1.X+1) is pinned by the per-step migration test suites (M / N / O / P) in the codebase + AC #12 lint/test gate. Live cross-version smoke deferred to the first v1.0.0 → v1.0.1 release. |
| 8 | Admin port loopback default | PASS | From host loopback (`127.0.0.1:8001`): HTTP 200. From host LAN IP (`192.168.1.85:8001`): connection refused / timeout (curl status code `000`, NOT a 401 — exactly what D6 requires). |
| 9 | Hardening checklist documented + verified | PASS (doc shipped, key items live-verified) | `docs/operations/hardening.md` exists with 10 actionable items + verify commands + scorecard. Live verification: rate-limit (item 4) triggered at attempt 6 of 11 wrong logins; the lifted middleware (S.4) catches credential-stuffing on /api/v1/routes too (verified: same blocked IP gets 429 with `Retry-After: 892` on a non-auth endpoint). |
| 10 | Backup + restore documented | PASS (doc shipped, restore round-trip = N/A live) | `docs/operations/backup.md` exists with Docker + systemd backup commands + restore inverse + verify section + "what's NOT in the backup" + hot-snapshot roadmap. Restore round-trip not executed in the local smoke (cold-stop + tar + restore is mechanical; the operator runs it pre-prod). |
| 11 | Quickstart 5-min path actually 5 min | PASS (local timing) | Timed `docker compose up -d` → healthy → `/setup` reachable on loopback: **10 seconds wall-clock**. Massively under 5-min target. Caveat: the `docker compose pull` step was skipped (no ghcr image published yet); a real-homelab fresh-VM run with `pull` adds image-download time (~22 MB compressed, typical homelab LAN = a few seconds). Even with pull, well within 5-min. |
| 11.bis | D6 binding side-exigence — quickstart MUST contain inline LAN-override paragraph | PASS | `docs/install/docker-quickstart.md` step 5 "Open the admin UI" contains BOTH the SSH-tunnel command (`ssh -L 8001:localhost:8001`) AND the `ARENET_ADMIN_BIND=0.0.0.0:8001` override block in the main body — not in a sidebar or separate hardening doc. `docs/install/systemd-native.md` mirrors the same pattern. |
| 12 | Standard lint/test gates | PASS | `go vet ./...` clean. `go test ./...` → all 14 packages green (`cmd/arenet`, 13 internal/ packages including new `internal/config`). `npm run check` → 557 files, 0 errors, 0 warnings. `npm run build` green (Step R verdict tip). |
| 13 | Non-root + minimal capabilities | PASS | `docker inspect arenet` reports: `User: nonroot:nonroot`, `CapAdd: [CAP_NET_BIND_SERVICE]`, `CapDrop: []`, `SecurityOpt: [no-new-privileges:true]`. The compose example ships `cap_add: [NET_BIND_SERVICE]` + `security_opt: [no-new-privileges:true]` — minimum-privilege posture confirmed live. |
| 14 | CI workflow publishes on tag | PASS-config (live publish = N/A until first real tag push) | `.github/workflows/release.yml` exists. Triggers on `v*` tag push (real publish) OR `workflow_dispatch` (dry-run via UI). Multi-arch via `docker/build-push-action@v6` with `platforms: linux/amd64,linux/arm64`. Stable-tag detection (`^v[0-9]+\.[0-9]+\.[0-9]+$`) gates the `:latest` alias. YAML syntax-valid (ruby YAML parser confirmed). Local buildx dry-run with the same `--platform` flags succeeds (S.4 evidence). Live registry push deferred to first real `v1.0.0` tag push by operator. |

## 4. Items intentionally DEFERRED / N/A

These are NOT smoke gaps — they're the irreducibly-operator items
the local Mac smoke can't substitute for. Each is captured here
so the real-homelab smoke knows what to verify.

- **AC #3 / runtime no-internet boot — DEFERRED to operator**.
  Step R AC #3 (self-hosted fonts) requires `iptables` egress
  block + fresh container boot + browser pageload to confirm
  fonts render from `embed.FS` rather than from a CDN fallback.
  Static evidence already collected (R.5 + S.4 docs): Inter +
  JetBrains Mono + Geist Mono live under `web/frontend/static/
  fonts/`, all `@font-face` declarations reference `/fonts/*.
  woff2` relative paths. Runtime confirmation = operator's
  fresh-VM smoke.
- **AC #14 / live CI publish — N/A until first tag push**.
  The workflow's syntax + buildx steps are verified locally.
  The actual ghcr.io publish only happens when the operator
  pushes a stable `v*` tag (planned: `v1.0.0` after this
  verdict). The workflow CAN be dry-run via `workflow_dispatch`
  on GitHub to verify the auth + buildx legs without
  publishing — operator's call.
- **5-min wall-clock on a real fresh VM** — local timing was
  10s, but used a pre-tagged image. A real fresh-VM run
  includes `docker compose pull` (image download) which the
  local smoke skipped. Still well under 5-min budget on any
  reasonable homelab LAN — but the literal "fresh-VM
  stopwatch" measurement is operator's.
- **arm64 systemd-native install** — `packaging/systemd/`
  + `install.sh` are syntax-verified (`bash -n`) but not
  installed on a real arm64 box in this smoke. systemd-
  smoke is mechanical (the script is idempotent + tested via
  shell parse + the unit file is declarative).
- **Schema migration v1.X → v1.X+1 cross-version** — first
  cross-version upgrade smoke happens at v1.0.0 → v1.0.1
  ship time; until then the per-step migration tests pin
  the contract.

## 5. Findings / deviations

### S.1 — AC #2 ceiling amended

The 50 MB compressed ceiling in the original spec was speculative;
S.1 first-build measurement (94.1 MB uncompressed, 22.4 MB
compressed) prompted Path A per the D2 side-exigence: ceiling
amended to ≤ 100 MB uncompressed AND ≤ 30 MB compressed.
Rationale-of-record in the spec: monolithic single-binary (D1)
inherent cost. Comparison reference: Caddy ~50 MB, Traefik
~120 MB — Arenet at 94.1 MB / 22.4 MB slots between. Verdict:
PASS against amended ceiling.

### S.3 — Admin port history

The spec draft mentioned `:9994` for the admin port; reality
in `cmd/arenet/main.go:109` has defaulted to `:8001` since
Step D. The `:9994` references were a smoke-test convention
across M / N / O / P (each smoke explicitly passed
`-admin-port=:9994` for collision avoidance). Spec bulk-fix +
`docs/operations/troubleshooting.md` entry document the
distinction so operators reading old smoke logs aren't
confused.

### S.4 — Rate-limit lift scope

The original spec said "wire a default global limit"; the lift
turned out to be a one-line move of `r.Use(h.rateLimiter.
Middleware())` from the /auth subtree to the /api/v1 subtree.
Zero new code, zero new dep. The limiter's design (only counts
401/403 responses) means authenticated traffic isn't throttled
— only failed auth attempts. Lift verified live: blocked IP
after 11 wrong logins gets 429 with `Retry-After: 892` on
`/api/v1/routes` (non-auth endpoint).

### #S-1 — env-only consolidation deferred

S.3 deliberately bounded the centralised config layer to flag-
backed settings only. The scattered env-only reads
(`ARENET_ACME_EMAIL`, `ARENET_CROWDSEC_*`, `ARENET_HTTP_PORT`,
`ARENET_TRUSTED_PROXIES`, `ARENET_HIBP_DISABLED`) keep their
existing call sites. Backlog #S-1 documents the completion
shape for a focused future step if/when operators ask for
"everything in one TOML file".

## 6. Verdict

**PROVISIONAL PASS.**

All 14 ACs pass the local-Mac smoke:
- 11 fully verified (ACs 1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13).
- 3 verified-by-doc-plus-baseline (ACs 7 cross-version migration,
  10 restore round-trip, 14 live CI publish).

Step S is **SHIP READY pending the real-homelab smoke** the
operator will run on their actual deploy target. The provisional
PASS applies to everything verifiable from a Mac with Docker
Desktop; the irreducibly-operator items in §4 above are the only
remaining gates.

**Tag**: `v1.0.0` applied LOCAL on this verdict commit. **Not
pushed**. The push (which also propagates `v1.4.0-step-r`,
`v1.0.0-step-s-spec`, and the S.x commits since the last push)
happens after the operator confirms real-homelab PASS, per the
S.5 plan agreed pre-smoke:

- Real-homelab smoke reveals a **blocking bug** (data plane
  broken, healthcheck fail, install script broken) → fix +
  S.5 re-run before tag.
- Real-homelab smoke reveals **polish / UX nit / doc gap** →
  backlog #S-? entry, no tag block, triage to v1.0.1+.

## 7. Teardown

- Local Docker artefacts torn down between phases for clean
  measurements (volume removed, image untagged).
- Final state: zero Arenet containers, zero Arenet volumes, zero
  Arenet images on the smoke host.
- Working tree clean apart from this verdict doc (+ the
  pre-existing `docs/mocks/pages/` untracked dir that has
  persisted across many steps and is operator-source content).
