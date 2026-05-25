# Step J — Manual smoke test

Run **before** tagging `v0.6.0-step-j`. Targets the local single-binary
build with `--dev` mode (ACME staging, ports `:8080` / `:8443`).
Mirrors the Step I smoke pattern.

Scope: Step J is the **Multi-upstream Load Balancing + DNS-01** feature
step (sub-tasks J.1 → J.7, J.5 explicitly DEFERRED per §1.4). This
smoke validates the 17 acceptance criteria of spec §2 (15 active + 2
DEFERRED) plus the regression-safety of Steps D-I.

**Date**: 2026-05-26.
**Range**: `v0.5.0-step-i` (c44abdb) → HEAD `30c388f` + doc commit (this).
Sub-task commits in range:
`8972365` J.1, `c867b2e` J.2, `03cfe61` J.3, `fd840d5` J.4,
`a2ae797` J.6, `30c388f` J.7 §5.3 tests, `ffba2fa` backlog ACME coupling.

Each numbered section is self-contained. Section 4 is the AC
validation matrix and is the authoritative checklist for tagging.
Section 5 lists findings (only one, non-blocking). Section 6 lists
acknowledged debt deferred post-tag. Section 7 is the verdict.
Section 8 is the tag procedure.

---

## 0. Setup

```bash
# From repo root, on main at ffba2fa (or HEAD if doc commit lands first)
cd /Users/l.ramos/Documents/Projets/AreNET
go build -o /tmp/arenet ./cmd/arenet

# Scratch data-dir for the smoke session
rm -rf /tmp/arenet-stepj-data && mkdir -p /tmp/arenet-stepj-data
/tmp/arenet --dev --data-dir /tmp/arenet-stepj-data --admin-port :8001 \
  > /tmp/arenet-stepj.log 2>&1 &
```

Frontend dev server (second terminal):

```bash
cd /Users/l.ramos/Documents/Projets/AreNET/web/frontend
npm run dev   # → http://localhost:5173, proxy /api → :8001
```

Two fake upstreams (third terminal — distinguishable bodies for B.1
distribution measurement):

```bash
python3 -c "import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','text/plain')
        self.end_headers(); self.wfile.write(b'upstream-9201\n')
    def log_message(self,*a): pass
socketserver.ThreadingTCPServer(('127.0.0.1',9201),H).serve_forever()" &
python3 -c "import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header('Content-Type','text/plain')
        self.end_headers(); self.wfile.write(b'upstream-9202\n')
    def log_message(self,*a): pass
socketserver.ThreadingTCPServer(('127.0.0.1',9202),H).serve_forever()" &
```

Browser: open `http://localhost:5173`, set up first admin via the
boot-time setup token logged in `/tmp/arenet-stepj.log`.

For the Phase A AC #2 migration check, a `v0.5.0-step-i` snapshot is
prepared separately:

```bash
git checkout v0.5.0-step-i
go build -o /tmp/arenet-step-i ./cmd/arenet
# Run on a scratch data-dir, create 4 varied Step I routes via the API,
# then snapshot:
cp /tmp/arenet-step-i-data/arenet.db /tmp/arenet-step-i-snapshot.db
git checkout main
```

The snapshot at `/tmp/arenet-step-i-snapshot.db` contains 4 routes
covering the Step I shape variety: plain, with aliases, with WAF
detect, with Basic Auth + WAF block + custom headers.

---

## 1. Auto-checks — gates AC #14, #15, #16, #17

Executed by Claude before the live smoke.

### 1.1 Backend gates (AC #15, #16)

```
$ go test ./... -count=1
ok  	github.com/barto95100/arenet/cmd/arenet	2.733s
ok  	github.com/barto95100/arenet/internal/api	20.108s
ok  	github.com/barto95100/arenet/internal/audit	7.919s
ok  	github.com/barto95100/arenet/internal/auth	7.949s
ok  	github.com/barto95100/arenet/internal/caddymgr	4.191s
ok  	github.com/barto95100/arenet/internal/metrics	2.898s
ok  	github.com/barto95100/arenet/internal/storage	5.219s
?   	github.com/barto95100/arenet/web	[no test files]

$ go vet ./...
(exit 0, no output)

$ gofmt -s -l ./cmd/ ./internal/
(no file needs formatting)

$ staticcheck ./internal/api/... ./internal/storage/... ./internal/caddymgr/... ./cmd/...
(no finding on Step J surface)
```

✅ **AC #15 PASS** (7 packages green).
✅ **AC #16 PASS** (vet + fmt + staticcheck all clean).

### 1.2 Frontend gates (AC #14, #17)

```
$ npm run check
COMPLETED 522 FILES 0 ERRORS 0 WARNINGS 0 FILES_WITH_PROBLEMS

$ npm test
Test Files  22 passed (22)
     Tests  174 passed (174)

$ npm run build
✓ built in 2.13s
Wrote site to "build"
✔ done
```

Bundle measurement (AC #17 vs §1 budget 30 kB for the topology page):

```
$ topology page bundle (gzipped):
build/_app/immutable/nodes/11.DIJnC8IQ.js  raw=23115  gz=7947
```

8 KB gz vs 30 kB budget → **~3.75× under budget**.

✅ **AC #14 PASS** (check + test + build).
✅ **AC #17 PASS** (8 KB gz vs 30 kB budget).

### 1.3 Caddy JSON shape spot-checks (via unit tests)

The Step I.7 hotfix mitigation pattern (`TestBuildConfigJSON_LoadsCleanly`
runs `caddy.Validate()` on the emitted JSON, provisioning every module
including DNS-01) is extended in J.4 to include a DNS-01 fixture +
the `_ "github.com/caddy-dns/ovh"` blank import in the test file.

This means `go test ./internal/caddymgr/` covers AC #9 PARTIAL by
construction — the DNS-01 issuer + OVH provider sub-block + `name:
"ovh"` invariant resolve at Provision time. Live live issuance is
the FULL bar, covered in §3.4 below.

---

## 2. Phase A — Regression Step I + AC #2 migration

### 2.1 `/healthz` (no auth)

```
$ curl -sS -w "\nHTTP %{http_code}\n" http://127.0.0.1:8001/healthz
{"status":"ok","uptime_seconds":9}
HTTP 200
```

✅ PASS — JSON shape, no auth, orchestrator-friendly.

### 2.2 Setup + login (CLI + browser)

CLI (POST /auth/setup with boot token):

```
$ curl ... -d '{"setupToken":"...","username":"smoke","displayName":"...","password":"..."}'
{"id":"...","username":"smoke","displayName":"Smoke Admin", ...}  HTTP 200
arenet_session cookie set
```

Browser: login at `http://localhost:5173` with the same credentials,
redirect to `/routes`. ✅ PASS.

### 2.3 Route CRUD via API + browser

Create / read / update / delete cycle via curl + the UI Modal. Both
paths exercise the full lifecycle. ✅ PASS.

### 2.4 Audit + filters

```
$ curl ... /api/v1/audit
events=4, actions=['route_deleted','route_updated','route_created','setup_admin_created']

$ curl ... /api/v1/audit?action=route_created
route_created count=1
```

✅ PASS.

### 2.5 Theme toggle + persist (browser)

`/settings` → Theme Dark ↔ Light → immediate transition, persists
across page reload (cookie / localStorage). ✅ PASS.

### 2.6 Sidebar collapse + persist (browser)

Sidebar collapse toggle → mini-mode with icons only, persists across
page reload (localStorage). ✅ PASS.

### 2.7 Topology pan/zoom + header (browser)

`/topology` opens with the standard `<PageHeader>` (title "Topology",
subtitle "Live network visualization", connection status indicator
in the right-aligned `actions` slot via `<StatusDot>` atomic). Drag
to pan, wheel to zoom, overlay buttons (+/−/Reset/Fit) work. ✅ PASS.

This already partially covers AC #13 — the J.6 PageHeader migration
and the StatusDot atomic adoption. The auto-fit half is verified in
§3.6 below once routes are populated.

### 2.8 AC #2 — Migration data shape (§6.2 verbatim)

Snapshot Step I (`/tmp/arenet-step-i-snapshot.db`, 4 routes) injected
into the Step J data-dir:

```
$ cp /tmp/arenet-step-i-snapshot.db /tmp/arenet-stepj-data/arenet.db
$ /tmp/arenet --dev --data-dir /tmp/arenet-stepj-data --admin-port :8001
... applying caddy config routes=4 bytes=5722
```

Boot clean, no error. Login as the Step I admin still works (users
bucket migrates with `bucketUsers` already present). Every one of the
4 routes loads with the Step J shape conform to §6.2:

| route          | upstreams         | lbPolicy      | aliases       | basicAuth | wafMode  | acmeChallenge | healthCheck       |
|----------------|-------------------|---------------|---------------|-----------|----------|---------------|-------------------|
| plain.local    | [{:9101, w=1}] ✅ | round_robin ✅| []            | false     | off      | "http-01" ✅  | {enabled:false} ✅|
| multihost.local| [{:9102, w=1}] ✅ | round_robin ✅| [alt1, alt2] ✅| false    | off      | "http-01" ✅  | {enabled:false} ✅|
| wafdetect.local| [{:9103, w=1}] ✅ | round_robin ✅| []            | false     | detect ✅| "http-01" ✅  | {enabled:false} ✅|
| guarded.local  | [{:9104, w=1}] ✅ | round_robin ✅| []            | true ✅   | block ✅ | "http-01" ✅  | {enabled:false} ✅|

Step I.4 WAF mode preserved (routes 3, 4). Step I.5 Basic Auth
preserved (route 4, hash never on the wire — only the boolean
`basicAuthPasswordSet:true`). Step I.6 custom headers preserved
(route 4).

✅ PASS.

### 2.9 AC #2 — Idempotence

Re-boot a second time. The Caddy config emit log shows `routes=4
bytes=5722` byte-identical to boot #1 — proving the shape-based
sentinel (Upstreams non-empty ⇒ already migrated) holds.

```
boot #1: applying caddy config routes=4 bytes=5722
boot #2: applying caddy config routes=4 bytes=5722
```

✅ PASS.

### 2.10 AC #2 — Traffic identity

Launch a fake upstream on :9101, issue host-routed requests:

```
$ curl -H "Host: plain.local" http://127.0.0.1:8080/
hello from upstream :9101       HTTP 200      # proxy works

$ curl -H "Host: alt1.local" http://127.0.0.1:8080/  -o /dev/null
HTTP 502                                       # alias matched, upstream not running

$ curl -H "Host: nonexistent.local" http://127.0.0.1:8080/  -o /dev/null
HTTP 404                                       # catch-all

$ curl -H "Host: guarded.local" http://127.0.0.1:8080/  -o /dev/null
HTTP 401                                       # Basic Auth challenge
```

Routes proxy identically to their Step I behaviour (alias matching
intact, catch-all intact, Basic Auth intact, Finding #9 chain order
`auth before WAF` preserved on guarded.local). ✅ PASS.

---

## 3. Phase B — Step J new features

Fresh scratch data-dir (option a per the smoke session decision —
Phase B should not carry the migrated Step I state forward).

### 3.1 B.1 (J.1) — Six LB policies + distribution

Created six routes, one per LB policy, all pointing at the same two
upstreams `:9201` + `:9202` (for `weighted_round_robin`, weights
1:4 → expected 20/80).

100 calls per policy via curl, distribution measured:

```
rr.local      100 calls → :9201=50  (50.0%)  :9202=50  (50.0%)
wrr.local     100 calls → :9201=20  (20.0%)  :9202=80  (80.0%)
lc.local      100 calls → :9201=52  (52.0%)  :9202=48  (48.0%)
iph.local     100 calls → :9201=100 (100.0%) :9202=0   ( 0.0%)
rnd.local     100 calls → :9201=54  (54.0%)  :9202=46  (46.0%)
frst.local    100 calls → :9201=100 (100.0%) :9202=0   ( 0.0%)
```

- `round_robin` → **50/50 exact** ✅
- `weighted_round_robin` (1:4) → **20/80 exact** ✅
- `least_conn` → 52/48, both reached, wired ✅
- `ip_hash` → 100/0, deterministic on same client IP ✅
- `random` → 54/46, both reached, wired ✅
- `first` → 100/0, failover behaviour (first upstream as long as
  it's reachable) ✅

✅ **AC #3 PASS** (six policies wired) — ✅ **AC #4 PASS** (round_robin
even) — ✅ **AC #5 PASS** (weighted proportional).

### 3.2 B.2 (J.2) — Active health check transition

Route `hc.local` with two upstreams + HC `enabled:true`, `interval:2s`,
`timeout:500ms`, `passes:2`, `fails:2`.

Baseline (both upstreams alive): 20 calls → 10/10 (perfect 50/50). ✅

Kill `:9202`, measure transition (10 calls per 1s tick):

```
tick  1  T+0.6s   :9201=5   :9202=0   502=5    # mid-flight
tick  2  T+1.8s   :9201=5   :9202=0   502=5    # one probe failed, second pending
tick  3  T+2.9s   :9201=10  :9202=0   502=0    # OUT OF ROTATION (fails=2 × interval=2s = ~4s theoretical max)
tick  4..12       :9201=10  :9202=0   502=0    # stable, 100% on :9201
```

Caddy log corroborates (`logger=http.handlers.reverse_proxy.health_checker.active`),
probes every 2s, error `connection refused` detected.

✅ **AC #6 PASS** — upstream pulled at T+2.9s, within theoretical
`fails × interval = 4s` window.

Restart `:9202`, measure recovery:

```
tick  1  T+0.1s   :9201=10  :9202=0     # still considered KO
tick  2  T+1.3s   :9201=10  :9202=0     # one probe passed
tick  3  T+2.4s   :9201=5   :9202=5     # BACK IN ROTATION
tick  4..12       :9201=5   :9202=5     # stable 50/50
```

✅ **AC #7 PASS** — upstream restored at T+2.4s, within theoretical
`passes × interval = 4s` window.

### 3.3 B.2 — AC #8 negative path

5 POSTs with invalid HC configs, each rejected with a clear API
error message:

| input                                  | expected | got                                                                 |
|----------------------------------------|----------|---------------------------------------------------------------------|
| `uri:""` with `enabled:true`           | 400      | ✅ 400 `"healthCheck.uri must not be empty when enabled"`           |
| `method:"POST"`                        | 400      | ✅ 400 `"healthCheck.method \"POST\" must be GET or HEAD"`          |
| `timeout >= interval`                  | 400      | ✅ 400 `"healthCheck.timeout must be strictly less than interval"`  |
| malformed `expect_body` regex          | 400      | ✅ 400 `"healthCheck.expectBody is not a valid regex: ..."`         |
| `passes: 0`                            | 400      | ⚠️ 201 + materialised to `passes:1` — see Finding F1 below          |

✅ **AC #8 PASS** (modulo F1 — see §5).

### 3.4 B.3 (J.3) — UI integration

Browser smoke: create a route `b3-via-ui.local` exercising every J.1
and J.2 UI surface in one form submission:

- Host typed, 3 upstreams added via `+ Add upstream` (LB selector
  appeared at row 2; weight column appeared on selecting
  `weighted_round_robin`).
- Weights typed `1`, `2`, `3`.
- HC sub-form deployed, enabled, filled with uri=`/healthz`,
  method=HEAD, interval=15s, timeout=3s, passes=3, fails=5,
  expectStatus=204.

Backend verification (read-back via `GET /routes` + direct BoltDB
dump): 18/18 fields traverse form → wire → BoltDB byte-for-byte
identical. Edit roundtrip in the modal re-displays every value.

✅ **PASS** — the J.7 §5.3 `openEdit round-trip` pivot test (`web/
frontend/src/routes/routes/page.test.ts`) is doubled in vivo.

### 3.5 B.4 (J.4) — DNS-01 wildcard live issuance

DNS provider configured via the Settings page with real OVH
credentials (endpoint `ovh-eu`, application key + secret + consumer
key for the `worldgeekwide.fr` zone). Badge transitioned to
"Configured" (green); placeholder `••• set (leave blank to keep)`
applied to all three secret inputs post-save (preserve-on-edit per
J.4 §5.4).

Route created via UI: host=`*.worldgeekwide.fr`, TLS enabled, ACME
challenge `dns-01` (automatically locked by the wildcard detection),
single upstream `http://127.0.0.1:9201`.

Submit at T0. Live tail of the Arenet log:

| T+      | event                                                    |
|---------|----------------------------------------------------------|
| 0.0s    | `enabling automatic TLS certificate management domains=[*.worldgeekwide.fr]` |
| 0.0s    | `lock acquired identifier=*.worldgeekwide.fr`           |
| 0.0s    | `ca=https://acme-staging-v02.api.letsencrypt.org/directory` ← γ recon validated live |
| 3.4s    | `new ACME account registered status=valid` (acct 295829963) |
| 3.4s    | `trying to solve challenge challenge_type=dns-01`       |
| 13.7s   | `authorization finalized authz_status=valid` ← LE DNS lookup ok |
| 17.3s   | `successfully downloaded available certificate chains count=3` |
| 17.3s   | `certificate obtained successfully issuer=acme-staging-v02.api.letsencrypt.org-directory` |

Total emission time: **~17 seconds** from Submit to wildcard cert
acquired. No error, no retry.

Cert stored at `~/Library/Application Support/Caddy/certificates/
acme-staging-v02.api.letsencrypt.org-directory/wildcard_.worldgeekwide.fr/`:

```
$ openssl x509 -in wildcard_.worldgeekwide.fr.crt -noout -subject -issuer -dates -ext subjectAltName
subject=CN=*.worldgeekwide.fr
issuer=C=US, O=Let's Encrypt, CN=(STAGING) Baloney Bulgur YE2
notBefore=May 25 21:05:15 2026 GMT
notAfter=Aug 23 21:05:14 2026 GMT
X509v3 Subject Alternative Name:
    DNS:*.worldgeekwide.fr
```

Browser end-to-end: `https://<any-subdomain>.worldgeekwide.fr:8443`
opens with the staging cert (browser warning expected — staging
roots not trusted), accept the warning → upstream `:9201` responds
`upstream-9201`. Full chain DNS-01 → cert → TLS server → reverse
proxy → upstream verified in vivo.

The spec §2 AC #9 wording explicitly allowed `PARTIAL or N/A` for
this AC. The smoke achieved **FULL**.

✅ **AC #9 FULL PASS** (promoted from acceptable PARTIAL).

### 3.6 B.5 (J.4 secret discipline) — AC #10

Three surfaces verified after the DNS provider was configured:

**API GET** (`/api/v1/settings/dns-providers/ovh`):

```json
{
    "endpoint": "ovh-eu",
    "applicationKey": "",
    "applicationSecret": "",
    "consumerKey": "",
    "configured": true
}
```

The three secrets are blanked server-side; `configured: true` is
the single status flag the UI binds to. ✅

**Audit log** (`dns_provider_updated` event):

```json
{
    "action": "dns_provider_updated",
    "targetType": "dns_provider",
    "targetId": "ovh",
    "beforeJson": null,
    "afterJson": {
        "endpoint": "ovh-eu",
        "application_key": "",
        "application_secret": "",
        "consumer_key": ""
    }
}
```

`beforeJson: null` is correct (first PUT, no prior row). `afterJson`
blanks all three secret fields verbatim. ✅

**BoltDB at-rest**: secrets stored in cleartext (16, 32, 32 chars
respectively, first 4 chars validate as expected OVH token shape).
This is the §5.4 design decision — Arenet must replay the credentials
to OVH at every cert renewal, hashing is therefore unusable. The
protection boundary is the BoltDB file's POSIX permissions (`0o600`,
operator-owned). At-rest encryption is out of scope v1.0 (backlog).

✅ **AC #10 PASS** — wire / audit blanked, BoltDB cleartext per design.

### 3.7 B.6 (J.6) — Topology auto-fit + PageHeader

Initial nav check (§2.7 above): `/topology` opens with the standard
`<PageHeader>` + `<StatusDot>` atomic in the actions slot, connection
status indicator visible. ✅

Post-B.3, with 9 routes in the BoltDB (6 B.1 + B.2 `hc.local` + B.3
`b3-via-ui.local` + B.4 `*.worldgeekwide.fr`): reopen `/topology` from
cold — the graph auto-fits the viewport on first non-empty data (no
zoomed-out blank, no zoomed-in microscopic, fits the rendered area
with padding). Pan / wheel-zoom / overlay buttons (Fit / Reset / +/−)
all functional.

✅ **AC #13 PASS** — visual redesign delivered via `<PageHeader>` +
`<StatusDot>` adoption + auto-fit on first non-empty data tick (Step
I Finding #10 resolved per the J.6 `shouldAutoFit` predicate + 11
new tests in `auto-fit.test.ts` + `topology/page.test.ts`).

---

## 4. AC validation matrix

The authoritative checklist for the tag.

| AC   | Description                                | Phase    | Result        |
|------|--------------------------------------------|----------|---------------|
| #1   | Multi-upstream pool round-trip             | B.1+B.3  | ✅ PASS       |
| #2   | Backward-compatible migration + idempotent + traffic identity | A | ✅ PASS |
| #3   | Six LB policies selectable + emitted       | B.1      | ✅ PASS       |
| #4   | round_robin distribution                   | B.1      | ✅ PASS (50/50) |
| #5   | weighted_round_robin distribution          | B.1      | ✅ PASS (20/80 on 1:4) |
| #6   | HC active removes failed upstream          | B.2      | ✅ PASS (T+2.9s) |
| #7   | HC active restores recovered upstream      | B.2      | ✅ PASS (T+2.4s) |
| #8   | HC config validation rejection             | B.2      | ✅ PASS (4/5 rules + F1 spec contradiction on the 5th) |
| #9   | DNS-01 wildcard issuance                   | B.4      | ✅ **FULL PASS** (promoted from acceptable PARTIAL — live cert emitted in 17s) |
| #10  | DNS provider credentials never echoed      | B.5      | ✅ PASS       |
| #11  | `audit_waf_match` event                    | —        | **DEFERRED §1.4** |
| #12  | `X-WAF-Match` header                       | —        | **DEFERRED §1.4** |
| #13  | Topology visual pass + auto-fit            | A + B.6  | ✅ PASS       |
| #14  | Frontend gates (`npm check` + `npm test`)  | 1.2      | ✅ PASS (174/174) |
| #15  | `go test ./...` green                      | 1.1      | ✅ PASS (7 packages) |
| #16  | `gofmt` + `go vet` + frontend linter clean | 1.1+1.2  | ✅ PASS       |
| #17  | Bundle budget                              | 1.2      | ✅ PASS (8 KB gz vs 30 kB) |

**Tally: 15 AC PASS, 2 DEFERRED per §1.4, 0 FAIL.**

---

## 5. Findings

### Finding F1 — spec §7 phase B.2 contradicts §5.2 on `passes: 0`

**Surface**: spec §7 phase B.2 (smoke plan, the AC #8 negative-path
sample list) cites `passes: 0` as a config that should be rejected
at the API layer.

**Code behaviour observed**: a POST with `passes: 0` is **accepted**.
The API layer's `materialiseHealthCheck` injects the default value
`1` for any zero / blank numeric HC sub-field (§1.3 decision 4
"Arenet materialises the defaults"). The subsequent
`validateHealthCheck` sees `passes: 1` and accepts.

**Why it's not a code bug**: §5.2 spells out the validation rules as
applying **post-materialisation**:

> "The API layer injects [the five defaults] on every create and
> update where `HealthCheck.Enabled` is true and the corresponding
> field is blank (zero string or zero int). The injection runs
> **before** validation, so the validation rules below face a
> fully-populated `HealthCheck`."

…then later:

> "`passes >= 1` and `fails >= 1`."

i.e. the rule `passes >= 1` is enforced on the **materialised** value,
which by construction is always `>= 1` after the materialise step.
The `passes: 0` input is therefore "blank-equivalent → use default
1", not "invalid". This is consistent with §1.3 decision 4 and with
the J.3 client-side validator (`page.svelte` rejects `passes < 0`
only, not `passes < 1`, with the matching inline comment "0 means
use default → blank-equiv, don't reject").

**Verdict**: spec §7 phase B.2 sample list is incorrect — the author
likely intended `passes: -1` (which IS rejected, both client-side
and server-side) but wrote `passes: 0`. The code is correct; §7
needs an amend.

**Action**: log to `docs/backlog-step-j.md` as a post-tag spec
amend (no code change needed). The §7 sample should either:
- be removed (the other four samples cover the rule space anyway)
- or replaced by `passes: -1` (negative value, genuinely rejected)
- or extended to mention that `passes: 0` is intentionally
  default-materialised, not rejected

**Severity**: spec doc fix, not a code defect. Non-blocking for the
tag.

---

## 6. Acknowledged debt (post-tag follow-ups)

Larger items recorded in `docs/backlog-step-j.md`. Highlights:

- **WAF observability completion** (AC #11, AC #12 — DEFERRED) —
  `coraza-caddy v2.5.0` exposes no hook to Coraza's matched rules;
  the only path is a custom Caddy module consuming `coraza/v3`
  directly (~600 LoC, security-critical). Disproportionate ownership
  for the observability surface; revisit if `coraza-caddy` lands a
  match hook or as a dedicated WAF step.

- **ACME directory / `--dev` coupling** — `acmeDirectoryURL(devMode)`
  ties the LE directory choice (staging vs prod) to the same `--dev`
  flag that picks listen ports. An operator who wants to dry-run
  DNS-01 against LE staging while keeping prod listen ports cannot.
  Mini-design recorded: env `ARENET_ACME_DIRECTORY_URL` (~15 LoC
  Go + 1 test). Worked around for this smoke via option γ (run
  in `--dev`, accept `:8443` port acknowledgement); the AC #9 wording
  explicitly allowed PARTIAL, but the smoke achieved FULL anyway.
  Already backlogged in `ffba2fa`.

- **F1 — spec §7 phase B.2 amend** (this smoke). `passes: 0` is
  default-materialised, not rejected; §7 sample list is incorrect.
  Spec doc fix, post-tag.

- **§5.3 frontend test suite** — closed by `30c388f` (this is the
  blocking debt that was promoted before this smoke).

- **J.4 frontend test gap** (acmeChallenge selector + (β) bandeaux
  + Settings DNS provider section) — recorded, not blocking,
  post-v0.6.0 follow-up.

- **Topology code-quality debt** (Sparkline extraction, Tooltip
  atomic migration in TopologyNode, Vitest coverage on visual
  components) — recorded, out of J.6 scope.

- **Migration pattern debt** (full-Route round-trip is fragile when
  removing fields; passthrough-map pattern required) — recorded
  during J.1 from Step I.4 root cause; rule documented for future
  migrations.

- **`@testing-library/svelte` scaffold note was stale** — corrected
  during J.6 recon (scaffold installed since Step F; the J.3 backlog
  entry described a gap that no longer existed). Now closed.

---

## 7. Verdict

**PASS — ship `v0.6.0-step-j`.**

15 acceptance criteria met (every active AC). 2 AC explicitly DEFERRED
by spec §1.4 (WAF observability completion — AC #11, AC #12). 0 AC
in FAIL state.

The one finding (F1) is a spec-doc contradiction with no code
implication, slated for a post-tag spec amend in
`docs/backlog-step-j.md`.

The DNS-01 acceptance criterion AC #9, which the spec explicitly
allowed to record as PARTIAL given the dependency on a real DNS
provider, was achieved in FULL: a wildcard certificate for
`*.worldgeekwide.fr` was emitted in 17 seconds against Let's Encrypt
staging via the OVH provider integration, and verified end-to-end
through the browser (cert presented by Arenet on `:8443`, upstream
proxied through).

---

## 8. Tag procedure (after PASS)

```bash
cd /Users/l.ramos/Documents/Projets/AreNET
git status                                # working tree clean expected
git checkout main
git pull --ff-only
# Commit this smoke doc + the F1 backlog entry first.
# Then:
git tag -a v0.6.0-step-j -m "Step J — Multi-upstream LB + DNS-01 ACME (OVH)"
git push origin v0.6.0-step-j
```

Tag message body suggestion:

```
Step J — Multi-upstream Load Balancing + DNS-01 ACME (OVH)

Sub-tasks J.1 → J.7 (J.5 deferred per §1.4):
- J.1 Multi-upstream pool + 6 LB policies + BoltDB migration
- J.2 Active health checks per route
- J.3 Multi-upstream UI (repeater + LB selector + HC sub-form)
- J.4 DNS-01 ACME (OVH) + Settings UI
- J.6 Topology visual pass (PageHeader + auto-fit)
- J.7 Closeout (§5.3 Routes-page test suite + live smoke)

15 / 15 active acceptance criteria PASS. 2 AC DEFERRED per §1.4
(WAF observability completion).

Live smoke: docs/smoke-test-step-j.md
Verdict: SHIP-READY.
```

---

**End of smoke doc.**
