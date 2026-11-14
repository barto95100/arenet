<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec — access-log journald duplicate / secret leak. Target: v2.81.1.
-->

# Access-log journald duplicate & secret leak — design

**Target version:** v2.81.1 (patch — security fix, additive to the emitted
Caddy config only when the access log is enabled)

## Problem

When the HTTP access log is enabled (`AccessLogConfig.Enabled`), Arenet
emits a single `logging.logs.arenet_access` sink that writes to a **file**
through a `filter` encoder (header + URI-param redaction) — see
`internal/caddymgr/access_log.go:174-211`, `manager.go:2570-2571`.

Arenet defines **no `default` logger**. Caddy therefore auto-creates one
(`caddy/logging.go:143-153` → `newDefaultProductionLog`): writer `stderr`,
plain JSON encoder under systemd (no TTY), **no include/exclude**. A log
with no include/exclude accepts every entry (`logging.go:227-229`,
`loggerAllowed:533-536`), so **every access entry is emitted twice**:

| Destination | Encoder | Secrets | Bounded by |
|---|---|---|---|
| File (`arenet_access` sink) | `filter` → redacted | masked ✓ | Arenet roll config ✓ |
| stderr → journald (auto `default`) | plain JSON | **in clear** ✗ | journald only ✗ |

Empirically confirmed on the operator's test VM (2026-11-14): the journald
copy shows `"Csrfpreventiontoken":["6AF20E6B:…"]` in clear (only Caddy's
four native headers — cookie/set-cookie/authorization/proxy-authorization —
are masked there), while the file shows `"Csrfpreventiontoken":["REDACTED"]`.

Two consequences:
1. **Secret leak.** Every credential the file masks (CSRFPreventionToken,
   `X-Api-Key`, `access_token=` URI params, …) is written in clear to the
   journal, which also survives log rotation and is often forwarded.
2. **Double write / unbounded journal.** Every request is logged twice; the
   journal copy ignores Arenet's roll ceiling.

This also explains the operator's point 2: `CSRFPreventionToken` is **not**
a gap in the redaction list — it contains the substring `token`, so
`logredact.IsSecretHeader` already masks it **in the file**. The leak is the
unfiltered journald duplicate, not the filter.

## Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| 1 | When the access log is on, `buildAccessLogging` also emits an explicit `default` logger carrying only `{"exclude": ["http.log.access.arenet_access"]}`. | Stops the access entries fanning out to the auto-created default/stderr logger. A `default` log with no writer/encoder falls back to stderr + the production encoder (`provisionCommon:350-351,381-383`), so all other (runtime) logs still reach the journal unchanged. |
| 2 | The `exclude` value is `accessLogInclude` (the composed `http.log.access.arenet_access`), reusing the existing constant. | Same name the file sink `include`s; the two cannot drift. Caddy's exclude matches it exactly (`loggerAllowed` prefix rule). |
| 3 | The off case stays byte-identical: no `logging` block emitted when the access log is disabled. | Non-regression for every install that never enables the log — unchanged from v2.50. |
| 4 | No change to the redaction filter, the file sink, or `default_logger_name`. The file remains the single, filtered, bounded access-log artifact. | The file was always the intended CrowdSec input (v2.50 design). Only the accidental journald duplicate is removed. |
| 5 | CrowdSec consumes the **file** (option B), not the journal. Documented, not auto-configured — Arenet never edits CrowdSec config behind the operator's back. | The file is filtered (no secrets into CrowdSec's DB) and bounded. Option A (journalctl) would require keeping the unfiltered duplicate. |

## Non-goals

- A Prometheus `/metrics` endpoint or auto-classify visibility — that is the
  separate lot 2 (point 3), tracked in its own spec.
- Changing where the file lands (`ResolveAccessLogPath` unchanged). The
  acquisition doc covers both the systemd `/var/log/arenet` path and the
  data-dir fallback `<data-dir>/logs/access.log`.
- Real per-request dedup or any change to what the file contains.

## Empirical gates

- `TestBuildConfigJSON_AccessLogOn_ExcludesAccessFromDefault` (new): with the
  log on, `logging.logs.default.exclude == ["http.log.access.arenet_access"]`.
  Reinjection: dropping the `default` entry fails it.
- `TestBuildConfigJSON_AccessLogOff_ByteIdentical` (existing): still passes —
  off emits no logging block.
- `TestBuildConfigJSON_LoadsCleanly_WithAccessLog` (existing, extended):
  `caddy.Validate` accepts the config with the explicit `default` logger.
- Live confirmation (operator, post-deploy): the journal no longer carries
  `http.log.access.arenet_access` lines; the file still does, redacted.
- Gates: `go build`, `go vet`, `gofmt -s`, `go test -race ./internal/caddymgr/`.

## Operator-facing

- Wiki `CrowdSec.md` / `CrowdSec-FR.md`: document the file acquisition
  (`/etc/crowdsec/acquis.d/arenet.yaml`, `labels: {type: caddy}`), the
  `crowdsecurity/caddy` collection, the two possible file paths, and the
  `/var/lib/arenet` 0700 permission (CrowdSec reads as root).
- No UI change; no new setting.
