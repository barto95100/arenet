<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan — access-log journald duplicate / secret leak. Target: v2.81.1.
-->

# Access-log journald duplicate & secret leak — plan

Spec: `docs/superpowers/specs/2026-11-14-access-log-journal-leak-design.md`

## T1 — guard first (fails on unmodified code)

- `internal/caddymgr/access_log_test.go`: add
  `TestBuildConfigJSON_AccessLogOn_ExcludesAccessFromDefault` asserting
  `logging.logs.default.exclude == ["http.log.access.arenet_access"]`.
  Run → RED on current code (no `default` logger emitted).

## T2 — emit the explicit default logger

- `internal/caddymgr/access_log.go` `buildAccessLogging`: return a `logs`
  map with both `default` (`{"exclude": [accessLogInclude]}`) and the
  existing `arenet_access` sink. Comment the why (journald duplicate +
  secret leak).
- Run the new test → GREEN. Reinject (drop the `default` entry) → RED,
  siblings still green. Restore from cp backup.

## T3 — extend existing guards

- `TestBuildConfigJSON_AccessLogOn_SinkAndServers`: also assert the
  `default` logger + its exclude, so the two sinks are checked together.
- `TestBuildConfigJSON_LoadsCleanly_WithAccessLog`: unchanged assertion, but
  confirm `caddy.Validate` still accepts the config with the default logger
  (it does — exclude-only default is valid).
- `TestBuildConfigJSON_AccessLogOff_ByteIdentical`: confirm still green.

## T4 — docs (operator deployment of the acquisition)

- `docs/wiki-seed/CrowdSec.md` + `CrowdSec-FR.md`: a "Feed Arenet's access
  log to CrowdSec" section —
  - `cscli collections install crowdsecurity/caddy`
  - `/etc/crowdsec/acquis.d/arenet.yaml` with `filenames:` +
    `labels: {type: caddy}`
  - both file paths (`/var/log/arenet/access.log` systemd,
    `<data-dir>/logs/access.log` fallback) and how to find the real one in
    Settings → Security
  - the `/var/lib/arenet` 0700 note (CrowdSec reads as root)
  - `systemctl reload crowdsec` + `cscli metrics` / `cscli parsers list` to
    verify acquisition.
- `docs/install/systemd-native.md`: note that the access log is file-only
  (no longer duplicated to the journal) from v2.81.1.

## Gates

`go build ./...`, `go vet ./...`, `gofmt -s`, `go test -race
./internal/caddymgr/`. Reinjection proof for the one load-bearing guard
(default-logger exclude).

## Out

No Prometheus endpoint (lot 2), no path-resolution change, no CrowdSec
config auto-edit, no release tag without operator go-ahead.
