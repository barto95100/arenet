# Troubleshooting

A short list of expected-but-surprising boot messages and the
"my install is broken" first-aid checklist. If your issue isn't
here, open an issue with the relevant log snippets.

## Boot warnings that are NOT errors

### "tee not found in $PATH" (dev mode only)

```
level=error msg="failed to install root certificate"
error="failed to execute tee: exec: \"tee\": executable file not found in $PATH"
```

**What it means**: in `--dev` mode Caddy attempts to install
its local-CA root cert by shelling out to `/usr/bin/tee`. The
distroless container image has no shell tools, so the install
fails non-fatally. The binary keeps running; the local-CA cert
just isn't trusted by the host (which doesn't matter in dev).

**Action**: none. In production (`--dev` not set) the local-CA
flow isn't used — ACME via Let's Encrypt is used instead, no
tee dependency.

### Admin port in old smoke logs: `:9994`

If you find log snippets from Step M / N / O / P / Q showing
admin on `:9994`, those are smoke-test artefacts. The
**production default is `:8001`** — that's what the binary's
`--admin-port` flag has defaulted to since Step D. Each
previous smoke explicitly passed `-admin-port=:9994` to avoid
collision with whatever else was running on the dev box; that
override was smoke-local, not the production default.

**Action**: none. Use `:8001` everywhere unless you've
explicitly set `ARENET_ADMIN_BIND` to something else.

### "no trusted proxies configured (X-Forwarded-For will be ignored)"

```
level=INFO msg="auth: no trusted proxies configured (X-Forwarded-For will be ignored)"
```

**What it means**: Arenet IS the reverse proxy in this
deployment; the operator hasn't told it to trust any upstream
proxy's X-Forwarded-For headers. Source IPs come from the
TCP connection directly.

**Action**: none unless you're running Arenet behind another
reverse proxy / CDN (Cloudflare, etc.). In that case, set
`ARENET_TRUSTED_PROXIES` to a comma-separated CIDR list of
the upstream proxies.

### "crowdsec bouncer not configured"

```
level=INFO msg="crowdsec bouncer not configured (set ARENET_CROWDSEC_API_KEY to enable the IP-reputation gate)"
```

**What it means**: you haven't wired Arenet to a CrowdSec
LAPI. The proxy still serves traffic; the IP-reputation
defence layer is just inactive.

**Action**: none unless you want to enable it. See
`docs/install/docker-quickstart.md` for the wiring.

## "I can't reach the admin port"

Checklist in priority order:

1. **The admin port is loopback-bound by default.** From a LAN
   machine, `curl http://<host>:8001/healthz` will fail.
   Either SSH-tunnel or set `ARENET_ADMIN_BIND=0.0.0.0:8001`
   (see `docs/install/docker-quickstart.md`).
2. **Healthcheck reports unhealthy in `docker compose ps`?**
   Check the logs:
   ```bash
   docker compose logs arenet | tail -50
   ```
   Usual culprits: another service on :80/:443, volume mount
   permissions, malformed env var values.
3. **Service won't start at all (systemd)?**
   ```bash
   sudo journalctl -u arenet -n 50
   ```
   Common: `/usr/local/bin/arenet` missing or not executable;
   `/var/lib/arenet` permissions drifted; env file has a typo.
4. **Port collision?**
   ```bash
   sudo ss -tlnp | grep -E ':(80|443|8001)'
   ```
   If something else is bound to one of those, change either
   the other thing or Arenet's bind via env vars.

## "I'm getting 429 Too Many Requests"

Step Q + S.4 rate-limit failed auth attempts per source IP.
10 wrong passwords in a row triggers a 15-minute block; the
next batch triggers a 1-hour block.

If you've locked yourself out:

1. Wait for the Retry-After window (the 429 response header
   tells you).
2. From the same source IP, a successful login resets the
   counter — so if you remember the password, retry once the
   window passes.
3. Last resort (if you've truly lost the admin password):
   stop the binary, use `arenet --restore` with a fresh user
   file (see `docs/operations/backup.md` for the restore
   path), restart.

## "I changed config but nothing happened"

Config precedence is `flag > env > TOML > default` per-field.
If you edited the TOML but the binary still uses an env value,
the env wins. The first INFO log line shows the resolved
values:

```
level=INFO msg="Arenet starting" version=v1.0.0 admin_port=:8001 data_dir=/var/lib/arenet dev=false
```

Compare those to what you expected; the field that differs
points at which precedence layer is overriding.

## "Schema migration failed on upgrade"

Step D8 auto-migrates schemas forward on first boot of a new
binary version. If a migration errors out, the binary refuses
to start.

1. Capture the error from the journal:
   ```bash
   sudo journalctl -u arenet --since "5 min ago" | grep -i migrat
   ```
2. **Restore from your backup** (the cold-stop + tar
   procedure documented in `docs/operations/backup.md`).
3. Open an issue with the migration error + your version
   transition path (e.g. v1.0.0 → v1.1.0).

If you didn't take a backup before upgrading, downgrade the
binary to the previous version — most schema migrations are
forward-only but the rollback is at the operator's discretion;
older binaries refuse to start against a newer schema (would
silently corrupt). The safe path is restore.

## Where to find logs

| Install | Command |
|---|---|
| Docker compose | `docker compose logs -f arenet` |
| systemd | `sudo journalctl -u arenet -f` |
| Local dev | binary's stdout/stderr in your terminal |

Log level defaults to `info`. Bump to `debug` via
`ARENET_LOG_LEVEL=debug` for boot diagnostics; do not leave
debug enabled in production (verbose + leaks request paths).
