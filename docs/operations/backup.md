# Backup &amp; restore

Arenet's state lives in three files inside the data directory
(`/var/lib/arenet` by default):

- `arenet.db` — BoltDB: routes, users, audit log, secrets.
- `metrics.db` — SQLite: observability counters + WAF/throttle
  event history.
- `audit.db` — (if present) audit-specific overflow store.

Plus the certmagic subdirectory:

- `certmagic/` — TLS certs + ACME account state.

The canonical backup is a **cold snapshot**: stop the binary,
tar the data directory, restart. BoltDB does not support hot
snapshots in v1.0 (a `--backup` subcommand is on the roadmap).

## Backup (Docker)

```bash
docker compose stop arenet
docker run --rm \
    -v arenet-data:/data:ro \
    -v "$(pwd)":/out \
    alpine:latest \
    tar czf /out/arenet-backup-$(date +%Y%m%d-%H%M%S).tar.gz -C /data .
docker compose start arenet
```

The downtime is the tar duration — typically &lt;5 seconds for a
homelab-sized state. Add the script to cron / systemd timer for
recurring snapshots.

## Backup (systemd native)

```bash
sudo systemctl stop arenet
sudo tar czf /var/backups/arenet-$(date +%Y%m%d-%H%M%S).tar.gz \
    -C /var/lib/arenet .
sudo systemctl start arenet
```

## Restore

```bash
# Docker:
docker compose stop arenet
docker run --rm \
    -v arenet-data:/data \
    -v "$(pwd)":/in \
    alpine:latest \
    sh -c "rm -rf /data/* && tar xzf /in/arenet-backup-YYYYMMDD-HHMMSS.tar.gz -C /data"
docker compose start arenet

# systemd:
sudo systemctl stop arenet
sudo rm -rf /var/lib/arenet/*
sudo tar xzf /var/backups/arenet-YYYYMMDD-HHMMSS.tar.gz -C /var/lib/arenet
sudo chown -R arenet:arenet /var/lib/arenet
sudo systemctl start arenet
```

## Verify

After restore, the audit log should show the route mutations
from before the snapshot:

```bash
curl -s http://127.0.0.1:8001/api/v1/audit?limit=10 | jq '.events[].action'
```

## What's NOT in the backup

- Caddy's runtime listeners (recreated from the BoltDB config
  on boot).
- The OWASP CRS rules (embedded in the binary, not state).
- Live observability counters in-flight at snapshot time (any
  partial-minute counter is lost; the next minute's bucket
  starts fresh).

## Hot-snapshot roadmap

A future `arenet backup --to PATH` subcommand will wrap
`bbolt.Tx.WriteTo` for online BoltDB snapshots + SQLite's `VACUUM
INTO` for the observability store, removing the cold-stop
requirement. Tracked in the v1.x backlog.
