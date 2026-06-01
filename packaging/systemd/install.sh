#!/usr/bin/env bash
# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  Ludovic Ramos
# Licensed under the GNU AGPL v3 or later. See LICENSE.
#
# Step S.2 — Native Linux install script for the systemd unit.
#
# What it does (idempotent — safe to re-run):
#   1. Creates the system user `arenet` (no shell, no home dir
#      content) if it doesn't already exist.
#   2. Creates /var/lib/arenet owned by arenet:arenet.
#   3. Creates /etc/arenet for the optional env file.
#   4. Copies arenet.service to /etc/systemd/system/.
#   5. Reloads systemd's unit registry.
#
# What it does NOT do:
#   - Install the `arenet` binary. The operator is expected to
#     have placed it at /usr/local/bin/arenet ahead of time
#     (download from releases page, build locally, etc.).
#   - Enable or start the unit. The operator runs
#     `systemctl enable --now arenet` once they're ready.
#   - Configure DNS provider, ACME email, etc. — that's the
#     /setup wizard's job on first boot.
#
# Usage:
#   sudo ./install.sh
#
# Uninstall (not provided as a script — left to the operator
# because deleting state is irreversible):
#   sudo systemctl stop arenet
#   sudo systemctl disable arenet
#   sudo rm /etc/systemd/system/arenet.service
#   sudo systemctl daemon-reload
#   # The data dir at /var/lib/arenet is preserved — delete
#   # manually if you really want to wipe state.

set -euo pipefail

# Pre-flight: must be root (writes to /etc, creates users).
if [[ $EUID -ne 0 ]]; then
	echo "error: install.sh must be run as root (try: sudo $0)" >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_FILE="${SCRIPT_DIR}/arenet.service"

if [[ ! -f "${UNIT_FILE}" ]]; then
	echo "error: arenet.service not found next to install.sh (${UNIT_FILE})" >&2
	exit 1
fi

# Pre-flight: binary must exist where the unit expects.
if [[ ! -x /usr/local/bin/arenet ]]; then
	echo "warning: /usr/local/bin/arenet not found or not executable." >&2
	echo "         Install the binary there before starting the service." >&2
	echo "         Continuing with the systemd-unit install anyway." >&2
fi

# 1. Create the system user.
if id arenet >/dev/null 2>&1; then
	echo "user 'arenet' already exists — skipping useradd"
else
	echo "creating system user 'arenet'"
	useradd \
		--system \
		--no-create-home \
		--home-dir /var/lib/arenet \
		--shell /usr/sbin/nologin \
		--user-group \
		arenet
fi

# 2. Data directory.
echo "ensuring /var/lib/arenet exists"
install -d -o arenet -g arenet -m 0750 /var/lib/arenet

# 3. Config directory (for the optional env file).
echo "ensuring /etc/arenet exists"
install -d -o root -g root -m 0755 /etc/arenet

# Drop a commented sample env file ONLY if the operator hasn't
# already created one (don't overwrite their config).
if [[ ! -f /etc/arenet/arenet.env ]]; then
	cat > /etc/arenet/arenet.env <<'EOF'
# Arenet env file — sourced by the systemd unit via
# EnvironmentFile=-/etc/arenet/arenet.env.
#
# Uncomment + edit the values below to override the binary's
# defaults. All keys are optional.

# ARENET_ADMIN_BIND=127.0.0.1:8001
# ARENET_DATA_DIR=/var/lib/arenet
# ARENET_LOG_LEVEL=info
EOF
	chmod 0644 /etc/arenet/arenet.env
	echo "wrote /etc/arenet/arenet.env (sample, commented out)"
else
	echo "/etc/arenet/arenet.env already exists — preserving operator config"
fi

# 4. Install the unit.
echo "installing arenet.service to /etc/systemd/system/"
install -o root -g root -m 0644 "${UNIT_FILE}" /etc/systemd/system/arenet.service

# 5. Reload systemd so it picks up the new unit.
echo "reloading systemd unit registry"
systemctl daemon-reload

echo
echo "Install done."
echo
echo "Next steps:"
echo "  1. Place the arenet binary at /usr/local/bin/arenet"
echo "     (download from releases page, or build with"
echo "      'cd cmd/arenet && go build -o /usr/local/bin/arenet')."
echo "  2. Optionally edit /etc/arenet/arenet.env to override defaults."
echo "  3. Start the service:"
echo "       sudo systemctl enable --now arenet"
echo "  4. Watch the boot logs for the setup token:"
echo "       sudo journalctl -u arenet -f | grep 'Setup token'"
echo "  5. Open http://localhost:8001 (or via SSH tunnel from a"
echo "     remote workstation) to complete /setup."
