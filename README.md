# Arenet

A homelab-friendly reverse proxy with integrated security, built on Caddy.

**Status:** v1.0 ship target — see [`docs/install/`](docs/install/) for deployment.

## Quickstart

Two install paths, both ≤5 minutes:

- **Docker** (recommended): [`docs/install/docker-quickstart.md`](docs/install/docker-quickstart.md)
- **Native Linux + systemd**: [`docs/install/systemd-native.md`](docs/install/systemd-native.md)

## Features

- 🔒 Integrated WAF via Coraza (OWASP CRS)
- 🛡️ Native CrowdSec bouncer for community threat intel
- 🎯 Live topology dashboard with real-time traffic visualization
- 🚀 Built on Caddy v2 (auto-HTTPS, HTTP/3, modern TLS)
- 📊 Per-route metrics, advanced health checks
- 🏠 Single-binary deployment, homelab-friendly UI
- 🎨 OKLCH visual system (Step R, v1.4)

## Documentation

- [`docs/install/`](docs/install/) — Docker + systemd install paths.
- [`docs/operations/`](docs/operations/) — backup, hardening, config, troubleshooting (post-S.4).
- [`docs/superpowers/specs/`](docs/superpowers/specs/) — per-step specs (M / N / O / P / R / S).

## License

AGPL-3.0 — see [LICENSE](LICENSE).

Inspired by [Zoraxy](https://github.com/tobychui/zoraxy) by tobychui, rebuilt on top of Caddy for production-grade security features.
