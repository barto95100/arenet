# Arenet - Homelab-friendly reverse proxy with integrated security
# Copyright (C) 2026  Ludovic Ramos
# Licensed under the GNU AGPL v3 or later. See LICENSE.

# Step S.1 — Multi-arch Docker image (linux/amd64 + linux/arm64).
#
# Three stages:
#   1. frontend — Node 20 Alpine builds the SvelteKit SPA into
#      web/frontend/build/. The build is consumed by stage 2 via
#      COPY --from=frontend.
#   2. backend — Go 1.25 Alpine compiles the static binary with
#      CGO_ENABLED=0 (distroless requires it). The frontend build
#      is copied INTO the source tree before `go build` so the
#      //go:embed directive at web/embed.go picks it up.
#   3. runtime — distroless static-debian12:nonroot. No shell, no
#      package manager, no debug tooling. Operators rely on
#      `docker logs`, `docker inspect`, `docker stats`, and the
#      built-in `arenet --healthcheck=...` subcommand.
#
# Build (multi-arch via buildx, push to a registry):
#
#   docker buildx build \
#     --platform linux/amd64,linux/arm64 \
#     --tag ghcr.io/barto95100/arenet:v1.0.0 \
#     --build-arg VERSION=v1.0.0 \
#     --push .
#
# Build (single-arch, local-only):
#
#   docker build --build-arg VERSION=v1.0.0-dev -t arenet:dev .
#
# The VERSION build arg lands at -X main.version=...; defaults to
# "dev" when omitted so a local `docker build` still produces a
# binary that reports a non-DEV version string.

# -----------------------------------------------------------------
# Stage 1 — frontend build (SvelteKit → static HTML+CSS+JS)
# -----------------------------------------------------------------
FROM node:24-alpine AS frontend
WORKDIR /src/web/frontend

# Layer-cached deps install: copy lockfiles first.
COPY web/frontend/package.json web/frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Now copy the actual source + build.
COPY web/frontend ./
RUN npm run build

# -----------------------------------------------------------------
# Stage 2 — Go backend build (static, stripped)
# -----------------------------------------------------------------
FROM golang:1.25-alpine AS backend
WORKDIR /src

# go.mod / go.sum first for layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Whole repo for the embed directive (web/embed.go reads
# all:frontend/build); the frontend build comes from stage 1.
COPY . .
COPY --from=frontend /src/web/frontend/build /src/web/frontend/build

# Cross-compile target derived from buildx TARGETOS/TARGETARCH.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

# Static binary. CGO_ENABLED=0 is mandatory for distroless/static
# (no libc). -ldflags "-s -w" strips debug symbols; -trimpath
# removes local paths from stack traces. The version string is
# injected at -X main.version.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -trimpath \
      -o /out/arenet \
      ./cmd/arenet

# Pre-create the runtime data dir so stage 3 can COPY it into the
# image with nonroot ownership (named-volume case fix).
RUN mkdir -p /out/data

# -----------------------------------------------------------------
# Stage 3 — distroless runtime
# -----------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# The distroless `nonroot` user is uid:gid 65532:65532. The Go
# binary lives at /usr/local/bin/arenet; the data directory at
# /var/lib/arenet matches the spec D4 default.
COPY --from=backend /out/arenet /usr/local/bin/arenet

# Pre-create /var/lib/arenet with nonroot ownership so named
# volumes inherit the correct ownership on first mount. Without
# this, Docker creates the dir implicitly via WORKDIR with root
# ownership, and the named volume becomes root-owned → nonroot
# (UID 65532) can't write → restart loop with permission denied.
# Bind mounts require the operator to chown the host dir
# separately (see docs/install/docker-quickstart.md).
COPY --from=backend --chown=nonroot:nonroot /out/data /var/lib/arenet

# Data plane ports + admin port. The container EXPOSE is purely
# informational — Docker doesn't open ports without an explicit
# `-p` / compose `ports:` directive.
EXPOSE 80 443 8001

# TLS cert storage path fix. certmagic stores certs under
# caddy.AppDataDir() = $HOME/.local/share/caddy on Linux. The
# distroless base sets NO $HOME (unlike systemd, which derives it
# from the arenet user's passwd entry), so without this the binary
# falls back to a relative "./caddy" dir resolved against WORKDIR —
# a different, cwd-dependent path that breaks reverse-proxy TLS in
# Docker while working fine on the binary. Pinning HOME here makes
# the container store certs at /var/lib/arenet/.local/share/caddy,
# identical to the systemd install and to what the docs describe.
# This ENV is the LOAD-BEARING fix: it is set before the process
# starts, so it is visible at program init when caddy.DefaultStorage
# freezes AppDataDir() (caddy/v2 storage.go:160). The Go-side
# resolveCertStorageHome() runs after init and only aligns certinfo's
# live-derived paths — it canNOT move Caddy's already-frozen storage,
# so setting HOME in the image is what actually repairs the handshake.
ENV HOME=/var/lib/arenet

# Run as nonroot (uid 65532). The systemd unit ships the same
# pattern via User=arenet + CAP_NET_BIND_SERVICE; Docker handles
# privileged-port bind via the runtime's CAP_NET_BIND_SERVICE
# (compose `cap_add: [NET_BIND_SERVICE]` makes it explicit).
USER nonroot:nonroot
WORKDIR /var/lib/arenet

# Distroless has no shell, so the entrypoint is the binary
# directly (no `sh -c` wrapping). Operators pass flags via
# compose `command:` or env vars.
ENTRYPOINT ["/usr/local/bin/arenet"]
CMD ["--admin-port=:8001", "--data-dir=/var/lib/arenet"]
