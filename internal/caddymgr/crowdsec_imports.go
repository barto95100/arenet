// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see https://www.gnu.org/licenses/.

package caddymgr

// Step N.1 — register the caddy-crowdsec-bouncer Caddy modules
// at process load time. The bouncer's `imports.go` does the same
// for downstream caddy-builds: pull in the `crowdsec` app
// (apps.crowdsec) and the `http` handler (http.handlers.crowdsec)
// via blank imports so Caddy's module registry knows about both
// IDs before our emitted JSON config asks for them.
//
// The bouncer also registers `appsec` and `layer4` modules. Step N
// v1.0 exercised neither, but v2.42 emits `layer4.matchers.crowdsec`
// for TCP services with CrowdSec armed — and each of the bouncer's
// subpackages registers ONLY its own module in its own `init()`, so
// importing `crowdsec` + `http` did not bring the layer-4 matcher in.
//
// The miss survived the test suite because the CrowdSec paths are
// the one family deliberately kept away from `caddy.Validate` (a
// provision dials LAPI, see crowdsec_test.go:301). The guard is
// therefore a registry lookup rather than a validate:
// TestLayer4ModuleIDs_AllRegistered in layer4_test.go asserts every
// module ID buildLayer4App can emit resolves in Caddy's registry,
// which is exactly the check that would have caught this at build
// time instead of at the operator's first save.
//
// File kept separate from manager.go so the dependency direction
// is obvious in a single `git grep` for the import path. This
// mirrors how Step M's coraza-caddy was wired (a single blank
// import documents the upstream contract).
//
// Apache 2.0 licensed (one-way compatible with AGPL v3) — see
// the project's go.sum + NOTICE handling.

import (
	// apps.crowdsec — the bouncer's polling + decision-cache app.
	_ "github.com/hslatman/caddy-crowdsec-bouncer/crowdsec"
	// http.handlers.crowdsec — the per-request matcher that
	// enforces decisions (403 ban / 429 throttle / 403
	// captcha-fallback per the bouncer's writeResponse switch).
	_ "github.com/hslatman/caddy-crowdsec-bouncer/http"
	// layer4.matchers.crowdsec — the same decisions, applied to a
	// raw connection before the relay dials the backend (v2.42).
	_ "github.com/hslatman/caddy-crowdsec-bouncer/layer4"
)
