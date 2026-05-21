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

package api

import (
	"net/http"
	"time"
)

// healthz is a minimal liveness endpoint for orchestrators (Docker
// HEALTHCHECK, Kubernetes liveness/readiness probes, uptime monitors).
//
// Design (Step H.3):
//   - Mounted at /healthz (NOT under /api/v1) so the path stays stable
//     across API versions — probe configs don't drift on releases.
//   - No auth (probes have no credentials).
//   - No audit: the handler simply doesn't call h.audit.Append; audit
//     is per-handler in Arenet, not a middleware, so the bypass is
//     implicit.
//   - Liveness-style: always 200 if the goroutine answers. No DB ping
//     — BoltDB is embedded, so a "DB down" scenario is a process-level
//     failure that already manifests as the binary not responding. A
//     /readyz that pings storage could be added later if needed.
//   - The root chi.Router applies its full middleware stack before
//     dispatching any route (chi enforces "all middlewares before any
//     route"), so probe hits do land in the structured log. For the
//     homelab single-instance target the volume is acceptable; a
//     `path=/healthz` filter in the log consumer removes the noise
//     trivially if it ever becomes an issue.
func (h *Handler) healthz(w http.ResponseWriter, r *http.Request) {
	resp := healthzResponse{
		Status:        "ok",
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
	}
	writeJSON(w, http.StatusOK, resp)
}

// healthzResponse is the JSON body of GET /healthz. Kept minimal on
// purpose — probe consumers parse only the HTTP status code; the body
// is for humans hitting the endpoint with curl.
type healthzResponse struct {
	Status        string `json:"status"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}
