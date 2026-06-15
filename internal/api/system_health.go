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
	"context"
	"encoding/json"
	"net/http"

	"github.com/barto95100/arenet/internal/systemhealth"
)

// SystemHealthChecker is the seam between the Arenet admin
// server's request loop and the systemhealth package's
// HealthChecker. Defined as an interface here so
// cmd/arenet's wiring layer can inject the configured
// *HealthChecker without internal/api importing the
// package-side constructors directly — keeping the api
// package's external dependency surface narrow.
type SystemHealthChecker interface {
	Run(ctx context.Context) systemhealth.Report
}

// systemHealth handles GET /system/health. Intentionally
// mounted OUTSIDE the auth middleware (see routes.go) — the
// endpoint is designed for external monitoring (Uptime Kuma,
// Prometheus blackbox_exporter, k8s readiness probe analog)
// and the response carries zero secrets / PII / internal
// IDs.
//
// HTTP status mapping per ADR D4:
//   - healthy / degraded → 200 OK
//   - unhealthy → 503 Service Unavailable
//
// JSON body shape — see systemhealth.Report. Stable key
// order via the slice-of-NamedReport (not a map).
func (h *Handler) systemHealth(w http.ResponseWriter, r *http.Request) {
	if h.systemHealthChecker == nil {
		// Endpoint wired but no checker injected — surface
		// a coherent degraded response rather than a 500.
		// External monitoring sees the same JSON shape it
		// would on any other call; the message field tells
		// the operator the wiring is incomplete.
		writeSystemHealthJSON(w, http.StatusOK, systemhealth.Report{
			Status:     systemhealth.StatusDegraded,
			Components: []systemhealth.NamedReport{},
		})
		return
	}

	report := h.systemHealthChecker.Run(r.Context())

	statusCode := http.StatusOK
	if report.Status == systemhealth.StatusUnhealthy {
		statusCode = http.StatusServiceUnavailable
	}
	writeSystemHealthJSON(w, statusCode, report)
}

// writeSystemHealthJSON serialises a Report with the agreed
// content-type. Separate helper so the handler's two
// emission paths (degraded-no-checker + run-result) share
// the same encoding.
func writeSystemHealthJSON(w http.ResponseWriter, statusCode int, report systemhealth.Report) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(report)
}
