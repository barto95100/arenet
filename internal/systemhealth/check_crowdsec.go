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

package systemhealth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CrowdSecConfigReader is the minimal surface CrowdSecCheck
// needs. The wiring file adapts *storage.Store via a thin
// wrapper around GetCrowdSecSettings (returns the bouncer
// LAPI URL + API key, both empty when CrowdSec is
// unconfigured).
type CrowdSecConfigReader interface {
	GetCrowdSecConfig(ctx context.Context) (lapiURL, apiKey string, configured bool, err error)
}

// CrowdSecCheck probes the configured LAPI endpoint at
// /v1/decisions using the bouncer API key. The endpoint +
// auth shape mirror the existing probeCrowdSecLAPI in
// internal/api/crowdsec_settings.go:450-494 (verified
// against live LAPI v1.6.x — accepts X-Api-Key header
// + responds 200/204 on success, 401/403 on bad auth).
//
// Classification per ADR D2:
//   - healthy: LAPI configured + reachable + 2xx response
//   - degraded: LAPI configured but unreachable / auth
//     failed / non-2xx. The bouncer fails open (Caddy data
//     plane keeps serving without the LAPI feed), so the
//     route stays workable — just without fresh decisions.
//   - degraded: LAPI not configured (fresh install / opt-out)
//   - unhealthy: NOT used. CrowdSec is optional in arenet's
//     posture; an unreachable LAPI is a degraded security
//     posture, not an unhealthy system.
type CrowdSecCheck struct {
	Config     CrowdSecConfigReader
	HTTPClient *http.Client
}

// Name implements ComponentCheck.
func (c *CrowdSecCheck) Name() string { return "crowdsec" }

// Check implements ComponentCheck.
func (c *CrowdSecCheck) Check(ctx context.Context) ComponentStatus {
	if c.Config == nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec config not wired (degraded mode)",
		}
	}

	lapiURL, apiKey, configured, err := c.Config.GetCrowdSecConfig(ctx)
	if err != nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec config read failed",
		}
	}
	if !configured {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "crowdsec not configured (bouncer disabled)",
		}
	}

	probeURL := strings.TrimRight(lapiURL, "/") + "/v1/decisions"

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "invalid LAPI URL",
		}
	}
	req.Header.Set("X-Api-Key", apiKey)
	req.Header.Set("User-Agent", "arenet/system-health")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ComponentStatus{
				Status:  StatusDegraded,
				Message: "lapi check timed out",
			}
		}
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "lapi unreachable",
		}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusNoContent:
		return ComponentStatus{
			Status:  StatusHealthy,
			Message: "lapi reachable",
		}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "lapi auth failed (invalid bouncer API key)",
		}
	default:
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: fmt.Sprintf("lapi unexpected status %d", resp.StatusCode),
		}
	}
}
