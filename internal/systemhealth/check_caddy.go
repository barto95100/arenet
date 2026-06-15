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

// CaddyCheck probes Caddy's loopback admin API at
// /config/. A reachable + 200-OK admin endpoint means
// caddy.Load (and therefore any future route reload) will
// work; a deadlocked admin endpoint (see commit cd09a34
// #R-CADDY-ADMIN-DEADLOCK) surfaces here as StatusUnhealthy.
//
// Default admin URL is http://127.0.0.1:2019 — Caddy's
// documented default when no `admin` block is set in the
// emitted config (which arenet doesn't set). Override via
// the AdminURL field if a future config tweak relocates the
// admin endpoint.
type CaddyCheck struct {
	// AdminURL is the base URL of Caddy's admin endpoint
	// (NO trailing /config/). Defaults to "http://127.0.0.1:2019"
	// when empty.
	AdminURL string
	// HTTPClient is the client used for the probe. Tests
	// override with an in-memory transport; production
	// leaves it nil and the check uses http.DefaultClient
	// (the ctx-timeout wrapper from HealthChecker.Run is
	// the authoritative deadline).
	HTTPClient *http.Client
}

// Name implements ComponentCheck.
func (c *CaddyCheck) Name() string { return "caddy" }

// Check implements ComponentCheck. A 2xx response is
// healthy. Network error → unhealthy ("admin endpoint not
// reachable"). Non-2xx response → unhealthy (Caddy is
// running but the admin surface is misbehaving).
func (c *CaddyCheck) Check(ctx context.Context) ComponentStatus {
	base := c.AdminURL
	if base == "" {
		base = "http://127.0.0.1:2019"
	}
	url := strings.TrimRight(base, "/") + "/config/"

	client := c.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: "invalid caddy admin URL",
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ComponentStatus{
				Status:  StatusUnhealthy,
				Message: "caddy admin check timed out",
			}
		}
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: "caddy admin endpoint not reachable",
		}
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: fmt.Sprintf("caddy admin returned HTTP %d", resp.StatusCode),
		}
	}

	return ComponentStatus{
		Status:  StatusHealthy,
		Message: "admin endpoint reachable",
	}
}
