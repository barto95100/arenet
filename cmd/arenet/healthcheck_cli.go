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

// Step S.1 — Docker healthcheck CLI subcommand. Distroless container
// images have no curl/wget; the compose `healthcheck.test` directive
// needs an in-binary probe. The flag --healthcheck=<URL> turns the
// binary into a one-shot HTTP client: GET URL with a tight 3s
// timeout, exit 0 on any 2xx, exit 1 on anything else (network
// error, non-2xx, timeout).
//
// Usage (in compose):
//
//   healthcheck:
//     test: ["CMD", "/usr/local/bin/arenet", "--healthcheck=http://127.0.0.1:8001/healthz"]
//     interval: 30s
//     timeout: 5s
//     retries: 3
//
// The probe URL points at the admin API's /healthz endpoint
// (Step H.3 — uptime_seconds JSON). The healthcheck CLI does NOT
// parse the body — a 2xx is sufficient evidence of liveness. The
// body schema is the admin API's concern, not the healthcheck's.

package main

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// healthcheckTimeout caps the probe at 3s. The compose
// healthcheck.timeout is 5s by default; staying under it ensures
// the probe terminates cleanly instead of the container runtime
// SIGKILLing the binary.
const healthcheckTimeout = 3 * time.Second

func runHealthcheckCLI(ctx context.Context, url string) error {
	probeCtx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: build request: %w", err)
	}
	// Identify the probe in access logs.
	req.Header.Set("User-Agent", "arenet-healthcheck")

	client := &http.Client{Timeout: healthcheckTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("healthcheck: GET %s returned %d", url, resp.StatusCode)
	}
	return nil
}
