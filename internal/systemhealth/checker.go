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
	"sync"
	"time"
)

// Run executes every configured check in parallel under the
// total-timeout budget, returning a fully-populated Report.
// Never errors — a check that fails / times out / panics
// surfaces as a degraded or unhealthy NamedReport in the
// output; the endpoint always returns a coherent shape so
// the monitoring stack can render a status row even on the
// worst day.
//
// Aggregation logic (D2):
//   - Any check at StatusUnhealthy → global StatusUnhealthy
//   - Else any check at StatusDegraded → global StatusDegraded
//   - Else StatusHealthy
//
// Caller's responsibility: map the global Status to an HTTP
// status code (200 for healthy/degraded, 503 for unhealthy).
func (h *HealthChecker) Run(ctx context.Context) Report {
	totalCtx, cancel := context.WithTimeout(ctx, TotalTimeout)
	defer cancel()

	results := make([]NamedReport, len(h.checks))

	var wg sync.WaitGroup
	for i, c := range h.checks {
		wg.Add(1)
		go func(idx int, chk ComponentCheck) {
			defer wg.Done()
			// Belt-and-braces: a check panicking would
			// otherwise crash the request goroutine and
			// abort the response. Translate panics into a
			// StatusUnhealthy row with a stable message
			// so the operator sees something actionable.
			defer func() {
				if r := recover(); r != nil {
					results[idx] = NamedReport{
						Name: chk.Name(),
						ComponentStatus: ComponentStatus{
							Status:  StatusUnhealthy,
							Message: "check panicked",
						},
					}
				}
			}()

			checkCtx, checkCancel := context.WithTimeout(totalCtx, PerCheckTimeout)
			defer checkCancel()
			start := time.Now()
			cs := chk.Check(checkCtx)
			// Populate LatencyMs if the check left it zero —
			// the wrapper observes the wall-clock duration
			// regardless of the check's own measurement,
			// so a forgetful check still reports its real
			// cost. Checks that intentionally report a
			// different signal (e.g. a TCP-probe component
			// that wants to expose handshake time, not the
			// full Check() runtime) override by setting
			// LatencyMs themselves.
			if cs.LatencyMs == 0 {
				cs.LatencyMs = time.Since(start).Milliseconds()
			}
			results[idx] = NamedReport{
				Name:            chk.Name(),
				ComponentStatus: cs,
			}
		}(i, c)
	}
	wg.Wait()

	// Aggregate the global status from the per-component
	// rows. Walk results in order so the worst seen status
	// short-circuits cleanly.
	global := StatusHealthy
	for _, r := range results {
		switch r.Status {
		case StatusUnhealthy:
			global = StatusUnhealthy
		case StatusDegraded:
			if global != StatusUnhealthy {
				global = StatusDegraded
			}
		}
	}

	return Report{
		Status:     global,
		Timestamp:  time.Now().UTC().Format(timestampFormat),
		Version:    h.version,
		Components: results,
	}
}
