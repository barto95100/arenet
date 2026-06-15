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
	"fmt"
	"time"
)

// CertInfoLister is the minimal surface CertmagicCheck
// needs. *certinfo.Tracker.List() satisfies it; the wiring
// file adapts via a thin wrapper that maps the
// CertRuntimeInfo slice into the CertEntry summary shape
// below (NotAfter timestamp + Status enum string — that's
// all the check needs).
type CertInfoLister interface {
	ListCertEntries() []CertEntry
}

// CertEntry is the minimal cert summary needed for the
// expiry-window + last-error classification. Mapped from
// certinfo.CertRuntimeInfo at the adapter layer so this
// package stays import-free of certinfo.
type CertEntry struct {
	Domain      string
	NotAfter    time.Time
	StatusValid bool // certinfo.Status == "VALID"
	StatusObtainFailed bool // certinfo.Status == "OBTAIN_FAILED"
}

// CertExpiryWarningWindow is the operator-visible "expiring
// soon" threshold. 14 days aligns with the industry
// convention: Let's Encrypt sends warnings at 20d, 14d
// leaves plenty of room for ACME retry on transient
// failures (DNS propagation, rate limits). V2 may surface
// this as an env-var-tunable knob.
const CertExpiryWarningWindow = 14 * 24 * time.Hour

// CertmagicCheck reads the certinfo tracker's in-memory
// state. No network call, no I/O — the tracker is the
// authoritative source for the per-domain ACME state that
// certmagic maintains in its background loop.
//
// Classification per ADR D2:
//   - healthy: tracker reports ≥1 cert and none are in the
//     warning window OR in an obtain-failed state
//   - degraded: ≥1 cert expiring within CertExpiryWarningWindow
//     OR ≥1 cert in OBTAIN_FAILED state (last renewal
//     attempt failed)
//   - degraded: no certs tracked (boot-degraded — fresh
//     install OR all routes use http://)
//   - unhealthy: NOT used. Cert provisioning failures are
//     time-bounded (ACME retries on its own schedule); the
//     correct operator signal is "fix the failing cert
//     soon" not "service down".
type CertmagicCheck struct {
	Lister CertInfoLister
}

// Name implements ComponentCheck.
func (c *CertmagicCheck) Name() string { return "certmagic" }

// Check implements ComponentCheck. In-memory read; ctx is
// honoured only to surface a timed-out message if a future
// adapter introduces network I/O.
func (c *CertmagicCheck) Check(ctx context.Context) ComponentStatus {
	// Respect ctx for forward-compat (the tracker is
	// in-memory today; an adapter that introduces I/O
	// would benefit from the deadline).
	select {
	case <-ctx.Done():
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "certmagic check timed out",
		}
	default:
	}

	if c.Lister == nil {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "certinfo tracker not configured (degraded mode)",
		}
	}

	entries := c.Lister.ListCertEntries()
	if len(entries) == 0 {
		return ComponentStatus{
			Status:  StatusDegraded,
			Message: "no certs tracked (no HTTPS routes provisioned)",
		}
	}

	now := time.Now().UTC()
	horizon := now.Add(CertExpiryWarningWindow)
	expiringSoon := 0
	failed := 0
	for _, e := range entries {
		if e.StatusObtainFailed {
			failed++
		}
		if !e.NotAfter.IsZero() && e.NotAfter.Before(horizon) {
			expiringSoon++
		}
	}

	if failed > 0 {
		return ComponentStatus{
			Status: StatusDegraded,
			Message: fmt.Sprintf("%d cert(s) failed last renewal, %d managed",
				failed, len(entries)),
		}
	}

	if expiringSoon > 0 {
		return ComponentStatus{
			Status: StatusDegraded,
			Message: fmt.Sprintf("%d cert(s) expiring <%dd, %d managed",
				expiringSoon, int(CertExpiryWarningWindow/(24*time.Hour)), len(entries)),
		}
	}

	return ComponentStatus{
		Status:  StatusHealthy,
		Message: fmt.Sprintf("%d cert(s) managed, none expiring <%dd", len(entries), int(CertExpiryWarningWindow/(24*time.Hour))),
	}
}
