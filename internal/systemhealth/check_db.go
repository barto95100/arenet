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
)

// RoutesCounter is the minimal surface BoltDBCheck needs.
// A thin adapter in cmd/arenet wraps *storage.Store's
// ListRoutes to return the count directly — keeping the
// check's interface free of the storage package import
// (which would pull storage's bbolt deps into the
// systemhealth tree).
type RoutesCounter interface {
	CountRoutes(ctx context.Context) (int, error)
}

// BoltDBCheck probes the routes BoltDB bucket. A successful
// ListRoutes within the deadline means the underlying bbolt
// file is readable, the routes bucket exists, and reads can
// complete — which transitively means every reload path can
// still source its data.
//
// Why ListRoutes and not a raw bbolt View: routes are the
// primary working set; if they read OK, the other buckets
// (sessions, audit, users, ...) are statistically also OK
// because they share the bbolt file's single-writer lock.
// A more granular per-bucket probe would inflate the V1
// surface without proving anything that the routes probe
// doesn't.
type BoltDBCheck struct {
	Counter RoutesCounter
}

// Name implements ComponentCheck.
func (c *BoltDBCheck) Name() string { return "db" }

// Check implements ComponentCheck. Routes count surfaces in
// the message for operator-side visibility ("boltdb OK,
// N routes"); on failure the message is the bare error
// type ("read failed: ...") without exposing the file path
// or internal bucket structure.
func (c *BoltDBCheck) Check(ctx context.Context) ComponentStatus {
	if c.Counter == nil {
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: "store not configured",
		}
	}

	count, err := c.Counter.CountRoutes(ctx)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ComponentStatus{
				Status:  StatusUnhealthy,
				Message: "boltdb read timed out",
			}
		}
		return ComponentStatus{
			Status:  StatusUnhealthy,
			Message: "boltdb read failed",
		}
	}

	return ComponentStatus{
		Status:  StatusHealthy,
		Message: fmt.Sprintf("boltdb OK, %d routes", count),
	}
}
