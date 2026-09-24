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

// Package l4metrics counts what a layer-4 relay carries.
//
// v2.42 — without this, a TCP or UDP service is a part of the
// installation nobody can watch: its traffic never crosses the HTTP
// chain, so the dashboard, the logs and the per-route counters see
// nothing of it. An operator would configure a database relay and
// have no way to know whether anyone ever connected.
//
// The shape is deliberately not the HTTP one. There are no status
// codes and no request latency at layer 4; what an operator asks is
// how many connections came, how many are open right now, how much
// went each way, and how many failed to reach the backend.
//
// Counters are cumulative since the process started, plus a live
// gauge for open connections. The registry is process-wide and
// installed once at boot, exactly like internal/metrics.
package l4metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// ServiceCounters is one service's live view.
type ServiceCounters struct {
	// Connections accepted since start.
	Connections uint64 `json:"connections"`
	// Active is how many are open right now.
	Active int64 `json:"active"`
	// BytesIn is what clients sent, BytesOut what they received.
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
	// Errors counts connections the relay could not complete —
	// almost always a backend that refused or timed out.
	Errors uint64 `json:"errors"`
	// LastConnectionAt is empty until the first connection.
	LastConnectionAt string `json:"lastConnectionAt,omitempty"`
}

type cell struct {
	connections atomic.Uint64
	active      atomic.Int64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
	errors      atomic.Uint64
	lastNanos   atomic.Int64
}

// Registry holds one cell per known service.
type Registry struct {
	mu    sync.RWMutex
	cells map[string]*cell
}

func NewRegistry() *Registry {
	return &Registry{cells: make(map[string]*cell)}
}

// Sync makes the registry hold exactly these services: cells for
// services that disappeared are dropped, new ones start at zero.
// Called on every successful apply, like the HTTP registry's Sync.
func (r *Registry) Sync(serviceIDs []string) {
	wanted := make(map[string]struct{}, len(serviceIDs))
	for _, id := range serviceIDs {
		wanted[id] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.cells {
		if _, keep := wanted[id]; !keep {
			delete(r.cells, id)
		}
	}
	for id := range wanted {
		if _, exists := r.cells[id]; !exists {
			r.cells[id] = &cell{}
		}
	}
}

// cellFor returns the cell, or nil when the service is unknown —
// which happens between an apply and the Sync that follows it. A
// missing cell must never cost a connection, so every caller treats
// nil as "do not count" rather than as an error.
func (r *Registry) cellFor(serviceID string) *cell {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cells[serviceID]
}

// Opened records an accepted connection.
func (r *Registry) Opened(serviceID string) {
	if c := r.cellFor(serviceID); c != nil {
		c.connections.Add(1)
		c.active.Add(1)
		c.lastNanos.Store(time.Now().UnixNano())
	}
}

// Closed records a finished connection and what it carried.
func (r *Registry) Closed(serviceID string, bytesIn, bytesOut uint64) {
	if c := r.cellFor(serviceID); c != nil {
		c.active.Add(-1)
		c.bytesIn.Add(bytesIn)
		c.bytesOut.Add(bytesOut)
	}
}

// Failed records a connection the relay could not complete.
func (r *Registry) Failed(serviceID string) {
	if c := r.cellFor(serviceID); c != nil {
		c.errors.Add(1)
	}
}

// Snapshot returns a copy of every known service's counters.
func (r *Registry) Snapshot() map[string]ServiceCounters {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make(map[string]ServiceCounters, len(r.cells))
	for id, c := range r.cells {
		sc := ServiceCounters{
			Connections: c.connections.Load(),
			Active:      c.active.Load(),
			BytesIn:     c.bytesIn.Load(),
			BytesOut:    c.bytesOut.Load(),
			Errors:      c.errors.Load(),
		}
		if nanos := c.lastNanos.Load(); nanos > 0 {
			sc.LastConnectionAt = time.Unix(0, nanos).UTC().Format(time.RFC3339)
		}
		out[id] = sc
	}
	return out
}
