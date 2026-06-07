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
	"strconv"

	"github.com/barto95100/arenet/internal/geo"
)

// geoEventsLimitCap is the spec §5.4 upper bound on the
// `limit` query param for GET /api/v1/observability/geo-
// events. Larger than the default so an investigation can
// pull the full ring buffer; smaller-or-equal to the bus
// ring capacity so the cap is always honest about what's
// available.
const geoEventsLimitCap = 500

// geoEventsDefaultLimit is the limit returned when the
// `limit` query parameter is missing or zero. Spec §5.4
// pins it to 100 — a comfortable initial paint that the WS
// stream then overlays with live events.
const geoEventsDefaultLimit = 100

// GeoEventReader is the read surface the GET handler uses
// to populate its response. *geo.Bus satisfies this via
// SnapshotLimited; declared at the api-package level so this
// file does not import internal/geo for more than the GeoEvent
// type (V.3 layering keeps the api package's coupling to geo
// minimal — Snapshot reads + the GeoEvent wire shape).
type GeoEventReader interface {
	SnapshotLimited(limit int) []geo.GeoEvent
	Stats() geo.BusStats
}

// geoEventsResponse is the wire shape spec §5.4 locks for
// GET /api/v1/observability/geo-events. `total` is the ring
// buffer's current size (NOT a DB count — geo events are
// in-memory only, no persistence across restart). `degraded`
// is true when the GeoIP lookup is degraded (V.1's nil
// Lookup case carried through the V.2 enricher); events
// still flow but lat/lon/country fields collapse to the
// sentinel values.
type geoEventsResponse struct {
	Events   []geo.GeoEvent `json:"events"`
	Total    int            `json:"total"`
	Degraded bool           `json:"degraded,omitempty"`
}

// securityGeoEvents handles GET /api/v1/observability/geo-
// events per spec §5.4. Query params:
//
//   - limit (optional): rows to return. Default 100, clamped
//     silently at geoEventsLimitCap (500). Non-positive or
//     non-integer → 400.
//
// AC #13 degraded paths:
//   - h.geoBus == nil → 200 with degraded=true, events=[],
//     total=0. Mirrors every other observability reader's
//     degraded contract (Step T AC #13 carried forward).
//   - geoLookup is degraded (V.1 nil case): events still
//     flow but the response carries degraded=true so the
//     frontend can surface the "GeoIP not configured" banner.
//
// Auth: hard-auth gated at the route mount. Viewer + admin
// both accepted (read-only endpoint, parallel to
// /security/decisions and /security/cert-events).
func (h *Handler) securityGeoEvents(w http.ResponseWriter, r *http.Request) {
	resp := geoEventsResponse{Events: []geo.GeoEvent{}}

	if h.geoBus == nil {
		resp.Degraded = true
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit := geoEventsDefaultLimit
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		if n > geoEventsLimitCap {
			n = geoEventsLimitCap
		}
		limit = n
	}

	events := h.geoBus.SnapshotLimited(limit)
	if events == nil {
		events = []geo.GeoEvent{}
	}

	resp.Events = events
	resp.Total = len(events)
	// Degraded flag honors the V.1 / V.2 GeoIP lookup
	// availability: when the geoIPDegraded flag is set the
	// events themselves still flow but with empty
	// lat/lon/country fields (V.2 enricher fallback).
	resp.Degraded = h.geoIPDegraded
	writeJSON(w, http.StatusOK, resp)
}
