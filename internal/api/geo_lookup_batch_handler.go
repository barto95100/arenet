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
	"encoding/json"
	"net"
	"net/http"

	"github.com/barto95100/arenet/internal/geo"
)

// Phase Z.5.3 — batch GeoIP lookup endpoint.
//
// Backs the /logs SOURCE IP column's "82.65.x.x · FR"
// rendering. The frontend collects every distinct srcIp /
// remoteIp on the merged activity-log rows and POSTs them
// in one call ; the server replies with one country code
// per IP (ISO 3166-1 alpha-2, "LAN" for RFC1918, "" when
// the MMDB has no record or is degraded).
//
// Endpoint shape :
//
//	POST /api/v1/geo/lookup-batch
//	{
//	  "ips": ["82.65.1.2", "192.168.1.5", "203.0.113.7"]
//	}
//	→ 200
//	{
//	  "results": {
//	    "82.65.1.2":  "FR",
//	    "192.168.1.5": "LAN",
//	    "203.0.113.7": ""
//	  }
//	}
//
// Auth : hard-auth gated at the route mount (same viewer-
// accessible convention as the other /security + /geo
// surfaces).
//
// AC #13 degraded paths :
//
//   - h.geoLookup == nil → 200 with results map entries set
//     to "" for every IP (no country suffix rendered on the
//     /logs page ; raw IP preserved).
//   - Single IP fails to parse → that IP's result is "" ;
//     the rest of the batch is still answered. This avoids
//     a single malformed cell taking down the whole batch.
//
// Cap : maxLookupBatchSize (256) bounds the request body so
// a hand-crafted curl can't trigger an unbounded loop. The
// frontend de-duplicates IPs before sending, so a single
// page's worth of activity log (200 rows max) always fits
// comfortably even with no duplicates.

const maxLookupBatchSize = 256

// GeoIPLookup is the narrow read surface this handler
// depends on. *geo.Lookup satisfies it via LookupIP. Same
// narrow-interface pattern as the other security readers
// so tests inject a fake without touching the MMDB.
type GeoIPLookup interface {
	LookupIP(ip net.IP) geo.Location
	// Loaded reports whether a real MMDB is installed (false in
	// degraded mode). Needed because the wired *geo.Lookup is now
	// always non-nil (a degraded &geo.Lookup{} when no DB is present),
	// so a nil check alone no longer detects the degraded state.
	Loaded() bool
}

type geoLookupBatchRequest struct {
	IPs []string `json:"ips"`
}

type geoLookupBatchResponse struct {
	Results  map[string]string `json:"results"`
	Degraded bool              `json:"degraded,omitempty"`
}

// geoLookupBatch handles POST /api/v1/geo/lookup-batch.
func (h *Handler) geoLookupBatch(w http.ResponseWriter, r *http.Request) {
	var req geoLookupBatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.IPs) > maxLookupBatchSize {
		writeError(w, http.StatusBadRequest, "too many IPs (cap 256)")
		return
	}

	resp := geoLookupBatchResponse{Results: map[string]string{}}
	if h.geoLookup == nil || !h.geoLookup.Loaded() {
		// AC #13 degraded : answer with empty strings, never
		// 5xx, so the frontend renders raw IPs cleanly. Covers both
		// an unwired lookup (nil) and a degraded one (no DB loaded).
		resp.Degraded = true
		for _, ip := range req.IPs {
			resp.Results[ip] = ""
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}

	for _, ipStr := range req.IPs {
		parsed := net.ParseIP(ipStr)
		if parsed == nil {
			// Single malformed cell doesn't take down the
			// batch ; the operator gets an empty string for
			// that IP and a populated value for the rest.
			resp.Results[ipStr] = ""
			continue
		}
		loc := h.geoLookup.LookupIP(parsed)
		// loc.Country is the ISO 3166-1 alpha-2 code for
		// public IPs, the "LAN" sentinel for RFC1918 /
		// loopback / link-local (per geo.LookupIP contract),
		// and the empty string when the MMDB has no record.
		// All three cases are operator-meaningful : "FR" for
		// the source country, "LAN" for homelab-internal,
		// "" for unknown / non-routable / IPv4-mapped IPv6.
		resp.Results[ipStr] = loc.Country
	}
	writeJSON(w, http.StatusOK, resp)
}
