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
	"strings"

	"github.com/barto95100/arenet/internal/geo"
)

// asnSearcher is the subset of *geo.ASNLookup the ASN endpoint uses.
type asnSearcher interface {
	Loaded() bool
	IndexReady() bool
	SearchASN(q string, limit int) []geo.ASNInfo
	NamesASN(asns []uint32) []geo.ASNInfo
}

// asnSearchResponse is the wire shape of GET /api/v1/geo/asn.
type asnSearchResponse struct {
	// Loaded is false when no GeoLite2-ASN database is installed
	// (the UI then points the operator to Settings → GeoIP).
	Loaded bool `json:"loaded"`
	// IndexReady is false while the name index of a freshly loaded
	// database is still being built (results may be empty).
	IndexReady bool          `json:"indexReady"`
	Results    []geo.ASNInfo `json:"results"`
}

// maxASNIDs caps the ids= list of one request.
const maxASNIDs = 200

// searchASN serves GET /api/v1/geo/asn (admin, v2.28):
//   - ?q=ovh&limit=20 — search by organisation name or AS number;
//   - ?ids=14061,16276 — resolve the names of saved rules.
//
// 400 on a malformed id; always 200 otherwise (loaded=false when the
// database is missing).
func (h *Handler) searchASN(w http.ResponseWriter, r *http.Request) {
	resp := asnSearchResponse{Results: []geo.ASNInfo{}}
	if h.asnLookup == nil || !h.asnLookup.Loaded() {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	resp.Loaded = true
	resp.IndexReady = h.asnLookup.IndexReady()

	if raw := strings.TrimSpace(r.URL.Query().Get("ids")); raw != "" {
		parts := strings.Split(raw, ",")
		if len(parts) > maxASNIDs {
			writeError(w, http.StatusBadRequest, "too many ids")
			return
		}
		ids := make([]uint32, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(p)), "AS"), 10, 32)
			if err != nil || n == 0 {
				writeError(w, http.StatusBadRequest, "invalid AS number: "+p)
				return
			}
			ids = append(ids, uint32(n))
		}
		resp.Results = h.asnLookup.NamesASN(ids)
		writeJSON(w, http.StatusOK, resp)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	resp.Results = h.asnLookup.SearchASN(r.URL.Query().Get("q"), limit)
	writeJSON(w, http.StatusOK, resp)
}
