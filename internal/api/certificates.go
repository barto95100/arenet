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

	"github.com/barto95100/arenet/internal/certinfo"
)

// listCertificates serves GET /api/certificates — the read surface
// for the Certificates page. Returns the full snapshot of every
// cert the internal/certinfo tracker knows about, sorted by
// NotAfter ascending (closest-to-expiry first per spec §3.2).
//
// Satisfies AC #1 (runtime metadata exposed) + AC #4 (single
// source of truth — no parallel endpoint).
// Step T spec v1.2.0-step-t-spec, implemented by 1350777 (T.1).
//
// Degraded mode (AC #13): when h.certInfo is nil — typically
// because cmd/arenet's reconcile path failed at boot and the
// singleton was never installed — the endpoint returns 200 with
// an empty array, NOT 500. The Certificates page then renders
// its "no certificates yet" empty state, which is the
// operator-correct outcome on a fresh install before any cert
// has been issued.
//
// The tracker's List() always returns a freshly-allocated slice
// (mutex-guarded snapshot), so we pass it through verbatim. A
// nil slice marshals to `null` in JSON — we coerce to an empty
// slice so the wire shape is always an array.
func (h *Handler) listCertificates(w http.ResponseWriter, _ *http.Request) {
	if h.certInfo == nil {
		writeJSON(w, http.StatusOK, []*certinfo.CertRuntimeInfo{})
		return
	}
	out := h.certInfo.List()
	if out == nil {
		out = []*certinfo.CertRuntimeInfo{}
	}
	writeJSON(w, http.StatusOK, out)
}
