// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

import "net/http"

// Request-body ceilings. Before these, the JSON handlers handed r.Body
// straight to json.Decoder, which buffers the whole top-level value
// before unmarshalling — so an attacker-chosen string of arbitrary size
// was fully materialised in the heap before any check ran. On the
// unauthenticated login/setup endpoints that is a pre-auth path to
// OOM-killing the single process, which takes down every proxied site
// because Caddy is embedded in the same binary (F4/F31).
//
// http.MaxBytesReader caps the read and, on overflow, makes the next
// Read fail so Decode returns an error the handler already turns into a
// 4xx — the body never grows past the cap.
const (
	// maxAPIBodyBytes is the blanket ceiling for the whole /api/v1
	// subtree: an anti-OOM backstop, not a precise per-endpoint limit.
	// Set above the backup import's own 64 MiB inner limit so that one
	// legitimate large upload still fits, while any body on the order of
	// the host's RAM is refused.
	maxAPIBodyBytes int64 = 80 << 20

	// maxAuthBodyBytes is the tight cap for the /auth subtree — login,
	// setup, unlock, password change, OIDC. Every payload there is a
	// handful of short fields; 64 KiB is already generous (an OIDC
	// form_post callback carrying a JWT is the largest) and keeps the
	// unauthenticated surface far from any memory pressure.
	maxAuthBodyBytes int64 = 64 << 10

	// maxGeoBatchBodyBytes caps POST /geo/lookup-batch, whose handler
	// rejects more than 256 IPs — but only AFTER decoding the array, so
	// the body needs its own bound. 256 IPv6 strings plus JSON overhead
	// is a few KiB; 64 KiB leaves ample room.
	maxGeoBatchBodyBytes int64 = 64 << 10
)

// bodyLimit returns a middleware that caps the request body at max bytes
// via http.MaxBytesReader. Mounted broadly (the /api/v1 ceiling) and
// again, tighter, on the sensitive subtrees — the innermost, smallest
// cap binds, so a tight subtree cap is not loosened by the outer one.
func bodyLimit(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, max)
			}
			next.ServeHTTP(w, r)
		})
	}
}
