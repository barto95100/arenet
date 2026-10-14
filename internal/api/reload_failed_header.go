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

// Telling the operator a reload was refused, without changing what the
// handler answers (v2.72).
//
// Six write paths log a failed Caddy reload and still answer 2xx, on
// purpose: the store write is already committed and undoing it would be
// worse — for the certificate delete it is impossible, the files are
// gone. Fourteen other paths roll back and answer 500 instead. That
// asymmetry is deliberate per handler.
//
// What was not deliberate is the silence. The UI then read the store
// back and rendered the new value, confirming a state the edge was not
// serving, with a plain success toast on top. #257 made systemhealth
// report it, which closed the worst of the gap; this closes the rest,
// where the operator actually is at that moment.
//
// A response HEADER rather than a body field, for one reason: two of
// the six answer 204 with no body at all (an error-template delete and
// an external-certificate delete), so a field cannot reach them. The
// header reaches every shape, and the frontend reads it in ONE place —
// the shared request() — so no call site has to remember to surface it
// and a seventh swallow site gets the caveat for free.
const reloadFailedHeader = "X-Arenet-Reload-Failed"

// markReloadFailed flags a response whose store write landed but whose
// Caddy reload did not.
//
// Must be called BEFORE the body is written: once WriteHeader has run,
// header mutations are silently dropped.
func markReloadFailed(w http.ResponseWriter) {
	w.Header().Set(reloadFailedHeader, "1")
}
