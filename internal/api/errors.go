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
	"net/http"
)

// writeError sends an HTTP error response in the canonical Arenet shape:
//
//	{"error": "<message>"}
//
// It also sets Content-Type and the appropriate status code.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// writeErrorCode emits a structured, i18n-able error:
//
//	{"error":"<EN fallback>","code":"<machine_code>","params":{...}}
//
// The frontend translates via t('errors.'+code, params); `error` is a
// non-localized fallback for logs / non-UI consumers. Use this for any
// user-facing error whose text carries data (names, counts). Plain
// writeError stays for internal / non-translated cases.
func writeErrorCode(w http.ResponseWriter, status int, code, message string, params map[string]any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := map[string]any{"error": message, "code": code}
	if len(params) > 0 {
		body["params"] = params
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeJSON serializes v as JSON with the given status. The encoder error
// (if any) is silently discarded: WriteHeader has already committed the
// status line so a fallback response is no longer possible. This is safe
// here because every callsite passes flat structs of strings and bools
// (routeResponse) or maps of strings — neither can fail encoding.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONWithHint writes resp as JSON with an extra top-level
// "lastHttpsRouteAffected" boolean merged in. Used by the route
// disable endpoint so the frontend can warn before removing the
// last HTTPS listener.
func writeJSONWithHint(w http.ResponseWriter, resp any, hint bool) {
	b, err := json.Marshal(resp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode response")
		return
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		writeError(w, http.StatusInternalServerError, "encode response")
		return
	}
	m["lastHttpsRouteAffected"] = hint
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(m)
}
