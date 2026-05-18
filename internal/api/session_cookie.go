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

	"github.com/barto95100/arenet/internal/auth"
)

// sessionCookieName is the cookie sent to and received from browsers.
// Mirrors the value used in internal/auth/middleware.go; duplicated
// here as an unexported constant rather than imported because the
// auth package keeps its copy unexported (encapsulation across layers).
const sessionCookieName = "arenet_session"

// setSessionCookie issues the Set-Cookie header for a freshly-created
// session per spec §4.11:
//
//	HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={86400|2592000}
//
// The Max-Age depends on rememberMe (24h or 30d sliding TTL). The
// Secure attribute is omitted in --dev mode (HTTP local).
func setSessionCookie(w http.ResponseWriter, sessionID string, rememberMe, devMode bool) {
	maxAge := int(auth.SessionTTLDefault.Seconds())
	if rememberMe {
		maxAge = int(auth.SessionTTLRememberMe.Seconds())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !devMode,
		SameSite: http.SameSiteStrictMode,
	})
}
