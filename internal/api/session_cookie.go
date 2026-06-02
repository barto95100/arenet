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

// themeCookieName is the cookie read by the FOUC bootstrap script in
// app.html (Step F §4.3). The bootstrap MUST read it from JS, so the
// cookie is intentionally NOT HttpOnly. It carries only a 4-char
// preference string ("dark" or "light") and has no security context.
const themeCookieName = "arenet_theme"

// themeCookieMaxAge is the absolute lifetime in seconds of arenet_theme.
// 30 days (spec §4.5) — long enough to survive normal browser sessions
// and idle periods. Logout clears the cookie explicitly; idle/silent
// session expirations leave it in place (acceptable per §4.5: the
// cookie carries only a UX preference, no security context).
const themeCookieMaxAge = 30 * 24 * 60 * 60

// setSessionCookie issues the Set-Cookie header for a freshly-created
// session per spec §4.11:
//
//	HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={86400|2592000}
//
// The Max-Age depends on rememberMe (24h or 30d sliding TTL). The
// Secure attribute is omitted in --dev mode (HTTP local).
func setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, rememberMe bool) {

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
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteStrictMode,
	})
}

// setThemeCookie issues the Set-Cookie header for arenet_theme per
// spec §4.5:
//
//	HttpOnly=false; Secure (prod); SameSite=Lax; Path=/; Max-Age=2592000
//
// Three deliberate differences from setSessionCookie:
//   - HttpOnly=false: the FOUC bootstrap script (§4.3) reads it from JS.
//   - SameSite=Lax (not Strict): with Strict the cookie is NOT sent on
//     the very first navigation from an external link, which breaks the
//     FOUC bootstrap on first paint. Lax sends it on top-level GETs from
//     any origin — exactly what the bootstrap needs.
//   - 30-day fixed Max-Age (not session-TTL-driven): the theme outlives
//     the session intentionally; a freshly logged-out user sees their
//     previously-set theme on the login page.
//
// Caller MUST pass a normalized value ("dark" or "light"); pre-Step-F
// users with `""` should be mapped to "dark" before this call so the
// cookie always carries a useful value for the bootstrap script.
func setThemeCookie(w http.ResponseWriter, r *http.Request, theme string) {
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    theme,
		Path:     "/",
		MaxAge:   themeCookieMaxAge,
		HttpOnly: false,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearThemeCookieOnResponse issues a Set-Cookie that deletes the
// arenet_theme cookie on the next browser write. Used by /auth/logout
// per spec §4.5 (the "explicit logout clears both cookies" lifecycle).
//
// The attributes other than MaxAge MUST exactly match the values used
// at set time, otherwise some browsers refuse the deletion.
func clearThemeCookieOnResponse(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     themeCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   isSecureRequest(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// normalizeThemeForCookie ensures the value written to the bootstrap
// cookie is always a useful "dark" or "light" — pre-Step-F users
// (themePreference == "") get the default "dark" the bootstrap would
// have picked anyway, but written explicitly so subsequent visits skip
// the localStorage / default fallback steps.
func normalizeThemeForCookie(theme string) string {
	if theme == auth.ThemeLight {
		return auth.ThemeLight
	}
	return auth.ThemeDark
}
// isSecureRequest returns true when the request was served over TLS,
// in which case cookies may be set with the Secure attribute.
//
// When the request arrives over HTTP (operator using admin via
// loopback HTTP or LAN HTTP — D6 default loopback admin), cookies
// MUST NOT have Secure: browsers silently refuse to store Secure
// cookies on non-HTTPS contexts (with localhost as the only
// exception, treated as secure-context), causing login to appear
// to succeed (POST /login → 200) but the session cookie to be
// dropped — every subsequent request comes in with no cookie and
// hits the 401 unauthenticated path. See finding #S-11.
//
// Future-proofing: when Arenet sits behind a TLS-terminating
// upstream proxy (Caddy, Traefik, Nginx), X-Forwarded-Proto
// would carry the original scheme. Trusting this header requires
// gating on the trusted-proxies list (Arenet already has the
// infrastructure via ARENET_TRUSTED_PROXIES). Adding the
// X-Forwarded-Proto path is intentionally deferred — the common
// deployments (SSH-tunneled loopback admin, direct HTTPS via
// Arenet's own TLS, or LAN HTTP admin) all work with the r.TLS
// check alone.
func isSecureRequest(r *http.Request) bool {
	return r != nil && r.TLS != nil
}
