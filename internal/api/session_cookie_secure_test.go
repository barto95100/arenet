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

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLogin_SessionCookieSecure_BehindTrustedTLSProxy pins F11: the
// documented admin deployment terminates TLS at a proxy (Arenet's own
// embedded Caddy, reached via an HTTPS route) and forwards to the admin
// API over plaintext loopback with X-Forwarded-Proto: https. r.TLS is
// then nil, so keying Secure off r.TLS alone dropped the attribute and
// the browser would send the session cookie back over any plaintext
// request to the same host. The resolved secure flag from
// IPExtractMiddleware must flag the cookie Secure in exactly this case,
// while refusing to trust a forwarded scheme from an untrusted caller.
func TestLogin_SessionCookieSecure_BehindTrustedTLSProxy(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string // the immediate hop
		xfProto    string // X-Forwarded-Proto header ("" = absent)
		wantSecure bool
	}{
		{
			name:       "trusted loopback proxy, X-Forwarded-Proto https",
			remoteAddr: "127.0.0.1:52000",
			xfProto:    "https",
			wantSecure: true,
		},
		{
			name:       "trusted loopback proxy, X-Forwarded-Proto http",
			remoteAddr: "127.0.0.1:52000",
			xfProto:    "http",
			wantSecure: false,
		},
		{
			name:       "trusted loopback proxy, no forwarded scheme",
			remoteAddr: "127.0.0.1:52000",
			xfProto:    "",
			wantSecure: false,
		},
		{
			name:       "untrusted caller forging X-Forwarded-Proto https",
			remoteAddr: "203.0.113.5:52000",
			xfProto:    "https",
			wantSecure: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, token := setupTestEnv(t)
			_, _ = adminBootstrap(t, env, token, "admin", testAdminPassword)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
				strings.NewReader(`{"username":"admin","password":"`+testAdminPassword+`","rememberMe":false}`))
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = tc.remoteAddr
			if tc.xfProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xfProto)
			}
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("login status = %d, want 200; body=%s", rec.Code, rec.Body.String())
			}

			c := findCookie(rec, sessionCookieName)
			if c == nil {
				t.Fatal("Set-Cookie arenet_session not emitted on successful login")
			}
			if c.Secure != tc.wantSecure {
				t.Errorf("session cookie Secure = %v; want %v (remoteAddr=%q, X-Forwarded-Proto=%q)",
					c.Secure, tc.wantSecure, tc.remoteAddr, tc.xfProto)
			}
		})
	}
}
