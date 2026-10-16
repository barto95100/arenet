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
	"net/url"
	"strings"
	"testing"
)

func TestSanitizeOIDCErrorParam(t *testing.T) {
	if got := sanitizeOIDCErrorParam("access_denied"); got != "access_denied" {
		t.Errorf("a real error code must pass through unchanged, got %q", got)
	}
	// CR/LF and controls are the log-injection vector — they must go.
	got := sanitizeOIDCErrorParam("x\r\n2026-01-01 FORGED login_success admin")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("newlines survived, log injection possible: %q", got)
	}
	// Unbounded growth is capped.
	if got := sanitizeOIDCErrorParam(strings.Repeat("A", 5000)); len(got) > oidcErrorParamMaxLen {
		t.Errorf("error param not capped: len=%d want <= %d", len(got), oidcErrorParamMaxLen)
	}
}

// The unauthenticated OIDC callback must not let a caller write unbounded
// or newline-bearing text into the audit trail via ?error=, nor an
// uncapped User-Agent (F29).
func TestOIDCCallback_ErrorParamAndUA_BoundedInAudit(t *testing.T) {
	env := newTestEnv(t, false)

	inject := "evil\r\n2026-01-01T00:00:00Z FORGED admin login_success " + strings.Repeat("Z", 4000)
	hugeUA := strings.Repeat("U", 4000)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/oidc/callback?error="+url.QueryEscape(inject), nil)
	req.Header.Set("User-Agent", hugeUA)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)

	evts := env.audit.Events()
	if len(evts) == 0 {
		t.Fatal("the callback error branch should have recorded an audit event")
	}
	e := evts[len(evts)-1]
	if strings.ContainsAny(e.Message, "\r\n") {
		t.Errorf("audit Message carries newlines from the attacker — log injection: %q", e.Message)
	}
	if len(e.Message) > oidcErrorParamMaxLen+len("idp_error=") {
		t.Errorf("audit Message not bounded: len=%d", len(e.Message))
	}
	if len(e.UserAgent) > maxAuditUserAgentBytes {
		t.Errorf("audit UserAgent not capped: len=%d want <= %d", len(e.UserAgent), maxAuditUserAgentBytes)
	}
}
