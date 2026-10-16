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

package caddymgr

import (
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// A forward-auth gate must strip conventional identity headers from the
// client request even when the provider does not copy them — otherwise a
// client sets Remote-Groups / X-Authentik-* / X-Forwarded-User itself and
// an upstream that reads them for role mapping trusts the spoofed value
// (F34/F35/F44/F45). The provider here copies only Remote-User; the strip
// must still cover the rest.
func TestForwardAuth_StripsUncopiedIdentityHeaders(t *testing.T) {
	routes := []storage.Route{{
		ID:         "app",
		Host:       "app.example.com",
		Upstreams:  []storage.Upstream{{URL: "http://127.0.0.1:9000", Weight: 1}},
		LBPolicy:   storage.LBPolicyRoundRobin,
		WAFMode:    "off",
		TLSEnabled: true,
		AuthMode:   storage.RouteAuthForwardAuth,
		ForwardAuth: storage.ForwardAuthRouteConfig{
			ProviderName: "authentik",
		},
	}}
	opts := buildOpts{
		DevMode: true,
		ForwardAuthProviders: map[string]storage.ForwardAuthProvider{
			"authentik": {
				Name:           "authentik",
				VerifyURL:      "http://127.0.0.1:9091",
				AuthRequestURI: "/outpost.goauthentik.io/auth/caddy",
				CopyHeaders:    []string{"Remote-User"}, // copies ONE; the rest must still be stripped
			},
		},
	}

	raw, err := buildConfigJSON(routes, opts)
	if err != nil {
		t.Fatalf("buildConfigJSON: %v", err)
	}
	got := string(raw)

	// These are not in CopyHeaders, so before the fix a client could
	// supply them and they would reach the upstream. The gate must delete
	// them from the incoming request.
	for _, h := range []string{"Remote-Groups", "X-Forwarded-User", "X-Authentik-*"} {
		if !strings.Contains(got, `"`+h+`"`) {
			t.Errorf("forward-auth gate does not strip %q from the client request — it can be spoofed (F34/F35)", h)
		}
	}
}
