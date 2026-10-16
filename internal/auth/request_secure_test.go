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

package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestIPExtractor_RequestIsSecure covers F11: a request is secure when
// it arrives over TLS directly, OR through a trusted proxy that
// forwarded X-Forwarded-Proto: https. X-Forwarded-Proto from an
// untrusted caller must never flip the result — otherwise a client on a
// plaintext path could forge a secure context.
func TestIPExtractor_RequestIsSecure(t *testing.T) {
	e, err := NewIPExtractor("10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewIPExtractor: %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		tlsState   bool   // r.TLS != nil
		xfProto    string // "" = header absent
		want       bool
	}{
		{
			name:       "direct TLS, no forwarded scheme",
			remoteAddr: "203.0.113.5:443",
			tlsState:   true,
			want:       true,
		},
		{
			name:       "loopback proxy forwards https",
			remoteAddr: "127.0.0.1:9000",
			xfProto:    "https",
			want:       true,
		},
		{
			name:       "configured trusted proxy forwards https",
			remoteAddr: "10.0.0.1:9000",
			xfProto:    "https",
			want:       true,
		},
		{
			name:       "trusted proxy forwards https as leftmost of a chain",
			remoteAddr: "10.0.0.1:9000",
			xfProto:    "https, http",
			want:       true,
		},
		{
			name:       "trusted proxy forwards http",
			remoteAddr: "127.0.0.1:9000",
			xfProto:    "http",
			want:       false,
		},
		{
			name:       "trusted proxy, no forwarded scheme",
			remoteAddr: "127.0.0.1:9000",
			xfProto:    "",
			want:       false,
		},
		{
			name:       "untrusted caller forging https is ignored",
			remoteAddr: "203.0.113.5:9000",
			xfProto:    "https",
			want:       false,
		},
		{
			name:       "untrusted caller, no TLS, no header",
			remoteAddr: "203.0.113.5:9000",
			xfProto:    "",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			if tc.tlsState {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.xfProto != "" {
				r.Header.Set("X-Forwarded-Proto", tc.xfProto)
			}
			if got := e.RequestIsSecure(r); got != tc.want {
				t.Errorf("RequestIsSecure = %v; want %v", got, tc.want)
			}
		})
	}
}
