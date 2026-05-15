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
	"strings"
	"testing"
)

func TestValidateHost(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string // expected error substring; empty = expect nil
	}{
		{"valid simple", "test.local", ""},
		{"valid localhost", "localhost", ""},
		{"valid deep", "a.b.c.d.example.com", ""},
		{"empty", "", "must not be empty"},
		{"whitespace only", "   ", "must not be empty"},
		{"internal whitespace", "foo bar.com", "must not contain whitespace"},
		{"leading dash", "-foo.com", "must be a valid hostname"},
		{"underscore", "foo_bar.com", "must be a valid hostname"},
		{"double dot", "foo..bar.com", "must be a valid hostname"},
		{"too long", strings.Repeat("a", 254), "must be a valid hostname"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHost(tc.in)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestValidateUpstreamURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantSub string
	}{
		{"valid http", "http://127.0.0.1:9999", ""},
		{"valid https", "https://example.com", ""},
		{"valid https with port", "https://example.com:8443/path", ""},
		{"empty", "", "must not be empty"},
		{"garbage", "not-a-url", "is not a valid URL"},
		{"ftp scheme", "ftp://example.com", "must use http or https scheme"},
		{"file scheme", "file:///etc/passwd", "must use http or https scheme"},
		{"no host", "http:///foo", "must include a host"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateUpstreamURL(tc.in)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q missing substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}
