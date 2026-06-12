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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestProbeOIDCDiscovery_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:          "https://idp.example",
			ScopesSupported: []string{"openid", "profile", "email", "groups"},
		})
	}))
	defer srv.Close()

	resp := probeOIDCDiscovery(context.Background(), srv.URL, []string{"openid", "email"})

	if !resp.Reachable {
		t.Fatalf("want reachable=true, got false (error=%q)", resp.Error)
	}
	if resp.Issuer != "https://idp.example" {
		t.Errorf("issuer mismatch: got %q", resp.Issuer)
	}
	if !resp.ScopesMatch {
		t.Errorf("want scopesMatch=true (saved ⊂ supported), got false; missing=%v", resp.MissingScopes)
	}
	wantSupported := []string{"email", "groups", "openid", "profile"} // sorted
	if !reflect.DeepEqual(resp.SupportedScopes, wantSupported) {
		t.Errorf("supportedScopes mismatch: got %v, want %v (sorted)", resp.SupportedScopes, wantSupported)
	}
}

func TestProbeOIDCDiscovery_ScopesMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryDoc{
			Issuer:          "https://idp.example",
			ScopesSupported: []string{"openid", "profile"},
		})
	}))
	defer srv.Close()

	resp := probeOIDCDiscovery(context.Background(), srv.URL, []string{"openid", "email", "groups"})

	if !resp.Reachable {
		t.Fatalf("want reachable=true, got false (error=%q)", resp.Error)
	}
	if resp.ScopesMatch {
		t.Errorf("want scopesMatch=false (saved has email+groups, supported lacks them), got true")
	}
	wantMissing := []string{"email", "groups"}
	if !reflect.DeepEqual(resp.MissingScopes, wantMissing) {
		t.Errorf("missingScopes mismatch: got %v, want %v", resp.MissingScopes, wantMissing)
	}
}

func TestProbeOIDCDiscovery_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	resp := probeOIDCDiscovery(context.Background(), srv.URL, []string{"openid"})

	if resp.Reachable {
		t.Errorf("want reachable=false for 503 discovery, got true")
	}
	if resp.Error == "" {
		t.Errorf("want non-empty error message for non-2xx")
	}
}

func TestProbeOIDCDiscovery_RedirectsNotFollowed(t *testing.T) {
	// A 301 from the discovery URL is a real misconfiguration
	// signal — the probe must NOT silently follow it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, nil, "https://elsewhere.example/.well-known/openid-configuration", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	resp := probeOIDCDiscovery(context.Background(), srv.URL, []string{"openid"})

	if resp.Reachable {
		t.Errorf("want reachable=false when discovery responds 301, got true")
	}
}

func TestProbeOIDCDiscovery_BadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>not JSON</html>"))
	}))
	defer srv.Close()

	resp := probeOIDCDiscovery(context.Background(), srv.URL, []string{"openid"})

	if resp.Reachable {
		t.Errorf("want reachable=false when discovery body is not JSON, got true")
	}
}

func TestProbeOIDCDiscovery_MalformedURL(t *testing.T) {
	resp := probeOIDCDiscovery(context.Background(), "not a url", []string{"openid"})
	if resp.Reachable || resp.Error == "" {
		t.Errorf("want reachable=false + error for malformed URL, got %+v", resp)
	}
}

func TestProbeOIDCDiscovery_NonHTTPScheme(t *testing.T) {
	resp := probeOIDCDiscovery(context.Background(), "ftp://idp.example", []string{"openid"})
	if resp.Reachable || resp.Error == "" {
		t.Errorf("want reachable=false + error for non-http scheme, got %+v", resp)
	}
}

func TestScopesDiff(t *testing.T) {
	cases := []struct {
		name      string
		saved     []string
		supported []string
		want      []string
	}{
		{"all present", []string{"openid", "email"}, []string{"openid", "email", "profile"}, nil},
		{"one missing", []string{"openid", "groups"}, []string{"openid", "email"}, []string{"groups"}},
		{"empty supported", []string{"openid"}, nil, []string{"openid"}},
		{"empty saved", nil, []string{"openid"}, nil},
		{"sorted output", []string{"z", "a", "m"}, nil, []string{"a", "m", "z"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopesDiff(tc.saved, tc.supported)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
