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

package topology

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeUpstreamAddr(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://10.0.4.12:8080", "10.0.4.12:8080"},
		{"https://10.0.4.12:8080", "10.0.4.12:8080"},
		{"h2c://10.0.4.12:8080", "10.0.4.12:8080"},
		{"10.0.4.12:8080", "10.0.4.12:8080"},
		{"http://10.0.4.12:8080/v2/path", "10.0.4.12:8080"},
		{"http://10.0.4.12:8080?q=1", "10.0.4.12:8080"},
		{"http://10.0.4.12:8080#frag", "10.0.4.12:8080"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeUpstreamAddr(c.in)
		if got != c.want {
			t.Errorf("normalizeUpstreamAddr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCaddyStatusProber_BeforeRefresh_AllUnknown(t *testing.T) {
	p := NewCaddyStatusProberWithURL("http://127.0.0.1:0/never") // unreachable
	if got := p.Status("http://10.0.4.12:8080"); got != StatusUnknown {
		t.Errorf("pre-Refresh status: got %q, want %q", got, StatusUnknown)
	}
}

func TestCaddyStatusProber_RefreshThenStatus(t *testing.T) {
	// Fake Caddy admin endpoint returning a 2-upstream payload —
	// one healthy (fails=0), one unhealthy (fails=3).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[
			{"address":"10.0.4.12:8080","num_requests":420,"fails":0},
			{"address":"10.0.4.13:8080","num_requests":17,"fails":3}
		]`))
	}))
	defer srv.Close()

	p := NewCaddyStatusProberWithURL(srv.URL)
	p.Refresh(context.Background())

	if got := p.Status("http://10.0.4.12:8080"); got != StatusHealthy {
		t.Errorf("healthy upstream: got %q, want %q", got, StatusHealthy)
	}
	if got := p.Status("http://10.0.4.13:8080"); got != StatusUnhealthy {
		t.Errorf("unhealthy upstream: got %q, want %q", got, StatusUnhealthy)
	}
	if got := p.Status("http://10.0.4.99:8080"); got != StatusUnknown {
		t.Errorf("absent upstream: got %q, want %q", got, StatusUnknown)
	}
}

func TestCaddyStatusProber_UnreachableLeavesStatusUnknown(t *testing.T) {
	p := NewCaddyStatusProberWithURL("http://127.0.0.1:1/refused")
	// Refresh against an unreachable endpoint MUST NOT panic and
	// MUST leave the cache in the "unknown" state.
	p.Refresh(context.Background())
	if got := p.Status("http://10.0.4.12:8080"); got != StatusUnknown {
		t.Errorf("after failed refresh: got %q, want %q", got, StatusUnknown)
	}
}

func TestCaddyStatusProber_NonJSONResponseLeavesStatusUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>not json</html>`))
	}))
	defer srv.Close()
	p := NewCaddyStatusProberWithURL(srv.URL)
	p.Refresh(context.Background())
	if got := p.Status("http://10.0.4.12:8080"); got != StatusUnknown {
		t.Errorf("after malformed response: got %q, want %q", got, StatusUnknown)
	}
}

func TestCaddyStatusProber_NonOKStatusLeavesStatusUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	p := NewCaddyStatusProberWithURL(srv.URL)
	p.Refresh(context.Background())
	if got := p.Status("http://10.0.4.12:8080"); got != StatusUnknown {
		t.Errorf("after 503: got %q, want %q", got, StatusUnknown)
	}
}
