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

package routecheck

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

func fastProber(httpAddr, httpsAddr string) *Prober {
	p := New(func() string { return httpAddr }, func() string { return httpsAddr })
	p.Interval, p.Timeout = 10*time.Millisecond, time.Second
	return p
}

func route(host string, tlsOn bool) storage.Route {
	return storage.Route{Host: host, TLSEnabled: tlsOn}
}

func TestProbe_HTTPStatuses(t *testing.T) {
	for code, want := range map[int]Status{
		200: StatusOK, 301: StatusOK, 401: StatusOK, 404: StatusOK, 500: StatusOK,
		502: StatusFailed, 503: StatusFailed, 504: StatusFailed,
	} {
		var gotHost, gotProbe string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotHost, gotProbe = r.Host, r.Header.Get(ProbeHeader)
			w.WriteHeader(code)
		}))
		res := fastProber(srv.Listener.Addr().String(), "").Probe(context.Background(), route("app.example.com", false))
		srv.Close()
		if res.Status != want || res.HTTPStatus != code {
			t.Errorf("%d → %+v, want %s", code, res, want)
		}
		if gotHost != "app.example.com" || gotProbe != "1" {
			t.Errorf("request host %q probe header %q", gotHost, gotProbe)
		}
	}
}

func TestProbe_RetriesThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res := fastProber(srv.Listener.Addr().String(), "").Probe(context.Background(), route("a.example", false))
	if res.Status != StatusOK || n.Load() != 3 {
		t.Errorf("res %+v after %d attempts", res, n.Load())
	}
}

func TestProbe_ListenerDown(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	_ = l.Close()
	res := fastProber(addr, "").Probe(context.Background(), route("a.example", false))
	if res.Status != StatusFailed {
		t.Errorf("closed listener: %+v", res)
	}
}

func TestProbe_TLS(t *testing.T) {
	var sni string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	srv.TLS = &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, nil
	}}
	srv.StartTLS()
	defer srv.Close()
	res := fastProber("", srv.Listener.Addr().String()).Probe(context.Background(), route("secure.example.com", true))
	if res.Status != StatusOK || sni != "secure.example.com" {
		t.Errorf("TLS probe %+v, SNI %q", res, sni)
	}
}

// TestProbe_PendingCertificate: a listener that cannot present a
// certificate (certmagic before ACME finished) is not a failure.
func TestProbe_PendingCertificate(t *testing.T) {
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return nil, errors.New("no certificate available for 'new.example.com'")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	res := fastProber("", l.Addr().String()).Probe(context.Background(), route("new.example.com", true))
	if res.Status != StatusPendingCertificate {
		t.Errorf("pending certificate: %+v", res)
	}
}

func TestProbe_Skips(t *testing.T) {
	p := fastProber("127.0.0.1:1", "127.0.0.1:1")
	for name, r := range map[string]storage.Route{
		"disabled":    {Host: "a.example", Disabled: true},
		"maintenance": {Host: "a.example", MaintenanceConfig: &storage.MaintenanceConfig{}},
		"wildcard":    {Host: "*.example.com", Aliases: []string{"*.other.com"}},
	} {
		if res := p.Probe(context.Background(), r); res.Status != StatusSkipped {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if h, ok := ProbeHost(storage.Route{Host: "*.example.com", Aliases: []string{"www.example.com"}}); !ok || h != "www.example.com" {
		t.Errorf("alias fallback: %q %t", h, ok)
	}
}
