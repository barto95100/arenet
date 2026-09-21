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

// Package routecheck probes a route right after it is applied (v2.35):
// one real request through the local Caddy listener, with the route's
// host as Host header and TLS SNI, classified as ok / failed /
// pending_certificate / skipped. The API uses it to warn about — or
// roll back — a route that stopped answering after a change.
package routecheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// Status is the outcome of a probe.
type Status string

// Probe outcomes.
const (
	// StatusOK: Caddy routed the request (any answer but 502/503/504).
	StatusOK Status = "ok"
	// StatusFailed: 502 / 503 / 504, or the listener did not answer.
	StatusFailed Status = "failed"
	// StatusPendingCertificate: the TLS handshake failed — the route's
	// certificate is not issued yet (caddy.Load returns before ACME).
	StatusPendingCertificate Status = "pending_certificate"
	// StatusSkipped: no probe (disabled, maintenance, no probeable host).
	StatusSkipped Status = "skipped"
)

// ProbeHeader marks Arenet's own probe requests.
const ProbeHeader = "X-Arenet-Probe"

const (
	defaultAttempts = 3
	defaultInterval = 2 * time.Second
	defaultTimeout  = 4 * time.Second
	loopbackHost    = "127.0.0.1"
)

// Result describes one route check.
type Result struct {
	Status     Status `json:"status"`
	Host       string `json:"host,omitempty"`
	HTTPStatus int    `json:"httpStatus,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// Failed reports a route that does not answer.
func (r Result) Failed() bool { return r.Status == StatusFailed }

// Prober sends the probes. The listen functions return Caddy's listen
// addresses (":8443", "0.0.0.0:443"…); only the port is used, the
// probe always dials the loopback.
type Prober struct {
	HTTPListen  func() string
	HTTPSListen func() string
	Attempts    int
	Interval    time.Duration
	Timeout     time.Duration
}

// New returns a Prober with the default retry policy (3 attempts, 2 s
// apart, 4 s each).
func New(httpListen, httpsListen func() string) *Prober {
	return &Prober{HTTPListen: httpListen, HTTPSListen: httpsListen,
		Attempts: defaultAttempts, Interval: defaultInterval, Timeout: defaultTimeout}
}

// ProbeHost picks the host to probe: the primary host, else the first
// non-wildcard alias; ok is false when every name is a wildcard.
func ProbeHost(r storage.Route) (string, bool) {
	for _, h := range append([]string{r.Host}, r.Aliases...) {
		h = strings.TrimSpace(h)
		if h != "" && !strings.Contains(h, "*") {
			return h, true
		}
	}
	return "", false
}

// Probe checks that r answers through Caddy. Disabled routes, routes
// in maintenance (they answer 503 on purpose) and wildcard-only routes
// are skipped. Retries until a non-failed outcome or Attempts is
// reached; the last outcome is returned.
func (p *Prober) Probe(ctx context.Context, r storage.Route) Result {
	if r.Disabled {
		return Result{Status: StatusSkipped, Detail: "route disabled"}
	}
	if r.MaintenanceConfig != nil {
		return Result{Status: StatusSkipped, Detail: "route in maintenance"}
	}
	host, ok := ProbeHost(r)
	if !ok {
		return Result{Status: StatusSkipped, Detail: "no probeable host (wildcard only)"}
	}
	var res Result
	for i := 0; i < max(p.Attempts, 1); i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return res
			case <-time.After(p.Interval):
			}
		}
		res = p.once(ctx, host, r.TLSEnabled)
		if !res.Failed() {
			return res
		}
	}
	return res
}

// once sends one probe request.
func (p *Prober) once(ctx context.Context, host string, useTLS bool) Result {
	listen, scheme := p.HTTPListen, "http"
	if useTLS {
		listen, scheme = p.HTTPSListen, "https"
	}
	port := portOf(listen())
	ctx, cancel := context.WithTimeout(ctx, p.Timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: p.Timeout}
	target := net.JoinHostPort(loopbackHost, port)
	client := &http.Client{
		Transport: &http.Transport{
			// Always the local listener, whatever the host resolves to.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, target)
			},
			// The probe checks routing, not the chain: internal CA in
			// dev, staging, fresh certs are all fine here.
			TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true}, //nolint:gosec // see above
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(host, port)+"/", nil)
	if err != nil {
		return Result{Status: StatusFailed, Host: host, Detail: err.Error()}
	}
	req.Host = host
	req.Header.Set(ProbeHeader, "1")
	resp, err := client.Do(req)
	if err != nil {
		return classifyError(host, err, useTLS)
	}
	_ = resp.Body.Close()
	return classifyStatus(host, resp.StatusCode)
}

// classifyStatus maps Caddy's answer: 502 (upstream unreachable), 503
// (no upstream available) and 504 (upstream timeout) are the proxy's
// own failures (reverseproxy.go statusError); anything else means the
// route served the request.
func classifyStatus(host string, code int) Result {
	switch code {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return Result{Status: StatusFailed, Host: host, HTTPStatus: code,
			Detail: fmt.Sprintf("the route answered %d %s", code, http.StatusText(code))}
	}
	return Result{Status: StatusOK, Host: host, HTTPStatus: code}
}

// classifyError: a TLS handshake failure on a TLS route is a pending
// certificate; anything else (refused, timeout) is a failure.
func classifyError(host string, err error, useTLS bool) Result {
	var recErr tls.RecordHeaderError
	var alert tls.AlertError
	if useTLS && (errors.As(err, &alert) || errors.As(err, &recErr) ||
		strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "handshake")) {
		return Result{Status: StatusPendingCertificate, Host: host,
			Detail: "TLS handshake failed — the certificate is probably still being issued"}
	}
	return Result{Status: StatusFailed, Host: host, Detail: err.Error()}
}

// portOf extracts the port of a listen address (":8443" → "8443").
func portOf(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return port
	}
	return strings.TrimPrefix(listen, ":")
}
