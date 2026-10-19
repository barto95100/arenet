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

package routehealth

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/caddyhc"
	"github.com/barto95100/arenet/internal/netguard"
	"github.com/barto95100/arenet/internal/storage"
)

// DefaultProbeTimeout bounds a single upstream probe.
const DefaultProbeTimeout = 4 * time.Second

// probeBodyLimit caps how much of the response body the expect-body regex
// is matched against, so a chatty upstream cannot pin memory.
const probeBodyLimit = 64 * 1024

// probeRouteUpstreams replays the route's health check directly against
// each of its upstreams, carrying the route's Host, and returns a map of
// normalized upstream address -> caddyhc status (healthy / unhealthy).
//
// This is the UN-COLLAPSED form of Caddy's active health check. Caddy
// keys host health by dial address in one global pool, so routes sharing
// an upstream share one verdict (reverseproxy/hosts.go:130,:308). Here the
// dial carries the route's OWN Host, so a shared multiplexing upstream
// (a Traefik fanning out by Host) routes the probe to the right backend
// and each route gets an independent verdict. The judgement mirrors the
// active HC: expect_status (0 = any 2xx) and, if set, the expect_body
// regex — NOT a lenient "any non-5xx is up", which would read a down
// backend that makes the proxy answer 404 as healthy.
//
// Owned here (not extracted from the API's probeHealthCheck) per the
// repo's convention of keeping the diagnostic plane and the data plane on
// separate code paths. SSRF-guarded via netguard, like every other probe.
//
// An address that cannot be read is omitted; a route whose HC is disabled
// returns an empty map (the caller treats "no verdict" as unknown).
func probeRouteUpstreams(ctx context.Context, r storage.Route, timeout time.Duration) map[string]string {
	out := make(map[string]string, len(r.Upstreams))
	if !r.HealthCheck.Enabled {
		return out
	}
	hc := r.HealthCheck
	host := hc.ProbeHost(r.Host)

	var bodyRe *regexp.Regexp
	if hc.ExpectBody != "" {
		re, err := regexp.Compile(hc.ExpectBody)
		if err != nil {
			// A bad regex cannot judge anything; leave every upstream
			// unknown rather than guess. The save-time validator should
			// have caught this already.
			return map[string]string{}
		}
		bodyRe = re
	}

	for _, u := range r.Upstreams {
		key := caddyhc.NormalizeAddr(u.URL)
		if key == "" {
			continue
		}
		out[key] = probeOneUpstream(ctx, u.URL, key, hc, host, bodyRe, timeout)
	}
	return out
}

// probeOneUpstream dials one upstream (by its canonical host:port) with the
// route's Host and HC request shape, and returns caddyhc.StatusHealthy or
// StatusUnhealthy. Any transport error, a status outside expect_status, or
// a body that fails the regex is unhealthy.
func probeOneUpstream(ctx context.Context, upstreamURL, dial string, hc storage.HealthCheck, host string, bodyRe *regexp.Regexp, timeout time.Duration) string {
	scheme := "http"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(upstreamURL)), "https://") {
		scheme = "https"
	}
	uri := hc.URI
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	method := hc.Method
	if method == "" {
		method = http.MethodGet
	}
	target := scheme + "://" + dial + uri

	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, method, target, nil)
	if err != nil {
		return caddyhc.StatusUnhealthy
	}
	if host != "" {
		req.Host = host
	}
	for name, value := range hc.Headers {
		req.Header.Set(name, value)
	}

	transport := &http.Transport{
		DialContext: netguard.NewDialer(timeout).DialContext,
		// The probe mirrors the active HC's question — "does this backend
		// serve my route" — which is reachability, not certificate trust;
		// a homelab https upstream with a self-signed cert must stay
		// probeable, exactly as the API's HC test allows.
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}, //nolint:gosec
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		// The active HC does not follow redirects, so neither do we — a
		// 3xx is a status like any other, judged against expect_status.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Do(req)
	if err != nil {
		return caddyhc.StatusUnhealthy
	}
	defer resp.Body.Close()

	if !statusMatches(resp.StatusCode, hc.ExpectStatus) {
		return caddyhc.StatusUnhealthy
	}
	if bodyRe != nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
		if !bodyRe.Match(body) {
			return caddyhc.StatusUnhealthy
		}
	}
	return caddyhc.StatusHealthy
}

// statusMatches mirrors the active HC's rule: expect_status 0 means "any
// 2xx", otherwise the status must equal it exactly.
func statusMatches(code, expect int) bool {
	if expect == 0 {
		return code >= 200 && code < 300
	}
	return code == expect
}
