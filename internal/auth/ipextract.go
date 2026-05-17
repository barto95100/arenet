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

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// IPExtractor resolves the client IP for incoming requests, honoring
// X-Forwarded-For from configured trusted proxies (Section 8).
//
// The extractor is goroutine-safe: trustedCIDRs is read-only after
// construction. No mutex is needed.
type IPExtractor struct {
	trustedCIDRs []*net.IPNet
}

// NewIPExtractor parses the comma-separated CIDR list (typically from
// the ARENET_TRUSTED_PROXIES environment variable) and returns a
// configured extractor.
//
// Returns an error if any CIDR is malformed; the server should
// fail-fast in this case (do not start, per spec §8.2).
//
// Pass an empty string (or whitespace only) to disable proxy trust
// entirely; in that case, ClientIP always returns RemoteAddr.
func NewIPExtractor(cidrList string) (*IPExtractor, error) {
	e := &IPExtractor{}
	cidrList = strings.TrimSpace(cidrList)
	if cidrList == "" {
		return e, nil
	}
	for _, raw := range strings.Split(cidrList, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid CIDR in ARENET_TRUSTED_PROXIES: %q", raw)
		}
		e.trustedCIDRs = append(e.trustedCIDRs, ipNet)
	}
	return e, nil
}

// TrustedCIDRs returns the list of parsed CIDRs in canonical form
// (the strings as returned by net.IPNet.String()). Used by startup
// logging in cmd/arenet (spec §8.7).
func (e *IPExtractor) TrustedCIDRs() []string {
	out := make([]string, 0, len(e.trustedCIDRs))
	for _, c := range e.trustedCIDRs {
		out = append(out, c.String())
	}
	return out
}

// ClientIP resolves the client IP for the given request per the
// algorithm in spec §8.3:
//
//  1. Parse RemoteAddr → strip port → get caller IP.
//  2. If caller IP is NOT in any trusted CIDR → return caller IP
//     (X-Forwarded-For is ignored).
//  3. Otherwise, read X-Forwarded-For, take the leftmost entry,
//     validate it. If valid → return it. If invalid → log Debug
//     and fall back to caller IP.
//
// Returns an empty string only if RemoteAddr itself is unparseable
// (which is exceptional). An empty client IP surfaces clearly in
// audit events and rate-limit buckets, making the anomaly visible.
func (e *IPExtractor) ClientIP(r *http.Request) string {
	callerIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr lacked a port (rare, e.g. Unix socket): use as-is.
		callerIP = r.RemoteAddr
	}
	callerParsed := net.ParseIP(callerIP)
	if callerParsed == nil {
		return "" // unparseable RemoteAddr
	}

	// Check if caller is a trusted proxy.
	trusted := false
	for _, cidr := range e.trustedCIDRs {
		if cidr.Contains(callerParsed) {
			trusted = true
			break
		}
	}
	if !trusted {
		return callerIP
	}

	// Caller is trusted: honor leftmost XFF entry.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return callerIP
	}
	leftmost := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	leftmost = strings.Trim(leftmost, "[]") // strip brackets if IPv6
	if leftmost == "" || net.ParseIP(leftmost) == nil {
		slog.Default().Debug("auth: malformed X-Forwarded-For, falling back to RemoteAddr",
			slog.String("xff", xff),
			slog.String("remote_addr", r.RemoteAddr),
		)
		return callerIP
	}
	return leftmost
}

// IPExtractMiddleware returns a chi-compatible middleware that
// resolves the client IP via the extractor and stores it in the
// request context under ClientIPKey (spec §8.6).
//
// Downstream consumers (rate limiter, audit helper) read the value
// via ClientIPFromContext.
func IPExtractMiddleware(extractor *IPExtractor) func(http.Handler) http.Handler {
	if extractor == nil {
		panic("auth.IPExtractMiddleware: extractor is nil")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractor.ClientIP(r)
			ctx := context.WithValue(r.Context(), ClientIPKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
