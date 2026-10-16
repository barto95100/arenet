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
// Loopback is ALWAYS trusted, and the list adds to it.
//
// v2.56.2 — the admin API listens on 127.0.0.1 and the documented way to
// reach the UI is an Arenet route, so the caller is Arenet's own embedded
// Caddy proxying over loopback. With loopback untrusted, every remote
// operator resolved to 127.0.0.1: the audit log recorded the loopback for
// everyone, and — worse — the login rate limiter bucketed every attempt
// from every source into one shared counter (ratelimit.go:399 keys on this
// same value), so per-IP brute-force protection did not exist and an
// attacker could exhaust the bucket the legitimate operator needs.
//
// Requiring ARENET_TRUSTED_PROXIES for Arenet's OWN proxy was a default
// that produced a wrong audit log and a broken limiter for every
// installation following the documentation.
//
// The residual risk is named rather than hidden: a process already running
// on the host can reach 127.0.0.1:8001 and forge X-Forwarded-For, which
// pollutes the audit IP and lets it rotate rate-limit buckets. That is a
// local-attacker scenario, where reading the BoltDB file directly is
// already available; the remote case this fixes is the realistic one.
func NewIPExtractor(cidrList string) (*IPExtractor, error) {
	e := &IPExtractor{trustedCIDRs: loopbackCIDRs()}
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

// loopbackCIDRs is the always-trusted set: Arenet's own embedded Caddy
// proxies the admin API over loopback, so this is not an external proxy
// being trusted, it is the process itself.
func loopbackCIDRs() []*net.IPNet {
	out := make([]*net.IPNet, 0, 2)
	for _, raw := range []string{"127.0.0.0/8", "::1/128"} {
		if _, n, err := net.ParseCIDR(raw); err == nil {
			out = append(out, n)
		}
	}
	return out
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

// callerTrusted reports whether the immediate caller (r.RemoteAddr,
// NOT any forwarded value) is in the trusted set — loopback, always,
// plus ARENET_TRUSTED_PROXIES. It is the same gate ClientIP applies
// before honoring X-Forwarded-For, kept separate so RequestIsSecure can
// reuse it for X-Forwarded-Proto without disturbing the IP path.
func (e *IPExtractor) callerTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range e.trustedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedProtoIsHTTPS reports whether the leftmost X-Forwarded-Proto
// entry is "https". The leftmost value is the scheme the original
// client used to reach the outermost proxy; intermediate hops append
// to the right. Caller trust is NOT checked here — RequestIsSecure
// gates on callerTrusted first.
func forwardedProtoIsHTTPS(r *http.Request) bool {
	xfp := r.Header.Get("X-Forwarded-Proto")
	if xfp == "" {
		return false
	}
	first := strings.TrimSpace(strings.SplitN(xfp, ",", 2)[0])
	return strings.EqualFold(first, "https")
}

// RequestIsSecure reports whether the request reached Arenet over a
// secure transport: directly over TLS, or through a TLS-terminating
// proxy whose immediate hop is trusted and that set
// X-Forwarded-Proto: https. An untrusted caller's X-Forwarded-Proto is
// ignored, so a client on a plaintext path cannot forge a secure
// context and trick Arenet into emitting Secure cookies it would then
// have to honor. Consumed via RequestIsSecureFromContext by the
// Set-Cookie helpers (F11).
func (e *IPExtractor) RequestIsSecure(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	return e.callerTrusted(r) && forwardedProtoIsHTTPS(r)
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
			ctx = context.WithValue(ctx, RequestSecureKey, extractor.RequestIsSecure(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
