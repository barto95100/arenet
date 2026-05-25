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

// Package api exposes the REST admin API for Arenet.
package api

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/barto95100/arenet/internal/storage"
)

// hostnameRE is a pragmatic RFC 1123 hostname check: dot-separated labels,
// each label 1-63 chars of alnum + dash, must start and end with alnum.
var hostnameRE = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`,
)

// validateHost checks that s is non-empty, contains no whitespace, and matches
// a basic hostname grammar. Returns the first failure with a user-facing
// English message.
func validateHost(s string) error {
	if strings.TrimSpace(s) == "" {
		return errors.New("host must not be empty")
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return errors.New("host must not contain whitespace")
	}
	if len(s) > 253 || !hostnameRE.MatchString(s) {
		return errors.New("host must be a valid hostname")
	}
	return nil
}

// validateUpstreamURL checks that s is a parsable absolute URL using the http
// or https scheme and that it carries a host component.
func validateUpstreamURL(s string) error {
	if s == "" {
		return errors.New("upstreamUrl must not be empty")
	}
	u, err := url.ParseRequestURI(s)
	if err != nil {
		return errors.New("upstreamUrl is not a valid URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return errors.New("upstreamUrl must use http or https scheme")
	}
	if u.Host == "" {
		return errors.New("upstreamUrl must include a host")
	}
	return nil
}

// validateUpstreamPool checks the Step J.1 upstream pool: at least
// one entry, each entry's URL parsable per validateUpstreamURL.
// Per-element Weight is NOT checked here — the API materialises
// Weight=0 → 1 before this function runs, so a weight that reaches
// the validator is, by construction, the API's chosen default or an
// explicit user value (which must be >= 1, asserted below).
//
// The friendly per-element error wraps validateUpstreamURL's
// existing message with the row index so operators can locate the
// offending pool element in a multi-upstream payload.
func validateUpstreamPool(pool []upstreamReq) error {
	if len(pool) == 0 {
		return errors.New("upstreams must contain at least one entry")
	}
	for i, u := range pool {
		if err := validateUpstreamURL(u.URL); err != nil {
			return fmt.Errorf("upstreams[%d]: %s", i, err.Error())
		}
		if u.Weight < 1 {
			return fmt.Errorf("upstreams[%d].weight must be >= 1", i)
		}
	}
	return nil
}

// validateLBPolicy checks that s is one of the six storage.LBPolicy*
// values. Empty string is rejected — the API is expected to have
// materialised the default ("round_robin") before this function
// runs, so an empty value here is a programming error.
func validateLBPolicy(s string) error {
	for _, p := range storage.LBPolicies {
		if s == p {
			return nil
		}
	}
	return fmt.Errorf("lbPolicy %q is not a valid policy", s)
}

// Step J.2 — five default values the API layer materialises into
// HealthCheck sub-fields before validation runs. uri is NOT in
// this set: there is no sensible default health-check path; the
// operator must always supply it when Enabled is true (§5.2). The
// constants live next to the validator so a single edit keeps the
// materialise-then-validate pipeline consistent.
const (
	defaultHCMethod   = "GET"
	defaultHCInterval = "30s"
	defaultHCTimeout  = "5s"
	defaultHCPasses   = 1
	defaultHCFails    = 1
)

// validateHealthCheck runs the eight Step J.2 API-layer rules on a
// healthCheckReq that has been through the defaults injection
// (Method/Interval/Timeout/Passes/Fails) + Method uppercase
// normalisation. Only called when h.Enabled is true; callers MUST
// guard.
//
// The validation messages use camelCase field names ("healthCheck.
// uri", "healthCheck.method", ...) because they surface to the API
// caller verbatim — friendlier 400 than the snake_case storage
// errors. The storage HealthCheck.validate() runs after, as the
// strict last line of defence against direct CreateRoute /
// UpdateRoute calls that bypass the API.
func validateHealthCheck(h healthCheckReq) error {
	if h.URI == "" {
		return errors.New("healthCheck.uri must not be empty when enabled")
	}
	if !strings.HasPrefix(h.URI, "/") {
		return fmt.Errorf("healthCheck.uri %q must start with /", h.URI)
	}
	if h.Method != "GET" && h.Method != "HEAD" {
		return fmt.Errorf("healthCheck.method %q must be GET or HEAD", h.Method)
	}
	interval, err := time.ParseDuration(h.Interval)
	if err != nil {
		return fmt.Errorf("healthCheck.interval %q is not a valid duration", h.Interval)
	}
	if interval <= 0 {
		return errors.New("healthCheck.interval must be strictly positive")
	}
	timeout, err := time.ParseDuration(h.Timeout)
	if err != nil {
		return fmt.Errorf("healthCheck.timeout %q is not a valid duration", h.Timeout)
	}
	if timeout <= 0 {
		return errors.New("healthCheck.timeout must be strictly positive")
	}
	if timeout >= interval {
		return errors.New("healthCheck.timeout must be strictly less than interval")
	}
	if h.ExpectStatus != 0 && (h.ExpectStatus < 100 || h.ExpectStatus > 599) {
		return fmt.Errorf("healthCheck.expectStatus %d must be 0 or in 100..599", h.ExpectStatus)
	}
	if h.ExpectBody != "" {
		if _, err := regexp.Compile(h.ExpectBody); err != nil {
			return fmt.Errorf("healthCheck.expectBody is not a valid regex: %v", err)
		}
	}
	if h.Passes < 1 {
		return errors.New("healthCheck.passes must be >= 1")
	}
	if h.Fails < 1 {
		return errors.New("healthCheck.fails must be >= 1")
	}
	return nil
}

// materialiseHealthCheck applies the five default values (and the
// Method uppercase normalisation) to an Enabled health check
// before validation runs. URI is NOT defaulted — it must come
// from the caller. The function returns a new healthCheckReq with
// the defaults filled in; the caller swaps the original with the
// returned one before passing it to validateHealthCheck and to
// the storage mapping.
//
// Called only when the caller has determined Enabled is true.
func materialiseHealthCheck(h healthCheckReq) healthCheckReq {
	if h.Method == "" {
		h.Method = defaultHCMethod
	}
	h.Method = strings.ToUpper(h.Method)
	if h.Interval == "" {
		h.Interval = defaultHCInterval
	}
	if h.Timeout == "" {
		h.Timeout = defaultHCTimeout
	}
	if h.Passes == 0 {
		h.Passes = defaultHCPasses
	}
	if h.Fails == 0 {
		h.Fails = defaultHCFails
	}
	return h
}
