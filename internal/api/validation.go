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
