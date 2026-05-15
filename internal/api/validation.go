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
	"net/url"
	"regexp"
	"strings"
	"unicode"
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
