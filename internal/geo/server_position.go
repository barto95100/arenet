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

package geo

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ServerPosition is the lat/lon of the Arenet server itself. Used by
// V.4 to anchor the topology map (server-at-center). Mode is "auto"
// when detected via DetectFromPublicIP, "manual" when V.4's operator
// override endpoint is used.
//
// Per Step V spec §3.4 — public-IP auto-detection at boot via
// ipify, with operator-supplied manual override as the fallback.
type ServerPosition struct {
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	City       string    `json:"city"`
	Country    string    `json:"country"`
	Mode       string    `json:"mode"`
	DetectedAt time.Time `json:"detectedAt"`
}

// ipifyURL is the endpoint queried by DetectFromPublicIP. Exported as
// a package variable so tests can swap it for an httptest.Server URL
// without spinning up a custom HTTP client. Production code MUST NOT
// mutate this value; only test code via SetIpifyURL.
//
// Default: api.ipify.org's plaintext endpoint. Returns just the IP
// in the response body, no JSON, no trailing newline.
var ipifyURL = "https://api.ipify.org?format=text"

// detectClient is the HTTP client used by DetectFromPublicIP. Exposed
// at package scope so tests can substitute a stub transport without
// touching ipifyURL when the failure mode under test is purely on the
// HTTP layer (DNS failure, connection refused, etc).
var detectClient = &http.Client{Timeout: 5 * time.Second}

// SetIpifyURL overrides the ipify endpoint. Test-only — intended for
// use with httptest.Server. Returns a restore function so callers
// can defer SetIpifyURL(...) cleanly.
func SetIpifyURL(u string) func() {
	prev := ipifyURL
	ipifyURL = u
	return func() { ipifyURL = prev }
}

// SetDetectClient overrides the HTTP client used by DetectFromPublicIP.
// Test-only. Returns a restore function.
func SetDetectClient(c *http.Client) func() {
	prev := detectClient
	detectClient = c
	return func() { detectClient = prev }
}

// DetectFromPublicIP discovers the Arenet server's public IP via
// ipify and resolves the resulting address through the given Lookup.
// Returns a populated ServerPosition with Mode="auto" on success.
//
// The ARENET_PUBLIC_IP env var, if set and non-empty, bypasses the
// network call entirely — useful for tests, air-gapped deployments,
// and operators who want to lock the detected IP.
//
// Returns an error when:
//   - lookup is nil (degraded GeoIP mode — caller falls back to manual
//     override per V.4);
//   - the env-supplied IP fails to parse;
//   - the HTTP request fails (timeout, DNS, non-2xx);
//   - the response body is not a valid IP;
//   - the GeoIP lookup yields no location (Found=false).
func DetectFromPublicIP(lookup *Lookup) (*ServerPosition, error) {
	if lookup == nil {
		return nil, errors.New("geo: server position requires a non-nil Lookup (GeoIP database not loaded)")
	}

	ipStr, err := resolvePublicIP()
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("geo: invalid public IP %q", ipStr)
	}

	loc := lookup.LookupIP(ip)
	if !loc.Found {
		return nil, fmt.Errorf("geo: public IP %s not resolved in MMDB", ipStr)
	}

	return &ServerPosition{
		Lat:        loc.Lat,
		Lon:        loc.Lon,
		City:       loc.City,
		Country:    loc.Country,
		Mode:       "auto",
		DetectedAt: time.Now().UTC(),
	}, nil
}

// resolvePublicIP returns the server's public IP either from the
// ARENET_PUBLIC_IP override or via an HTTP GET to ipifyURL.
func resolvePublicIP() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ARENET_PUBLIC_IP")); override != "" {
		return override, nil
	}

	req, err := http.NewRequest(http.MethodGet, ipifyURL, nil)
	if err != nil {
		return "", fmt.Errorf("geo: build ipify request: %w", err)
	}
	resp, err := detectClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("geo: ipify request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("geo: ipify returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", fmt.Errorf("geo: read ipify body: %w", err)
	}
	return strings.TrimSpace(string(body)), nil
}
