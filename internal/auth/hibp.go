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

// SHA-1 is used ONLY for the HaveIBeenPwned k-anonymity protocol,
// which mandates it for compatibility reasons (spec §7.2). We NEVER
// use SHA-1 for password storage — passwords are hashed with argon2id
// (see userstore.go and decision Q4). Static-analysis tooling that
// flags crypto/sha1 imports as a "weak hash" warning is correct in
// general but does not apply to this file: SHA-1 is the wire protocol
// here, not a security primitive.

package auth

import (
	"bufio"
	"context"
	"crypto/sha1" // HIBP wire protocol only, NOT for storage — see package doc.
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// HIBPStatus reflects the outcome of a HIBP check. Stored on User
// as a plain string (see types.go HIBPStatusXxx constants); the
// CheckPassword method returns the same string values.
//
// Step D Phase 1 deliberately keeps this as a string alias rather
// than a newtype to avoid casting friction with User.HIBPCheckStatus
// (spec §3.2). Phase 2 may revisit.
const (
	// HIBPTimeoutSync is the hard timeout applied to synchronous HIBP
	// checks (password creation / change). "Sync" in the name
	// anticipates a future HIBPTimeoutAsync for the deferred re-check
	// flow (Phase 2 / spec §7.6).
	HIBPTimeoutSync = 5 * time.Second

	// hibpDefaultBaseURL is the production HIBP Pwned Passwords API.
	// Tests substitute their own URL via the unexported baseURL field
	// (constructed directly without NewHIBPClient).
	hibpDefaultBaseURL = "https://api.pwnedpasswords.com"

	// hibpUserAgent identifies Arenet to HIBP per their fair-use
	// guidelines. They ask only for a sensible User-Agent.
	hibpUserAgent = "Arenet/0.1 (homelab-reverse-proxy)"

	// envHIBPDisabled is the environment variable name documented in
	// spec §7.8. Setting it to exactly "true" disables HIBP entirely
	// (other values, including "True"/"1"/"yes", leave HIBP enabled —
	// AC-CONFIG-04 from spec §10.9).
	envHIBPDisabled = "ARENET_HIBP_DISABLED"
)

// HIBPClient performs k-anonymity checks against the HaveIBeenPwned
// Pwned Passwords API (spec §7.3).
//
// The client is stateless apart from the http.Client (which holds
// its own connection pool). Safe for concurrent use.
type HIBPClient struct {
	httpClient *http.Client
	baseURL    string
	userAgent  string
	disabled   bool
}

// NewHIBPClient constructs a production client honoring
// ARENET_HIBP_DISABLED. Tests that need a custom base URL (to point
// at a httptest.Server) construct the struct directly with the
// unexported fields.
func NewHIBPClient() *HIBPClient {
	return &HIBPClient{
		httpClient: &http.Client{Timeout: HIBPTimeoutSync},
		baseURL:    hibpDefaultBaseURL,
		userAgent:  hibpUserAgent,
		disabled:   os.Getenv(envHIBPDisabled) == "true",
	}
}

// CheckPassword queries HIBP for the given plaintext password using
// the k-anonymity protocol (spec §7.2):
//
//  1. Compute SHA-1(password), uppercase hex.
//  2. Send only the first 5 chars (the prefix) to HIBP.
//  3. Search the 35-char suffix in HIBP's response.
//
// Returns one of: HIBPStatusClean, HIBPStatusCompromised,
// HIBPStatusPending (network/timeout/parse error), or
// HIBPStatusSkipped (when disabled via env var).
//
// The returned error is non-nil ONLY for programming bugs (SHA-1
// hashing is unconditionally computable, so encoding failures
// indicate code bugs). Network and parse failures are translated
// into HIBPStatusPending without an error, so callers do not need
// to special-case timeouts (spec §7.3).
//
// SECURITY: the plaintext password is never logged. The 5-char
// prefix and the SHA-1 hash are not considered sensitive (millions
// of users share each bucket) but the plaintext itself stays in
// this function's stack and is never written to slog.
func (c *HIBPClient) CheckPassword(ctx context.Context, password string) (string, error) {
	if c.disabled {
		return HIBPStatusSkipped, nil
	}

	// Compute SHA-1 of the password (HIBP protocol requirement, NOT
	// a storage hash — see package doc).
	hash := sha1.Sum([]byte(password))
	hashHex := strings.ToUpper(hex.EncodeToString(hash[:]))
	prefix := hashHex[:5]
	suffix := hashHex[5:]

	url := c.baseURL + "/range/" + prefix
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return HIBPStatusPending, fmt.Errorf("hibp: build request: %w", err)
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Network error, DNS, timeout, TLS — all translate to
		// "pending" so callers don't need to distinguish.
		return HIBPStatusPending, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// 5xx, 429, etc. — treat as pending.
		return HIBPStatusPending, nil
	}

	// Response format: lines of "SUFFIX:COUNT".
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		sep := strings.IndexByte(line, ':')
		if sep <= 0 {
			continue // malformed line, skip
		}
		// HIBP returns hash suffixes in uppercase. We computed our suffix
		// in uppercase at the strings.ToUpper call above. Exact comparison
		// is sufficient (and avoids the per-rune case-folding cost of
		// strings.EqualFold).
		if line[:sep] == suffix {
			return HIBPStatusCompromised, nil
		}
	}
	if err := scanner.Err(); err != nil {
		// Read error mid-stream — pending.
		return HIBPStatusPending, nil
	}

	// Suffix not found in the response: password is clean.
	return HIBPStatusClean, nil
}
