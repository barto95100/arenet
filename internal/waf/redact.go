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

package waf

import (
	"regexp"
	"strings"
)

// redactPlaceholder is the marker substituted in place of a
// redacted secret. Visible in the stored Event so an operator
// understands "this part was scrubbed before storage" rather
// than wondering why the payload looks truncated.
const redactPlaceholder = "[REDACTED]"

// Redaction patterns. Compiled once at init; the Redact path
// is hot (called on every Event before storage) so allocation
// matters. Each pattern targets a credential-shape we expect
// to see in either headers carried into the payload sample
// or query strings carried into the request path.
//
// The patterns are intentionally lenient — we'd rather over-
// redact a non-secret than leak a real one. Spec §1.6.2
// documents the best-effort guarantee.
var (
	// reBearer matches `Authorization: Bearer <token>` in any
	// case, with the token consuming until whitespace, end-
	// of-line, or a quote/semicolon/ampersand boundary.
	reBearer = regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)[^\s"';&]+`)

	// reCookie matches the entire Cookie header value (until
	// EOL or the next header-delimiting CRLF). We redact the
	// VALUE; the header name stays so the operator can see
	// what was removed.
	reCookie = regexp.MustCompile(`(?i)(cookie\s*:\s*)[^\r\n]+`)

	// reSetCookie mirrors reCookie for response-side leakage
	// (a WAF event that captures a response header would
	// otherwise expose session tokens).
	reSetCookie = regexp.MustCompile(`(?i)(set-cookie\s*:\s*)[^\r\n]+`)

	// reSensitiveQueryParam matches common credential-shaped
	// query string keys and replaces the value with the
	// placeholder. Key list intentionally short and
	// well-known; broader regex would risk false-positive
	// redactions on attack payloads we WANT to keep visible
	// (e.g. `?path=../etc/passwd` should NOT be redacted).
	//
	// `(?i)` for case-insensitive key match. The capture
	// group keeps the `key=` prefix so we can rewrite to
	// `key=[REDACTED]` cleanly. The value match stops at the
	// next `&` boundary or end of string.
	// v2.56 — the token variants were missing. The alternation is
	// anchored on `?` or `&`, so `token` never matched
	// `?access_token=`: what precedes `token=` there is `access_`, not a
	// separator. Vaultwarden puts the user's access token in the URI, so
	// the one parameter most worth redacting was the one that got
	// through.
	//
	// The prefixes are spelled out rather than matched as a suffix
	// (`\w*token`), which would also swallow a legitimate `?mytoken=` or
	// `?csrftoken=` an attack payload might carry. Over-redacting here
	// costs forensic detail, which is the whole point of this store.
	reSensitiveQueryParam = regexp.MustCompile(
		`(?i)((?:^|[?&])(?:password|passwd|api[-_]?key|(?:access_|id_|refresh_)?token|secret|session|auth)=)[^&]+`)
)

// Redact runs the input through every declared pattern,
// replacing each match's secret-bearing portion with
// [REDACTED]. Returns the modified string; safe to call
// repeatedly (idempotent — re-redacting an already-redacted
// string is a no-op because [REDACTED] does not match any
// pattern's secret group).
//
// Pure function. Used by the EventSink on RequestPath +
// PayloadSample before persistence. The caller is responsible
// for the byte cap (Truncate); Redact does not change the
// length contract.
//
// Spec §1.6.2 documents the patterns and the best-effort
// guarantee — payload bytes the patterns miss may still
// reach storage; the 256-byte cap on PayloadSample bounds
// the worst case.
func Redact(s string) string {
	if s == "" {
		return s
	}
	s = reBearer.ReplaceAllString(s, "${1}"+redactPlaceholder)
	s = reCookie.ReplaceAllString(s, "${1}"+redactPlaceholder)
	s = reSetCookie.ReplaceAllString(s, "${1}"+redactPlaceholder)
	s = reSensitiveQueryParam.ReplaceAllString(s, "${1}"+redactPlaceholder)
	return s
}

// RedactSnippet bounds the cost of scrubbing an untrusted value before
// it is stored as an event sample. Redact runs four unanchored regex
// passes, each of which allocates about two copies of its whole input,
// so running it on a raw multi-megabyte matched value (an ARGS value up
// to SecRequestBodyLimit, or a ~1 MiB header) allocated ~8x and scanned
// 4x the length on the request goroutine — a handful of such requests
// saturated CPU and GC for every route on the host (F5).
//
// The value is first truncated to a small window (twice the final cap,
// leaving room for a prefix like "Authorization:" to still be matched),
// then redacted, then truncated to the final cap. Redact therefore never
// sees more than 2*maxBytes, whatever the attacker sends.
func RedactSnippet(s string, maxBytes int) string {
	return Truncate(Redact(Truncate(s, maxBytes*2)), maxBytes)
}

// credentialMask replaces an event payload sample whose matched variable
// is itself a credential — Redact's text patterns need a "header:" or
// "key=" prefix and so miss a BARE matched value like a raw cookie or
// password (F5). The whole sample is dropped rather than shown.
const credentialMask = "[credential redacted]"

// credentialArgKeys are argument names whose value is a credential; a
// CRS match on one of these must never persist the raw value into the
// viewer-readable waf_event store.
var credentialArgKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "pass": true,
	"token": true, "access_token": true, "refresh_token": true,
	"secret": true, "client_secret": true, "apikey": true,
	"api_key": true, "auth": true, "authorization": true, "session": true,
}

// credentialHeaderKeys are request headers that carry a credential.
var credentialHeaderKeys = map[string]bool{
	"authorization": true, "proxy-authorization": true, "cookie": true,
	"x-api-key": true, "x-auth-token": true, "x-amz-security-token": true,
}

// isCredentialVar reports whether matchedVar ("NAME:key", as
// requestSnippetFromMatch builds it) names a value that is itself a
// credential, so its sample must be masked rather than merely redacted.
func isCredentialVar(matchedVar string) bool {
	name, key, ok := strings.Cut(matchedVar, ":")
	if !ok {
		return false
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	key = strings.ToLower(strings.TrimSpace(key))
	switch {
	case strings.HasPrefix(name, "REQUEST_COOKIES"):
		// Every cookie value is a bearer-equivalent credential.
		return true
	case name == "REQUEST_HEADERS":
		return credentialHeaderKeys[key]
	case strings.HasPrefix(name, "ARGS"):
		return credentialArgKeys[key]
	}
	return false
}

// payloadSampleFor returns the stored sample for a matched value: a fixed
// mask when the variable is a credential carrier, otherwise the
// cost-bounded redaction (F5). cap is the final byte cap.
func payloadSampleFor(payload, matchedVar string, cap int) string {
	if isCredentialVar(matchedVar) {
		return credentialMask
	}
	return RedactSnippet(payload, cap)
}
