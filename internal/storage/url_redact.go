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

package storage

import (
	"net/url"
	"regexp"
	"strings"
)

// A webhook URL inside an error string is still a credential (v2.73).
//
// A Discord, Slack or Teams webhook URL carries its secret in the
// PATH, which is why the channel API redacts it on read and in audit
// rows. But Go's net/http puts the full request URL into transport
// errors — `Post "https://discord.com/api/webhooks/123/<token>": dial
// tcp: i/o timeout` — and that string was persisted verbatim as
// Channel.LastError and fanned out to two viewer-readable surfaces:
// the alert-event history and the audit log's before/after blobs.
//
// Worse than the API leak: bucketAlertingChannels seals only the
// `config` field, so LastError bypassed encryption at rest too, and
// the v2.30 remediation migration scrubbed config.url and friends but
// never this field.
//
// Redacting at the point of persistence means the database, the audit
// trail and every read surface are clean from one change. The useful
// half of the message — "dial tcp: i/o timeout", "context deadline
// exceeded" — survives, and the channel is identified by its row, so
// nothing diagnostic is lost.

// urlInTextRE finds an http(s) URL inside free text.
//
// The terminators are the characters that cannot appear in a URL in
// practice and that Go's error strings put around one: whitespace, the
// double quote net/url's errors wrap it in, and the angle brackets and
// backtick that other formatters use. A trailing ':' or '.' is trimmed
// separately, because `Post "https://host/path": dial` would otherwise
// swallow the colon.
var urlInTextRE = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `]+`)

// RedactURLsInText replaces every http(s) URL in s with its
// scheme://host plus a redaction marker, leaving the rest of the text
// intact.
//
// Applied to anything derived from an error that may have touched an
// operator-configured endpoint. Returns s unchanged when it holds no
// URL, so it is safe to call on every message.
func RedactURLsInText(s string) string {
	if s == "" || !strings.Contains(s, "://") {
		return s
	}
	return urlInTextRE.ReplaceAllStringFunc(s, func(match string) string {
		// Punctuation the surrounding sentence owns, not the URL.
		//
		// ']' and '}' are deliberately NOT in this set, even though a
		// sentence can end a URL with one: URLRedacted itself is
		// "[redacted]", so trimming ']' here made the function
		// non-idempotent — a second pass over an already-redacted
		// message produced "[redacted]]". Redaction runs twice by
		// design (at persistence, and again on the read path for rows
		// written before that), so idempotence is a requirement, not
		// a nicety. There is a test.
		trailing := ""
		for len(match) > 0 && strings.ContainsRune(`:.,;)`, rune(match[len(match)-1])) {
			trailing = match[len(match)-1:] + trailing
			match = match[:len(match)-1]
		}
		return redactURL(match) + trailing
	})
}

// redactURL keeps the scheme and host and discards everything that
// could carry a secret: the path, the query and any userinfo.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return URLRedacted
	}
	return u.Scheme + "://" + u.Host + "/" + URLRedacted
}

// URLRedacted is the marker a redacted URL path carries.
//
// The same literal internal/api's auditRedacted uses, so the operator
// never sees two different words for the same thing — the audit log's
// redaction and an error message's redaction read alike. Exported so
// the API layer and the tests recognise it without duplicating it.
const URLRedacted = "[redacted]"
