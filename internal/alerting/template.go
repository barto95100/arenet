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

package alerting

import (
	"bytes"
	"text/template"
)

// AL.1.b — sandboxed template helper used by both
// WebhookSender (bodyTemplate) and EmailSender
// (subjectTemplate + bodyTemplate).
//
// Sandboxing posture (D8):
//   - text/template (NOT html/template) — operators sending
//     to webhook receivers / SMTP servers want raw text,
//     not HTML-escaped. The auto-escaping html/template
//     does is wrong for both surfaces.
//   - NO sprig — sprig's `env`, `expandenv`, `randAscii`,
//     `getHostByName`, `tpl` open SSRF + env-leak + RCE
//     surfaces that a hand-edited operator template
//     shouldn't have. Stdlib text/template's built-in
//     funcs (printf, eq, len, ...) are sufficient for
//     V1's "format an alert into a string" use case.
//   - No `FuncMap` extension. Templates only see the
//     AlertEvent fields (.Severity, .Subject, etc.) and
//     stdlib formatters (.Timestamp.Format). Operators
//     who need richer formatting can route through an
//     intermediate processor (alertmanager, n8n, ...).
//
// V2 candidate: a small whitelist FuncMap with
// {{lower}}, {{upper}}, {{date "..."}} once operator
// feedback identifies real ergonomic needs.

// compileBodyTemplate parses a user-supplied template
// string. Returns the compiled template ready for
// .Execute, or an error if parsing failed. The error is
// surfaced to the API caller at create/update time so
// the operator gets immediate feedback on a typo.
func compileBodyTemplate(tmpl string) (*template.Template, error) {
	// Name is operator-facing only when an error mentions
	// it — give it a friendly handle.
	return template.New("alerting").Option("missingkey=zero").Parse(tmpl)
}

// renderTemplate executes a pre-compiled template against
// a data context. The Option("missingkey=zero") flag set
// at compile time means a `{{.NoSuchField}}` reference
// renders as the zero value (empty string for strings)
// instead of an error — operator-friendly default for
// the live data plane (a stale template against a
// V2-renamed AlertEvent field doesn't error the send,
// just renders a placeholder).
//
// Data is `any` so callers pass AlertEvent (AL.1.b
// senders) or alertEventTemplateContext (AL.2.b watcher
// fire-path) without separate helpers.
func renderTemplate(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}
