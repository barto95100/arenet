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

// Package alerting ships the Step AL alerting subsystem
// foundation: the AlertEvent payload type, the Severity
// enum, and the AlertSender interface that every channel
// kind (webhook V1, email V1, slack + discord V2)
// implements.
//
// AL.1.a (this file) ships the types only — no senders, no
// CRUD, no UI. The downstream sub-tasks build on top:
//   - AL.1.b: WebhookSender + EmailSender concrete impls
//   - AL.1.c: Channel CRUD HTTP endpoints + audit emissions
//   - AL.1.d: Sender registry + dispatch fan-out
//   - AL.2:   Rule engine + watcher firing AlertEvents
//   - AL.3b:  alert_event SQLite read endpoints
//   - AL.4:   Frontend Settings card + activity widget
//
// Step AL ADR: docs/superpowers/decisions/2026-06-15-step-al-decisions.md
// Step AL spec: docs/superpowers/specs/2026-06-15-step-al-alerting.md
package alerting

import (
	"context"
	"fmt"
	"time"
)

// Severity is the 4-level enum that drives per-channel
// MinSeverity filtering (D5 ADR). Lower int = lower
// severity (inverted from syslog by design — operators
// reading the dashboard expect "warning < critical" not
// "warning > critical"). Wire form is the lowercased
// string token; the int representation is the storage
// shape (single byte in SQLite alert_event.severity).
type Severity int

const (
	// SeverityInfo: informational — "rule fired, no action
	// required, just FYI". Example: "managed_domain
	// renewed cleanly".
	SeverityInfo Severity = iota
	// SeverityWarning: degraded condition that the
	// operator should look at but doesn't require
	// immediate action. Example: "WAF block rate
	// elevated", "1 cert expiring in 14d".
	SeverityWarning
	// SeverityCritical: actionable condition requiring
	// operator attention soon. Example: "LAPI unreachable
	// for 5min", "cert obtain failed twice in 24h".
	SeverityCritical
	// SeverityEmergency: arenet itself is in trouble; the
	// data plane may be impaired. Example: "Caddy admin
	// endpoint unreachable", "BoltDB read failure",
	// "schema migration error". Mapped to PagerDuty's
	// "P0" tier in cross-system correlation.
	SeverityEmergency
)

// String returns the lowercase wire token. Stable across
// the codebase (frontend type union, DB row, API
// response, channel payload templates).
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	case SeverityEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

// ParseSeverity inverts String. Unknown / empty input
// returns (SeverityInfo, error) — callers decide whether
// to surface the error to the operator or treat as a
// default. The frontend's rule editor uses the error path
// to validate operator input; the storage layer's row
// scan uses it defensively (a future migration that
// widens the enum would surface here as a clean error
// rather than a silent miscategorisation).
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info":
		return SeverityInfo, nil
	case "warning":
		return SeverityWarning, nil
	case "critical":
		return SeverityCritical, nil
	case "emergency":
		return SeverityEmergency, nil
	default:
		return SeverityInfo, fmt.Errorf("alerting: unknown severity %q", s)
	}
}

// MarshalJSON emits the wire token so AlertEvent
// serialisation reads naturally on the wire ("severity":
// "warning" not "severity": 1). Channel payload templates
// can then substitute the field directly into the
// notification body.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// UnmarshalJSON accepts the wire token. Strict by design:
// a typo in a hand-edited webhook config surfaces as a
// JSON unmarshal error rather than silently degrading to
// info. The 1-byte slice trim handles the surrounding
// quotes the decoder leaves in place.
func (s *Severity) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return fmt.Errorf("alerting: severity expects a quoted string, got %q", data)
	}
	parsed, err := ParseSeverity(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	*s = parsed
	return nil
}

// AlertEvent is the kind-agnostic payload every rule fire
// produces. Senders translate it into their per-kind wire
// shape (webhook JSON POST, SMTP message body, etc.) at
// dispatch time.
//
// Fields rationale:
//   - ID: UUID generated at rule-fire time. Surfaces in
//     the alert_event table for replay + in the
//     notification payload so an operator can grep
//     across channels (one fire, multiple notifications,
//     same correlation ID).
//   - Timestamp: when the rule's trigger condition was
//     evaluated — NOT when the notification was sent
//     (which may be later if the channel queued or
//     retried).
//   - RuleID: FK to the BoltDB rule row at fire time. The
//     rule may be deleted later; downstream consumers
//     (alert_event readers, dashboards) use RuleName as
//     the operator-visible label and treat RuleID as
//     opaque.
//   - RuleName: snapshot at fire time so a future rename
//     doesn't retroactively relabel old events.
//   - Severity: drives per-channel MinSeverity filtering
//     (D5 ADR).
//   - Category: free-form taxonomy (waf / crowdsec / cert
//     / system / ...) for downstream filtering. The
//     watcher (AL.2) populates this from the source
//     observability table it queries.
//   - Subject: short human-readable summary, used as the
//     notification title (email subject, webhook
//     "subject" field, slack header).
//   - Body: longer description; may contain Markdown for
//     channels that render it (Slack blocks, Discord
//     embeds). Plain text for webhook / email.
//   - Context: structured key/value payload for
//     downstream consumers (alertmanager-compatible
//     processors, custom webhook receivers). Not
//     intended for human reading.
//   - Labels: operator-defined string→string pairs for
//     routing/filtering (env=prod, team=ops, host=...).
//     V1 has no routing-by-label logic; the field is
//     reserved so V2's per-channel label match can ship
//     without a migration.
type AlertEvent struct {
	ID        string            `json:"id"`
	Timestamp time.Time         `json:"timestamp"`
	RuleID    string            `json:"rule_id"`
	RuleName  string            `json:"rule_name"`
	Severity  Severity          `json:"severity"`
	Category  string            `json:"category"`
	Subject   string            `json:"subject"`
	Body      string            `json:"body,omitempty"`
	Context   map[string]any    `json:"context,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// AlertSender is the seam every channel-kind concrete
// implementation satisfies. Kept minimal for V1 — no
// Validate(config) error, no TestConnection() method —
// to avoid over-engineering before the second concrete
// impl lands and reveals real polymorphism needs.
//
// V2 may extend with TestConnection(ctx) error (operator
// "test this channel" button) when AL.1.c CRUD UI ships;
// the interface widening is additive (existing senders
// keep working with a default impl).
type AlertSender interface {
	// Kind returns the wire-shape token identifying the
	// channel kind ("webhook", "email"). Mirrors
	// Channel.Kind — the dispatch layer uses Kind() to
	// route an AlertEvent to the right sender.
	Kind() string

	// Send delivers the AlertEvent. MUST honour ctx for
	// cancellation/timeout. Returns nil on success.
	// Errors are classified by the dispatch layer:
	//   - transient (network timeout, 5xx upstream) →
	//     retry with backoff per channel config
	//   - permanent (4xx upstream, malformed config) →
	//     skip retry, mark channel.LastError, surface
	//     in the activity log
	// The interface intentionally does NOT discriminate
	// transient vs permanent: the dispatch layer
	// inspects the wrapped error type (e.g. context.
	// DeadlineExceeded, net.Error with Timeout()). V2
	// may introduce a sentinel ErrPermanent if the
	// dispatch heuristic proves insufficient.
	Send(ctx context.Context, evt AlertEvent) error
}
