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
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"strings"
)

// AL.1.b — per-kind Channel.Config shapes + validators.
// Each kind defines a typed struct so the senders can
// json.Unmarshal once at Send() time and read fields by
// name. Validation runs at create/update time on the CRUD
// layer + at sender construction time (defence-in-depth).

// WebhookConfig is the operator-supplied config for a
// webhook channel. Mirrors the wire shape decided in
// AL.1.b D2.
type WebhookConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers,omitempty"`
	TimeoutSeconds int               `json:"timeoutSeconds"`
	// BodyTemplate is an optional text/template string. When
	// empty, the sender marshals the AlertEvent directly as
	// JSON. When set, the sender renders the template with
	// the AlertEvent as the data context (.Severity, .Subject,
	// etc.). text/template (NOT html/template) on purpose —
	// the webhook body is not HTML-rendered.
	BodyTemplate string `json:"bodyTemplate,omitempty"`
}

const (
	webhookDefaultMethod         = "POST"
	webhookDefaultTimeoutSeconds = 10
	webhookMinTimeoutSeconds     = 1
	webhookMaxTimeoutSeconds     = 60
)

// WithDefaults returns a copy of the config with
// operator-omitted fields filled in. Called by Validate
// before the strict checks so an operator who leaves
// Method blank gets POST (the documented default), not a
// validation error.
func (c WebhookConfig) WithDefaults() WebhookConfig {
	if c.Method == "" {
		c.Method = webhookDefaultMethod
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = webhookDefaultTimeoutSeconds
	}
	return c
}

// Validate runs the kind-specific checks.
func (c WebhookConfig) Validate() error {
	filled := c.WithDefaults()
	if filled.URL == "" {
		return errors.New("webhook: url must not be empty")
	}
	u, err := url.Parse(filled.URL)
	if err != nil {
		return fmt.Errorf("webhook: url is malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("webhook: url scheme must be http or https")
	}
	if u.Host == "" {
		return errors.New("webhook: url must include a host")
	}
	if filled.Method != "POST" {
		// V1 limit per AL.1.b D2 — PUT/PATCH defer V2.
		return fmt.Errorf("webhook: method %q not supported (V1: POST only)", filled.Method)
	}
	if filled.TimeoutSeconds < webhookMinTimeoutSeconds ||
		filled.TimeoutSeconds > webhookMaxTimeoutSeconds {
		return fmt.Errorf("webhook: timeoutSeconds %d out of range [%d, %d]",
			filled.TimeoutSeconds, webhookMinTimeoutSeconds, webhookMaxTimeoutSeconds)
	}
	if filled.BodyTemplate != "" {
		if _, err := compileBodyTemplate(filled.BodyTemplate); err != nil {
			return fmt.Errorf("webhook: bodyTemplate compile failed: %w", err)
		}
	}
	return nil
}

// EmailConfig is the operator-supplied config for an
// email channel.
type EmailConfig struct {
	SMTPHost        string   `json:"smtpHost"`
	SMTPPort        int      `json:"smtpPort"`
	SMTPUsername    string   `json:"smtpUsername"`
	SMTPPassword    string   `json:"smtpPassword"` // SECRET — J.4 discipline
	From            string   `json:"from"`
	To              []string `json:"to"`
	CC              []string `json:"cc,omitempty"`
	BCC             []string `json:"bcc,omitempty"`
	UseTLS          bool     `json:"useTLS"`          // implicit TLS (port 465)
	UseStartTLS     bool     `json:"useStartTLS"`     // STARTTLS upgrade (port 587)
	SubjectTemplate string   `json:"subjectTemplate,omitempty"`
	BodyTemplate    string   `json:"bodyTemplate,omitempty"`
}

const (
	// emailDefaultSubject is the fallback subject when no
	// SubjectTemplate is set. The {severity} prefix matches
	// the alertmanager/pagerduty convention so the operator's
	// inbox filters can route on it.
	emailDefaultSubject = "[{{.Severity}}] {{.Subject}}"
	// emailDefaultBody is plain-text. Channels that want
	// richer formatting (Markdown / HTML) override via
	// BodyTemplate.
	emailDefaultBody = `Alert: {{.Subject}}
Severity: {{.Severity}}
Category: {{.Category}}
Rule: {{.RuleName}}
Time: {{.Timestamp.Format "2006-01-02 15:04:05 MST"}}

{{.Body}}`
)

// Validate runs the kind-specific checks.
func (c EmailConfig) Validate() error {
	if c.SMTPHost == "" {
		return errors.New("email: smtpHost must not be empty")
	}
	if strings.Contains(c.SMTPHost, ":") {
		return errors.New("email: smtpHost must not contain a port; use smtpPort instead")
	}
	if c.SMTPPort <= 0 || c.SMTPPort > 65535 {
		return fmt.Errorf("email: smtpPort %d out of range [1, 65535]", c.SMTPPort)
	}
	if c.UseTLS && c.UseStartTLS {
		return errors.New("email: useTLS and useStartTLS are mutually exclusive (pick one)")
	}
	if c.From == "" {
		return errors.New("email: from must not be empty")
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return fmt.Errorf("email: from address %q is malformed: %w", c.From, err)
	}
	if len(c.To) == 0 {
		return errors.New("email: to must have at least one recipient")
	}
	for _, recips := range [][]string{c.To, c.CC, c.BCC} {
		for _, addr := range recips {
			if _, err := mail.ParseAddress(addr); err != nil {
				return fmt.Errorf("email: recipient %q is malformed: %w", addr, err)
			}
		}
	}
	if c.SubjectTemplate != "" {
		if _, err := compileBodyTemplate(c.SubjectTemplate); err != nil {
			return fmt.Errorf("email: subjectTemplate compile failed: %w", err)
		}
	}
	if c.BodyTemplate != "" {
		if _, err := compileBodyTemplate(c.BodyTemplate); err != nil {
			return fmt.Errorf("email: bodyTemplate compile failed: %w", err)
		}
	}
	return nil
}

// ParseWebhookConfig unmarshals a raw Channel.Config JSON
// into the typed WebhookConfig + validates.
func ParseWebhookConfig(raw json.RawMessage) (WebhookConfig, error) {
	var c WebhookConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return WebhookConfig{}, fmt.Errorf("webhook config not valid JSON: %w", err)
	}
	if err := c.Validate(); err != nil {
		return WebhookConfig{}, err
	}
	return c.WithDefaults(), nil
}

// ParseEmailConfig unmarshals a raw Channel.Config JSON
// into the typed EmailConfig + validates.
func ParseEmailConfig(raw json.RawMessage) (EmailConfig, error) {
	var c EmailConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return EmailConfig{}, fmt.Errorf("email config not valid JSON: %w", err)
	}
	if err := c.Validate(); err != nil {
		return EmailConfig{}, err
	}
	return c, nil
}
