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
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// AL.1.b — EmailSender. SMTP delivery via the stdlib
// net/smtp client. V1 = one attempt, no retry (per D1
// ADR). Failure modes:
//   - dial error (connection refused, DNS) → wrapped
//   - TLS handshake fail → wrapped
//   - AUTH PLAIN/LOGIN reject → wrapped
//   - MAIL FROM / RCPT TO reject → wrapped
//   - context cancelled → SetDeadline propagates the
//     ctx.Deadline if set; deferred close cuts the
//     connection mid-dial
//
// Why net/smtp (stdlib) over go-mail / emersion: zero new
// dependencies. The V1 feature set (PLAIN/LOGIN auth,
// implicit-TLS or STARTTLS, simple From/To/Cc/Bcc) fits
// what stdlib provides. V2 may swap for a richer client
// if operator feedback identifies needs (DKIM signing,
// attachments, etc.).

// EmailSender ships AlertEvent via SMTP.
type EmailSender struct {
	cfg EmailConfig
	// dialer is the seam tests inject to bypass real SMTP.
	// Production leaves it nil and Send uses the default
	// net.Dialer + tls.Dial paths. Tests inject a func
	// that returns a hand-rolled smtp.Client backed by an
	// in-memory transport.
	dialer EmailDialer
}

// EmailDialer is the seam EmailSender uses to obtain an
// *smtp.Client. Production wires net.Dialer + tls.Dial
// under the hood; tests inject a stub.
type EmailDialer func(ctx context.Context, host string, port int, useTLS bool) (*smtp.Client, error)

// NewEmailSender constructs a sender from a typed config.
// dialer may be nil — the sender falls back to the
// production net.Dialer + tls.Dial paths.
func NewEmailSender(cfg EmailConfig, dialer EmailDialer) *EmailSender {
	return &EmailSender{cfg: cfg, dialer: dialer}
}

// Kind implements AlertSender.
func (s *EmailSender) Kind() string { return "email" }

// Send implements AlertSender. The SMTP conversation runs
// to completion or fails — there's no partial-success
// state at the protocol level (every RCPT TO is its own
// command but a single rejected recipient stops the send).
func (s *EmailSender) Send(ctx context.Context, evt AlertEvent) error {
	subject, body, err := s.renderMessage(evt)
	if err != nil {
		return fmt.Errorf("email: render: %w", err)
	}
	return s.deliver(ctx, []byte(s.buildMessage(subject, body)))
}

// EmailAttachment is one file attached to an email (v2.33).
type EmailAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// SendWithAttachment sends a plain-text email carrying one attachment
// to the channel's recipients (scheduled backups, v2.33). The channel's
// subject / body templates are not used: the caller supplies both.
func (s *EmailSender) SendWithAttachment(ctx context.Context, subject, body string, att EmailAttachment) error {
	msg, err := s.buildMultipartMessage(subject, body, att, time.Now())
	if err != nil {
		return fmt.Errorf("email: build message: %w", err)
	}
	return s.deliver(ctx, msg)
}

// deliver runs one SMTP conversation: dial, optional STARTTLS, AUTH,
// MAIL / RCPT, DATA. There is no partial-success state.
func (s *EmailSender) deliver(ctx context.Context, msg []byte) error {
	dialer := s.dialer
	if dialer == nil {
		dialer = productionDialer
	}

	client, err := dialer(ctx, s.cfg.SMTPHost, s.cfg.SMTPPort, s.cfg.UseTLS)
	if err != nil {
		return fmt.Errorf("email: dial smtp: %w", err)
	}
	defer func() { _ = client.Close() }()

	// STARTTLS upgrade if requested. Mutually exclusive
	// with UseTLS (validated at config time).
	if s.cfg.UseStartTLS {
		tlsCfg := &tls.Config{ServerName: s.cfg.SMTPHost, MinVersion: tls.VersionTLS12}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("email: starttls: %w", err)
		}
	}

	// AUTH only when credentials supplied. Operators with
	// a relay-style local SMTP (homelab Postfix on
	// 127.0.0.1:25 without auth) leave Username + Password
	// blank and skip AUTH entirely.
	if s.cfg.SMTPUsername != "" {
		auth := smtp.PlainAuth("", s.cfg.SMTPUsername, s.cfg.SMTPPassword, s.cfg.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email: auth: %w", err)
		}
	}

	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("email: MAIL FROM: %w", err)
	}
	// All To/CC/BCC go through RCPT TO; BCC is hidden by
	// virtue of not being listed in the message headers.
	for _, r := range concat3(s.cfg.To, s.cfg.CC, s.cfg.BCC) {
		if err := client.Rcpt(r); err != nil {
			return fmt.Errorf("email: RCPT TO %s: %w", r, err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("email: write data: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email: close data: %w", err)
	}
	return client.Quit()
}

// renderMessage executes the subject/body templates with
// the configured defaults when the operator left them
// empty. Both subject and body are rendered fresh per
// call — caching the compiled templates is a future
// micro-optimisation (a homelab dispatches <1 email/sec
// in practice, so the parse-on-each-send overhead is
// invisible).
func (s *EmailSender) renderMessage(evt AlertEvent) (subject, body string, err error) {
	subjectTmpl := s.cfg.SubjectTemplate
	if subjectTmpl == "" {
		subjectTmpl = emailDefaultSubject
	}
	bodyTmpl := s.cfg.BodyTemplate
	if bodyTmpl == "" {
		bodyTmpl = emailDefaultBody
	}

	st, err := compileBodyTemplate(subjectTmpl)
	if err != nil {
		return "", "", fmt.Errorf("subject template compile: %w", err)
	}
	subject, err = renderTemplate(st, evt)
	if err != nil {
		return "", "", fmt.Errorf("subject template render: %w", err)
	}

	bt, err := compileBodyTemplate(bodyTmpl)
	if err != nil {
		return "", "", fmt.Errorf("body template compile: %w", err)
	}
	body, err = renderTemplate(bt, evt)
	if err != nil {
		return "", "", fmt.Errorf("body template render: %w", err)
	}
	return subject, body, nil
}

// buildMessage assembles the RFC 5322 message envelope.
// To/Cc are listed in the headers (operator-visible);
// Bcc is intentionally OMITTED from the headers but each
// Bcc address still receives the message via the RCPT
// TO command. This is the standard SMTP Bcc semantic.
func (s *EmailSender) buildMessage(subject, body string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", s.cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(s.cfg.To, ", "))
	if len(s.cfg.CC) > 0 {
		fmt.Fprintf(&b, "Cc: %s\r\n", strings.Join(s.cfg.CC, ", "))
	}
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=UTF-8\r\n")
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "\r\n%s\r\n", body)
	return b.String()
}

// attachmentLineLen is the base64 line length of an attachment
// (RFC 2045 caps lines at 76 characters).
const attachmentLineLen = 76

// buildMultipartMessage assembles a multipart/mixed message: the
// plain-text body then the base64 attachment. Headers follow
// buildMessage (Bcc omitted); the subject is RFC 2047-encoded so
// non-ASCII text survives.
func (s *EmailSender) buildMultipartMessage(subject, body string, att EmailAttachment, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	var head strings.Builder
	fmt.Fprintf(&head, "From: %s\r\n", s.cfg.From)
	fmt.Fprintf(&head, "To: %s\r\n", strings.Join(s.cfg.To, ", "))
	if len(s.cfg.CC) > 0 {
		fmt.Fprintf(&head, "Cc: %s\r\n", strings.Join(s.cfg.CC, ", "))
	}
	fmt.Fprintf(&head, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&head, "Date: %s\r\n", now.Format(time.RFC1123Z))
	fmt.Fprintf(&head, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&head, "Content-Type: multipart/mixed; boundary=%q\r\n\r\n", mw.Boundary())

	text, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"text/plain; charset=UTF-8"},
		"Content-Transfer-Encoding": {"8bit"},
	})
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(text, strings.ReplaceAll(body, "\n", "\r\n")); err != nil {
		return nil, err
	}

	ct := att.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	part, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {mime.FormatMediaType(ct, map[string]string{"name": att.Filename})},
		"Content-Disposition":       {mime.FormatMediaType("attachment", map[string]string{"filename": att.Filename})},
		"Content-Transfer-Encoding": {"base64"},
	})
	if err != nil {
		return nil, err
	}
	enc := base64.StdEncoding.EncodeToString(att.Data)
	for len(enc) > attachmentLineLen {
		if _, err := io.WriteString(part, enc[:attachmentLineLen]+"\r\n"); err != nil {
			return nil, err
		}
		enc = enc[attachmentLineLen:]
	}
	if _, err := io.WriteString(part, enc+"\r\n"); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	return append([]byte(head.String()), b.Bytes()...), nil
}

// productionDialer is the default EmailDialer when the
// caller passes nil. Honours ctx via the dialer's
// Deadline.
func productionDialer(ctx context.Context, host string, port int, useTLS bool) (*smtp.Client, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline, hasDeadline := ctx.Deadline()
	d := net.Dialer{}
	if hasDeadline {
		d.Deadline = deadline
	} else {
		// Defensive ceiling: no deadline supplied by the
		// caller → cap at 30s so a stuck dial doesn't pin
		// the dispatcher goroutine forever. V1 dispatcher
		// always supplies a deadline; this is belt-and-
		// braces.
		d.Timeout = 30 * time.Second
	}

	var conn net.Conn
	var err error
	if useTLS {
		// Implicit TLS (port 465) — connect with TLS from
		// the first byte.
		conn, err = tls.DialWithDialer(&d, "tcp", addr,
			&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, err
	}
	return smtp.NewClient(conn, host)
}

// concat3 returns a single slice containing every entry
// from a, b, c in that order. Used by Send to walk the
// full recipient list for RCPT TO.
func concat3(a, b, c []string) []string {
	out := make([]string, 0, len(a)+len(b)+len(c))
	out = append(out, a...)
	out = append(out, b...)
	out = append(out, c...)
	return out
}
