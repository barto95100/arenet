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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"strings"
	"sync"
	"testing"
)

// AL.1.b — EmailSender pinning tests.
//
// The standard library's net/smtp client is awkward to fake
// because *smtp.Client wraps an *textproto.Conn directly.
// The approach: spin up a tiny in-process SMTP-protocol
// stub on a local pipe and have the test's EmailDialer
// return an *smtp.Client backed by that pipe. The stub
// only implements the verbs Send walks (EHLO, AUTH PLAIN,
// MAIL FROM, RCPT TO, DATA, QUIT).
//
// Coverage per the brief: success via stub, AUTH fail,
// connection refused, RCPT TO reject. Implicit-TLS / TLS
// handshake paths are tested via Validate (the operator-
// surface invariants) — exercising real TLS in a unit test
// would require a self-signed cert pair and a TLS listener,
// which buys low coverage value vs. the wire-protocol
// fidelity of the stub.

// smtpStub is a minimal in-process SMTP server for tests.
// scripted controls the conversation: each verb the
// client sends consults the per-verb hook to decide which
// reply to write. Default replies (when no hook is set)
// are RFC 5321 success codes.
type smtpStub struct {
	listener net.Listener
	wg       sync.WaitGroup

	// Recorded conversation, in order of receipt. Tests
	// inspect this after Send completes.
	mu       sync.Mutex
	received []string

	// Per-verb overrides. nil → write the default success
	// reply for that verb.
	onAuth string // e.g. "535 5.7.8 Authentication failed"
	onRcpt string // e.g. "550 5.1.1 No such user"
}

func newSMTPStub(t *testing.T) *smtpStub {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &smtpStub{listener: l}
	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

func (s *smtpStub) addr() string {
	return s.listener.Addr().String()
}

func (s *smtpStub) close() {
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *smtpStub) record(line string) {
	s.mu.Lock()
	s.received = append(s.received, line)
	s.mu.Unlock()
}

func (s *smtpStub) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go s.serve(conn)
	}
}

func (s *smtpStub) serve(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	defer bw.Flush()

	// Greeting.
	_, _ = bw.WriteString("220 stub.test ESMTP ready\r\n")
	_ = bw.Flush()

	inData := false
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		s.record(line)

		if inData {
			if line == "." {
				_, _ = bw.WriteString("250 2.0.0 OK\r\n")
				_ = bw.Flush()
				inData = false
			}
			continue
		}

		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			// Advertise AUTH PLAIN so smtp.Client.Auth uses it.
			_, _ = bw.WriteString("250-stub.test Hello\r\n")
			_, _ = bw.WriteString("250-AUTH PLAIN\r\n")
			_, _ = bw.WriteString("250 SIZE 10485760\r\n")
		case strings.HasPrefix(line, "AUTH"):
			if s.onAuth != "" {
				_, _ = bw.WriteString(s.onAuth + "\r\n")
			} else {
				_, _ = bw.WriteString("235 2.7.0 Authentication successful\r\n")
			}
		case strings.HasPrefix(line, "MAIL FROM"):
			_, _ = bw.WriteString("250 2.1.0 Sender OK\r\n")
		case strings.HasPrefix(line, "RCPT TO"):
			if s.onRcpt != "" {
				_, _ = bw.WriteString(s.onRcpt + "\r\n")
			} else {
				_, _ = bw.WriteString("250 2.1.5 Recipient OK\r\n")
			}
		case line == "DATA":
			_, _ = bw.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
			inData = true
		case line == "QUIT":
			_, _ = bw.WriteString("221 2.0.0 Bye\r\n")
			_ = bw.Flush()
			return
		default:
			_, _ = bw.WriteString("502 5.5.2 Command not recognised\r\n")
		}
		_ = bw.Flush()
	}
}

// stubDialer returns an EmailDialer that connects to the
// stub server instead of doing real DNS+TCP. The smtp.Client
// host argument MUST be "localhost" so smtp.PlainAuth
// permits credential transmission over the plaintext test
// loopback (PlainAuth refuses to send creds over an
// unencrypted connection unless the server name matches
// localhost / 127.0.0.1 — see net/smtp/auth.go).
func stubDialer(stub *smtpStub) EmailDialer {
	return func(_ context.Context, _ string, _ int, _ bool) (*smtp.Client, error) {
		conn, err := net.Dial("tcp", stub.addr())
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(conn, "localhost")
	}
}

func sampleEmailCfg() EmailConfig {
	// SMTPHost must be "localhost" (or 127.0.0.1) so
	// smtp.PlainAuth permits AUTH PLAIN over the test
	// stub's plaintext loopback. PlainAuth refuses to
	// transmit credentials over an unencrypted connection
	// unless the configured server name matches the
	// loopback hostnames — see net/smtp/auth.go's
	// isLocalhost check.
	return EmailConfig{
		SMTPHost:     "localhost",
		SMTPPort:     2525,
		SMTPUsername: "alice",
		SMTPPassword: "s3cret",
		From:         "alerts@example.com",
		To:           []string{"ops@example.com"},
	}
}

func TestEmailSender_Success(t *testing.T) {
	stub := newSMTPStub(t)
	defer stub.close()

	sender := NewEmailSender(sampleEmailCfg(), stubDialer(stub))
	if err := sender.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	wantSubstrings := []string{"EHLO", "AUTH PLAIN", "MAIL FROM:<alerts@example.com>", "RCPT TO:<ops@example.com>", "DATA", "QUIT"}
	for _, want := range wantSubstrings {
		found := false
		for _, got := range stub.received {
			if strings.Contains(got, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("conversation missing %q; got %v", want, stub.received)
		}
	}

	// Subject template default = "[{{.Severity}}] {{.Subject}}".
	// sampleEvent has Severity=warning, Subject="WAF block...".
	var subjectSeen bool
	for _, got := range stub.received {
		if strings.Contains(got, "Subject: [warning] WAF block rate elevated") {
			subjectSeen = true
			break
		}
	}
	if !subjectSeen {
		t.Errorf("Subject header with rendered template not seen in conversation; got %v", stub.received)
	}
}

func TestEmailSender_AuthFail(t *testing.T) {
	stub := newSMTPStub(t)
	stub.onAuth = "535 5.7.8 Authentication failed"
	defer stub.close()

	sender := NewEmailSender(sampleEmailCfg(), stubDialer(stub))
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want auth error")
	}
	if !strings.Contains(err.Error(), "email: auth") {
		t.Errorf("err = %q; want 'email: auth' prefix", err.Error())
	}
}

func TestEmailSender_RcptReject(t *testing.T) {
	stub := newSMTPStub(t)
	stub.onRcpt = "550 5.1.1 User unknown"
	defer stub.close()

	sender := NewEmailSender(sampleEmailCfg(), stubDialer(stub))
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want RCPT TO error")
	}
	if !strings.Contains(err.Error(), "RCPT TO ops@example.com") {
		t.Errorf("err = %q; want recipient address in message", err.Error())
	}
}

func TestEmailSender_DialError(t *testing.T) {
	sender := NewEmailSender(sampleEmailCfg(), func(_ context.Context, _ string, _ int, _ bool) (*smtp.Client, error) {
		return nil, errors.New("connect: refused")
	})
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want dial error")
	}
	if !strings.Contains(err.Error(), "email: dial smtp") {
		t.Errorf("err = %q; want 'email: dial smtp' prefix", err.Error())
	}
}

func TestEmailSender_MultiRecipientRcptCount(t *testing.T) {
	stub := newSMTPStub(t)
	defer stub.close()

	cfg := sampleEmailCfg()
	cfg.To = []string{"ops@example.com", "oncall@example.com"}
	cfg.CC = []string{"audit@example.com"}
	cfg.BCC = []string{"shadow@example.com"}

	sender := NewEmailSender(cfg, stubDialer(stub))
	if err := sender.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	stub.mu.Lock()
	defer stub.mu.Unlock()
	var rcptCount int
	for _, got := range stub.received {
		if strings.HasPrefix(got, "RCPT TO") {
			rcptCount++
		}
	}
	if rcptCount != 4 {
		t.Errorf("RCPT TO count = %d; want 4 (to + cc + bcc)", rcptCount)
	}

	// BCC must NOT appear in DATA headers, but To + Cc must.
	dataPayload := strings.Join(stub.received, "\n")
	if !strings.Contains(dataPayload, "To: ops@example.com") {
		t.Errorf("DATA section missing 'To: ops@example.com'")
	}
	if !strings.Contains(dataPayload, "Cc: audit@example.com") {
		t.Errorf("DATA section missing 'Cc: audit@example.com'")
	}
	if strings.Contains(dataPayload, "Bcc:") {
		t.Errorf("DATA section leaked Bcc header (must be RCPT-only)")
	}
	if strings.Contains(dataPayload, "shadow@example.com") {
		// shadow only appears in the RCPT TO command line, never
		// in DATA — the conversation log will have it once but
		// not inside the message body after DATA.
		var seenInData bool
		afterData := false
		for _, line := range stub.received {
			if line == "DATA" {
				afterData = true
				continue
			}
			if afterData && line == "." {
				break
			}
			if afterData && strings.Contains(line, "shadow@example.com") {
				seenInData = true
				break
			}
		}
		if seenInData {
			t.Errorf("Bcc recipient leaked into DATA section")
		}
	}
}

// silence unused-import linter if a future refactor drops
// io / fmt / etc.
var _ = io.EOF
var _ = fmt.Sprintf
