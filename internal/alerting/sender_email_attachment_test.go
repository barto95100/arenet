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

package alerting

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func TestBuildMultipartMessage_AttachmentRoundTrips(t *testing.T) {
	s := NewEmailSender(EmailConfig{
		From: "arenet@example.com", To: []string{"ops@example.com"},
		CC: []string{"cc@example.com"}, BCC: []string{"hidden@example.com"},
	}, nil)
	data := bytes.Repeat([]byte(`{"schema_version":"2.0.0","x":"é"}`), 200) // > one base64 line
	raw, err := s.buildMultipartMessage("Sauvegarde Arenet — réussie", "Ligne 1\nLigne 2", EmailAttachment{
		Filename: "arenet-backup-auto-20260921-030000.json", ContentType: "application/json", Data: data,
	}, time.Date(2026, 9, 21, 3, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if strings.Contains(string(raw), "hidden@example.com") {
		t.Error("Bcc must not appear in the headers")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || subject != "Sauvegarde Arenet — réussie" {
		t.Errorf("subject = %q, %v", subject, err)
	}
	if msg.Header.Get("Date") == "" || msg.Header.Get("Cc") != "cc@example.com" {
		t.Errorf("headers: %v", msg.Header)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("content type %q %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])

	textPart, err := mr.NextPart()
	if err != nil {
		t.Fatalf("text part: %v", err)
	}
	text, _ := io.ReadAll(textPart)
	if string(text) != "Ligne 1\r\nLigne 2" {
		t.Errorf("body = %q", text)
	}

	att, err := mr.NextPart()
	if err != nil {
		t.Fatalf("attachment part: %v", err)
	}
	if att.FileName() != "arenet-backup-auto-20260921-030000.json" {
		t.Errorf("filename = %q", att.FileName())
	}
	enc, _ := io.ReadAll(att)
	for _, line := range strings.Split(strings.TrimSpace(string(enc)), "\r\n") {
		if len(line) > attachmentLineLen {
			t.Fatalf("base64 line of %d chars", len(line))
		}
	}
	got, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(string(enc), "\r\n", ""))
	if err != nil || !bytes.Equal(got, data) {
		t.Errorf("attachment does not round-trip (err=%v, %d vs %d bytes)", err, len(got), len(data))
	}
	if _, err := mr.NextPart(); err != io.EOF {
		t.Errorf("unexpected extra part: %v", err)
	}
}
