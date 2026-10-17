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
	"context"
	"strings"
	"testing"
	"time"
)

// TestSenders_RefuseCloudMetadata pins that the URL-based channel senders
// (and therefore the operator Test button, which dispatches through them)
// cannot be pointed at cloud instance metadata. Before the shared guard
// the senders used the default transport and would happily POST to
// 169.254.169.254 — a config-time SSRF that hands back instance
// credentials.
func TestSenders_RefuseCloudMetadata(t *testing.T) {
	evt := AlertEvent{Subject: "t", Body: "m", Severity: SeverityCritical}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	t.Run("webhook", func(t *testing.T) {
		s := NewWebhookSender(WebhookConfig{URL: "http://169.254.169.254/latest/meta-data/", TimeoutSeconds: 2})
		err := s.Send(ctx, evt)
		if err == nil {
			t.Fatal("webhook Send to the metadata address succeeded; the SSRF guard must refuse it")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("err = %v; want the guard's \"not allowed\" refusal, not an ordinary dial failure", err)
		}
	})

	t.Run("discord", func(t *testing.T) {
		s := NewDiscordSender(DiscordConfig{WebhookURL: "http://[fd00:ec2::254]/api/webhooks/x/y", TimeoutSeconds: 2})
		err := s.Send(ctx, evt)
		if err == nil {
			t.Fatal("discord Send to the IPv6 metadata address succeeded; the SSRF guard must refuse it")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("err = %v; want the guard's \"not allowed\" refusal", err)
		}
	})
}
