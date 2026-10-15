// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package backup

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// A Discord webhook URL is a secret in a backup too (v2.73).
//
// visitSecrets is the single list of secret fields used BOTH by backup
// redaction and by passphrase sealing, and its per-kind switch handled
// email and webhook only. The Discord kind shipped in v2.53 with its
// credential in a field named webhookUrl — not url, which is the
// generic webhook kind's name — so it matched no branch and was
// written in cleartext into every backup artifact: the "no-secrets"
// export, the passphrase-encrypted export whose own header declares it
// encrypted, and every scheduled backup file, including the ones
// mailed as SMTP attachments under covering text saying the secrets
// are encrypted.
//
// Anyone who read such a file could post into the operator's alert
// channel — a forged "certificate renewal failed, re-authenticate
// here" is indistinguishable from a real Arenet alert, because it
// arrives through the real channel.

// This is the test that matters: it walks the kinds list rather than a
// hand-written set, so a kind added tomorrow without declaring its
// secrets fails here instead of shipping in the clear.
func TestEveryChannelKindDeclaresItsSecrets(t *testing.T) {
	for _, kind := range storage.AlertChannelKinds {
		if _, ok := channelSecretStringFields[kind]; !ok {
			t.Errorf("channel kind %q declares no secret fields.\n"+
				"If it genuinely has none, add an explicit empty slice: "+
				"\"considered, has none\" and \"nobody thought about it\" must not look alike.\n"+
				"If it has one, add it — an undeclared credential is written in cleartext "+
				"into every backup, including the ones labelled encrypted.", kind)
		}
	}
}

// And the union the restore path uses must cover each kind's keys, or a
// restored channel's sentinel is never resolved back to its live value.
func TestAllChannelSecretStringFieldsCoversEveryKind(t *testing.T) {
	union := map[string]bool{}
	for _, k := range allChannelSecretStringFields() {
		union[k] = true
	}
	for kind, keys := range channelSecretStringFields {
		for _, k := range keys {
			if !union[k] {
				t.Errorf("kind %q declares secret key %q, which the restore path's union omits",
					kind, k)
			}
		}
	}
}

// visitChannelConfig is the function both the redactor and the sealer
// go through, so one test over it covers both artifacts.
func TestVisitChannelConfig_VisitsTheDiscordWebhookURL(t *testing.T) {
	const secret = "https://discord.com/api/webhooks/123456/aBcD-TOKEN"
	cfg := json.RawMessage(`{"webhookUrl":` + quote(secret) + `,"username":"arenet"}`)

	var visited []string
	out, err := visitChannelConfig("alert_channels[0].", storage.ChannelKindDiscord, cfg,
		func(path, v string) (string, error) {
			visited = append(visited, path)
			return "SEALED", nil
		})
	if err != nil {
		t.Fatalf("visitChannelConfig: %v", err)
	}

	if len(visited) != 1 || !strings.HasSuffix(visited[0], "config.webhookUrl") {
		t.Errorf("the Discord webhook URL was not visited; visited = %v", visited)
	}
	if strings.Contains(string(out), secret) {
		t.Errorf("the secret survived into the output: %s", out)
	}
	// The non-secret field is untouched, so a restored channel still
	// knows its display name.
	if !strings.Contains(string(out), `"username":"arenet"`) {
		t.Errorf("a non-secret field was altered: %s", out)
	}
}

// The two kinds that already worked must keep working — this change
// replaced their switch with a map lookup.
func TestVisitChannelConfig_KeepsEmailAndWebhookCovered(t *testing.T) {
	cases := []struct {
		kind     string
		cfg      string
		secret   string
		wantPath string
	}{
		{
			kind:     storage.ChannelKindEmail,
			cfg:      `{"smtpPassword":"p4ssw0rd","smtpHost":"mail.example.com"}`,
			secret:   "p4ssw0rd",
			wantPath: "config.smtpPassword",
		},
		{
			kind:     storage.ChannelKindWebhook,
			cfg:      `{"url":"https://hooks.example.com/t/SECRET"}`,
			secret:   "SECRET",
			wantPath: "config.url",
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			var visited []string
			out, err := visitChannelConfig("c.", tc.kind, json.RawMessage(tc.cfg),
				func(path, v string) (string, error) {
					visited = append(visited, path)
					return "SEALED", nil
				})
			if err != nil {
				t.Fatalf("visitChannelConfig: %v", err)
			}
			found := false
			for _, p := range visited {
				if strings.HasSuffix(p, tc.wantPath) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: %q not visited; visited = %v", tc.kind, tc.wantPath, visited)
			}
			if strings.Contains(string(out), tc.secret) {
				t.Errorf("%s: secret survived: %s", tc.kind, out)
			}
		})
	}
}

// The generic webhook kind's auth HEADERS are a map, not a string, and
// their values are credentials too. Pinned separately because the
// registry splits string keys from map keys.
func TestVisitChannelConfig_VisitsWebhookAuthHeaders(t *testing.T) {
	cfg := json.RawMessage(`{"url":"https://h.example.com/x","headers":{"Authorization":"Bearer T0KEN"}}`)
	out, err := visitChannelConfig("c.", storage.ChannelKindWebhook, cfg,
		func(path, v string) (string, error) { return "SEALED", nil })
	if err != nil {
		t.Fatalf("visitChannelConfig: %v", err)
	}
	if strings.Contains(string(out), "T0KEN") {
		t.Errorf("a webhook auth header value survived: %s", out)
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
