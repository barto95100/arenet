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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/storage"
)

// v2.39 — a webhook URL is a secret, so GET redacts it. Saving the
// channel back (what the UI does) must keep the stored URL: before the
// fix it stored "https://host/[redacted]" and the channel silently
// stopped sending.

const webhookURL = "https://discord.example/api/webhooks/123/SECRET-TOKEN"

func seedRedactionChannel(t *testing.T, env *testEnv) storage.Channel {
	t.Helper()
	cfg, _ := json.Marshal(alerting.WebhookConfig{
		URL:            webhookURL,
		TimeoutSeconds: 10,
		Headers:        map[string]string{"Authorization": "Bearer secret-value"},
	})
	ch, err := env.store.CreateAlertChannel(context.Background(), storage.Channel{
		ID: uuid.NewString(), Name: "discord", Kind: storage.ChannelKindWebhook, Enabled: true, MinSeverity: 1, Config: cfg,
	})
	if err != nil {
		t.Fatalf("seed channel: %v", err)
	}
	return ch
}

func getChannel(t *testing.T, env *testEnv, id string) alertChannelResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/settings/alerting/channels/"+id, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET channel: %d %s", rec.Code, rec.Body)
	}
	var out alertChannelResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func putChannel(t *testing.T, env *testEnv, id string, cfg any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	body, _ := json.Marshal(map[string]any{
		"name": "discord", "kind": "webhook", "enabled": true, "minSeverity": 1,
		"config": json.RawMessage(raw),
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerting/channels/"+id, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

func storedWebhook(t *testing.T, env *testEnv, id string) alerting.WebhookConfig {
	t.Helper()
	ch, err := env.store.GetAlertChannel(context.Background(), id)
	if err != nil {
		t.Fatalf("get stored: %v", err)
	}
	var cfg alerting.WebhookConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		t.Fatalf("decode stored: %v", err)
	}
	return cfg
}

func TestAlertChannel_EditKeepsRedactedSecrets(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedRedactionChannel(t, env)

	got := getChannel(t, env, ch.ID)
	var shown alerting.WebhookConfig
	if err := json.Unmarshal(got.Config, &shown); err != nil {
		t.Fatalf("decode response config: %v", err)
	}
	if shown.URL != "https://discord.example/[redacted]" || shown.Headers["Authorization"] != auditRedacted {
		t.Fatalf("GET must redact the URL and the header values: %+v", shown)
	}
	if got.SecretsLost {
		t.Error("a healthy channel must not be flagged as lost")
	}

	// The UI sends back exactly what it was shown.
	if rec := putChannel(t, env, ch.ID, shown); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	stored := storedWebhook(t, env, ch.ID)
	if stored.URL != webhookURL || stored.Headers["Authorization"] != "Bearer secret-value" {
		t.Fatalf("round-trip lost the secrets: %+v", stored)
	}

	// An empty header value keeps the stored one (pre-existing
	// contract); an empty URL is refused by validation.
	if rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{URL: webhookURL, TimeoutSeconds: 10, Headers: map[string]string{"Authorization": ""}}); rec.Code != http.StatusOK {
		t.Fatalf("PUT empty header: %d %s", rec.Code, rec.Body)
	}
	if stored = storedWebhook(t, env, ch.ID); stored.Headers["Authorization"] != "Bearer secret-value" {
		t.Fatalf("empty header value must keep the stored one: %+v", stored.Headers)
	}
	if rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{URL: "", TimeoutSeconds: 10}); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty URL: %d, want 400", rec.Code)
	}
}

func TestAlertChannel_EditCanReplaceTheURL(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedRedactionChannel(t, env)
	next := "https://other.example/hooks/NEW"
	if rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{URL: next, TimeoutSeconds: 10}); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if stored := storedWebhook(t, env, ch.ID); stored.URL != next {
		t.Fatalf("stored URL = %q, want the new one", stored.URL)
	}
}

func TestAlertChannel_ReportsAnAlreadyLostURL(t *testing.T) {
	env := newTestEnv(t, false)
	cfg, _ := json.Marshal(alerting.WebhookConfig{URL: "https://discord.example/" + auditRedacted, TimeoutSeconds: 10})
	ch, err := env.store.CreateAlertChannel(context.Background(), storage.Channel{
		ID: uuid.NewString(), Name: "broken", Kind: storage.ChannelKindWebhook, Enabled: true, MinSeverity: 1, Config: cfg,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := getChannel(t, env, ch.ID); !got.SecretsLost {
		t.Fatal("a channel whose stored URL is the placeholder must be flagged")
	}
	// Retyping the URL repairs it.
	if rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{URL: webhookURL, TimeoutSeconds: 10}); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body)
	}
	if got := getChannel(t, env, ch.ID); got.SecretsLost {
		t.Fatal("still flagged after retyping the URL")
	}
}

// v2.72 — renaming a header key stored the placeholder as its value.
//
// GET redacts every header value to "[redacted]" and the modal binds
// that literal into a visible text input. The merge inherits BY KEY: if
// the key is not found in stored.Headers the branch falls through and
// the placeholder is persisted verbatim. No validator rejected it, and
// webhookURLLost only inspected the URL, so SecretsLost stayed false.
//
// Sequence: edit a webhook whose header key has a typo —
// "Authorizaton" — fix the key to "Authorization", leave the value
// field showing "[redacted]", save. The bearer token is now the
// five-word placeholder and the channel 401s at the next real alert,
// with a success toast behind it.
//
// The existing test above covers an unchanged key and an empty value. A
// RENAMED key was the untested gap.

func TestAlertChannel_RenamingAHeaderKeyIsRefused(t *testing.T) {
	env := newTestEnv(t, false)
	ch := seedRedactionChannel(t, env)

	// What the operator sees, with the key corrected and the value left
	// as the placeholder they cannot read.
	rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{
		URL:            "https://discord.example/[redacted]",
		TimeoutSeconds: 10,
		Headers:        map[string]string{"X-Renamed": auditRedacted},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 — a placeholder under a key with no stored "+
			"counterpart must be refused, not persisted; body=%s", rec.Code, rec.Body)
	}

	// And the original header is untouched: a refusal that half-applied
	// would be worse than the defect.
	stored := storedWebhook(t, env, ch.ID)
	if stored.Headers["Authorization"] != "Bearer secret-value" {
		t.Errorf("the refused save modified the stored headers: %+v", stored.Headers)
	}
}

func TestAlertChannel_RenamingAHeaderWithANewValueIsAccepted(t *testing.T) {
	// The refusal must be about an unreadable placeholder, not about
	// renaming. An operator who retypes the value is doing the right
	// thing and must not be blocked.
	env := newTestEnv(t, false)
	ch := seedRedactionChannel(t, env)

	rec := putChannel(t, env, ch.ID, alerting.WebhookConfig{
		URL:            "https://discord.example/[redacted]",
		TimeoutSeconds: 10,
		Headers:        map[string]string{"X-Renamed": "Bearer brand-new"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rec.Code, rec.Body)
	}
	stored := storedWebhook(t, env, ch.ID)
	if stored.Headers["X-Renamed"] != "Bearer brand-new" {
		t.Errorf("the new header value did not persist: %+v", stored.Headers)
	}
	if _, ok := stored.Headers["Authorization"]; ok {
		t.Errorf("the old key should be gone after a rename: %+v", stored.Headers)
	}
}

func TestAlertChannel_AlreadyDamagedHeaderIsReportedAsLost(t *testing.T) {
	// The other half: a channel damaged before this fix must say so.
	// webhookURLLost is the existing concept — "a stored secret carries
	// the placeholder" — and headers are the same thing. Without this a
	// channel stays silently dead with nothing on screen about it.
	env := newTestEnv(t, false)
	ch := seedRedactionChannel(t, env)

	// Write the damaged state straight to the store, which is what the
	// old merge produced.
	damaged, _ := json.Marshal(alerting.WebhookConfig{
		URL:            webhookURL,
		TimeoutSeconds: 10,
		Headers:        map[string]string{"Authorization": auditRedacted},
	})
	stored, err := env.store.GetAlertChannel(context.Background(), ch.ID)
	if err != nil {
		t.Fatalf("GetAlertChannel: %v", err)
	}
	stored.Config = damaged
	if _, err := env.store.UpdateAlertChannel(context.Background(), stored); err != nil {
		t.Fatalf("UpdateAlertChannel: %v", err)
	}

	got := getChannel(t, env, ch.ID)
	if !got.SecretsLost {
		t.Error("a stored header carrying the placeholder must set secretsLost")
	}
}
