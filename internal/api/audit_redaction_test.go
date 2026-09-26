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
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

const (
	leakWebhookURL   = "https://discord.example/api/webhooks/1/LEAK-WEBHOOK"
	leakHeader       = "Bearer LEAK-HEADER"
	leakUpstreamAuth = "Bearer LEAK-UPSTREAM"
	leakHash         = "$argon2id$LEAK-HASH"
	leakSMTP         = "LEAK-SMTP"
)

func leakyRoute() storage.Route {
	return storage.Route{
		ID:             "r1",
		Host:           "app.example.com",
		BasicAuth:      storage.BasicAuthRouteConfig{Username: "u", PasswordHash: leakHash},
		RequestHeaders: map[string]string{"Authorization": leakUpstreamAuth, "X-Plain": "visible"},
		PathRules: []storage.PathRule{{
			PathPrefix: "/admin",
			BasicAuth:  &storage.BasicAuthRouteConfig{Username: "a", PasswordHash: leakHash},
		}},
	}
}

func leakyWebhook() storage.Channel {
	cfg, _ := json.Marshal(map[string]any{
		"url": leakWebhookURL, "method": "POST", "timeoutSeconds": 5,
		"headers": map[string]string{"Authorization": leakHeader},
	})
	return storage.Channel{ID: "c1", Name: "discord", Kind: storage.ChannelKindWebhook, Config: cfg}
}

func assertNoLeak(t *testing.T, what string, payload []byte) {
	t.Helper()
	for _, s := range []string{"LEAK-WEBHOOK", "LEAK-HEADER", "LEAK-UPSTREAM", "LEAK-HASH", leakSMTP} {
		if strings.Contains(string(payload), s) {
			t.Errorf("%s leaks %s: %s", what, s, payload)
		}
	}
}

func TestAuditRedaction_NewEvents(t *testing.T) {
	route := routeForAudit(leakyRoute())
	b, _ := json.Marshal(route)
	assertNoLeak(t, "route audit", b)
	if route.RequestHeaders["X-Plain"] != "visible" {
		t.Error("non-sensitive header must stay readable")
	}
	orig := leakyRoute()
	if orig.PathRules[0].BasicAuth.PasswordHash != leakHash {
		t.Error("fixture sanity")
	}

	ch := alertChannelForAudit(leakyWebhook())
	assertNoLeak(t, "channel audit", ch.Config)
	if !strings.Contains(string(ch.Config), "https://discord.example/") {
		t.Errorf("webhook host should stay auditable: %s", ch.Config)
	}
}

func TestScrubAuditSecrets_RewritesOldEvents(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewStore(filepath.Join(t.TempDir(), "arenet.db"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	defer func() { _ = store.Close() }()
	as := audit.NewStore(store.DB())

	// Events as pre-v2.30 versions wrote them.
	routeJSON, _ := json.Marshal(leakyRoute())
	ch := leakyWebhook()
	chJSON, _ := json.Marshal(ch)
	emailCfg, _ := json.Marshal(map[string]any{"smtpHost": "smtp.example.com", "smtpPassword": leakSMTP})
	emailJSON, _ := json.Marshal(storage.Channel{ID: "c2", Kind: storage.ChannelKindEmail, Config: emailCfg})
	for _, e := range []audit.Event{
		{Action: "route_created", TargetType: auditTargetRoute, TargetID: "r1", AfterJSON: routeJSON},
		{Action: "route_updated", TargetType: auditTargetRoute, TargetID: "r1", BeforeJSON: routeJSON, AfterJSON: routeJSON},
		{Action: "alerting_channel_created", TargetType: auditTargetAlertChannel, TargetID: "c1", AfterJSON: chJSON},
		{Action: "alerting_channel_created", TargetType: auditTargetAlertChannel, TargetID: "c2", AfterJSON: emailJSON},
		{Action: "user_created", TargetType: "user", TargetID: "u1", AfterJSON: json.RawMessage(`{"username":"alice"}`)},
	} {
		if err := as.Append(ctx, e); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	before, _, _ := as.List(ctx, audit.Filter{Limit: 10})

	n, err := ScrubAuditSecrets(ctx, as)
	if err != nil || n != 4 {
		t.Fatalf("ScrubAuditSecrets = %d, %v (want 4)", n, err)
	}
	if n, _ := ScrubAuditSecrets(ctx, as); n != 0 {
		t.Errorf("second scrub rewrote %d events", n)
	}
	after, _, _ := as.List(ctx, audit.Filter{Limit: 10})
	if len(after) != len(before) {
		t.Fatalf("event count changed: %d → %d", len(before), len(after))
	}
	for i, e := range after {
		assertNoLeak(t, e.Action, append(append([]byte{}, e.BeforeJSON...), e.AfterJSON...))
		if e.ID != before[i].ID || !e.Timestamp.Equal(before[i].Timestamp) || e.Action != before[i].Action {
			t.Errorf("event identity changed: %+v → %+v", before[i], e)
		}
		if e.TargetType == auditTargetRoute && !strings.Contains(string(e.AfterJSON), "visible") {
			t.Errorf("scrub dropped non-secret data: %s", e.AfterJSON)
		}
	}
}
