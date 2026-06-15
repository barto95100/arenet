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
	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// AL.1.b — Channel CRUD handler tests. Coverage: full CRUD
// cycle, GET secret redaction (webhook headers + email
// password), audit-before/after redaction, preserve-on-edit,
// /test endpoint via httptest sender.

func seedWebhookChannel(t *testing.T, store *storage.Store) storage.Channel {
	t.Helper()
	cfg := alerting.WebhookConfig{
		URL:            "http://webhook.example.com",
		Method:         "POST",
		TimeoutSeconds: 5,
		Headers: map[string]string{
			"Authorization": "Bearer super-secret-token",
		},
	}
	raw, _ := json.Marshal(cfg)
	c := storage.Channel{
		ID:          uuid.NewString(),
		Name:        "ops-webhook",
		Kind:        storage.ChannelKindWebhook,
		Enabled:     true,
		MinSeverity: 0,
		Config:      raw,
	}
	created, err := store.CreateAlertChannel(context.Background(), c)
	if err != nil {
		t.Fatalf("seed webhook channel: %v", err)
	}
	return created
}

func seedEmailChannel(t *testing.T, store *storage.Store) storage.Channel {
	t.Helper()
	cfg := alerting.EmailConfig{
		SMTPHost:     "smtp.example.com",
		SMTPPort:     587,
		SMTPUsername: "alerts",
		SMTPPassword: "the-real-smtp-password",
		From:         "alerts@example.com",
		To:           []string{"ops@example.com"},
		UseStartTLS:  true,
	}
	raw, _ := json.Marshal(cfg)
	c := storage.Channel{
		ID:          uuid.NewString(),
		Name:        "ops-email",
		Kind:        storage.ChannelKindEmail,
		Enabled:     true,
		MinSeverity: 1,
		Config:      raw,
	}
	created, err := store.CreateAlertChannel(context.Background(), c)
	if err != nil {
		t.Fatalf("seed email channel: %v", err)
	}
	return created
}

func TestAlertChannel_CRUD_Success(t *testing.T) {
	env := newTestEnv(t, false)

	body := `{"name":"ops-webhook","kind":"webhook","enabled":true,"minSeverity":1,"config":{"url":"http://webhook.example.com","method":"POST","timeoutSeconds":5}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/alerting/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: status=%d body=%s", rec.Code, rec.Body)
	}
	var created alertChannelResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode POST response: %v", err)
	}
	if created.ID == "" {
		t.Errorf("response missing id")
	}

	// LIST
	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/alerting/channels", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST: status=%d body=%s", rec.Code, rec.Body)
	}

	// GET
	req = httptest.NewRequest(http.MethodGet, "/api/v1/settings/alerting/channels/"+created.ID, nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET: status=%d body=%s", rec.Code, rec.Body)
	}

	// PUT
	body = `{"name":"ops-webhook","kind":"webhook","enabled":false,"minSeverity":2,"config":{"url":"http://webhook.example.com","method":"POST","timeoutSeconds":10}}`
	req = httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerting/channels/"+created.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}

	// DELETE
	req = httptest.NewRequest(http.MethodDelete, "/api/v1/settings/alerting/channels/"+created.ID, nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE: status=%d body=%s", rec.Code, rec.Body)
	}
}

func TestAlertChannel_GET_WebhookHeaderValueRedacted(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedWebhookChannel(t, env.store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/alerting/channels/"+seeded.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	// Stored secret MUST NOT leak.
	if strings.Contains(body, "super-secret-token") {
		t.Errorf("webhook header secret leaked in GET body: %s", body)
	}
	// Header KEY must remain visible so the operator can
	// audit which headers were configured.
	if !strings.Contains(body, "Authorization") {
		t.Errorf("header key 'Authorization' missing from GET body: %s", body)
	}
	// Redacted sentinel.
	if !strings.Contains(body, "[redacted]") {
		t.Errorf("redaction sentinel missing in GET body: %s", body)
	}
}

func TestAlertChannel_GET_EmailPasswordRedacted(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedEmailChannel(t, env.store)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/settings/alerting/channels/"+seeded.ID, nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if strings.Contains(body, "the-real-smtp-password") {
		t.Errorf("smtp password leaked in GET body: %s", body)
	}
	// Username, host, port, recipients MUST remain visible.
	if !strings.Contains(body, `"smtpUsername":"alerts"`) {
		t.Errorf("smtpUsername missing from GET body: %s", body)
	}
}

func TestAlertChannel_Audit_SecretsRedacted(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedEmailChannel(t, env.store)

	// PUT with a rotated password so both before + after
	// audit blobs are exercised.
	cfg := alerting.EmailConfig{
		SMTPHost:     "smtp.example.com",
		SMTPPort:     587,
		SMTPUsername: "alerts",
		SMTPPassword: "rotated-NEW-password",
		From:         "alerts@example.com",
		To:           []string{"ops@example.com"},
		UseStartTLS:  true,
	}
	raw, _ := json.Marshal(cfg)
	body := `{"name":"ops-email","kind":"email","enabled":true,"minSeverity":1,"config":` + string(raw) + `}`

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerting/channels/"+seeded.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}

	events := env.audit.Events()
	var evt *audit.Event
	for i := range events {
		if events[i].Action == audit.ActionAlertChannelUpdated {
			evt = &events[i]
			break
		}
	}
	if evt == nil {
		t.Fatalf("alert_channel_updated event not emitted; events=%+v", events)
	}
	if strings.Contains(string(evt.BeforeJSON), "the-real-smtp-password") {
		t.Errorf("audit BeforeJSON leaked previous password: %s", evt.BeforeJSON)
	}
	if strings.Contains(string(evt.AfterJSON), "rotated-NEW-password") {
		t.Errorf("audit AfterJSON leaked rotated password: %s", evt.AfterJSON)
	}
}

func TestAlertChannel_PUT_PreservesPasswordOnEmptyValue(t *testing.T) {
	env := newTestEnv(t, false)
	seeded := seedEmailChannel(t, env.store)

	// PUT with empty SMTPPassword — must preserve stored value.
	body := `{"name":"ops-email","kind":"email","enabled":true,"minSeverity":1,"config":{"smtpHost":"smtp.example.com","smtpPort":587,"smtpUsername":"alerts","smtpPassword":"","from":"alerts@example.com","to":["ops@example.com"],"useStartTLS":true,"useTLS":false}}`

	req := httptest.NewRequest(http.MethodPut, "/api/v1/settings/alerting/channels/"+seeded.ID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: status=%d body=%s", rec.Code, rec.Body)
	}

	stored, err := env.store.GetAlertChannel(context.Background(), seeded.ID)
	if err != nil {
		t.Fatalf("GetAlertChannel: %v", err)
	}
	var got alerting.EmailConfig
	if err := json.Unmarshal(stored.Config, &got); err != nil {
		t.Fatalf("unmarshal stored config: %v", err)
	}
	if got.SMTPPassword != "the-real-smtp-password" {
		t.Errorf("SMTPPassword NOT preserved on empty PUT: got %q want the-real-smtp-password", got.SMTPPassword)
	}
}

func TestAlertChannel_Test_SuccessFiresSender(t *testing.T) {
	env := newTestEnv(t, false)

	// Spin up a local webhook receiver and register it as a channel.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := alerting.WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5}
	raw, _ := json.Marshal(cfg)
	channel := storage.Channel{
		ID:          uuid.NewString(),
		Name:        "live-test",
		Kind:        storage.ChannelKindWebhook,
		Enabled:     true,
		MinSeverity: 0,
		Config:      raw,
	}
	created, err := env.store.CreateAlertChannel(context.Background(), channel)
	if err != nil {
		t.Fatalf("create channel: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/alerting/channels/"+created.ID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/test: status=%d body=%s", rec.Code, rec.Body)
	}
	var resp alertChannelTestResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /test response: %v", err)
	}
	if !resp.OK {
		t.Errorf("/test response OK=false err=%q; want OK=true", resp.Error)
	}

	// Last-sent must be recorded on the channel row.
	stored, _ := env.store.GetAlertChannel(context.Background(), created.ID)
	if stored.LastSentAt == nil {
		t.Errorf("LastSentAt nil after successful /test — MarkAlertChannelSendResult not called")
	}
}

func TestAlertChannel_Test_FailureRecordsError(t *testing.T) {
	env := newTestEnv(t, false)

	// 500-returning server → sender returns error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := alerting.WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5}
	raw, _ := json.Marshal(cfg)
	channel := storage.Channel{
		ID:          uuid.NewString(),
		Name:        "live-failtest",
		Kind:        storage.ChannelKindWebhook,
		Enabled:     true,
		MinSeverity: 0,
		Config:      raw,
	}
	created, _ := env.store.CreateAlertChannel(context.Background(), channel)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/alerting/channels/"+created.ID+"/test", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/test: status=%d body=%s (test endpoint returns 200 + body.ok=false on send fail)", rec.Code, rec.Body)
	}
	var resp alertChannelTestResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.OK {
		t.Errorf("/test response OK=true; want OK=false (server returned 500)")
	}
	if resp.Error == "" {
		t.Errorf("/test response Error empty on failure")
	}

	stored, _ := env.store.GetAlertChannel(context.Background(), created.ID)
	if stored.LastError == "" {
		t.Errorf("LastError empty after failed /test")
	}
}

func TestAlertChannel_POST_RejectsInvalidConfig(t *testing.T) {
	env := newTestEnv(t, false)
	// Missing URL — webhook config validator fails.
	body := `{"name":"bad","kind":"webhook","enabled":true,"minSeverity":0,"config":{"method":"POST","timeoutSeconds":5}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/alerting/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST invalid: status=%d; want 400. body=%s", rec.Code, rec.Body)
	}
}

func TestAlertChannel_POST_RejectsDuplicateName(t *testing.T) {
	env := newTestEnv(t, false)
	seedWebhookChannel(t, env.store)

	body := `{"name":"ops-webhook","kind":"webhook","enabled":true,"minSeverity":0,"config":{"url":"http://other.example.com","method":"POST","timeoutSeconds":5}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/settings/alerting/channels", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("POST duplicate name: status=%d; want 409. body=%s", rec.Code, rec.Body)
	}
}
