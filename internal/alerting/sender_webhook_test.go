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
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// AL.1.b — WebhookSender pinning tests. Coverage per the
// operator's brief: success, network error, 5xx, 4xx,
// timeout, header propagation, template rendering.

func sampleEvent() AlertEvent {
	return AlertEvent{
		ID:        "evt-1234",
		Timestamp: time.Date(2026, 6, 15, 10, 30, 0, 0, time.UTC),
		RuleID:    "rule-abc",
		RuleName:  "test-rule",
		Severity:  SeverityWarning,
		Category:  "waf",
		Subject:   "WAF block rate elevated",
		Body:      "Triggered by 25 blocks in 60s window",
	}
}

func TestWebhookSender_Success200(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if r.Method != http.MethodPost {
			t.Errorf("method = %s; want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q; want application/json; charset=utf-8", ct)
		}
		if ua := r.Header.Get("User-Agent"); ua != "arenet/alerting-webhook" {
			t.Errorf("User-Agent = %q; want arenet/alerting-webhook", ua)
		}
		// Body must be the marshalled AlertEvent.
		body, _ := io.ReadAll(r.Body)
		var got AlertEvent
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if got.Subject != "WAF block rate elevated" {
			t.Errorf("body.Subject = %q", got.Subject)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5})
	if err := sender.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits = %d; want exactly 1 (no retries per D1)", hits)
	}
}

func TestWebhookSender_5xxReturnsError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	sender := NewWebhookSender(WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5})
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %q; want status 500 in message", err.Error())
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits = %d; want exactly 1 (D1: no retry on 5xx)", hits)
	}
}

func TestWebhookSender_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	sender := NewWebhookSender(WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5})
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want error on 4xx")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("err = %q; want status 400 in message", err.Error())
	}
}

func TestWebhookSender_NetworkErrorReturnsError(t *testing.T) {
	// Closed server — connect refused.
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	srv.Close()

	sender := NewWebhookSender(WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 2})
	err := sender.Send(context.Background(), sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want network error")
	}
	if !strings.Contains(err.Error(), "webhook: send") {
		t.Errorf("err = %q; want wrapped 'webhook: send' prefix", err.Error())
	}
}

func TestWebhookSender_TimeoutReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// TimeoutSeconds=1 → http.Client.Timeout = 1s; the
	// 300ms handler completes well under that. Use a
	// context-side cancel to force the timeout path.
	sender := NewWebhookSender(WebhookConfig{URL: srv.URL, Method: "POST", TimeoutSeconds: 5})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := sender.Send(ctx, sampleEvent())
	if err == nil {
		t.Fatalf("Send: nil; want context-deadline error")
	}
}

func TestWebhookSender_HeadersPropagated(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(WebhookConfig{
		URL:            srv.URL,
		Method:         "POST",
		TimeoutSeconds: 5,
		Headers: map[string]string{
			"Authorization": "Bearer secret123",
			"X-Custom":      "value",
		},
	})
	if err := sender.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if v := got.Get("Authorization"); v != "Bearer secret123" {
		t.Errorf("Authorization = %q; want Bearer secret123", v)
	}
	if v := got.Get("X-Custom"); v != "value" {
		t.Errorf("X-Custom = %q; want value", v)
	}
}

func TestWebhookSender_TemplateRendering(t *testing.T) {
	var capturedBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		capturedBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sender := NewWebhookSender(WebhookConfig{
		URL:            srv.URL,
		Method:         "POST",
		TimeoutSeconds: 5,
		BodyTemplate:   `{"text":"[{{.Severity}}] {{.Subject}}"}`,
	})
	if err := sender.Send(context.Background(), sampleEvent()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	wantBody := `{"text":"[warning] WAF block rate elevated"}`
	if capturedBody != wantBody {
		t.Errorf("body = %q; want %q", capturedBody, wantBody)
	}
}
