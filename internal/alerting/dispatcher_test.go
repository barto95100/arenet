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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// AL.1.b — Dispatcher pinning tests. Coverage:
//   - happy path: enabled channel above severity → Fired
//   - disabled channel → Skipped (not Failed)
//   - MinSeverity gate → Skipped (not Failed)
//   - channel not found → Failed
//   - sender Send error → Failed + MarkAlertChannelSendResult called

// fakeChannelLoader satisfies ChannelLoader from an
// in-memory map. Tracks MarkAlertChannelSendResult calls
// so tests can assert the result is persisted on every
// path (success + failure).
type fakeChannelLoader struct {
	channels map[string]storage.Channel
	marks    []markCall
}

type markCall struct {
	id      string
	sendErr error
}

func (f *fakeChannelLoader) GetAlertChannel(_ context.Context, id string) (storage.Channel, error) {
	ch, ok := f.channels[id]
	if !ok {
		return storage.Channel{}, storage.ErrNotFound
	}
	return ch, nil
}

func (f *fakeChannelLoader) MarkAlertChannelSendResult(_ context.Context, id string, sendErr error) error {
	f.marks = append(f.marks, markCall{id: id, sendErr: sendErr})
	return nil
}

func webhookChannel(t *testing.T, id, name string, enabled bool, minSev int, url string) storage.Channel {
	t.Helper()
	cfg := WebhookConfig{URL: url, Method: "POST", TimeoutSeconds: 5}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal webhook cfg: %v", err)
	}
	return storage.Channel{
		ID:          id,
		Name:        name,
		Kind:        storage.ChannelKindWebhook,
		Enabled:     enabled,
		MinSeverity: minSev,
		Config:      raw,
	}
}

func TestDispatcher_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	loader := &fakeChannelLoader{
		channels: map[string]storage.Channel{
			"ch-1": webhookChannel(t, "ch-1", "primary", true, 0, srv.URL),
		},
	}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"ch-1"})

	if len(res.Fired) != 1 || res.Fired[0] != "ch-1" {
		t.Errorf("Fired = %v; want [ch-1]", res.Fired)
	}
	if len(res.Failed) != 0 {
		t.Errorf("Failed = %v; want empty", res.Failed)
	}
	if len(res.Skipped) != 0 {
		t.Errorf("Skipped = %v; want empty", res.Skipped)
	}
	if len(loader.marks) != 1 || loader.marks[0].sendErr != nil {
		t.Errorf("marks = %v; want one mark with sendErr=nil", loader.marks)
	}
}

func TestDispatcher_DisabledChannelSkipped(t *testing.T) {
	loader := &fakeChannelLoader{
		channels: map[string]storage.Channel{
			"ch-1": webhookChannel(t, "ch-1", "paused", false, 0, "http://unused.example.com"),
		},
	}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"ch-1"})

	if _, ok := res.Skipped["ch-1"]; !ok {
		t.Errorf("Skipped missing ch-1; got %v", res.Skipped)
	}
	if len(res.Fired) != 0 {
		t.Errorf("Fired = %v; want empty (disabled)", res.Fired)
	}
	if len(res.Failed) != 0 {
		t.Errorf("Failed = %v; want empty (disabled skip is silent, not failed)", res.Failed)
	}
	if len(loader.marks) != 0 {
		t.Errorf("marks = %v; want zero (skipped channels don't update last-sent)", loader.marks)
	}
}

func TestDispatcher_MinSeverityGateSkipped(t *testing.T) {
	// Event is Warning(1); channel gate is Critical(2).
	// Event must be filtered out.
	loader := &fakeChannelLoader{
		channels: map[string]storage.Channel{
			"ch-1": webhookChannel(t, "ch-1", "critical-only", true, 2, "http://unused.example.com"),
		},
	}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"ch-1"})

	if _, ok := res.Skipped["ch-1"]; !ok {
		t.Errorf("Skipped missing ch-1; got %v", res.Skipped)
	}
	if len(res.Fired) != 0 || len(res.Failed) != 0 {
		t.Errorf("Fired=%v Failed=%v; want both empty", res.Fired, res.Failed)
	}
}

func TestDispatcher_ChannelNotFoundFailed(t *testing.T) {
	loader := &fakeChannelLoader{channels: map[string]storage.Channel{}}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"ghost"})

	if _, ok := res.Failed["ghost"]; !ok {
		t.Errorf("Failed missing ghost; got %v", res.Failed)
	}
	if len(res.Fired) != 0 {
		t.Errorf("Fired = %v; want empty", res.Fired)
	}
}

func TestDispatcher_SendErrorFailedAndMarked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	loader := &fakeChannelLoader{
		channels: map[string]storage.Channel{
			"ch-1": webhookChannel(t, "ch-1", "broken", true, 0, srv.URL),
		},
	}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"ch-1"})

	if _, ok := res.Failed["ch-1"]; !ok {
		t.Errorf("Failed missing ch-1; got %v", res.Failed)
	}
	if len(loader.marks) != 1 {
		t.Fatalf("marks = %v; want one", loader.marks)
	}
	if loader.marks[0].sendErr == nil {
		t.Errorf("mark sendErr = nil; want non-nil (send failed with 500)")
	}
}

func TestDispatcher_OneBadChannelDoesNotBlockOthers(t *testing.T) {
	// Two channels. First fails (closed server); second
	// succeeds. The good channel MUST fire despite the
	// bad one — partial-success contract.
	goodSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer goodSrv.Close()
	badSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	badSrv.Close()

	loader := &fakeChannelLoader{
		channels: map[string]storage.Channel{
			"bad":  webhookChannel(t, "bad", "bad", true, 0, badSrv.URL),
			"good": webhookChannel(t, "good", "good", true, 0, goodSrv.URL),
		},
	}
	d := NewDispatcher(loader, nil)
	res := d.Dispatch(context.Background(), sampleEvent(), []string{"bad", "good"})

	if len(res.Fired) != 1 || res.Fired[0] != "good" {
		t.Errorf("Fired = %v; want [good]", res.Fired)
	}
	if _, ok := res.Failed["bad"]; !ok {
		t.Errorf("Failed missing 'bad'; got %v", res.Failed)
	}
}

// Sentinel to silence unused linter if SenderFor is the only
// public-only seam used by future tests.
var _ = errors.New
