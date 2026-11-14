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

package automation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A configured, never-used writer reports configured + not-failed, and
// the counters start at zero. engine is nil here (HealthSnapshot tolerates
// it); the counter plumbing is exercised by the engine's own push tests.
func TestHealthSnapshot_ConfiguredWriter(t *testing.T) {
	w, err := NewWatcherClient(WatcherConfig{
		LAPIURL: "http://127.0.0.1:8080", MachineID: "m", Password: "p",
	})
	if err != nil {
		t.Fatalf("NewWatcherClient: %v", err)
	}
	m := NewDefaultManager(nil, nil, w)

	snap := m.HealthSnapshot()
	if !snap.WriterConfigured {
		t.Error("WriterConfigured = false, want true")
	}
	if snap.WriterLoginFailed {
		t.Error("WriterLoginFailed = true on a fresh writer, want false")
	}
	if snap.PushSuccess != 0 || snap.PushPermanent != 0 || snap.PushDropped != 0 {
		t.Errorf("fresh counters non-zero: %+v", snap)
	}
}

// The silent-failure signal: a writer whose login LAPI rejected (401)
// carries loginFailed, and HealthSnapshot surfaces it — this is what the
// Prometheus gauge turns into 1.
//
// Reinjection: dropping `snap.WriterLoginFailed = w.LoginFailed()` in
// HealthSnapshot leaves this false and fails the test.
func TestHealthSnapshot_LoginFailedPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	w, err := NewWatcherClient(WatcherConfig{
		LAPIURL: srv.URL, MachineID: "m", Password: "p",
	})
	if err != nil {
		t.Fatalf("NewWatcherClient: %v", err)
	}
	// A 401 sets the sticky loginFailed flag.
	if err := w.Login(context.Background()); err == nil {
		t.Fatal("Login against a 401 server returned nil error")
	}
	if !w.LoginFailed() {
		t.Fatal("precondition: writer did not record loginFailed")
	}

	m := NewDefaultManager(nil, nil, w)
	snap := m.HealthSnapshot()
	if !snap.WriterLoginFailed {
		t.Error("WriterLoginFailed = false, want true after a 401 login")
	}
	if !snap.WriterConfigured {
		t.Error("WriterConfigured = false, want true")
	}
}

// Boot-degraded / cleared: no writer → not configured, gauge source false.
func TestHealthSnapshot_NoWriter(t *testing.T) {
	m := NewDefaultManager(nil, nil, nil)
	snap := m.HealthSnapshot()
	if snap.WriterConfigured {
		t.Error("WriterConfigured = true with no writer, want false")
	}
	if snap.WriterLoginFailed {
		t.Error("WriterLoginFailed = true with no writer, want false")
	}

	// And after ClearCredentials on a previously-configured manager.
	w, _ := NewWatcherClient(WatcherConfig{LAPIURL: "http://x", MachineID: "m", Password: "p"})
	m2 := NewDefaultManager(nil, nil, w)
	m2.ClearCredentials()
	if m2.HealthSnapshot().WriterConfigured {
		t.Error("WriterConfigured = true after ClearCredentials, want false")
	}
}
