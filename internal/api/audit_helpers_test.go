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
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
	"github.com/barto95100/arenet/internal/storage"
)

// newAuthDepsForTest builds the auth dependencies needed by NewHandler
// in audit_helpers tests. These tests do not exercise auth flows, so
// the returned objects are functional but not used by any code path
// the tests trigger.
func newAuthDepsForTest(t *testing.T, store *storage.Store, logger *slog.Logger) (
	*auth.UserStore, *auth.SessionStore, *auth.HIBPClient, *auth.RateLimiter, *SetupTokenHolder,
) {
	t.Helper()
	t.Setenv("ARENET_HIBP_DISABLED", "true")
	return auth.NewUserStore(store.DB()),
		auth.NewSessionStore(store.DB()),
		auth.NewHIBPClient(),
		auth.NewRateLimiter(logger),
		NewSetupTokenHolder()
}

// newTestHandler constructs a Handler with the supplied audit appender
// and a logger writing into the provided buffer (for log assertions).
func newTestHandler(t *testing.T, auditAppender AuditAppender, logBuf io.Writer) *Handler {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "arenet.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	logger := slog.New(slog.NewJSONHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	users, sessions, hibp, rl, setupTok := newAuthDepsForTest(t, store, logger)
	return NewHandler(store, &fakeReloader{}, auditAppender, users, sessions, hibp, rl, setupTok, false, logger)
}

// reqWithAuth returns a fake request with auth context populated.
func reqWithAuth(method, target, userID, username, clientIP, userAgent string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	if userAgent != "" {
		r.Header.Set("User-Agent", userAgent)
	}
	ctx := r.Context()
	if userID != "" {
		ctx = context.WithValue(ctx, auth.UserIDKey, userID)
	}
	if username != "" {
		ctx = context.WithValue(ctx, auth.UsernameKey, username)
	}
	if clientIP != "" {
		ctx = context.WithValue(ctx, auth.ClientIPKey, clientIP)
	}
	return r.WithContext(ctx)
}

// --- appendAudit -------------------------------------------------------

func TestAppendAudit_FillsContextFields(t *testing.T) {
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	r := reqWithAuth(http.MethodPost, "/api/v1/routes", "user-uuid", "admin", "203.0.113.5", "Mozilla/5.0")
	h.appendAudit(r, audit.Event{
		Action:     audit.ActionRouteCreated,
		TargetType: "route",
		TargetID:   "route-uuid",
		AfterJSON:  []byte(`{"host":"example.com"}`),
	})

	got := appender.Events()
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	e := got[0]
	if e.ActorUserID != "user-uuid" {
		t.Errorf("ActorUserID = %q, want user-uuid", e.ActorUserID)
	}
	if e.ActorUsernameSnapshot != "admin" {
		t.Errorf("ActorUsernameSnapshot = %q, want admin", e.ActorUsernameSnapshot)
	}
	if e.IP != "203.0.113.5" {
		t.Errorf("IP = %q, want 203.0.113.5", e.IP)
	}
	if e.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q, want Mozilla/5.0", e.UserAgent)
	}
	if e.Action != audit.ActionRouteCreated {
		t.Errorf("Action overwritten: %q", e.Action)
	}
	if e.TargetID != "route-uuid" {
		t.Errorf("TargetID lost: %q", e.TargetID)
	}
}

func TestAppendAudit_EmptyContextValuesAreEmptyFields(t *testing.T) {
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	// No auth keys in context (unauthenticated event like login_failure).
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil)
	h.appendAudit(r, audit.Event{Action: audit.ActionLoginFailure})

	got := appender.Events()
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	e := got[0]
	if e.ActorUserID != "" {
		t.Errorf("ActorUserID = %q, want empty", e.ActorUserID)
	}
	if e.ActorUsernameSnapshot != "" {
		t.Errorf("ActorUsernameSnapshot = %q, want empty", e.ActorUsernameSnapshot)
	}
	if e.IP != "" {
		t.Errorf("IP = %q, want empty", e.IP)
	}
}

// TestAppendAudit_FailureLogsWarnNoPanic: per decision D2, audit
// emission is best-effort. A failed Append must log Warn but never
// propagate to the caller or panic.
func TestAppendAudit_FailureLogsWarnNoPanic(t *testing.T) {
	appender := &fakeAuditAppender{nextErr: errors.New("simulated db hiccup")}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	r := reqWithAuth(http.MethodPost, "/", "u1", "admin", "1.2.3.4", "ua")

	// Wrapped in a defer-recover to assert no panic.
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("appendAudit panicked: %v", rec)
			}
		}()
		h.appendAudit(r, audit.Event{
			Action:   audit.ActionRouteCreated,
			TargetID: "route-1",
		})
	}()

	logs := logBuf.String()
	if !strings.Contains(logs, `"level":"WARN"`) {
		t.Errorf("expected WARN log, got: %s", logs)
	}
	if !strings.Contains(logs, "audit append failed") {
		t.Errorf("expected 'audit append failed' message, got: %s", logs)
	}
	if !strings.Contains(logs, `"action":"`+audit.ActionRouteCreated+`"`) {
		t.Errorf("expected action field, got: %s", logs)
	}
}

// TestAppendAudit_DoesNotLogMessageField is the security guard
// against accidental message leakage. The Message field may contain
// free text (login_failure reason etc.) that a careless caller might
// fill with sensitive content (the attempted password!). The helper
// must NOT echo Message into slog on failure.
func TestAppendAudit_DoesNotLogMessageField(t *testing.T) {
	appender := &fakeAuditAppender{nextErr: errors.New("simulated failure")}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	canary := "DO-NOT-LEAK-THIS-MESSAGE-CONTENT-canary-x97z"
	r := reqWithAuth(http.MethodPost, "/", "u1", "admin", "1.2.3.4", "ua")
	h.appendAudit(r, audit.Event{
		Action:   audit.ActionLoginFailure,
		Message:  canary,
		TargetID: "target-1",
	})

	if strings.Contains(logBuf.String(), canary) {
		t.Errorf("evt.Message LEAKED into Warn log: %s", logBuf.String())
	}
}

// TestAppendAudit_AlsoDoesNotLogUserAgent: User-Agent strings can be
// arbitrary user input. Tier 2 leakage check.
func TestAppendAudit_AlsoDoesNotLogUserAgent(t *testing.T) {
	appender := &fakeAuditAppender{nextErr: errors.New("simulated failure")}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	canaryUA := "CANARY-USER-AGENT-NEVER-LOG-y32k"
	r := reqWithAuth(http.MethodPost, "/", "u1", "admin", "1.2.3.4", canaryUA)
	h.appendAudit(r, audit.Event{Action: audit.ActionRouteCreated})

	if strings.Contains(logBuf.String(), canaryUA) {
		t.Errorf("User-Agent LEAKED into Warn log: %s", logBuf.String())
	}
}

// --- appendAuditBackground ----------------------------------------------

func TestAppendAuditBackground_FillsActorUserIDOnly(t *testing.T) {
	appender := &fakeAuditAppender{}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	h.appendAuditBackground(context.Background(), "user-uuid", audit.Event{
		Action:     audit.ActionPasswordHIBPClean,
		TargetType: "user",
		TargetID:   "user-uuid",
	})

	got := appender.Events()
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	e := got[0]
	if e.ActorUserID != "user-uuid" {
		t.Errorf("ActorUserID = %q, want user-uuid", e.ActorUserID)
	}
	// IP, UA, ActorUsernameSnapshot intentionally empty (no live request).
	if e.IP != "" {
		t.Errorf("IP must be empty for background event, got %q", e.IP)
	}
	if e.UserAgent != "" {
		t.Errorf("UserAgent must be empty for background event, got %q", e.UserAgent)
	}
	if e.ActorUsernameSnapshot != "" {
		t.Errorf("ActorUsernameSnapshot must be empty for background event, got %q", e.ActorUsernameSnapshot)
	}
}

func TestAppendAuditBackground_FailureLogsWarnNoPanic(t *testing.T) {
	appender := &fakeAuditAppender{nextErr: errors.New("simulated")}
	var logBuf bytes.Buffer
	h := newTestHandler(t, appender, &logBuf)

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("appendAuditBackground panicked: %v", rec)
			}
		}()
		h.appendAuditBackground(context.Background(), "user-uuid", audit.Event{
			Action:   audit.ActionPasswordCompromisedDetected,
			TargetID: "user-uuid",
		})
	}()

	logs := logBuf.String()
	if !strings.Contains(logs, "audit append (background) failed") {
		t.Errorf("expected background warn message, got: %s", logs)
	}
}

// --- mustMarshalForAudit ------------------------------------------------

func TestMustMarshalForAudit_HappyPath(t *testing.T) {
	v := struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	}{Host: "example.com", Port: 8080}
	got := mustMarshalForAudit(v)
	if got == nil {
		t.Fatal("got nil, want non-nil")
	}
	want := `{"host":"example.com","port":8080}`
	if string(got) != want {
		t.Errorf("got %s, want %s", string(got), want)
	}
}

func TestMustMarshalForAudit_Nil(t *testing.T) {
	got := mustMarshalForAudit(nil)
	// nil marshals to JSON "null"; not an error.
	if string(got) != "null" {
		t.Errorf("got %q, want \"null\"", string(got))
	}
}

// TestMustMarshalForAudit_UnmarshalableReturnsNilNoPanic: the
// function name starts with "Must" but does NOT panic on
// unmarshalable input (per spec §5.9 and plan §4.3 implementation
// notes). Returns nil so the event is still emitted, just without
// the diff.
func TestMustMarshalForAudit_UnmarshalableReturnsNilNoPanic(t *testing.T) {
	// A channel cannot be JSON-marshalled.
	ch := make(chan int)
	defer close(ch)

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("mustMarshalForAudit panicked on unmarshalable input: %v", rec)
			}
		}()
		got := mustMarshalForAudit(ch)
		if got != nil {
			t.Errorf("got %s, want nil", string(got))
		}
	}()
}

// TestMustMarshalForAudit_CircularReferenceReturnsNilNoPanic: deep
// circular references trigger json.Marshal to error rather than loop
// forever; the function must surface this as nil, not panic.
//
// Item #3 from the sub-agent review checklist (§6.4).
func TestMustMarshalForAudit_CircularReferenceReturnsNilNoPanic(t *testing.T) {
	type node struct {
		Next *node
	}
	a := &node{}
	a.Next = a // circular

	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("mustMarshalForAudit panicked on circular reference: %v", rec)
			}
		}()
		got := mustMarshalForAudit(a)
		if got != nil {
			t.Errorf("got %s, want nil for circular reference", string(got))
		}
	}()
}

// TestMustMarshalForAudit_PerformsNoSanitization is the documentation
// counterpart to the SECURITY note on mustMarshalForAudit. The
// function MUST NOT perform any field stripping; callers are
// responsible for sanitization. This test exists to make that
// contract self-documenting: if a future refactor adds sanitization
// inside the function, this test will catch the behavior change.
func TestMustMarshalForAudit_PerformsNoSanitization(t *testing.T) {
	v := struct {
		Username     string `json:"username"`
		PasswordHash string `json:"password_hash"`
	}{Username: "admin", PasswordHash: "$argon2id$v=19$m=65536$...HASH..."}
	got := mustMarshalForAudit(v)
	if !strings.Contains(string(got), "password_hash") {
		t.Errorf("function appears to have stripped password_hash; "+
			"sanitization is the CALLER's responsibility, not this function's. "+
			"Output: %s", string(got))
	}
}
