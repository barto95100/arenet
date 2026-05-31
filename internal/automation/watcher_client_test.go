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

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLAPI is a minimal LAPI mock for the watcher client.
// Tracks login + push call counts so tests assert the right
// interactions happened. Mutable login response so tests can
// switch between 200 / 401 / 503 between calls.
type fakeLAPI struct {
	server *httptest.Server

	loginCalls atomic.Int32
	pushCalls  atomic.Int32

	// loginResponse codes (drained in order). Empty → 200.
	loginResponses []int
	loginIdx       atomic.Int32

	// loginToken returned on 200. Empty → "fake-jwt".
	loginToken string
	// loginExpire returned on 200 (RFC3339). Empty →
	// time.Now().Add(1h).
	loginExpire string

	// pushResponses codes (drained in order). Empty → 201.
	pushResponses []int
	pushIdx       atomic.Int32

	// pushIDs returned on success. Empty → ["alert-1"].
	pushIDs []string

	// lastAlertBody is the last alert body received, for
	// shape assertions.
	lastAlertBody string
	// lastAuthHeader is the last Authorization header sent,
	// for token assertions.
	lastAuthHeader string
}

func newFakeLAPI() *fakeLAPI {
	f := &fakeLAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", f.handleLogin)
	mux.HandleFunc("/v1/alerts", f.handlePush)
	f.server = httptest.NewServer(mux)
	return f
}

func (f *fakeLAPI) close() {
	f.server.Close()
}

func (f *fakeLAPI) handleLogin(w http.ResponseWriter, r *http.Request) {
	f.loginCalls.Add(1)
	idx := int(f.loginIdx.Add(1) - 1)
	code := http.StatusOK
	if idx < len(f.loginResponses) {
		code = f.loginResponses[idx]
	}
	if code != http.StatusOK {
		http.Error(w, "fake error", code)
		return
	}
	token := f.loginToken
	if token == "" {
		token = "fake-jwt"
	}
	expire := f.loginExpire
	if expire == "" {
		expire = time.Now().Add(1 * time.Hour).UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":   200,
		"token":  token,
		"expire": expire,
	})
}

func (f *fakeLAPI) handlePush(w http.ResponseWriter, r *http.Request) {
	f.pushCalls.Add(1)
	f.lastAuthHeader = r.Header.Get("Authorization")
	body, _ := io.ReadAll(r.Body)
	f.lastAlertBody = string(body)

	idx := int(f.pushIdx.Add(1) - 1)
	code := http.StatusCreated
	if idx < len(f.pushResponses) {
		code = f.pushResponses[idx]
	}
	if code != http.StatusOK && code != http.StatusCreated {
		http.Error(w, "fake error", code)
		return
	}
	ids := f.pushIDs
	if len(ids) == 0 {
		ids = []string{"alert-1"}
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(ids)
}

func (f *fakeLAPI) cfg(machineID, password string) WatcherConfig {
	return WatcherConfig{
		LAPIURL:   f.server.URL,
		MachineID: machineID,
		Password:  password,
	}
}

// --- NewWatcherClient ----------------------------------------------------

func TestNewWatcherClient_EmptyCreds_ErrCredentialsRequired(t *testing.T) {
	cases := []WatcherConfig{
		{},
		{LAPIURL: "http://x"},
		{LAPIURL: "http://x", MachineID: "m"}, // password missing
		{MachineID: "m", Password: "p"},       // url missing
	}
	for _, c := range cases {
		if _, err := NewWatcherClient(c); !errors.Is(err, ErrCredentialsRequired) {
			t.Errorf("NewWatcherClient(%+v) err=%v, want ErrCredentialsRequired", c, err)
		}
	}
}

func TestNewWatcherClient_DoesNotPerformIO(t *testing.T) {
	// NB: spec says constructor MUST NOT hit LAPI. A transient
	// LAPI outage at boot should not fail Arenet startup.
	c, err := NewWatcherClient(WatcherConfig{
		LAPIURL:   "http://127.0.0.1:1", // black hole port
		MachineID: "m",
		Password:  "p",
	})
	if err != nil {
		t.Fatalf("constructor failed: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

// --- Login ---------------------------------------------------------------

func TestWatcherClient_Login_Success(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()

	c, err := NewWatcherClient(f.cfg("arenet", "secret"))
	if err != nil {
		t.Fatalf("NewWatcherClient: %v", err)
	}
	if err := c.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if f.loginCalls.Load() != 1 {
		t.Errorf("loginCalls=%d, want 1", f.loginCalls.Load())
	}
	tok, _ := c.EnsureJWT(context.Background())
	if tok != "fake-jwt" {
		t.Errorf("token=%q, want fake-jwt", tok)
	}
	// EnsureJWT should NOT trigger a second login — cached.
	if f.loginCalls.Load() != 1 {
		t.Errorf("EnsureJWT triggered unexpected login: count=%d", f.loginCalls.Load())
	}
}

func TestWatcherClient_Login_401_ErrLoginFailed_Sticky(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	f.loginResponses = []int{http.StatusUnauthorized}

	c, _ := NewWatcherClient(f.cfg("arenet", "wrong"))
	err := c.Login(context.Background())
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("err=%v, want ErrLoginFailed", err)
	}
	if !c.LoginFailed() {
		t.Error("LoginFailed sticky flag not set after 401")
	}
}

func TestWatcherClient_Login_503_ErrLAPIUnavailable_Retryable(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	f.loginResponses = []int{http.StatusServiceUnavailable}

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	err := c.Login(context.Background())
	if !errors.Is(err, ErrLAPIUnavailable) {
		t.Fatalf("err=%v, want ErrLAPIUnavailable", err)
	}
	if c.LoginFailed() {
		t.Error("LoginFailed sticky flag set on 5xx (should retry-able)")
	}
}

func TestWatcherClient_Login_NetworkError_ErrLAPIUnavailable(t *testing.T) {
	// Point at a closed port — sub-millisecond connection
	// refusal locally.
	c, _ := NewWatcherClient(WatcherConfig{
		LAPIURL:   "http://127.0.0.1:1",
		MachineID: "m", Password: "p",
		HTTPClient: &http.Client{Timeout: 200 * time.Millisecond},
	})
	err := c.Login(context.Background())
	if !errors.Is(err, ErrLAPIUnavailable) {
		t.Fatalf("err=%v, want ErrLAPIUnavailable", err)
	}
}

// --- EnsureJWT refresh ---------------------------------------------------

func TestWatcherClient_EnsureJWT_RefreshesNearExpiry(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	// First login returns a JWT that expires within the
	// safety margin — EnsureJWT should refresh on next call.
	f.loginExpire = time.Now().Add(jwtRefreshSafetyMargin - 30*time.Second).UTC().Format(time.RFC3339)

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	if _, err := c.EnsureJWT(context.Background()); err != nil {
		t.Fatalf("first EnsureJWT: %v", err)
	}
	if f.loginCalls.Load() != 1 {
		t.Fatalf("first EnsureJWT triggered loginCalls=%d, want 1", f.loginCalls.Load())
	}

	// Now switch the fake to a normal-expiry response for
	// the second login.
	f.loginExpire = ""
	if _, err := c.EnsureJWT(context.Background()); err != nil {
		t.Fatalf("second EnsureJWT: %v", err)
	}
	if f.loginCalls.Load() != 2 {
		t.Errorf("expected refresh on near-expiry token: loginCalls=%d, want 2", f.loginCalls.Load())
	}
}

func TestWatcherClient_EnsureJWT_CachesUntilSafetyMargin(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	// Fresh 1h-expiry token — well beyond the 5min safety
	// margin. Three EnsureJWT calls should result in one
	// login.
	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	for i := 0; i < 3; i++ {
		if _, err := c.EnsureJWT(context.Background()); err != nil {
			t.Fatalf("EnsureJWT[%d]: %v", i, err)
		}
	}
	if f.loginCalls.Load() != 1 {
		t.Errorf("loginCalls=%d, want 1 (cached for 3 calls)", f.loginCalls.Load())
	}
}

// --- PushAlert -----------------------------------------------------------

func sampleAlert() Alert {
	now := time.Now().UTC().Format(time.RFC3339)
	return Alert{
		Scenario: "arenet/waf-sqli",
		Source: AlertSource{
			Scope: "Ip", Value: "1.2.3.4", IP: "1.2.3.4",
		},
		Decisions: []AlertDecision{{
			Duration: "4h",
			Origin:   "arenet",
			Scenario: "arenet/waf-sqli",
			Scope:    "Ip",
			Type:     "ban",
			Value:    "1.2.3.4",
		}},
		Message:         "P.5 smoke fixture",
		Capacity:        0,
		EventsCount:     1,
		Leakspeed:       "0s",
		ScenarioHash:    "",
		ScenarioVersion: "",
		Simulated:       false,
		StartAt:         now,
		StopAt:          now,
		Events:          []map[string]any{},
	}
}

func TestWatcherClient_PushAlert_Success_StringIDs(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	f.pushIDs = []string{"alert-42"}

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	ids, err := c.PushAlert(context.Background(), sampleAlert())
	if err != nil {
		t.Fatalf("PushAlert: %v", err)
	}
	if len(ids) != 1 || ids[0] != "alert-42" {
		t.Errorf("ids=%v, want [alert-42]", ids)
	}
	if !strings.HasPrefix(f.lastAuthHeader, "Bearer fake-jwt") {
		t.Errorf("Authorization header = %q, want Bearer fake-jwt prefix", f.lastAuthHeader)
	}
	if !strings.Contains(f.lastAlertBody, `"arenet/waf-sqli"`) {
		t.Errorf("alert body missing scenario: %s", f.lastAlertBody)
	}
	if !strings.Contains(f.lastAlertBody, `"arenet"`) {
		t.Errorf("alert body missing origin=arenet: %s", f.lastAlertBody)
	}
}

func TestWatcherClient_PushAlert_400_PermanentError(t *testing.T) {
	// LAPI rejecting the alert SHAPE (not auth) should
	// surface as ErrLoginFailed-class (don't retry — fixing
	// the shape needs a code change). The writer goroutine
	// in P.2 treats this as a permanent drop.
	f := newFakeLAPI()
	defer f.close()
	f.pushResponses = []int{http.StatusBadRequest}

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	_, err := c.PushAlert(context.Background(), sampleAlert())
	if !errors.Is(err, ErrLoginFailed) {
		t.Errorf("err=%v, want ErrLoginFailed (permanent class)", err)
	}
}

func TestWatcherClient_PushAlert_401_ClearsToken_Retryable(t *testing.T) {
	// JWT expired race between EnsureJWT and the HTTP round-
	// trip. Push surfaces as ErrLAPIUnavailable (retryable);
	// the cached token is cleared so the next PushAlert
	// re-logs in.
	f := newFakeLAPI()
	defer f.close()
	f.pushResponses = []int{http.StatusUnauthorized}

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	_, err := c.PushAlert(context.Background(), sampleAlert())
	if !errors.Is(err, ErrLAPIUnavailable) {
		t.Fatalf("err=%v, want ErrLAPIUnavailable (retryable)", err)
	}
	// Token cleared → next EnsureJWT re-logs in.
	startLogins := f.loginCalls.Load()
	_, _ = c.EnsureJWT(context.Background())
	if f.loginCalls.Load() != startLogins+1 {
		t.Errorf("expected re-login after 401-on-push: logins delta=%d, want 1",
			f.loginCalls.Load()-startLogins)
	}
}

func TestWatcherClient_PushAlert_503_Retryable(t *testing.T) {
	f := newFakeLAPI()
	defer f.close()
	f.pushResponses = []int{http.StatusServiceUnavailable}

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	_, err := c.PushAlert(context.Background(), sampleAlert())
	if !errors.Is(err, ErrLAPIUnavailable) {
		t.Errorf("err=%v, want ErrLAPIUnavailable", err)
	}
}

func TestWatcherClient_PushAlert_IntegerIDsResponse(t *testing.T) {
	// Some LAPI builds return integer IDs rather than string.
	// The client should handle both.
	f := newFakeLAPI()
	defer f.close()
	// Override handlePush to return integer-shaped IDs.
	f.server.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/watchers/login", f.handleLogin)
	mux.HandleFunc("/v1/alerts", func(w http.ResponseWriter, r *http.Request) {
		f.pushCalls.Add(1)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode([]int64{42, 43})
	})
	f.server = httptest.NewServer(mux)

	c, _ := NewWatcherClient(f.cfg("arenet", "secret"))
	ids, err := c.PushAlert(context.Background(), sampleAlert())
	if err != nil {
		t.Fatalf("PushAlert: %v", err)
	}
	if len(ids) != 2 || ids[0] != "42" || ids[1] != "43" {
		t.Errorf("ids=%v, want [42 43]", ids)
	}
}

// --- AC #15 boot-degraded ------------------------------------------------

// TestWatcherClient_ErrCredentialsRequired_SentinelCheckable pins
// the AC #15 contract: the boot path (cmd/arenet/main.go) checks
// errors.Is(err, ErrCredentialsRequired) and skips trigger-engine
// wiring on the sentinel. Sentinel must be a distinct error.
func TestWatcherClient_ErrCredentialsRequired_SentinelCheckable(t *testing.T) {
	_, err := NewWatcherClient(WatcherConfig{})
	if !errors.Is(err, ErrCredentialsRequired) {
		t.Fatalf("err=%v, want ErrCredentialsRequired sentinel", err)
	}
}
