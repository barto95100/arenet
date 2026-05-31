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

// Package automation wires the Step P auto-classify loop:
// Arenet observes WAF / throttle / auth-failure events,
// applies operator-configured rules, and writes the matching
// decisions to LAPI via the watcher credential path (the only
// upstream-supported write surface, see spec D1.A rationale).
//
// This file is the write-side LAPI client. Distinct from the
// Step N StreamBouncer in internal/crowdsec (which is GET-only
// against /v1/decisions/stream using bouncer API key auth).
// The watcher client uses POST /v1/watchers/login → JWT →
// POST /v1/alerts (LAPI's data model: a Decision is a child
// of an Alert, the canonical write surface).
package automation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ErrCredentialsRequired is returned by NewWatcherClient when
// the operator has not configured watcher credentials yet.
// Boot path in cmd/arenet/main.go checks for this sentinel and
// skips the trigger engine wiring entirely (AC #15 boot-
// degraded: empty creds → no trigger engine, no-op writer,
// data plane unaffected).
var ErrCredentialsRequired = errors.New("automation: watcher credentials not configured")

// ErrLoginFailed is returned by Login / EnsureJWT when LAPI
// rejects the credentials (401 / 403) or returns an
// unexpected error. Callers should NOT retry on this — the
// operator must fix the credentials in Settings. Wrapped to
// preserve the upstream HTTP status + body for the audit
// trail.
var ErrLoginFailed = errors.New("automation: watcher login failed")

// ErrLAPIUnavailable is returned by Login / EnsureJWT / Push
// when LAPI is unreachable (network error, 5xx response).
// Callers SHOULD retry with backoff (the spec D7.A writer
// goroutine does this).
var ErrLAPIUnavailable = errors.New("automation: LAPI unavailable")

// jwtRefreshSafetyMargin is the time before the JWT's
// expiration at which EnsureJWT refreshes preemptively.
// Default 5 minutes — matches §3.5 spec wording.
const jwtRefreshSafetyMargin = 5 * time.Minute

// httpTimeout caps any single Login or PushAlert call so a
// hung LAPI doesn't pin a goroutine forever. The writer
// goroutine (spec §3.3) does its own per-attempt timeout +
// backoff loop; this is the per-request ceiling.
const httpTimeout = 10 * time.Second

// WatcherConfig holds the read-only parameters NewWatcherClient
// needs. Mirror of crowdsec.LiveSourceConfig shape (N.2).
type WatcherConfig struct {
	// LAPIURL is the CrowdSec LAPI base URL (e.g.
	// "http://127.0.0.1:8080/" — trailing slash optional;
	// the client normalises). Empty → ErrCredentialsRequired.
	LAPIURL string
	// MachineID is the cscli-issued watcher identifier.
	// Empty → ErrCredentialsRequired.
	MachineID string
	// Password is the watcher secret. Empty →
	// ErrCredentialsRequired.
	Password string
	// UserAgent identifies Arenet to LAPI. Helpful for the
	// operator's `cscli machines list` to distinguish the
	// Arenet writer from other clients.
	UserAgent string
	// HTTPClient is optional — pass nil to use the package's
	// default (http.Client with httpTimeout). Tests inject a
	// recording client; production wiring leaves it nil.
	HTTPClient *http.Client
}

// WatcherClient is the write-side LAPI client. Thread-safe:
// the JWT cache + the underlying http.Client both tolerate
// concurrent callers. The intended caller pattern in P.2 is
// a single writer goroutine, but the type does not assume
// single-threading.
type WatcherClient struct {
	cfg    WatcherConfig
	client *http.Client

	mu          sync.Mutex // protects token + expiresAt
	token       string
	expiresAt   time.Time
	loginFailed bool // sticky: once login fails the writer pauses
}

// NewWatcherClient validates the config + returns a client.
// Empty fields return ErrCredentialsRequired without doing any
// network I/O — the boot path uses this as the AC #15 signal
// to skip the trigger engine entirely.
//
// NB: NewWatcherClient does NOT log in. The first Login call
// (or the first PushAlert, which calls EnsureJWT internally)
// hits LAPI. Constructing the client is purely a config-shape
// check; the live LAPI handshake is deferred so a transient
// LAPI outage at boot doesn't fail Arenet startup.
func NewWatcherClient(cfg WatcherConfig) (*WatcherClient, error) {
	if cfg.LAPIURL == "" || cfg.MachineID == "" || cfg.Password == "" {
		return nil, ErrCredentialsRequired
	}
	// Normalise URL: trailing slash optional on input, removed
	// internally so we control the path joining.
	cfg.LAPIURL = strings.TrimRight(cfg.LAPIURL, "/")
	if cfg.UserAgent == "" {
		cfg.UserAgent = "arenet/1.3 (watcher-writer)"
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: httpTimeout}
	}
	return &WatcherClient{
		cfg:    cfg,
		client: httpClient,
	}, nil
}

// Login performs a fresh POST /v1/watchers/login. On success,
// caches the JWT + expiry. On 401/403, returns ErrLoginFailed
// (the operator must fix credentials). On network / 5xx,
// returns ErrLAPIUnavailable (caller retries with backoff).
//
// Concurrent callers serialise on c.mu — only one login round-
// trip happens at a time. The cached token is shared.
func (c *WatcherClient) Login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginLocked(ctx)
}

func (c *WatcherClient) loginLocked(ctx context.Context) error {
	body, err := json.Marshal(map[string]any{
		"machine_id": c.cfg.MachineID,
		"password":   c.cfg.Password,
	})
	if err != nil {
		// Marshal of a string-map shouldn't fail; treat as
		// programming error if it does.
		return fmt.Errorf("automation: marshal login body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.LAPIURL+"/v1/watchers/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("automation: build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: login round-trip: %v", ErrLAPIUnavailable, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusOK:
		// Continue to parse.
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		c.loginFailed = true
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: status=%d body=%s", ErrLoginFailed,
			resp.StatusCode, string(bodyBytes))
	default:
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: status=%d body=%s", ErrLAPIUnavailable,
			resp.StatusCode, string(bodyBytes))
	}

	// On 200, parse {code, token, expire}. The `expire` field
	// is an RFC3339 timestamp per the WatcherAuthResponse
	// model.
	var out struct {
		Code   int64  `json:"code"`
		Token  string `json:"token"`
		Expire string `json:"expire"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("automation: decode login response: %w", err)
	}
	if out.Token == "" {
		return fmt.Errorf("automation: login 200 but empty token")
	}
	expiresAt, err := time.Parse(time.RFC3339, out.Expire)
	if err != nil {
		// LAPI is supposed to emit RFC3339; if it doesn't,
		// default to 1h-from-now and re-login at the safety
		// margin. Conservative posture against upstream
		// format drift.
		expiresAt = time.Now().Add(1 * time.Hour)
	}
	c.token = out.Token
	c.expiresAt = expiresAt
	c.loginFailed = false
	return nil
}

// EnsureJWT returns a valid token, refreshing if within the
// safety margin of expiry. Thread-safe. Callers (the writer
// goroutine in P.2) call this once per push; the LRU caches
// the result for the duration of the JWT.
//
// On refresh failure, the existing token (if any) is left in
// place but the loginFailed sticky flag is set so the caller
// can pause emissions. Eventually consistent: the next refresh
// attempt (driven by EnsureJWT calls at the next push) will
// retry. Operator-visible via the "automation_login_failures_
// per_hour" metric the writer goroutine reports.
func (c *WatcherClient) EnsureJWT(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// First call: no token yet → login.
	if c.token == "" {
		if err := c.loginLocked(ctx); err != nil {
			return "", err
		}
		return c.token, nil
	}

	// Within safety margin of expiry → refresh.
	if time.Until(c.expiresAt) <= jwtRefreshSafetyMargin {
		if err := c.loginLocked(ctx); err != nil {
			// Keep the (about-to-expire) token; caller can
			// still try one push with it. The next call
			// re-enters this branch and re-tries the login.
			return "", err
		}
	}
	return c.token, nil
}

// LoginFailed reports whether the most recent login attempt
// returned ErrLoginFailed (sticky until a subsequent login
// succeeds). The writer goroutine reads this to decide
// whether to pause emissions vs continue with retries.
func (c *WatcherClient) LoginFailed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginFailed
}

// AlertSource is the source.* subset of the CrowdSec Alert
// model we populate when pushing. Mirrors
// crowdsec@v1.6.3/pkg/models/source.go required-field
// pattern: Scope + Value are pointers in the upstream model
// to indicate "required, must be present"; we mirror that as
// non-pointer strings here and let the marshaller emit
// non-empty values.
type AlertSource struct {
	// Scope is one of "Ip" / "Range" / "Country" / "AS".
	// v1.3 (P spec D3.1.A) emits "Ip" only.
	Scope string `json:"scope"`
	// Value is the IP / CIDR / country code / AS number.
	Value string `json:"value"`
	// IP is the bare IP form (LAPI uses it for geo
	// enrichment). For Scope="Ip" we set IP == Value.
	IP string `json:"ip,omitempty"`
}

// AlertDecision is the decision sub-object inside an alert.
// Mirrors crowdsec@v1.6.3/pkg/models/decision.go.
type AlertDecision struct {
	// Duration is a Go-formatted duration string (e.g.
	// "4h", "30m"). LAPI parses with time.ParseDuration.
	Duration string `json:"duration"`
	// Origin identifies who created the decision. Step P
	// uses "arenet" — distinct from "cscli" / "crowdsec" /
	// "lists" / "CAPI" per the upstream Origin enum. LAPI
	// does not validate origin strictly (verified via
	// source read at crowdsec@v1.6.3/pkg/apiserver/
	// controllers/v1/alerts.go), so "arenet" is accepted.
	Origin string `json:"origin"`
	// Scenario is the human-readable label visible in
	// `/security/decisions`. Step P D3.3.A uses the
	// "arenet/<category>" prefix convention.
	Scenario string `json:"scenario"`
	// Scope mirrors AlertSource.Scope.
	Scope string `json:"scope"`
	// Type is the decision action — "ban" / "captcha" /
	// "throttle". v1.3 emits "ban" only.
	Type string `json:"type"`
	// Value mirrors AlertSource.Value.
	Value string `json:"value"`
}

// Alert is the wire shape Arenet POSTs to /v1/alerts. The
// upstream model has many required fields beyond what's
// semantically necessary for a single decision push; we
// populate them with sensible non-empty defaults so LAPI's
// validator accepts the alert. Marked clearly which fields
// are operator-meaningful vs which are LAPI-format
// requirements.
type Alert struct {
	// Operator-meaningful:
	Scenario  string          `json:"scenario"`
	Source    AlertSource     `json:"source"`
	Decisions []AlertDecision `json:"decisions"`
	Message   string          `json:"message"`

	// LAPI-format requirements (zero values rejected by the
	// alerts.go validator):
	Capacity        int    `json:"capacity"`         // 0 OK once non-nil
	EventsCount     int    `json:"events_count"`     // count of triggering events
	Leakspeed       string `json:"leakspeed"`        // "0s" for non-bucket triggers
	ScenarioHash    string `json:"scenario_hash"`    // "" but must be present
	ScenarioVersion string `json:"scenario_version"` // "" but must be present
	Simulated       bool   `json:"simulated"`        // false
	StartAt         string `json:"start_at"`         // RFC3339
	StopAt          string `json:"stop_at"`          // RFC3339

	// Empty array fields LAPI's validator expects:
	Events []map[string]any `json:"events"`
}

// PushAlert sends a single alert to LAPI. Returns the LAPI-
// assigned alert ID list (one per alert in the batch — we
// send single-alert batches for now). On 4xx, returns
// ErrLoginFailed wrapped with status + body so the caller
// distinguishes "creds bad" from "alert shape wrong" via the
// status code in the wrapped error.
//
// EnsureJWT runs first; a transient login failure surfaces as
// the same error shape callers see for a 5xx push response
// (ErrLAPIUnavailable). The writer goroutine in P.2 retries
// with exponential backoff on ErrLAPIUnavailable; gives up on
// ErrLoginFailed.
func (c *WatcherClient) PushAlert(ctx context.Context, alert Alert) ([]string, error) {
	token, err := c.EnsureJWT(ctx)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal([]Alert{alert})
	if err != nil {
		return nil, fmt.Errorf("automation: marshal alert: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.LAPIURL+"/v1/alerts", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("automation: build push request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: push round-trip: %v", ErrLAPIUnavailable, err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusCreated:
		// LAPI returns the alert IDs as a JSON array of
		// strings on success.
		var ids []string
		if err := json.Unmarshal(bodyBytes, &ids); err != nil {
			// Some LAPI builds return integer IDs; fall
			// back to a numeric decode + string convert.
			var nums []int64
			if err2 := json.Unmarshal(bodyBytes, &nums); err2 == nil {
				ids = make([]string, len(nums))
				for i, n := range nums {
					ids[i] = fmt.Sprintf("%d", n)
				}
			} else {
				return nil, fmt.Errorf("automation: decode push response: %w (body=%s)", err, string(bodyBytes))
			}
		}
		return ids, nil
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		// JWT may have expired between EnsureJWT and the
		// HTTP round-trip (race). Mark loginFailed so the
		// next EnsureJWT call refreshes; surface as
		// retryable to the writer.
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		return nil, fmt.Errorf("%w: push got %d body=%s", ErrLAPIUnavailable,
			resp.StatusCode, string(bodyBytes))
	default:
		// 4xx other than 401/403 = alert shape problem
		// (LAPI's validator rejected the payload). Surface
		// as ErrLoginFailed-class (don't retry — fixing the
		// shape requires code change). The writer treats
		// this as a permanent drop.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return nil, fmt.Errorf("%w: push got %d body=%s", ErrLoginFailed,
				resp.StatusCode, string(bodyBytes))
		}
		return nil, fmt.Errorf("%w: push got %d body=%s", ErrLAPIUnavailable,
			resp.StatusCode, string(bodyBytes))
	}
}
