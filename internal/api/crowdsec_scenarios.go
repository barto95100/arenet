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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/barto95100/arenet/internal/storage"
)

// Step CS.2.C — Scenarios tab via LAPI /v1/alerts (JWT auth).
//
// GET /api/v1/security/crowdsec/scenarios
//
// Why /v1/alerts and not /v1/metrics:
//   - Day-7 empirical finding: CrowdSec 1.7.8 doesn't expose
//     cs_bucket_pour_* (the metrics the original brief assumed).
//     The metrics that DO exist (cs_node_hits_total etc.) only
//     fire if CrowdSec acquires logs Arenet matches — a separate
//     wiring step the operator hasn't done.
//   - /v1/alerts is the JSON-native, prereq-free path. Returns
//     all alerts (scenarios that fired) with full context.
//
// Why JWT and not bouncer API key:
//   - Empirical: `curl -H "X-Api-Key: ..." /v1/alerts` returns
//     401 "cookie token is empty". /v1/alerts lives in the LAPI
//     MachineRoutes group, JWT-only.
//   - The JWT is obtained via POST /v1/watchers/login with
//     {machine_id, password}.
//
// Why reuse Security Automation (Feature A) credentials:
//   - The auto-writer already requires a watcher (cscli machines
//     add arenet-writer) → operator-configured machine_id +
//     password persisted in BoltDB.
//   - CrowdSec auth doesn't distinguish read-machine vs write-
//     machine — one watcher login grants both. Reusing avoids
//     making the operator register a second machine.
//   - Coupling lifecycle made explicit in the 412 response
//     message + the Scenarios tab's "Configure Security
//     Automation" CTA.
//
// JWT cache strategy:
//   - In-memory cache (token, expiresAt) per Handler instance.
//   - golang.org/x/sync/singleflight dedupes concurrent logins:
//     5 simultaneous Scenarios polls during JWT expiry → 1
//     login round-trip, 4 wait + reuse.
//   - Auto-retry once on 401 with fresh login. Second 401 →
//     surface as 502 "machine credentials rejected" (no loop).
//   - Lazy invalidate on first 401 — no reactive coupling to
//     /settings/automation/credentials swap signal. Operator
//     rotates creds → next Scenarios poll fails, retries with
//     fresh login, succeeds with new creds. ~1 stale response
//     budget per rotation; acceptable.

// crowdSecScenariosWindow is the look-back used for the
// /v1/alerts call. Matches the brief's 24h spec. Hardcoded for
// now; if operators want longer windows later we can promote
// it to a query param.
//
// IMPORTANT — empirical Day-7 finding (HF on 0ffc3b6): LAPI
// v1.7.8's /v1/alerts handler rejects an absolute RFC3339
// timestamp on `?since=` with HTTP 500 in ~60µs (parser-side
// rejection, before the SQL query). LAPI expects a Go
// duration string ("24h", "1h30m", "7d") on this endpoint —
// confirmed by curl in both shapes against AreNET-test:
//
//   ?since=2026-06-08T15:48:07Z → 500 (rejected by parser)
//   ?since=24h                  → 200 + JSON array of alerts
//
// Source verification (CLAUDE.md §Empirical verification):
// crowdsec@v1.6.3/pkg/database/utils.go:72-95 — LAPI's
// custom ParseDuration first handles a `Nd` suffix (days),
// then delegates to Go stdlib time.ParseDuration. So any
// shape Go accepts ("24h", "24h0m0s", "1h30m45s") works on
// the wire. time.Duration.String() emits "24h0m0s" for
// 24*time.Hour — that's accepted by Go ParseDuration and
// therefore by LAPI. The "24h" form is just cosmetically
// cleaner when an operator types it by hand; both round-
// trip identically through the LAPI parser.
const crowdSecScenariosWindow = 24 * time.Hour

// crowdSecScenariosSinceParam returns the value to send on
// /v1/alerts?since=. See the const above for why this is a
// duration string and not a timestamp.
func crowdSecScenariosSinceParam() string {
	return crowdSecScenariosWindow.String()
}

// crowdSecJWTSafetyMargin is the slack applied to LAPI's
// returned `expire` timestamp so we re-login slightly BEFORE
// the JWT actually expires. Avoids a thundering herd of
// 401-then-retry on the natural expiry boundary.
const crowdSecJWTSafetyMargin = 30 * time.Second

// crowdSecJWTManager owns the cached JWT for the alerts proxy.
// Single-instance per Handler. Goroutine-safe via mu + the
// singleflight group.
//
// The cache key is the (lapiURL, machineID) tuple, hashed into
// a string. If the operator changes the auto-writer's URL or
// machine_id, the cache is naturally invalidated (the next
// lookup misses and forces a fresh login). The password field
// participates only at login time, never as a key — a password
// rotation that keeps the same machine_id will produce a 401
// on the cached JWT, the lazy-invalidate path then logs in
// with the new password.
type crowdSecJWTManager struct {
	mu        sync.RWMutex
	sf        singleflight.Group
	cacheKey  string
	token     string
	expiresAt time.Time
}

func newCrowdSecJWTManager() *crowdSecJWTManager {
	return &crowdSecJWTManager{}
}

// invalidate clears the cached JWT regardless of expiry. Used
// when a 401 comes back on a request that used a previously-
// valid JWT — the operator may have rotated credentials, or
// LAPI restarted with a new signing key.
func (m *crowdSecJWTManager) invalidate() {
	m.mu.Lock()
	m.token = ""
	m.expiresAt = time.Time{}
	m.mu.Unlock()
}

// getOrLogin returns a valid JWT for (lapiURL, machineID,
// password). If the cache holds a fresh token for the same
// (lapiURL, machineID), it's returned without a network call.
// Otherwise a singleflight-dedup'd POST /v1/watchers/login
// fetches a fresh one.
//
// The login network call is bounded by `timeout`. The caller
// should match this against the configured automation
// LAPIURL's timeout (we reuse the CrowdSecConfig.TimeoutSeconds
// budget — same wire, same per-request cap).
func (m *crowdSecJWTManager) getOrLogin(ctx context.Context, lapiURL, machineID, password string, timeout time.Duration) (string, error) {
	key := lapiURL + "\x00" + machineID

	m.mu.RLock()
	if m.cacheKey == key && m.token != "" && time.Now().Before(m.expiresAt) {
		t := m.token
		m.mu.RUnlock()
		return t, nil
	}
	m.mu.RUnlock()

	// singleflight ensures only one login fires for a given
	// key across N concurrent callers. Other callers receive
	// the same token without dialing LAPI.
	v, err, _ := m.sf.Do(key, func() (interface{}, error) {
		// Recheck after acquiring the singleflight slot — a
		// concurrent peer may have populated the cache.
		m.mu.RLock()
		if m.cacheKey == key && m.token != "" && time.Now().Before(m.expiresAt) {
			t := m.token
			m.mu.RUnlock()
			return t, nil
		}
		m.mu.RUnlock()

		tok, exp, lerr := loginToLAPI(ctx, lapiURL, machineID, password, timeout)
		if lerr != nil {
			return "", lerr
		}
		m.mu.Lock()
		m.cacheKey = key
		m.token = tok
		m.expiresAt = exp.Add(-crowdSecJWTSafetyMargin)
		m.mu.Unlock()
		return tok, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// loginToLAPI POSTs to /v1/watchers/login and returns the JWT
// + its expiry. Errors are classified the same way as the CS.1
// Test Connection probe (timeout / refused / DNS / TLS). A 401
// or 403 here means the machine credentials are invalid —
// distinct error message so the handler can produce a 502 with
// the right wording.
func loginToLAPI(ctx context.Context, lapiURL, machineID, password string, timeout time.Duration) (string, time.Time, error) {
	body, _ := json.Marshal(map[string]string{
		"machine_id": machineID,
		"password":   password,
	})

	loginCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	loginURL := strings.TrimRight(lapiURL, "/") + "/v1/watchers/login"
	req, _ := http.NewRequestWithContext(loginCtx, http.MethodPost, loginURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "arenet/crowdsec-scenarios")

	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		return "", time.Time{}, fmt.Errorf("lapi login transport: %w", doErr)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK:
		// happy path
	case http.StatusUnauthorized, http.StatusForbidden:
		return "", time.Time{}, errLAPIAuthRejected
	default:
		return "", time.Time{}, fmt.Errorf("lapi login: unexpected status %d", resp.StatusCode)
	}

	var out struct {
		Code   int64  `json:"code"`
		Expire string `json:"expire"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("lapi login: decode response: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("lapi login: empty token in response")
	}

	// LAPI's `expire` is RFC3339 (with or without nano). Fall
	// back to a 1h assumption if unparseable — better stale-
	// cache eviction than failing every request on a format
	// edge case.
	exp := time.Now().Add(1 * time.Hour)
	if out.Expire != "" {
		if t, err := time.Parse(time.RFC3339Nano, out.Expire); err == nil {
			exp = t
		} else if t, err := time.Parse(time.RFC3339, out.Expire); err == nil {
			exp = t
		}
	}
	return out.Token, exp, nil
}

// errLAPIAuthRejected is the sentinel for "machine creds
// rejected". The handler classifies these as 502 (LAPI-side
// failure) with a wording that points at Settings → Security
// Automation rather than at the bouncer config.
var errLAPIAuthRejected = errors.New("lapi rejected machine credentials")

// scenarioAggregate is the per-scenario wire shape returned
// by GET /api/v1/security/crowdsec/scenarios.
type scenarioAggregate struct {
	// Name is the scenario identifier (e.g.
	// "crowdsecurity/http-cve" or "manual"). Full form,
	// not short — the UI can shorten if it wants.
	Name string `json:"name"`
	// Alerts24h is the count of alerts of this scenario in
	// the 24h look-back window.
	Alerts24h int `json:"alerts24h"`
	// LastSeen is the most-recent alert's StartAt (or
	// CreatedAt fallback) over the window, RFC3339 UTC.
	LastSeen string `json:"lastSeen,omitempty"`
	// SampleScope + SampleValue describe ONE alert's source —
	// picked from the most-recent alert in the group. The UI
	// uses these as a hint ("the most recent alert from this
	// scenario was triggered against IP X"); they're NOT
	// canonical (other alerts in the same group can have
	// different scopes / values).
	SampleScope string `json:"sampleScope,omitempty"`
	SampleValue string `json:"sampleValue,omitempty"`
}

type scenariosResponse struct {
	Scenarios []scenarioAggregate `json:"scenarios"`
	Meta      scenariosMeta       `json:"meta"`
}

type scenariosMeta struct {
	// TotalAlerts is the raw count of LAPI alerts the
	// handler aggregated (sum of all Alerts24h values).
	TotalAlerts int `json:"totalAlerts"`
	// WindowHours echoes the look-back the handler applied
	// (24 today, may become a query param later).
	WindowHours int `json:"windowHours"`
}

// listCrowdSecScenarios serves GET /api/v1/security/crowdsec/scenarios.
//
// Status codes:
//   200 — happy path (empty scenarios list is OK; meta.totalAlerts=0)
//   412 — Security Automation not configured (412 Precondition
//         Failed signals "you need to do X before this works")
//   502 — LAPI unreachable OR machine creds rejected after retry
//   500 — storage read failed
func (h *Handler) listCrowdSecScenarios(w http.ResponseWriter, r *http.Request) {
	creds, perr := h.store.GetWatcherCredentials(r.Context())
	if perr != nil && !errors.Is(perr, storage.ErrNotFound) {
		h.logger.Error("get watcher credentials (scenarios)", "err", perr)
		writeError(w, http.StatusInternalServerError, "failed to load automation credentials")
		return
	}
	if errors.Is(perr, storage.ErrNotFound) || !storage.WatcherCredentialsConfigured(creds) {
		writeError(w, http.StatusPreconditionFailed,
			"security automation not configured — set machine credentials in Settings → Security Automation to enable the Scenarios tab")
		return
	}

	// Time budget: reuse the bouncer's configured timeout if
	// present; else 5s. The two configs typically share the
	// same LAPI host, so the timeout is naturally compatible.
	timeoutSec := 5
	if cs, err := h.store.GetCrowdSecConfig(r.Context()); err == nil && cs.TimeoutSeconds > 0 {
		timeoutSec = cs.TimeoutSeconds
	}
	timeout := time.Duration(timeoutSec) * time.Second

	scenarios, fetchErr := h.fetchScenariosFromLAPI(r.Context(), creds, timeout)
	if fetchErr != nil {
		// fetchScenariosFromLAPI returns either errLAPIAuth-
		// Rejected (after retry) or a wrapped transport error
		// from the classifier. Map both to 502 with
		// operator-friendly wording.
		if errors.Is(fetchErr, errLAPIAuthRejected) {
			writeError(w, http.StatusBadGateway,
				"machine credentials rejected by LAPI — re-verify Settings → Security Automation")
			return
		}
		writeError(w, http.StatusBadGateway, classifyProbeError(fetchErr, creds.Password))
		return
	}

	total := 0
	for _, s := range scenarios {
		total += s.Alerts24h
	}
	writeJSON(w, http.StatusOK, scenariosResponse{
		Scenarios: scenarios,
		Meta: scenariosMeta{
			TotalAlerts: total,
			WindowHours: int(crowdSecScenariosWindow / time.Hour),
		},
	})
}

// fetchScenariosFromLAPI performs the login + alerts fetch +
// aggregation. Returns the aggregated slice ordered by
// Alerts24h desc, ties broken by Name asc (deterministic
// across reruns).
//
// Retry contract: a 401 on the alerts fetch invalidates the
// cached JWT, logs in once more, retries the alerts fetch.
// A second 401 surfaces as errLAPIAuthRejected (no loop).
func (h *Handler) fetchScenariosFromLAPI(ctx context.Context, creds storage.WatcherCredentials, timeout time.Duration) ([]scenarioAggregate, error) {
	// First attempt — use the cached JWT (or login if cold).
	alerts, err := h.alertsWithJWT(ctx, creds, timeout, false)
	if err != nil {
		// 401 on a cached JWT → invalidate + retry once.
		if errors.Is(err, errLAPIAuthRejected) {
			alerts, err = h.alertsWithJWT(ctx, creds, timeout, true)
		}
		if err != nil {
			return nil, err
		}
	}
	return aggregateAlertsByScenario(alerts), nil
}

// alertsWithJWT is a single attempt at the login+alerts pair.
// `forceLogin=true` means invalidate the cache before login —
// used on the retry path.
func (h *Handler) alertsWithJWT(ctx context.Context, creds storage.WatcherCredentials, timeout time.Duration, forceLogin bool) ([]rawAlert, error) {
	if forceLogin {
		h.crowdsecJWT.invalidate()
	}
	jwt, err := h.crowdsecJWT.getOrLogin(ctx, creds.LAPIURL, creds.MachineID, creds.Password, timeout)
	if err != nil {
		return nil, err
	}

	alertsURL := strings.TrimRight(creds.LAPIURL, "/") + "/v1/alerts?" + url.Values{
		"since": {crowdSecScenariosSinceParam()},
		"limit": {"100"},
	}.Encode()

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, _ := http.NewRequestWithContext(fetchCtx, http.MethodGet, alertsURL, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("User-Agent", "arenet/crowdsec-scenarios")

	resp, doErr := http.DefaultClient.Do(req)
	if doErr != nil {
		return nil, doErr
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		// happy paths
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, errLAPIAuthRejected
	default:
		return nil, fmt.Errorf("lapi /v1/alerts: unexpected status %d", resp.StatusCode)
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if readErr != nil {
		return nil, fmt.Errorf("lapi /v1/alerts: read body: %w", readErr)
	}
	if len(body) == 0 || string(body) == "null" {
		return nil, nil
	}
	var alerts []rawAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("lapi /v1/alerts: decode: %w", err)
	}
	return alerts, nil
}

// rawAlert is the subset of models.Alert the aggregator
// consumes. Fields kept as pointers per the swagger spec's
// "Required: true" markers — defensive nil-checks below.
type rawAlert struct {
	ID        int64   `json:"id,omitempty"`
	Scenario  *string `json:"scenario"`
	Message   *string `json:"message"`
	StartAt   *string `json:"start_at"`
	StopAt    *string `json:"stop_at"`
	CreatedAt string  `json:"created_at,omitempty"`
	Source    *struct {
		Scope *string `json:"scope"`
		Value *string `json:"value"`
		IP    string  `json:"ip,omitempty"`
	} `json:"source"`
	EventsCount *int32 `json:"events_count"`
}

// aggregateAlertsByScenario groups alerts by scenario name,
// computes counts + most-recent timestamp + sample source.
// Ordered by Alerts24h desc, ties broken by Name asc.
func aggregateAlertsByScenario(alerts []rawAlert) []scenarioAggregate {
	type acc struct {
		count    int
		lastTime time.Time
		scope    string
		value    string
	}
	bucket := make(map[string]*acc, 16)
	for _, a := range alerts {
		name := derefPtr(a.Scenario)
		if name == "" {
			name = "(unknown)"
		}
		b, ok := bucket[name]
		if !ok {
			b = &acc{}
			bucket[name] = b
		}
		b.count++

		// Pick the timestamp: StartAt preferred (when the
		// alert was triggered), CreatedAt fallback. Parse both
		// best-effort.
		ts := parseLAPITime(derefPtr(a.StartAt))
		if ts.IsZero() {
			ts = parseLAPITime(a.CreatedAt)
		}
		if ts.After(b.lastTime) {
			b.lastTime = ts
			if a.Source != nil {
				b.scope = derefPtr(a.Source.Scope)
				b.value = derefPtr(a.Source.Value)
				if b.value == "" {
					b.value = a.Source.IP
				}
			}
		}
	}
	out := make([]scenarioAggregate, 0, len(bucket))
	for name, b := range bucket {
		row := scenarioAggregate{
			Name:        name,
			Alerts24h:   b.count,
			SampleScope: b.scope,
			SampleValue: b.value,
		}
		if !b.lastTime.IsZero() {
			row.LastSeen = b.lastTime.UTC().Format(timestampFormat)
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Alerts24h != out[j].Alerts24h {
			return out[i].Alerts24h > out[j].Alerts24h
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// derefPtr returns the pointed-to string or "" when the
// pointer is nil. Matches the deref helper in crowdsec_
// decisions.go but kept package-private to that file; copied
// here so the two files don't develop a coupling for a
// 3-line helper.
func derefPtr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// parseLAPITime parses LAPI's RFC3339 (with or without nano)
// timestamp string. Returns zero time on parse failure (callers
// fall back to the alternate field).
func parseLAPITime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
