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

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/barto95100/arenet/internal/throttle"
)

// Rate-limit thresholds and windows for per-IP auth failure tracking.
//
// Spec / decision sources (Step D):
//   - docs/superpowers/specs/2026-05-17-step-d-auth-design.md §1.4
//     "Locked decisions" — foundation policy (Tier 1 + Tier 2 per IP).
//   - docs/superpowers/specs/2026-05-17-step-d-auth-design.md §4.3
//     "POST /api/v1/auth/login" — 429 response shape (Retry-After
//     header + human message "15 minutes" / "1 hour").
//   - docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md
//     Q6 — chosen tier values (5/5min → 15min, 10/1h → 1h).
//   - docs/superpowers/decisions/2026-05-17-step-d-design-decisions-final.md
//     D8 — in-memory storage, trusted-proxies env var, slog WARN
//     on every Tier 2 hit.
//
// The two tiers operate concurrently: each failure increments both
// counters; whichever threshold is hit first triggers the corresponding
// block. The longer block wins when both fire simultaneously.
const (
	Tier1Threshold = 5                // 5 failures
	Tier1Window    = 5 * time.Minute  // within 5 minutes
	Tier1Block     = 15 * time.Minute // → block 15 minutes

	Tier2Threshold = 10        // 10 failures
	Tier2Window    = time.Hour // within 1 hour
	Tier2Block     = time.Hour // → block 1 hour

	// CleanupInterval is how often the cleanup goroutine sweeps the
	// rate limiter's state map for inactive entries. Not in spec —
	// implementation hygiene (D8 in-memory storage).
	CleanupInterval = 30 * time.Minute

	// InactiveAfter is the duration an entry must be inactive (no
	// failures, no active block) before being garbage-collected.
	// Not in spec — implementation hygiene.
	InactiveAfter = 2 * time.Hour
)

// BlockedIP describes a currently rate-limited IP. Exposed for the
// future Step F Security UI (see docs/roadmap.md); not used by Step D
// HTTP handlers directly.
type BlockedIP struct {
	IP           string    `json:"ip"`
	BlockedUntil time.Time `json:"blocked_until"`
	FailureCount int       `json:"failure_count"`
}

// counter holds the per-IP rate-limit state. Access must be
// serialized through RateLimiter.mu.
type counter struct {
	// failures is a sliding window of failure timestamps within the
	// last Tier2Window (longest window). Older entries are pruned on
	// each access. Always sorted ascending (Hit appends, append is
	// monotonic in time).
	failures []time.Time
	// blockedUntil is the wall-clock time at which the current block
	// expires. Zero value = not blocked. Set by Hit when a tier
	// threshold is reached.
	blockedUntil time.Time
	// blockDuration is the original duration assigned when the
	// current block was activated (Tier1Block or Tier2Block).
	// Preserved verbatim so writeRateLimited can produce the exact
	// human message ("15 minutes" or "1 hour") without arithmetic
	// approximation on the remaining time.
	blockDuration time.Duration
	// lastSeen tracks the most recent state-changing operation. The
	// cleanup goroutine uses it to garbage-collect entries inactive
	// for more than InactiveAfter.
	lastSeen time.Time
}

// RateLimiter enforces per-IP authentication failure limits in two
// tiers (Tier 1: 5/5min → 15min block; Tier 2: 10/1h → 1h block).
//
// Storage is in-memory only (decision D8). On server restart all
// counters are cleared; this is acceptable given the typical low
// volume of auth traffic on a homelab admin tool.
//
// RateLimiter is safe for concurrent use.
type RateLimiter struct {
	mu      sync.Mutex
	state   map[string]*counter
	logger  *slog.Logger
	nowFunc func() time.Time // overridable for tests
}

// NewRateLimiter constructs a rate limiter with an injected logger.
// The logger is used to emit the Tier 2 Warn line that operators
// rely on for attack observability (AC-RATE-04). Passing nil panics.
func NewRateLimiter(logger *slog.Logger) *RateLimiter {
	if logger == nil {
		panic("auth.NewRateLimiter: logger is nil")
	}
	return &RateLimiter{
		state:   make(map[string]*counter),
		logger:  logger,
		nowFunc: time.Now,
	}
}

// now returns the current time via the overridable hook (used by tests).
func (rl *RateLimiter) now() time.Time {
	return rl.nowFunc().UTC()
}

// Allow returns (allowed, retryAfter, blockDuration).
//
// allowed: false if the IP is currently blocked.
// retryAfter: duration until the block expires (for the Retry-After header).
// blockDuration: the original tier block duration (Tier1Block=15min or
// Tier2Block=1h). Returned separately to preserve the original tier
// identity for message selection: comparing retryAfter to Tier1Block
// directly is fragile because time advances between the moment of Hit
// and the moment of Allow, making the equality check unreliable.
//
// Empty IP is always allowed (the IP extractor failed; not associable
// to a bucket — see spec §8.5 "empty IP surfaces in audit").
func (rl *RateLimiter) Allow(ip string) (allowed bool, retryAfter, blockDuration time.Duration) {
	if ip == "" {
		return true, 0, 0
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	c, ok := rl.state[ip]
	if !ok {
		return true, 0, 0
	}
	now := rl.now()
	if c.blockedUntil.IsZero() || !now.Before(c.blockedUntil) {
		return true, 0, 0
	}
	return false, c.blockedUntil.Sub(now), c.blockDuration
}

// Hit records an authentication failure for the given IP and may
// trigger a Tier 1 or Tier 2 block. attemptedUsername is included in
// the Tier 2 Warn log; empty string is acceptable.
//
// Empty IP is a no-op (consistent with Allow).
//
// Implementation note: the Tier 2 slog.Warn call is performed AFTER
// releasing the mutex, using a snapshot of the fields captured while
// the lock was held. This avoids holding the mutex during logger
// I/O (negligible for slog.Default but matters for custom handlers
// that may forward to a network endpoint or block on a slow writer).
func (rl *RateLimiter) Hit(ip, attemptedUsername string) {
	if ip == "" {
		return
	}

	// Snapshot fields needed for the optional Tier 2 log + the
	// Step Q throttle event; populated while the mutex is held,
	// emitted/logged AFTER Unlock. Same pattern as the original
	// Tier 2 Warn line, generalised — keeps the auth hot path
	// off the global throttle sink and any custom slog handler
	// I/O (D7.A: emit outside mutex).
	var (
		blockTriggered  bool
		emittedTier     int
		logCount        int
		logBlockedUntil time.Time
		logBlockDur     time.Duration
	)

	rl.mu.Lock()
	now := rl.now()
	c := rl.state[ip]
	if c == nil {
		c = &counter{}
		rl.state[ip] = c
	}

	// Prune timestamps older than the longest window (Tier 2).
	cutoff := now.Add(-Tier2Window)
	keep := c.failures[:0]
	for _, ts := range c.failures {
		if ts.After(cutoff) {
			keep = append(keep, ts)
		}
	}
	c.failures = keep
	c.failures = append(c.failures, now)
	c.lastSeen = now

	// Count failures in each tier window.
	tier1Cutoff := now.Add(-Tier1Window)
	tier1Count := 0
	for _, ts := range c.failures {
		if ts.After(tier1Cutoff) {
			tier1Count++
		}
	}
	tier2Count := len(c.failures) // already pruned to Tier 2 window

	// Determine if a block triggers. Longer block wins if both fire.
	var newBlock time.Duration
	var triggeredTier int
	if tier2Count >= Tier2Threshold {
		newBlock = Tier2Block
		triggeredTier = 2
	} else if tier1Count >= Tier1Threshold {
		newBlock = Tier1Block
		triggeredTier = 1
	}

	if newBlock > 0 {
		candidate := now.Add(newBlock)
		// Extend block only if longer than the current one.
		if candidate.After(c.blockedUntil) {
			c.blockedUntil = candidate
			c.blockDuration = newBlock
		}
		// Step Q D1.A: emit on EVERY block decision (Tier 1
		// OR Tier 2). The sink layer's LRU bounds repeat
		// noise; the bucket counter bumps on every absorbed
		// emit (incl. LRU-suppressed) so the timeline tick
		// reflects attack volume.
		blockTriggered = true
		emittedTier = triggeredTier
		logBlockedUntil = c.blockedUntil
		logBlockDur = c.blockDuration
		if triggeredTier == 2 {
			logCount = tier2Count
		}
	}
	rl.mu.Unlock()

	// Emit OUTSIDE the mutex. Tier 2 keeps its operator-facing
	// Warn line (existing AC-RATE-04); Tier 1 stays silent on
	// slog (high-volume during a credential-stuffing build-up;
	// the dashboard is the right surface for that — D1 §94).
	if blockTriggered {
		if emittedTier == 2 {
			rl.logger.Warn("rate limit tier 2 triggered, IP blocked",
				slog.String("ip", ip),
				slog.String("username_attempted", attemptedUsername),
				slog.Int("failure_count_window", logCount),
				slog.Time("blocked_until", logBlockedUntil),
				slog.String("suggestion", "consider blocking this IP at network level"),
			)
		}
		if sink := throttle.GetGlobalSink(); sink != nil {
			sink.Emit(throttle.Event{
				Ts:                   now,
				Tier:                 emittedTier,
				SrcIP:                ip,
				AttemptedUsername:    attemptedUsername,
				BlockedUntil:         logBlockedUntil,
				BlockDurationSeconds: int(logBlockDur.Round(time.Second) / time.Second),
			})
		}
	}
}

// Reset clears the failure counters and any active block for the
// given IP. Called by the /login and /unlock handlers after a
// successful auth, so a legitimate user who typoed a few times is
// not penalized after they finally succeed.
//
// Empty IP is a no-op.
func (rl *RateLimiter) Reset(ip string) {
	if ip == "" {
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	delete(rl.state, ip)
}

// GetBlockedIPs returns a snapshot of every currently-blocked IP,
// sorted by IP for deterministic output. Used by the future Step F
// Security UI; not exposed via HTTP in Step D.
func (rl *RateLimiter) GetBlockedIPs() []BlockedIP {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	out := make([]BlockedIP, 0)
	for ip, c := range rl.state {
		if c.blockedUntil.IsZero() || !now.Before(c.blockedUntil) {
			continue
		}
		out = append(out, BlockedIP{
			IP:           ip,
			BlockedUntil: c.blockedUntil,
			FailureCount: len(c.failures),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// Start launches the background goroutine that garbage-collects
// entries inactive for more than InactiveAfter. The goroutine exits
// when ctx is cancelled.
//
// Calling Start multiple times spawns multiple goroutines; the caller
// is responsible for invoking it exactly once (typically from
// cmd/arenet at server startup, in Chunk 4).
func (rl *RateLimiter) Start(ctx context.Context) {
	go rl.cleanupLoop(ctx)
}

func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.sweep()
		}
	}
}

// sweep removes entries whose last activity is older than
// InactiveAfter AND whose block has expired. Bounds memory growth.
func (rl *RateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := rl.now()
	cutoff := now.Add(-InactiveAfter)
	for ip, c := range rl.state {
		blockActive := !c.blockedUntil.IsZero() && now.Before(c.blockedUntil)
		if !blockActive && c.lastSeen.Before(cutoff) {
			delete(rl.state, ip)
		}
	}
}

// Middleware returns a chi-compatible HTTP middleware that:
//  1. Rejects requests from blocked IPs with 429 + Retry-After.
//  2. Lets the handler run and observes the response status.
//  3. Increments the failure counter on 401 or 403 responses.
//
// The IP is read from the request context (populated by
// IPExtractMiddleware, Section 8). Empty IPs are not rate-limited.
//
// attemptedUsername is read from context AFTER the handler runs,
// allowing handlers to enrich Tier 2 logs via SetAttemptedUsername.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := ClientIPFromContext(r.Context())
			if allowed, retryAfter, blockDuration := rl.Allow(ip); !allowed {
				writeRateLimited(w, retryAfter, blockDuration)
				return
			}
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			status := ww.Status()
			if status == http.StatusUnauthorized || status == http.StatusForbidden {
				rl.Hit(ip, AttemptedUsernameFromContext(r.Context()))
			}
		})
	}
}

// writeRateLimited sends the 429 response with Retry-After header
// and JSON error body per spec §5.3.
//
// retryAfter is the remaining time until the block expires (used for
// the HTTP header). blockDuration is the original block duration
// (Tier1Block or Tier2Block) used to pick the exact human-readable
// message verbatim from spec §5.3.
func writeRateLimited(w http.ResponseWriter, retryAfter, blockDuration time.Duration) {
	secs := int(retryAfter.Round(time.Second) / time.Second)
	if secs < 1 {
		secs = 1
	}
	var msg string
	switch blockDuration {
	case Tier1Block:
		msg = "too many attempts, retry after 15 minutes"
	case Tier2Block:
		msg = "too many attempts, retry after 1 hour"
	default:
		msg = fmt.Sprintf("too many attempts, retry after %d seconds", secs)
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
