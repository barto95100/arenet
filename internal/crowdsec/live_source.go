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

package crowdsec

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

// LiveSourceConfig holds the LAPI connection parameters
// surfaced to cmd/arenet/main.go. Tests use newFakeSource
// instead; production wiring builds a LiveSource via NewLiveSource.
type LiveSourceConfig struct {
	// APIURL of the LAPI instance, including trailing slash
	// (the underlying StreamBouncer appends one if missing,
	// but emitting the canonical form upstream keeps logs
	// consistent).
	APIURL string
	// APIKey from `cscli bouncers add arenet` on the
	// CrowdSec host (Step N spec D9.A).
	APIKey string
	// UserAgent identifies Arenet to LAPI in the
	// X-User-Agent header. Useful for the operator's
	// `cscli bouncers list` to distinguish our consumer
	// from the enforcement-side caddy-crowdsec-bouncer.
	UserAgent string
	// TickerInterval is the LAPI poll cadence. Step N spec
	// D7.A locks 60s — kept configurable so a future tuning
	// pass can lower it without re-wiring main.go.
	TickerInterval time.Duration
}

// LiveSource is the production Source backed by
// github.com/crowdsecurity/go-cs-bouncer's StreamBouncer.
// Polls LAPI on TickerInterval and emits a StreamDelta per
// response on the Out channel.
//
// Implements Source so the Consumer in stream.go drives both
// the live wiring (this type) and the test wiring (fakeSource
// in stream_test.go) identically.
type LiveSource struct {
	bouncer *csbouncer.StreamBouncer
	out     chan StreamDelta
	logger  *slog.Logger
	done    chan struct{}
}

// NewLiveSource constructs a LiveSource. Returns an error
// when the StreamBouncer's Init() rejects the config (empty
// LAPI URL, empty key, unreachable LAPI per
// RetryInitialConnect=false, etc.). Production wiring in
// cmd/arenet/main.go logs the error at INFO and continues
// the boot in degraded mode (AC #13: data plane stays alive
// even when the reputation gate cannot be wired).
func NewLiveSource(cfg LiveSourceConfig, logger *slog.Logger) (*LiveSource, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.APIKey == "" {
		return nil, errors.New("crowdsec: NewLiveSource requires an API key")
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "http://127.0.0.1:8080/"
	}
	if cfg.TickerInterval <= 0 {
		cfg.TickerInterval = SleepInterval
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "arenet/1.1"
	}

	b := &csbouncer.StreamBouncer{
		APIKey:                 cfg.APIKey,
		APIUrl:                 cfg.APIURL,
		UserAgent:              cfg.UserAgent,
		TickerInterval:         cfg.TickerInterval.String(),
		TickerIntervalDuration: cfg.TickerInterval,
		// AC #13 fail-open: don't block boot if LAPI is
		// unreachable initially. The StreamBouncer's internal
		// retry loop kicks in (10s linear) so the first
		// successful poll lands a bit later, but boot
		// completes immediately.
		RetryInitialConnect: true,
		// Default scopes: ip + range. Country / AS could be
		// added in a future spec revision; v1.0 mirrors the
		// LAPI default filter (per N spec research §1.1).
		Scopes: []string{"ip", "range"},
	}
	if err := b.Init(); err != nil {
		return nil, err
	}

	return &LiveSource{
		bouncer: b,
		out:     make(chan StreamDelta, 16),
		logger:  logger,
		done:    make(chan struct{}),
	}, nil
}

// Start launches two goroutines: (1) the StreamBouncer's own
// Run, which polls LAPI and pushes raw model responses onto
// its internal Stream channel; (2) our translator, which
// drains that channel and pushes our StreamDelta shape onto
// Out.
//
// The two-goroutine design is forced by go-cs-bouncer's
// public surface (Stream chan *models.DecisionsStreamResponse
// not directly composable with our chan StreamDelta — we
// translate model types to our internal types at the
// boundary, which keeps internal/crowdsec free of imports
// of the bouncer model package outside this file).
//
// Returns immediately after launching. Errors from the
// StreamBouncer's Run propagate via its internal logger; we
// log a debug line at translator-exit so an operator can see
// the goroutine's lifecycle.
func (s *LiveSource) Start(ctx context.Context) error {
	if s.bouncer.Stream == nil {
		s.bouncer.Stream = make(chan *models.DecisionsStreamResponse, 16)
	}
	go func() {
		defer close(s.done)
		// go-cs-bouncer v0.0.15 StreamBouncer.Run(ctx) does
		// not return an error — failures are logged via the
		// bouncer's internal logger. A newer go-cs-bouncer
		// release exposes the error; if we upgrade, restore
		// the err-return + slog wrapping.
		s.bouncer.Run(ctx)
	}()
	go s.translateLoop(ctx)
	return nil
}

// Out implements the Source interface.
func (s *LiveSource) Out() <-chan StreamDelta {
	return s.out
}

// translateLoop drains the StreamBouncer's raw channel and
// translates each model response to our internal StreamDelta
// shape, pushing it onto Out. Exits when ctx is cancelled OR
// the upstream channel closes.
func (s *LiveSource) translateLoop(ctx context.Context) {
	defer close(s.out)
	for {
		select {
		case <-ctx.Done():
			return
		case resp, ok := <-s.bouncer.Stream:
			if !ok {
				return
			}
			delta := translateResponse(resp)
			select {
			case <-ctx.Done():
				return
			case s.out <- delta:
			}
		}
	}
}

// translateResponse maps a CrowdSec model.DecisionsStreamResponse
// into our Step-N internal StreamDelta. Drops decisions
// missing critical fields (UUID, Value, Type) — the upstream
// model uses pointer fields for omitempty, so nil-deref
// guarding is mandatory.
//
// Origin is intentionally dropped here per Step N spec D5.B
// (operator-facing subset only).
func translateResponse(resp *models.DecisionsStreamResponse) StreamDelta {
	delta := StreamDelta{}
	if resp == nil {
		return delta
	}
	now := time.Now().UTC()
	for _, d := range resp.New {
		if d == nil {
			continue
		}
		uuid := d.UUID
		if uuid == "" {
			continue
		}
		// Required fields per the upstream model: Type,
		// Scope, Value. Each is *string; nil means absent.
		if d.Type == nil || d.Scope == nil || d.Value == nil {
			continue
		}
		// duration → seconds. The upstream Duration is a
		// time.Duration as *string (e.g. "1h30m"); parse
		// defensively, fall back to 0 on parse failure.
		var durationSecs int
		var expiresAt time.Time
		if d.Duration != nil {
			if dur, err := time.ParseDuration(*d.Duration); err == nil {
				durationSecs = int(dur.Seconds())
				expiresAt = now.Add(dur)
			}
		}
		// LAPI's "until" field is the authoritative expiry
		// when present (it survives bouncer restart).
		if d.Until != "" {
			if t, err := time.Parse(time.RFC3339, d.Until); err == nil {
				expiresAt = t.UTC()
			}
		}
		scenario := ""
		if d.Scenario != nil {
			scenario = *d.Scenario
		}
		delta.New = append(delta.New, Decision{
			UUID:            uuid,
			Ts:              now,
			Scope:           *d.Scope,
			Value:           *d.Value,
			Type:            *d.Type,
			Scenario:        scenario,
			ExpiresAt:       expiresAt,
			DurationSeconds: durationSecs,
		})
	}
	for _, d := range resp.Deleted {
		if d == nil || d.UUID == "" {
			continue
		}
		delta.Deleted = append(delta.Deleted, d.UUID)
	}
	return delta
}
