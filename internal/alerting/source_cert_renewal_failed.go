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
	"fmt"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// cert_renewal_failed Source.
//
// Counts cert_event rows of type "cert_failed" over a sliding
// window ending at "now". Returns the count as a
// SourceValue.Float so a ThresholdEvaluator can compare it
// against a per-rule limit (operator typically configures
// "> 0" — any failure in the window fires).
//
// Sibling of waf_event_rate (the only event-counter source
// before this one). The cert_expiry source covers the
// COUNTDOWN side (days until NotAfter) ; this source covers
// the RENEWAL FAILURE side (a certmagic cert_failed event
// has been ingested into cert_event recently). The two
// together close the ops awareness gap : the operator either
// sees a fresh failure within minutes (this source) OR a
// quiet 30-day-stuck-renewal as the expiry countdown crosses
// the threshold (cert_expiry).
//
// Default window of 24h matches the Let's Encrypt failed-
// renewal retry cadence — certmagic retries an Order failure
// with exponential backoff but within 24h a stuck domain
// has fired several cert_failed events. Operators wiring this
// source typically pair it with a 24h cooldown on the rule
// so the same outage doesn't page them every polling tick.

// CertRenewalFailedParams is the Source.Read params shape.
type CertRenewalFailedParams struct {
	// Domain narrows the count to one domain. Empty =
	// count across all domains (the default — operators
	// usually want a single "any cert is failing" alert,
	// not one rule per domain).
	Domain string `json:"domain,omitempty"`
	// WindowSecs is the lookback window in seconds. Range
	// [60, 604800]. Defaults to 86400 (24h) when zero —
	// matches the Let's Encrypt retry cadence rationale
	// in the file-level comment.
	WindowSecs int `json:"windowSecs"`
}

const (
	certRenewalFailedDefaultWindowSecs = 86400  // 24h
	certRenewalFailedMinWindowSecs     = 60     // 1m
	certRenewalFailedMaxWindowSecs     = 604800 // 7d
)

// CertEventCounter is the seam the source reads through.
// *observability.Store satisfies it via CountCertEvents.
// Declared on the consumer side so the alerting package
// doesn't take a structural dep on the store's broader
// surface — mirrors WafEventReader's local-interface
// pattern.
type CertEventCounter interface {
	CountCertEvents(ctx context.Context, filter observability.CertEventFilter) (int64, error)
}

// CertRenewalFailedSource counts cert_failed rows.
type CertRenewalFailedSource struct {
	counter CertEventCounter
	now     func() time.Time // injectable for tests
}

// NewCertRenewalFailedSource constructs the source. counter
// may be nil — Read returns an error so the watcher records
// "observability disabled" rather than panicking. Same AC
// #13 degraded-mode contract as the other sources.
func NewCertRenewalFailedSource(counter CertEventCounter) *CertRenewalFailedSource {
	return &CertRenewalFailedSource{
		counter: counter,
		now:     time.Now,
	}
}

// Name implements Source.
func (s *CertRenewalFailedSource) Name() string { return "cert_renewal_failed" }

// ValidateParams implements Source.
func (s *CertRenewalFailedSource) ValidateParams(raw json.RawMessage) error {
	var p CertRenewalFailedParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("cert_renewal_failed: params not valid JSON: %w", err)
	}
	w := p.WindowSecs
	if w == 0 {
		w = certRenewalFailedDefaultWindowSecs
	}
	if w < certRenewalFailedMinWindowSecs || w > certRenewalFailedMaxWindowSecs {
		return fmt.Errorf("cert_renewal_failed: windowSecs %d out of range [%d, %d]",
			p.WindowSecs, certRenewalFailedMinWindowSecs, certRenewalFailedMaxWindowSecs)
	}
	return nil
}

// Read implements Source. Returns the count of cert_failed
// rows in the window as a Float. The Type filter pins us
// to "cert_failed" specifically — cert_obtained and
// cert_ocsp_revoked are excluded (they're not renewal
// failures and the operator doesn't want a paged-at-3am
// alert on a successful renewal).
func (s *CertRenewalFailedSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.counter == nil {
		return SourceValue{}, errors.New("cert_renewal_failed: observability counter not wired (boot-degraded)")
	}

	var p CertRenewalFailedParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return SourceValue{}, fmt.Errorf("cert_renewal_failed: params decode: %w", err)
	}
	if p.WindowSecs == 0 {
		p.WindowSecs = certRenewalFailedDefaultWindowSecs
	}

	now := s.now()
	filter := observability.CertEventFilter{
		Domain: p.Domain,
		Type:   "cert_failed",
		From:   now.Add(-time.Duration(p.WindowSecs) * time.Second),
		To:     now,
	}
	count, err := s.counter.CountCertEvents(ctx, filter)
	if err != nil {
		return SourceValue{}, fmt.Errorf("cert_renewal_failed: count: %w", err)
	}

	labels := map[string]string{
		"window_secs": fmt.Sprintf("%d", p.WindowSecs),
	}
	if p.Domain != "" {
		labels["domain"] = p.Domain
	}
	v := FloatValue(float64(count))
	v.Labels = labels
	return v, nil
}
