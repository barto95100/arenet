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

package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/barto95100/arenet/internal/storage"
)

// Bounds on the threshold window. They are the ones the rule form
// already advertises on its input (min="1" max="365"); until v2.72
// nothing enforced them, so the attribute was decorative and a rule
// could be stored on a window the engine would not use.
const (
	certManualExpiringDefaultThresholdDays = 30  // 30d
	certManualExpiringMinThresholdDays     = 1   // 1d
	certManualExpiringMaxThresholdDays     = 365 // 1y
)

// CertStore is the seam this source reads through (*storage.Store satisfies it).
type CertStore interface {
	ListExternalCertificates(ctx context.Context) ([]storage.ExternalCertificate, error)
}

// CertManualExpiringParams is the Source.Read params shape.
type CertManualExpiringParams struct {
	ThresholdDays int `json:"thresholdDays"`
}

// CertManualExpiringSource counts externally-uploaded certificates
// whose NotAfter falls within a threshold window. Manual certs are
// not auto-renewed (no ACME issuer behind them), so this is the
// safety net that surfaces a looming expiry to the operator.
type CertManualExpiringSource struct {
	store CertStore
	now   func() time.Time
}

// NewCertManualExpiringSource constructs the source. store may be
// nil — Read returns an error so the watcher records "boot-degraded"
// rather than panicking.
func NewCertManualExpiringSource(store CertStore) *CertManualExpiringSource {
	return &CertManualExpiringSource{store: store, now: time.Now}
}

// Name implements Source.
func (s *CertManualExpiringSource) Name() string { return "cert_manual_expiring" }

// ValidateParams implements Source.
func (s *CertManualExpiringSource) ValidateParams(raw json.RawMessage) error {
	var p CertManualExpiringParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("cert_manual_expiring: params not valid JSON: %w", err)
	}
	// Absent, null and 0 all mean "use the default", exactly as in
	// waf_event_rate and cert_renewal_failed. Anything else has to be
	// a window Read will actually honour: a negative or zero value was
	// accepted here and then silently replaced by 30 at Read time, so
	// the rule alerted on a window the form never showed.
	d := p.ThresholdDays
	if d == 0 {
		d = certManualExpiringDefaultThresholdDays
	}
	if d < certManualExpiringMinThresholdDays || d > certManualExpiringMaxThresholdDays {
		return fmt.Errorf("cert_manual_expiring: thresholdDays %d out of range [%d, %d]",
			p.ThresholdDays, certManualExpiringMinThresholdDays, certManualExpiringMaxThresholdDays)
	}
	return nil
}

// Read implements Source. Returns the count of external certificates
// whose NotAfter is before now+thresholdDays, as a Float.
func (s *CertManualExpiringSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.store == nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: store not wired (boot-degraded)")
	}
	p := CertManualExpiringParams{ThresholdDays: certManualExpiringDefaultThresholdDays}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return SourceValue{}, fmt.Errorf("cert_manual_expiring: params decode: %w", err)
		}
	}
	// Rules stored before the ValidateParams bounds existed may still
	// carry a non-positive window; keep honouring the default for them
	// rather than reading a cutoff in the past.
	if p.ThresholdDays <= 0 {
		p.ThresholdDays = certManualExpiringDefaultThresholdDays
	}
	certs, err := s.store.ListExternalCertificates(ctx)
	if err != nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: list: %w", err)
	}
	now := s.now()
	cutoff := now.Add(time.Duration(p.ThresholdDays) * 24 * time.Hour)
	// The numeric value the ThresholdEvaluator fires on is the count
	// of certs inside the window; the Context payload names each of
	// them so the alert body has actionable detail (spec §7), mirroring
	// source_cert_renewal_failed / source_cert_expiry which populate
	// SourceValue.Context.
	within := make([]map[string]any, 0)
	for _, c := range certs {
		if c.NotAfter.IsZero() || !c.NotAfter.Before(cutoff) {
			continue
		}
		daysLeft := c.NotAfter.Sub(now).Hours() / 24
		within = append(within, map[string]any{
			"id":       c.ID,
			"name":     c.Name,
			"dnsNames": c.DNSNames,
			"notAfter": c.NotAfter.UTC().Format(time.RFC3339),
			"daysLeft": daysLeft,
		})
	}
	v := FloatValue(float64(len(within)))
	v.Context = map[string]any{
		"certs": within,
		"count": len(within),
	}
	return v, nil
}
