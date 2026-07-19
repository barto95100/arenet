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
	"fmt"
	"time"

	"github.com/barto95100/arenet/internal/storage"
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
	return nil
}

// Read implements Source. Returns the count of external certificates
// whose NotAfter is before now+thresholdDays, as a Float.
func (s *CertManualExpiringSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.store == nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: store not wired (boot-degraded)")
	}
	p := CertManualExpiringParams{ThresholdDays: 30}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return SourceValue{}, fmt.Errorf("cert_manual_expiring: params decode: %w", err)
		}
	}
	if p.ThresholdDays <= 0 {
		p.ThresholdDays = 30
	}
	certs, err := s.store.ListExternalCertificates(ctx)
	if err != nil {
		return SourceValue{}, fmt.Errorf("cert_manual_expiring: list: %w", err)
	}
	cutoff := s.now().Add(time.Duration(p.ThresholdDays) * 24 * time.Hour)
	count := 0
	for _, c := range certs {
		if !c.NotAfter.IsZero() && c.NotAfter.Before(cutoff) {
			count++
		}
	}
	return FloatValue(float64(count)), nil
}
