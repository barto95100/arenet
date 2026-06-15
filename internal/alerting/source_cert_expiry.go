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

	"github.com/barto95100/arenet/internal/certinfo"
)

// AL.2.a — cert_expiry Source.
//
// Returns days-until-NotAfter for a configured domain, or
// the earliest-expiring cert in the tracker when no
// domain is supplied. Returns SourceValue.Float so a
// ThresholdEvaluator can fire on "< 14 days remaining".
//
// Reader audit (commit body): *certinfo.Tracker already
// exposes Get(domain) (*CertRuntimeInfo, bool) +
// List() []*CertRuntimeInfo. CertRuntimeInfo.NotAfter is
// the authoritative expiry timestamp. No tracker
// modification needed.

// CertExpiryParams is the Source.Read params shape.
type CertExpiryParams struct {
	// Host is the cert domain to inspect. Empty = use the
	// earliest-expiring cert across the tracker (List()
	// is sorted NotAfter ascending; first element wins).
	Host string `json:"host,omitempty"`
}

// CertLister is the seam the source reads through.
// *certinfo.Tracker satisfies it via Get + List.
type CertLister interface {
	Get(domain string) (*certinfo.CertRuntimeInfo, bool)
	List() []*certinfo.CertRuntimeInfo
}

// CertExpirySource emits days-until-expiry as a Float.
type CertExpirySource struct {
	lister CertLister
	now    func() time.Time // injectable for tests
}

// NewCertExpirySource constructs the source. lister may
// be nil — Read returns an error so the watcher records
// the boot-degraded state (mirrors the AC #13 contract).
func NewCertExpirySource(lister CertLister) *CertExpirySource {
	return &CertExpirySource{
		lister: lister,
		now:    time.Now,
	}
}

// Name implements Source.
func (s *CertExpirySource) Name() string { return "cert_expiry" }

// ValidateParams implements Source. CertExpiryParams has
// only the optional Host field — no real shape constraints
// beyond "valid JSON".
func (s *CertExpirySource) ValidateParams(raw json.RawMessage) error {
	var p CertExpiryParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("cert_expiry: params not valid JSON: %w", err)
	}
	return nil
}

// Read implements Source. Returns days-until-NotAfter as
// a Float (can be negative — an expired cert reports a
// negative count). Operators expecting "expired" alerts
// configure threshold "< 0".
func (s *CertExpirySource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.lister == nil {
		return SourceValue{}, errors.New("cert_expiry: cert tracker not wired (boot-degraded)")
	}
	var p CertExpiryParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return SourceValue{}, fmt.Errorf("cert_expiry: params decode: %w", err)
	}

	var info *certinfo.CertRuntimeInfo
	if p.Host != "" {
		got, ok := s.lister.Get(p.Host)
		if !ok {
			return SourceValue{}, fmt.Errorf("cert_expiry: host %q not tracked", p.Host)
		}
		info = got
	} else {
		all := s.lister.List()
		if len(all) == 0 {
			return SourceValue{}, errors.New("cert_expiry: no certs tracked yet")
		}
		// List() is sorted NotAfter ascending (closest-to-
		// expiry first per certinfo/tracker.go:129). The
		// first element is the earliest-expiring cert.
		info = all[0]
	}

	if info.NotAfter.IsZero() {
		return SourceValue{}, fmt.Errorf("cert_expiry: host %q has zero NotAfter (cert not yet observed)", info.Domain)
	}

	until := info.NotAfter.Sub(s.now())
	days := until.Hours() / 24
	v := FloatValue(days)
	v.Labels = map[string]string{
		"host":      info.Domain,
		"not_after": info.NotAfter.UTC().Format(time.RFC3339),
		"issuer":    info.Issuer,
	}
	v.Context = map[string]any{
		"days_remaining": days,
		"hours_remaining": until.Hours(),
		"status":         string(info.Status),
	}
	return v, nil
}
