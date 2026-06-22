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
	"strings"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// stubCertCounter is the CertEventCounter test double : records
// the filter it was called with + returns a canned count/err.
type stubCertCounter struct {
	count  int64
	err    error
	called observability.CertEventFilter
	calls  int
}

func (s *stubCertCounter) CountCertEvents(_ context.Context, f observability.CertEventFilter) (int64, error) {
	s.calls++
	s.called = f
	return s.count, s.err
}

func TestCertRenewalFailedSource_NoFailures(t *testing.T) {
	counter := &stubCertCounter{count: 0}
	src := NewCertRenewalFailedSource(counter)
	raw := json.RawMessage(`{"windowSecs":3600}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil || *got.Float != 0 {
		t.Errorf("count = %v; want 0", got.Float)
	}
	// Filter contract — pinned because the rest of the
	// source's value depends on us actually querying for
	// cert_failed specifically (not cert_obtained or
	// cert_ocsp_revoked).
	if counter.called.Type != "cert_failed" {
		t.Errorf("filter.Type = %q; want cert_failed", counter.called.Type)
	}
}

func TestCertRenewalFailedSource_OneFailure(t *testing.T) {
	counter := &stubCertCounter{count: 1}
	src := NewCertRenewalFailedSource(counter)
	raw := json.RawMessage(`{"windowSecs":3600}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil || *got.Float != 1 {
		t.Errorf("count = %v; want 1 (operator's typical '> 0' threshold trip point)", got.Float)
	}
}

func TestCertRenewalFailedSource_MultipleFailures(t *testing.T) {
	counter := &stubCertCounter{count: 5}
	src := NewCertRenewalFailedSource(counter)
	raw := json.RawMessage(`{"windowSecs":86400}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Float == nil || *got.Float != 5 {
		t.Errorf("count = %v; want 5", got.Float)
	}
}

func TestCertRenewalFailedSource_DomainFilterPropagates(t *testing.T) {
	counter := &stubCertCounter{count: 0}
	src := NewCertRenewalFailedSource(counter)
	raw := json.RawMessage(`{"windowSecs":3600,"domain":"vault.example.com"}`)
	if _, err := src.Read(context.Background(), raw); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if counter.called.Domain != "vault.example.com" {
		t.Errorf("filter.Domain = %q; want vault.example.com (operator pinning the alert to one domain)", counter.called.Domain)
	}
}

func TestCertRenewalFailedSource_WindowBoundary(t *testing.T) {
	// Pin the From timestamp matches now - windowSecs ; the
	// alert's lookback window has to be the operator-supplied
	// value, not silently widened/narrowed.
	counter := &stubCertCounter{}
	fixedNow := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	src := NewCertRenewalFailedSource(counter)
	src.now = func() time.Time { return fixedNow }
	raw := json.RawMessage(`{"windowSecs":600}`)
	if _, err := src.Read(context.Background(), raw); err != nil {
		t.Fatalf("Read: %v", err)
	}
	wantFrom := fixedNow.Add(-600 * time.Second)
	if !counter.called.From.Equal(wantFrom) {
		t.Errorf("filter.From = %v; want %v", counter.called.From, wantFrom)
	}
	if !counter.called.To.Equal(fixedNow) {
		t.Errorf("filter.To = %v; want %v (the now boundary)", counter.called.To, fixedNow)
	}
}

func TestCertRenewalFailedSource_DefaultsTo24h(t *testing.T) {
	counter := &stubCertCounter{}
	fixedNow := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)
	src := NewCertRenewalFailedSource(counter)
	src.now = func() time.Time { return fixedNow }
	raw := json.RawMessage(`{}`)
	if _, err := src.Read(context.Background(), raw); err != nil {
		t.Fatalf("Read: %v", err)
	}
	wantFrom := fixedNow.Add(-24 * time.Hour)
	if !counter.called.From.Equal(wantFrom) {
		t.Errorf("default window = %v; want %v (24h matches LE retry cadence rationale)", counter.called.From, wantFrom)
	}
}

func TestCertRenewalFailedSource_Validate_WindowTooSmall(t *testing.T) {
	src := NewCertRenewalFailedSource(&stubCertCounter{})
	raw := json.RawMessage(`{"windowSecs":10}`)
	if err := src.ValidateParams(raw); err == nil {
		t.Errorf("nil err; want window-range error (10s < 60s min)")
	}
}

func TestCertRenewalFailedSource_Validate_WindowTooLarge(t *testing.T) {
	src := NewCertRenewalFailedSource(&stubCertCounter{})
	raw := json.RawMessage(`{"windowSecs":999999999}`)
	if err := src.ValidateParams(raw); err == nil {
		t.Errorf("nil err; want window-range error (> 7d max)")
	}
}

func TestCertRenewalFailedSource_Validate_BadJSON(t *testing.T) {
	src := NewCertRenewalFailedSource(&stubCertCounter{})
	raw := json.RawMessage(`{not-json`)
	if err := src.ValidateParams(raw); err == nil {
		t.Errorf("nil err; want JSON decode error")
	}
}

func TestCertRenewalFailedSource_Read_CounterNil(t *testing.T) {
	src := NewCertRenewalFailedSource(nil)
	_, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":3600}`))
	if err == nil || !strings.Contains(err.Error(), "not wired") {
		t.Errorf("err = %v; want boot-degraded error", err)
	}
}

func TestCertRenewalFailedSource_Read_CounterError(t *testing.T) {
	counter := &stubCertCounter{err: errors.New("sqlite: disk full")}
	src := NewCertRenewalFailedSource(counter)
	_, err := src.Read(context.Background(), json.RawMessage(`{"windowSecs":3600}`))
	if err == nil || !strings.Contains(err.Error(), "count") {
		t.Errorf("err = %v; want count-wrap of counter error", err)
	}
}

func TestCertRenewalFailedSource_Name(t *testing.T) {
	src := NewCertRenewalFailedSource(&stubCertCounter{})
	if got := src.Name(); got != "cert_renewal_failed" {
		t.Errorf("Name = %q; want cert_renewal_failed (the registry key + AlertRule.Source value operators reference)", got)
	}
}

func TestCertRenewalFailedSource_LabelsCarryDomain(t *testing.T) {
	counter := &stubCertCounter{count: 1}
	src := NewCertRenewalFailedSource(counter)
	raw := json.RawMessage(`{"windowSecs":3600,"domain":"vault.example.com"}`)
	got, err := src.Read(context.Background(), raw)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.Labels["domain"] != "vault.example.com" {
		t.Errorf("labels[domain] = %q; want vault.example.com (the rendered alert template references this label)", got.Labels["domain"])
	}
	if got.Labels["window_secs"] != "3600" {
		t.Errorf("labels[window_secs] = %q; want 3600", got.Labels["window_secs"])
	}
}
