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

package observability

import (
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/certinfo"
)

// stubSubmitter captures Submit calls so the adapter tests can
// assert the post-translation CertEvent contents.
type stubSubmitter struct {
	calls []CertEvent
}

func (s *stubSubmitter) Submit(e CertEvent) {
	s.calls = append(s.calls, e)
}

// TestAdapter_CertObtained_MapsToInfoWithRenewal pins the
// happy-path translation: a certmagic cert_obtained event with
// renewal=true becomes CertEvent{Level: INFO, Type: Obtained,
// Renewal: true, ...}. The renewal bit is the AC #1 signal
// that distinguishes a first issuance from a successful
// renewal (spec §6 AC #1 wording).
func TestAdapter_CertObtained_MapsToInfoWithRenewal(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)

	adapter.HandleCertEvent(certinfo.Event{
		Kind:      certinfo.EventCertObtained,
		Domain:    "*.example.com",
		IsRenewal: true,
		Issuer:    "Let's Encrypt",
		At:        now,
	})

	if len(sink.calls) != 1 {
		t.Fatalf("Submit calls = %d, want 1", len(sink.calls))
	}
	got := sink.calls[0]
	if got.Level != CertEventLevelInfo {
		t.Errorf("Level = %v, want Info", got.Level)
	}
	if got.Type != CertEventTypeObtained {
		t.Errorf("Type = %v, want Obtained", got.Type)
	}
	if got.Domain != "*.example.com" {
		t.Errorf("Domain = %q, want *.example.com", got.Domain)
	}
	if !got.Renewal {
		t.Errorf("Renewal = false, want true (renewal disambiguation per cert_obtained payload)")
	}
	if got.Issuer != "Let's Encrypt" {
		t.Errorf("Issuer = %q, want Let's Encrypt", got.Issuer)
	}
	if !got.Ts.Equal(now) {
		t.Errorf("Ts = %v, want %v", got.Ts, now)
	}
}

// TestAdapter_CertObtained_FirstIssue carries renewal=false:
// fresh first-issuance, not a renewal.
func TestAdapter_CertObtained_FirstIssue(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:      certinfo.EventCertObtained,
		Domain:    "first.example.com",
		IsRenewal: false,
		Issuer:    "Let's Encrypt",
		At:        time.Now(),
	})
	if len(sink.calls) != 1 {
		t.Fatalf("Submit calls = %d, want 1", len(sink.calls))
	}
	if sink.calls[0].Renewal {
		t.Errorf("Renewal = true, want false (first issue)")
	}
	if sink.calls[0].Type != CertEventTypeObtained {
		t.Errorf("Type = %v, want Obtained", sink.calls[0].Type)
	}
}

// TestAdapter_CertFailed_MapsToErrorWithErrorString pins the
// cert_failed translation: CertEvent{Level: ERROR, Type:
// Failed, Error: <verbatim>} per spec §6 AC #2.
func TestAdapter_CertFailed_MapsToErrorWithErrorString(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	const errMsg = "subject 'test.local' does not qualify for a public certificate"

	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventCertFailed,
		Domain: "test.local",
		Error:  errMsg,
		At:     time.Now(),
	})

	if len(sink.calls) != 1 {
		t.Fatalf("Submit calls = %d, want 1", len(sink.calls))
	}
	got := sink.calls[0]
	if got.Level != CertEventLevelError {
		t.Errorf("Level = %v, want Error", got.Level)
	}
	if got.Type != CertEventTypeFailed {
		t.Errorf("Type = %v, want Failed", got.Type)
	}
	if got.Error != errMsg {
		t.Errorf("Error = %q, want %q", got.Error, errMsg)
	}
}

// TestAdapter_CertOCSPRevoked_MapsToError pins spec §3.6: cert
// revocation is INCLUDED as level=ERROR for security signal.
func TestAdapter_CertOCSPRevoked_MapsToError(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventCertOCSPRevoked,
		Domain: "revoked.example.com",
		At:     time.Now(),
	})
	if len(sink.calls) != 1 {
		t.Fatalf("Submit calls = %d, want 1", len(sink.calls))
	}
	got := sink.calls[0]
	if got.Level != CertEventLevelError {
		t.Errorf("Level = %v, want Error", got.Level)
	}
	if got.Type != CertEventTypeOCSPRevoked {
		t.Errorf("Type = %v, want OCSPRevoked", got.Type)
	}
	if got.Domain != "revoked.example.com" {
		t.Errorf("Domain = %q, want revoked.example.com", got.Domain)
	}
}

// TestAdapter_CertObtaining_Dropped pins spec §3.3 LOCKED:
// cert_obtaining is NOT persisted (retry noise; outcomes are
// captured by obtained/failed). The Subscribe seam still fires
// it for any future real-time consumer; this test only proves
// the sink path stays clean.
func TestAdapter_CertObtaining_Dropped(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventCertObtaining,
		Domain: "x.example.com",
		At:     time.Now(),
	})
	if len(sink.calls) != 0 {
		t.Fatalf("Submit calls = %d, want 0 (Obtaining is dropped per spec §3.3)", len(sink.calls))
	}
}

// TestAdapter_EventCertRemoved_Dropped pins spec §3.8 LOCKED:
// EventCertRemoved is the synthetic event the tracker fires on
// managed-domain DELETE (HF3 commit e4177e4). The audit log's
// ActionManagedDomainDeleted is the canonical record; the
// sink path skips this kind to avoid double-recording.
func TestAdapter_EventCertRemoved_Dropped(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventCertRemoved,
		Domain: "deleted.example.com",
		At:     time.Now(),
	})
	if len(sink.calls) != 0 {
		t.Fatalf("Submit calls = %d, want 0 (Removed is dropped per spec §3.8)", len(sink.calls))
	}
}

// TestAdapter_UnknownEventKind_DroppedDefensively pins the
// default branch: a future EventKind addition lands on the
// adapter unmapped → drop without panic. Adding a real new
// kind would require a parallel CertEventType addition; until
// both land, dropping is the safest default.
func TestAdapter_UnknownEventKind_DroppedDefensively(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventKind("future_event_kind_not_yet_defined"),
		Domain: "x",
		At:     time.Now(),
	})
	if len(sink.calls) != 0 {
		t.Fatalf("Submit calls = %d, want 0 (unknown kind dropped)", len(sink.calls))
	}
}

// TestNewCertEventAdapter_NilSink_Panics pins the wiring-bug
// guard: a nil sink is a programmer error (the U.2 wire-up in
// cmd/arenet/main.go always passes a real sink); failing fast
// surfaces it at boot instead of NPE on the first event.
func TestNewCertEventAdapter_NilSink_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewCertEventAdapter(nil) did not panic")
		}
	}()
	NewCertEventAdapter(nil)
}

// TestAdapter_TimestampPassesThroughVerbatim pins that Event.At
// is the source of truth for the row's ts (NOT time.Now() at
// the adapter). Important for offline replay scenarios where
// the producer's timestamp matters.
func TestAdapter_TimestampPassesThroughVerbatim(t *testing.T) {
	sink := &stubSubmitter{}
	adapter := NewCertEventAdapter(sink)
	const tsRFC = "2026-06-06T01:23:45Z"
	ts, _ := time.Parse(time.RFC3339, tsRFC)
	adapter.HandleCertEvent(certinfo.Event{
		Kind:   certinfo.EventCertFailed,
		Domain: "x.example.com",
		Error:  "boom",
		At:     ts,
	})
	if len(sink.calls) != 1 {
		t.Fatalf("Submit calls = %d", len(sink.calls))
	}
	if !sink.calls[0].Ts.Equal(ts) {
		t.Errorf("Ts = %v, want %v", sink.calls[0].Ts, ts)
	}
}
