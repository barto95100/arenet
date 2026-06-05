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

package certinfo

import (
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fixedNow returns a clock that always reads the same instant —
// makes the status-derivation tests independent of wall-clock
// drift during CI.
func fixedNow(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// TestTracker_StatusPrecedence pins the §2 AC #2 precedence
// table: a fresh OBTAIN_FAILED beats every cert state, EXPIRED
// beats RENEWAL_PENDING and VALID, RENEWAL_PENDING beats VALID,
// VALID is the fallthrough.
func TestTracker_StatusPrecedence(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	tracker := NewTracker()
	tracker.SetNow(fixedNow(now))

	cases := []struct {
		name      string
		notAfter  time.Time
		hasError  bool
		errorAge  time.Duration
		wantState Status
	}{
		{
			name:      "valid — far from expiry, no failure",
			notAfter:  now.Add(60 * 24 * time.Hour),
			wantState: StatusValid,
		},
		{
			name:      "renewal pending — inside the 30d margin",
			notAfter:  now.Add(20 * 24 * time.Hour),
			wantState: StatusRenewalPending,
		},
		{
			name:      "expired — NotAfter in the past",
			notAfter:  now.Add(-1 * time.Hour),
			wantState: StatusExpired,
		},
		{
			name:      "obtain_failed beats valid when failure is fresh",
			notAfter:  now.Add(60 * 24 * time.Hour),
			hasError:  true,
			errorAge:  1 * time.Hour,
			wantState: StatusObtainFailed,
		},
		{
			name:      "obtain_failed beats renewal_pending when failure is fresh",
			notAfter:  now.Add(20 * 24 * time.Hour),
			hasError:  true,
			errorAge:  1 * time.Hour,
			wantState: StatusObtainFailed,
		},
		{
			name:      "obtain_failed expires after 24h — falls back to valid",
			notAfter:  now.Add(60 * 24 * time.Hour),
			hasError:  true,
			errorAge:  25 * time.Hour,
			wantState: StatusValid,
		},
		{
			name:      "unknown — no NotAfter recorded yet",
			notAfter:  time.Time{},
			wantState: StatusUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tracker := NewTracker()
			tracker.SetNow(fixedNow(now))
			tracker.RecordCert(&CertRuntimeInfo{
				Domain:    "x.example.com",
				NotAfter:  tc.notAfter,
				NotBefore: now.Add(-90 * 24 * time.Hour),
				Issuer:    "Let's Encrypt",
			})
			if tc.hasError {
				// RecordCert clears prior failure, so set failure
				// AFTER. Force the timestamp through SetNow window
				// shifting (set clock back, record failure, set
				// clock forward to evaluate freshness).
				tracker.SetNow(fixedNow(now.Add(-tc.errorAge)))
				tracker.RecordFailure("x.example.com", "boom")
				tracker.SetNow(fixedNow(now))
			}
			got, ok := tracker.Get("x.example.com")
			if !ok {
				t.Fatalf("Get returned !ok")
			}
			if got.Status != tc.wantState {
				t.Fatalf("Status=%q want=%q", got.Status, tc.wantState)
			}
		})
	}
}

// TestTracker_RecordCert_ClearsFailure pins the spec invariant
// "a successful re-issuance clears OBTAIN_FAILED": once cert_obtained
// fires for a domain that was previously in failure, the status
// must flip back to VALID even within the 24h freshness window.
func TestTracker_RecordCert_ClearsFailure(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	tr := NewTracker()
	tr.SetNow(fixedNow(now))

	tr.RecordFailure("x.example.com", "transient")
	info, _ := tr.Get("x.example.com")
	if info.Status != StatusObtainFailed {
		t.Fatalf("setup: status=%q want=OBTAIN_FAILED", info.Status)
	}

	tr.RecordCert(&CertRuntimeInfo{
		Domain:   "x.example.com",
		NotAfter: now.Add(60 * 24 * time.Hour),
		Issuer:   "Let's Encrypt",
	})
	info, _ = tr.Get("x.example.com")
	if info.Status != StatusValid {
		t.Fatalf("after RecordCert status=%q want=VALID", info.Status)
	}
	if info.LastError != nil || info.LastErrorAt != nil {
		t.Fatalf("after RecordCert LastError=%v LastErrorAt=%v — want both nil",
			info.LastError, info.LastErrorAt)
	}
}

// TestTracker_RecordCert_Idempotent pins that calling RecordCert
// twice with identical input leaves the tracker in the same state
// (no duplicate entries, latest snapshot wins for the metadata
// fields).
func TestTracker_RecordCert_Idempotent(t *testing.T) {
	tr := NewTracker()
	info := &CertRuntimeInfo{
		Domain:   "x.example.com",
		NotAfter: time.Now().Add(60 * 24 * time.Hour),
		Issuer:   "Let's Encrypt",
		Source:   SourceSpecific,
	}
	tr.RecordCert(info)
	tr.RecordCert(info)
	got := tr.List()
	if len(got) != 1 {
		t.Fatalf("List() len=%d want=1", len(got))
	}
}

// TestTracker_List_SortedByNotAfter pins the §3.2 wire-shape sort:
// closest-to-expiry first.
func TestTracker_List_SortedByNotAfter(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	tr := NewTracker()
	tr.SetNow(fixedNow(now))

	tr.RecordCert(&CertRuntimeInfo{Domain: "later.example.com", NotAfter: now.Add(60 * 24 * time.Hour)})
	tr.RecordCert(&CertRuntimeInfo{Domain: "soon.example.com", NotAfter: now.Add(7 * 24 * time.Hour)})
	tr.RecordCert(&CertRuntimeInfo{Domain: "mid.example.com", NotAfter: now.Add(30 * 24 * time.Hour)})

	got := tr.List()
	if len(got) != 3 {
		t.Fatalf("List() len=%d want=3", len(got))
	}
	wantOrder := []string{"soon.example.com", "mid.example.com", "later.example.com"}
	for i, g := range got {
		if g.Domain != wantOrder[i] {
			t.Fatalf("List()[%d].Domain=%q want=%q", i, g.Domain, wantOrder[i])
		}
	}
}

// TestTracker_NormalizeDomain pins that GET/Record key on the
// normalized form — uppercase + whitespace input must hit the
// same entry as lowercase.
func TestTracker_NormalizeDomain(t *testing.T) {
	tr := NewTracker()
	tr.RecordCert(&CertRuntimeInfo{Domain: "X.Example.COM", NotAfter: time.Now().Add(48 * time.Hour)})

	if _, ok := tr.Get("x.example.com"); !ok {
		t.Fatalf("Get(lowercase) miss after RecordCert(uppercase)")
	}
	if _, ok := tr.Get("  x.example.com  "); !ok {
		t.Fatalf("Get(whitespaced) miss")
	}
}

// TestTracker_Subscribe pins AC #18 — the forward-compat seam
// for Step T+1. A handler attached via Subscribe must receive an
// Event for every RecordCert / RecordFailure / RecordObtaining.
func TestTracker_Subscribe(t *testing.T) {
	tr := NewTracker()
	var got []Event
	var mu sync.Mutex
	tr.Subscribe(captureHandler{cb: func(e Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	}})

	tr.RecordObtaining("a.example.com")
	tr.RecordCert(&CertRuntimeInfo{Domain: "a.example.com", NotAfter: time.Now().Add(48 * time.Hour), Issuer: "Let's Encrypt"})
	tr.RecordFailure("b.example.com", "boom")

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("captured %d events, want 3", len(got))
	}
	if got[0].Kind != EventCertObtaining || got[0].Domain != "a.example.com" {
		t.Fatalf("event[0]=%+v", got[0])
	}
	if got[1].Kind != EventCertObtained || got[1].Domain != "a.example.com" {
		t.Fatalf("event[1]=%+v", got[1])
	}
	if got[2].Kind != EventCertFailed || got[2].Domain != "b.example.com" || got[2].Error != "boom" {
		t.Fatalf("event[2]=%+v", got[2])
	}
}

// TestTracker_Subscribe_Unsubscribe pins that an unsubscribed
// handler stops receiving events — required so test isolation
// doesn't carry over and so T+1's persister can shut down
// cleanly without leaking goroutines on next-cycle events.
func TestTracker_Subscribe_Unsubscribe(t *testing.T) {
	tr := NewTracker()
	var hits int32
	unsub := tr.Subscribe(captureHandler{cb: func(Event) {
		atomic.AddInt32(&hits, 1)
	}})

	tr.RecordObtaining("a.example.com")
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("before unsub hits=%d want=1", got)
	}
	unsub()
	tr.RecordObtaining("b.example.com")
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("after unsub hits=%d want=1 (still)", got)
	}
}

// TestTracker_Subscribe_PanicRecovery pins that a panicking
// handler can't take down the tracker — a buggy T+1 consumer
// must not break the primary cache job.
func TestTracker_Subscribe_PanicRecovery(t *testing.T) {
	tr := NewTracker()
	tr.Subscribe(captureHandler{cb: func(Event) {
		panic("intentional test panic")
	}})
	// Should not crash the test process.
	tr.RecordObtaining("a.example.com")
}

// TestTracker_ConcurrentReadWrite pins data-race-freedom under
// -race: many readers (Get + List) racing with many writers
// (RecordCert + RecordFailure) on overlapping keys.
func TestTracker_ConcurrentReadWrite(t *testing.T) {
	tr := NewTracker()
	// Seed so List has something to sort.
	for i := 0; i < 50; i++ {
		tr.RecordCert(&CertRuntimeInfo{
			Domain:   randDomain(i),
			NotAfter: time.Now().Add(time.Duration(i) * 24 * time.Hour),
		})
	}

	var wg sync.WaitGroup
	const goroutines = 16
	const iters = 200

	for g := 0; g < goroutines; g++ {
		wg.Add(2)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				tr.RecordCert(&CertRuntimeInfo{
					Domain:   randDomain(i + seed*100),
					NotAfter: time.Now().Add(time.Duration(i) * time.Hour),
				})
			}
		}(g)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				_, _ = tr.Get(randDomain(i + seed*100))
				_ = tr.List()
			}
		}(g)
	}
	wg.Wait()
}

// TestSnapshot_NeverSerializesNilSANList pins the hotfix-following-
// T.5 invariant: every snapshot the tracker emits via Get / List
// MUST produce JSON where sanList is at worst an empty array,
// never `null`. The crash this prevents:
//
//   - Backend constructs an entry without SANList (RecordFailure
//     for a never-seen domain → placeholder entry; cert_obtained
//     fallback when on-disk leaf read failed → minimal entry).
//   - snapshot() copies SANList via append([]string(nil), nil...)
//     which returns nil (Go nil-slice gotcha).
//   - encoding/json renders nil []string as JSON null.
//   - Frontend Domaines table reads cert.sanList.length →
//     TypeError on null.
//
// Empirically captured against AreNET-test on 2026-06-05 with
// OBTAIN_FAILED rows for *.test.local. The fix in tracker.go
// snapshot() forces a non-nil slice before assignment; this
// test pins it so a future refactor doesn't reintroduce the
// gotcha at any constructor path.
func TestSnapshot_NeverSerializesNilSANList(t *testing.T) {
	now := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name  string
		setup func(tr *Tracker)
		key   string
	}{
		{
			name: "RecordFailure-only — placeholder entry (no prior cert obtained)",
			setup: func(tr *Tracker) {
				tr.RecordFailure("never.example.com", "boom")
			},
			key: "never.example.com",
		},
		{
			name: "RecordCert with nil SANList — cert_obtained fallback path",
			setup: func(tr *Tracker) {
				tr.RecordCert(&CertRuntimeInfo{
					Domain:   "fallback.example.com",
					Issuer:   "Let's Encrypt",
					Source:   SourceSpecific,
					NotAfter: now.Add(60 * 24 * time.Hour),
					// SANList intentionally omitted (nil)
				})
			},
			key: "fallback.example.com",
		},
		{
			name: "RecordCert with empty SANList — explicit empty",
			setup: func(tr *Tracker) {
				tr.RecordCert(&CertRuntimeInfo{
					Domain:   "empty.example.com",
					SANList:  []string{},
					Issuer:   "Let's Encrypt",
					Source:   SourceSpecific,
					NotAfter: now.Add(60 * 24 * time.Hour),
				})
			},
			key: "empty.example.com",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewTracker()
			tr.SetNow(fixedNow(now))
			tc.setup(tr)

			info, ok := tr.Get(tc.key)
			if !ok {
				t.Fatalf("Get(%q) miss", tc.key)
			}
			if info.SANList == nil {
				t.Fatalf("snapshot SANList is nil — snapshot() must coerce to []")
			}
			data, err := json.Marshal(info)
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if strings.Contains(string(data), `"sanList":null`) {
				t.Fatalf(
					"sanList serializes to null — frontend assumes array. body=%s",
					data,
				)
			}
			// Round-trip: List() goes through the same snapshot
			// path, so the whole-list output must also be
			// null-free.
			listData, err := json.Marshal(tr.List())
			if err != nil {
				t.Fatalf("json.Marshal(List): %v", err)
			}
			if strings.Contains(string(listData), `"sanList":null`) {
				t.Fatalf(
					"List() serializes some sanList to null. body=%s",
					listData,
				)
			}
		})
	}
}

func randDomain(i int) string {
	// Deterministic but spread enough that goroutines hit overlapping
	// AND distinct keys.
	return "host" + itoa(i%97) + ".example.com"
}

// itoa avoids strconv to keep the test free of imports beyond
// the stdlib basics already in use.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [4]byte
	n := len(buf)
	for i > 0 {
		n--
		buf[n] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[n:])
}

// captureHandler is the test-only EventHandler implementation
// used by Subscribe tests.
type captureHandler struct {
	cb func(Event)
}

func (c captureHandler) HandleCertEvent(e Event) {
	if c.cb != nil {
		c.cb(e)
	}
}
