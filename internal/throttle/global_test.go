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

package throttle

import (
	"sync"
	"sync/atomic"
	"testing"
)

// stubSink lets us prove GetGlobalSink returns the value
// SetGlobalSink installed (vs. always-nil or stale).
type stubSink struct {
	calls atomic.Int64
}

func (s *stubSink) Emit(_ Event) { s.calls.Add(1) }

func TestSetGlobalSink_RoundTrip(t *testing.T) {
	t.Cleanup(func() { SetGlobalSink(nil) })

	s := &stubSink{}
	SetGlobalSink(s)
	got := GetGlobalSink()
	if got == nil {
		t.Fatal("GetGlobalSink returned nil after SetGlobalSink")
	}
	got.Emit(Event{})
	if s.calls.Load() != 1 {
		t.Errorf("Emit count = %d, want 1 — returned sink is not the installed one", s.calls.Load())
	}
}

func TestSetGlobalSink_NilClears(t *testing.T) {
	// Anti-regression on the AC #13 degraded path: passing nil
	// MUST clear the pointer, not install a non-nil interface
	// wrapping nil (the classic Go nil-pointer-vs-nil-interface
	// trap).
	SetGlobalSink(&stubSink{})
	SetGlobalSink(nil)
	if got := GetGlobalSink(); got != nil {
		t.Errorf("GetGlobalSink = %v after SetGlobalSink(nil); want nil", got)
	}
}

func TestSetGlobalSink_Replaces(t *testing.T) {
	t.Cleanup(func() { SetGlobalSink(nil) })

	first := &stubSink{}
	second := &stubSink{}
	SetGlobalSink(first)
	SetGlobalSink(second)
	GetGlobalSink().Emit(Event{})
	if first.calls.Load() != 0 {
		t.Errorf("first sink got %d Emit(s); should have been replaced", first.calls.Load())
	}
	if second.calls.Load() != 1 {
		t.Errorf("second sink got %d Emit(s); want 1", second.calls.Load())
	}
}

func TestGetGlobalSink_NeverPanicsWhenUnset(t *testing.T) {
	// Cleanup so other tests start with nil.
	SetGlobalSink(nil)
	got := GetGlobalSink()
	if got != nil {
		t.Errorf("expected nil before any Set, got %v", got)
	}
}

func TestSetGlobalSink_ConcurrentSafe(t *testing.T) {
	// SetGlobalSink + GetGlobalSink under contention. The
	// rate limiter (caller of GetGlobalSink) runs on every
	// auth request; the boot path (caller of SetGlobalSink)
	// runs once. Atomic.Pointer makes this safe; assert it
	// under -race.
	t.Cleanup(func() { SetGlobalSink(nil) })

	var wg sync.WaitGroup
	const workers = 8
	const perWorker = 1000
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			s := &stubSink{}
			for i := 0; i < perWorker; i++ {
				SetGlobalSink(s)
				_ = GetGlobalSink()
			}
		}()
	}
	wg.Wait()
}
