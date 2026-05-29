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
	"sync"
	"sync/atomic"
	"testing"
)

type stubSink struct {
	emits      atomic.Int64
	tombstones atomic.Int64
}

func (s *stubSink) Emit(_ Decision)       { s.emits.Add(1) }
func (s *stubSink) Tombstone(uuid string) { s.tombstones.Add(1); _ = uuid }

func TestSetGlobalSink_RoundTrip(t *testing.T) {
	t.Cleanup(func() { SetGlobalSink(nil) })

	s := &stubSink{}
	SetGlobalSink(s)
	got := GetGlobalSink()
	if got == nil {
		t.Fatal("GetGlobalSink returned nil after SetGlobalSink")
	}
	got.Emit(Decision{UUID: "u"})
	got.Tombstone("u")
	if s.emits.Load() != 1 {
		t.Errorf("emits = %d, want 1", s.emits.Load())
	}
	if s.tombstones.Load() != 1 {
		t.Errorf("tombstones = %d, want 1", s.tombstones.Load())
	}
}

func TestSetGlobalSink_NilClears(t *testing.T) {
	// Anti-regression on the AC #13 degraded path: passing
	// nil MUST clear the pointer, not install a non-nil
	// interface wrapping nil (the classic Go
	// nil-pointer-vs-nil-interface trap).
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
	GetGlobalSink().Emit(Decision{})
	if first.emits.Load() != 0 {
		t.Errorf("first sink got %d emits; should have been replaced", first.emits.Load())
	}
	if second.emits.Load() != 1 {
		t.Errorf("second sink got %d emits; want 1", second.emits.Load())
	}
}

func TestGetGlobalSink_NilWhenUnset(t *testing.T) {
	SetGlobalSink(nil)
	if got := GetGlobalSink(); got != nil {
		t.Errorf("expected nil before any Set, got %v", got)
	}
}

func TestSetGlobalSink_ConcurrentSafe(t *testing.T) {
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
