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

package metrics

import (
	"sync"
	"testing"
)

func TestGlobal_SetRegistry_FirstCallWins(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	first := NewRegistry()
	SetRegistry(first)
	if got := GlobalRegistry(); got != first {
		t.Errorf("after SetRegistry(first), GlobalRegistry()=%p want %p", got, first)
	}

	// Second SetRegistry MUST be a silent no-op.
	second := NewRegistry()
	SetRegistry(second)
	if got := GlobalRegistry(); got != first {
		t.Errorf("after second SetRegistry, GlobalRegistry()=%p want %p (first), got %p (second)", got, first, second)
	}
}

func TestGlobal_GlobalRegistry_NilBeforeSet(t *testing.T) {
	t.Cleanup(ResetForTest)
	ResetForTest()

	if got := GlobalRegistry(); got != nil {
		t.Errorf("GlobalRegistry() before SetRegistry = %v, want nil", got)
	}
}

func TestGlobal_ResetForTest_AllowsResetting(t *testing.T) {
	t.Cleanup(ResetForTest)

	ResetForTest()
	SetRegistry(NewRegistry())
	if GlobalRegistry() == nil {
		t.Fatal("expected non-nil after first SetRegistry")
	}

	ResetForTest()
	if GlobalRegistry() != nil {
		t.Errorf("ResetForTest must clear the singleton")
	}

	// After reset, SetRegistry works again.
	r := NewRegistry()
	SetRegistry(r)
	if GlobalRegistry() != r {
		t.Errorf("SetRegistry after ResetForTest did not install the new registry")
	}
}

func TestGlobal_SetRegistry_ConcurrentCalls(t *testing.T) {
	// Many goroutines calling SetRegistry concurrently. Only one
	// pointer must survive, no race detected.
	t.Cleanup(ResetForTest)
	ResetForTest()

	const N = 100
	regs := make([]*Registry, N)
	for i := range regs {
		regs[i] = NewRegistry()
	}

	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			SetRegistry(regs[i])
		}(i)
	}
	wg.Wait()

	winner := GlobalRegistry()
	if winner == nil {
		t.Fatal("no SetRegistry winner")
	}
	// The winner must be one of the candidates.
	found := false
	for _, r := range regs {
		if r == winner {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("winner is not one of the candidates")
	}
}
