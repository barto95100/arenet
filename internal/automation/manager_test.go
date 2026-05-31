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

package automation

import (
	"errors"
	"testing"
)

func TestDefaultManager_CredentialsConfigured_False_OnNilWriter(t *testing.T) {
	mgr := NewDefaultManager(nil, NewRuleSetHolder(DefaultRuleSet()), nil)
	if mgr.CredentialsConfigured() {
		t.Error("nil initial writer should report CredentialsConfigured=false")
	}
	if mgr.Writer() != nil {
		t.Error("nil initial writer: Writer() should return nil")
	}
}

func TestDefaultManager_SetCredentials_RecreatesAndSwaps(t *testing.T) {
	// Pin the P.3 wiring checklist item #3: SetCredentials
	// constructs a fresh WatcherClient and atomically swaps
	// the pointer. Sticky loginFailed state from a previous
	// client is discarded.
	mgr := NewDefaultManager(nil, NewRuleSetHolder(DefaultRuleSet()), nil)

	err := mgr.SetCredentials(WatcherConfig{
		LAPIURL: "http://127.0.0.1:8080", MachineID: "arenet", Password: "secret",
	})
	if err != nil {
		t.Fatalf("SetCredentials: %v", err)
	}
	if !mgr.CredentialsConfigured() {
		t.Error("CredentialsConfigured should be true after SetCredentials")
	}
	w := mgr.Writer()
	if w == nil {
		t.Fatal("Writer() should be non-nil after SetCredentials")
	}

	// Second swap with different creds — should yield a
	// distinct client. The Manager doesn't expose internals
	// to compare directly; we test the swap by checking
	// LoginFailed flips back to false (the new client has
	// no sticky state).
	if err := mgr.SetCredentials(WatcherConfig{
		LAPIURL: "http://127.0.0.1:8080", MachineID: "arenet", Password: "different",
	}); err != nil {
		t.Fatalf("second SetCredentials: %v", err)
	}
	w2 := mgr.Writer()
	if w2 == nil {
		t.Fatal("Writer() should still be non-nil after re-swap")
	}
	if w2.LoginFailed() {
		t.Error("fresh client should not have loginFailed sticky from the previous one")
	}
}

func TestDefaultManager_SetCredentials_ErrCredentialsRequired(t *testing.T) {
	mgr := NewDefaultManager(nil, NewRuleSetHolder(DefaultRuleSet()), nil)
	err := mgr.SetCredentials(WatcherConfig{})
	if !errors.Is(err, ErrCredentialsRequired) {
		t.Errorf("err=%v, want ErrCredentialsRequired", err)
	}
	if mgr.CredentialsConfigured() {
		t.Error("CredentialsConfigured should remain false after rejected SetCredentials")
	}
}

func TestDefaultManager_ClearCredentials_DisablesWriter(t *testing.T) {
	mgr := NewDefaultManager(nil, NewRuleSetHolder(DefaultRuleSet()), nil)
	_ = mgr.SetCredentials(WatcherConfig{
		LAPIURL: "u", MachineID: "m", Password: "p",
	})
	if !mgr.CredentialsConfigured() {
		t.Fatal("setup: CredentialsConfigured should be true")
	}
	mgr.ClearCredentials()
	if mgr.CredentialsConfigured() {
		t.Error("after ClearCredentials, CredentialsConfigured should be false")
	}
	if mgr.Writer() != nil {
		t.Error("Writer() should return nil after ClearCredentials")
	}
}

func TestDefaultManager_SetRules_AtomicSwap(t *testing.T) {
	holder := NewRuleSetHolder(DefaultRuleSet())
	mgr := NewDefaultManager(nil, holder, nil)

	if holder.Get().AnyEnabled() {
		t.Fatal("setup: default rules should be all-disabled")
	}
	// Build a RuleSet with one rule enabled, swap.
	next := DefaultRuleSet()
	r := next.Rules[SourceWafSQLi]
	r.Enabled = true
	next.Rules[SourceWafSQLi] = r
	mgr.SetRules(next)

	got := holder.Get()
	if !got.AnyEnabled() {
		t.Error("after SetRules, holder should reflect the new RuleSet")
	}
}

func TestGlobalManager_SetGet(t *testing.T) {
	// Restore after test so other tests in the package see a
	// clean global.
	t.Cleanup(func() { SetManager(nil) })

	if GetManager() != nil {
		// Defensive — a stale global from another test
		// would cause cascading false-positives.
		SetManager(nil)
	}

	mgr := NewDefaultManager(nil, NewRuleSetHolder(DefaultRuleSet()), nil)
	SetManager(mgr)

	got := GetManager()
	if got != mgr {
		t.Errorf("GetManager mismatch: got %v, want %v", got, mgr)
	}

	SetManager(nil)
	if GetManager() != nil {
		t.Error("SetManager(nil) should unregister")
	}
}
