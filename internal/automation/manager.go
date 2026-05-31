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
	"sync"
	"sync/atomic"
)

// Manager is the operator-facing surface the REST API uses to
// reconfigure the running trigger engine. Decoupled from the
// concrete Engine type via this interface so the test suite
// can inject a fake.
//
// Production wiring (cmd/arenet/main.go) constructs a
// *DefaultManager and registers it as the global via
// SetManager. The API handlers in internal/api fetch the
// global via Manager() — same pattern as
// crowdsec.SetGlobalSink (Step N).
//
// Three operator-driven mutations:
//
//   - SetRules(rs)       — atomic swap. Called by PUT
//     /settings/automation/rules.
//   - SetCredentials(c)  — recreate the WatcherClient with
//     the new credentials + invalidate
//     any sticky loginFailed state.
//     Called by PUT /settings/automation/
//     credentials.
//   - ClearCredentials() — disable the writer (no-op drain
//     mode). Called by DELETE /settings/
//     automation/credentials.
//
// Plus a read-side observer:
//
//   - CredentialsConfigured() bool — reports whether the
//     writer is currently wired
//     (drives the GET response's
//     `credentialsConfigured` flag).
type Manager interface {
	SetRules(rs RuleSet)
	SetCredentials(cfg WatcherConfig) error
	ClearCredentials()
	CredentialsConfigured() bool
}

// DefaultManager wires an Engine + a swappable WatcherClient
// holder. The recreate-and-swap pattern (P.2 checklist item
// #3 / option b) keeps the WatcherClient itself stateless
// regarding credential rotations — when creds change, we
// build a new client and atomically swap the pointer.
// Sticky loginFailed flag on the old client is discarded
// with the old client.
type DefaultManager struct {
	engine *Engine
	rules  *RuleSetHolder

	mu     sync.RWMutex
	writer *WatcherClient // nil = disabled (AC #15 boot-degraded)
}

// NewDefaultManager wires a Manager around an Engine + Rules
// holder. The engine is expected to have been constructed
// with the same Rules holder so RuleSet swaps propagate.
//
// initialWriter may be nil — that signals the boot-degraded
// path (no watcher credentials yet). The engine's writer is
// then the no-op drain (per P.2 design).
//
// Callers MUST register the result via SetManager() so the
// API layer can reach it.
func NewDefaultManager(engine *Engine, rules *RuleSetHolder, initialWriter *WatcherClient) *DefaultManager {
	return &DefaultManager{
		engine: engine,
		rules:  rules,
		writer: initialWriter,
	}
}

// SetRules atomically replaces the engine's RuleSet. The
// next engine tick uses the new set; an in-flight intent
// emitted under the OLD rules completes its writer pipeline
// with the OLD scenario / duration (the values were captured
// into the Intent struct at emit time, not re-read).
func (m *DefaultManager) SetRules(rs RuleSet) {
	m.rules.Set(rs)
}

// SetCredentials recreates the underlying WatcherClient with
// the given config + swaps the engine's writer pointer
// atomically. The sticky loginFailed state on the previous
// client (if any) is discarded — the operator's correction
// takes effect immediately.
//
// Returns the underlying NewWatcherClient error on bad
// config (ErrCredentialsRequired on empty fields).
func (m *DefaultManager) SetCredentials(cfg WatcherConfig) error {
	client, err := NewWatcherClient(cfg)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.writer = client
	m.mu.Unlock()
	// Engine reads m.Writer() at writerLoop attempt time
	// (see the Writer accessor below), so the swap is
	// visible to the next push without restarting any
	// goroutine.
	return nil
}

// ClearCredentials sets the writer to nil — boot-degraded
// mode. The writer loop's nil-Writer path drains intents
// silently; the operator can re-configure credentials at
// any time without an Arenet restart.
func (m *DefaultManager) ClearCredentials() {
	m.mu.Lock()
	m.writer = nil
	m.mu.Unlock()
}

// CredentialsConfigured reports the current state for the
// GET /settings/automation response.
func (m *DefaultManager) CredentialsConfigured() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.writer != nil
}

// Writer returns the current WatcherClient (or nil if creds
// not configured). Called by the Engine's writer loop on
// every intent; the atomic swap in SetCredentials makes the
// new client visible without restarting the goroutine.
//
// Returned value satisfies the Writer interface from
// trigger.go so engine.processIntent can call EnsureJWT +
// PushAlert directly.
func (m *DefaultManager) Writer() Writer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.writer == nil {
		return nil
	}
	return m.writer
}

// --- Global manager singleton ----------------------------------------------

var globalManager atomic.Pointer[Manager]

// SetManager registers the global Manager. The API handlers
// fetch it via Manager() to reconfigure the running engine.
// Same pattern as crowdsec.SetGlobalSink. nil unregisters.
func SetManager(m Manager) {
	if m == nil {
		globalManager.Store(nil)
		return
	}
	globalManager.Store(&m)
}

// GetManager returns the registered global Manager. nil when
// none is registered (the AC #15 boot-degraded path: empty
// watcher creds at boot → no Manager → API handlers return
// 503 / disabled on writes).
func GetManager() Manager {
	p := globalManager.Load()
	if p == nil {
		return nil
	}
	return *p
}
