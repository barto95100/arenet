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
	"sort"
	"strings"
	"sync"
	"time"
)

// RenewalMargin is the runway before a cert's NotAfter at which
// the derived status flips from VALID to RENEWAL_PENDING. Mirrors
// the certmagic default renewal window (1/3 of cert lifetime —
// for a 90-day LE cert that's 30 days). Hard-coded here rather
// than threaded through config because every cert in the system
// uses the same renewal policy today (§1.1 of the spec: LE only).
const RenewalMargin = 30 * 24 * time.Hour

// FailureFreshness is the window during which a cert_failed event
// suppresses the natural VALID/RENEWAL_PENDING status and surfaces
// OBTAIN_FAILED instead (§2 AC #2 of the spec). 24h matches the
// spec's wording and lets the operator notice failed renewals
// without spamming the badge after a single transient hiccup.
const FailureFreshness = 24 * time.Hour

// Tracker is the in-memory cache of per-domain runtime cert
// metadata. Reads are served by GET /api/certificates; writes
// come from two sources: ReconcileFromDisk at boot, and the
// EventHandler module on every certmagic event.
//
// Concurrency: every method is safe for concurrent use. List() is
// in the hot path of the API endpoint (called per request); the
// internal map access takes the read lock and the snapshot is a
// freshly-allocated slice so the caller can iterate without
// holding the mutex.
//
// Subscribe seam: external consumers (Step T+1 ACME events log)
// can attach via Subscribe to receive an Event for every
// state-changing certmagic event the tracker processes. Handlers
// are invoked synchronously from the tracker's update path; they
// must not block. The seam is no-op in T (no consumers attached)
// but the dispatch loop exists so T+1 can wire its persister
// without touching tracker internals.
type Tracker struct {
	mu       sync.RWMutex
	byDomain map[string]*entry

	subsMu sync.RWMutex
	subs   []EventHandler

	now func() time.Time // injectable for tests
}

// entry is the internal mutable shape stored per domain. We keep
// the persistent metadata (Domain, SANList, Issuer, NotBefore,
// NotAfter, Source) separate from the volatile failure state so
// a cert_failed event can populate failure fields without
// clobbering the cert's identity, and so a subsequent
// cert_obtained event clears the failure state cleanly.
type entry struct {
	Domain    string
	SANList   []string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	Source    Source

	LastError   string
	LastErrorAt time.Time
}

// NewTracker returns an empty tracker. The caller (cmd/arenet/main.go)
// installs it as the package-level singleton via SetTracker, then
// seeds it via ReconcileFromDisk before mgr.Start so the cache is
// populated before any cert_* event flows in.
//
// Satisfies AC #1 (runtime metadata exposed) — the tracker is the
// in-memory source-of-truth GET /api/certificates reads from.
// Satisfies AC #18 (forward-compat seam) — Subscribe() declared
// below is the hook Step T+1's ACME events log attaches to.
// Step T spec v1.2.0-step-t-spec, implemented by 1350777 (T.1).
func NewTracker() *Tracker {
	return &Tracker{
		byDomain: make(map[string]*entry),
		now:      time.Now,
	}
}

// Get returns the current CertRuntimeInfo for a domain, deriving
// Status and Source against the wall-clock at call time. Returns
// (nil, false) when the domain is unknown to the tracker.
func (t *Tracker) Get(domain string) (*CertRuntimeInfo, bool) {
	key := normalizeDomain(domain)
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byDomain[key]
	if !ok {
		return nil, false
	}
	return t.snapshot(e), true
}

// List returns a snapshot of every tracked cert, sorted by
// NotAfter ascending (closest-to-expiry first per §3.2 of the
// spec). The returned slice is freshly allocated; callers may
// iterate / mutate without affecting tracker state.
func (t *Tracker) List() []*CertRuntimeInfo {
	t.mu.RLock()
	out := make([]*CertRuntimeInfo, 0, len(t.byDomain))
	for _, e := range t.byDomain {
		out = append(out, t.snapshot(e))
	}
	t.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].NotAfter.Before(out[j].NotAfter)
	})
	return out
}

// snapshot copies a mutable entry into the wire-shape
// CertRuntimeInfo with Status + LastError fields derived against
// the current wall-clock. Must be called while holding at least
// the read lock — it accesses entry fields directly.
func (t *Tracker) snapshot(e *entry) *CertRuntimeInfo {
	now := t.now()
	// SAN list must never marshal to JSON null. Go nil-slice
	// gotcha: `append([]string(nil), nil...)` returns nil, and
	// encoding/json renders a nil []string as `null`. The
	// frontend's Domaines table reads cert.sanList.length and
	// would crash on null. Force an empty (non-nil) slice when
	// the source entry was created via a path that never
	// populated SANList (placeholder from RecordFailure for a
	// never-seen domain; cert_obtained fallback when the on-disk
	// leaf read failed). Hotfix following T.5 / T.4 deploy.
	sans := append([]string(nil), e.SANList...)
	if sans == nil {
		sans = []string{}
	}
	out := &CertRuntimeInfo{
		Domain:    e.Domain,
		SANList:   sans,
		Issuer:    e.Issuer,
		NotBefore: e.NotBefore,
		NotAfter:  e.NotAfter,
		Source:    e.Source,
	}
	// Status precedence (per spec §2 AC #2): OBTAIN_FAILED fresh →
	// EXPIRED → RENEWAL_PENDING → VALID → UNKNOWN.
	switch {
	case !e.LastErrorAt.IsZero() && now.Sub(e.LastErrorAt) < FailureFreshness:
		out.Status = StatusObtainFailed
		errCopy := e.LastError
		atCopy := e.LastErrorAt
		out.LastError = &errCopy
		out.LastErrorAt = &atCopy
	case e.NotAfter.IsZero():
		// We learned of this domain (via an event) but never got the
		// metadata — bootstrap warm-up window or reconcile-failed.
		out.Status = StatusUnknown
	case !now.Before(e.NotAfter):
		out.Status = StatusExpired
	case e.NotAfter.Sub(now) <= RenewalMargin:
		out.Status = StatusRenewalPending
	default:
		out.Status = StatusValid
	}
	return out
}

// RecordCert seeds or refreshes the persistent metadata for a
// domain. Called by ReconcileFromDisk (boot) and the EventHandler
// on every successful cert_obtained event after re-parsing the
// new on-disk leaf. Idempotent — applying the same metadata twice
// leaves the tracker in the same state.
//
// Source is supplied by the caller because Source detection
// requires knowing the route + managed-domain context, which the
// tracker itself doesn't carry. Reconcile defaults Source to
// SourceSpecific; the event handler upgrades it to wildcard/apex
// when it can infer from the cert's primary subject.
//
// Delegates to RecordCertWithRenewal with renewal=false — every
// pre-U.2 caller treated cert_obtained without renewal context.
// Kept as the legacy entry point so reconcile-from-disk and any
// other historical caller stays signature-compatible.
func (t *Tracker) RecordCert(c *CertRuntimeInfo) {
	t.RecordCertWithRenewal(c, false)
}

// RecordCertWithRenewal is the U.2 variant of RecordCert that
// forwards the certmagic event payload's `renewal` bool through
// the fan-out. The cert_event sink (Step U.2 adapter) uses this
// to distinguish a fresh issue (Renewal=false) from a successful
// renewal (Renewal=true) when persisting the row to cert_event —
// matching certmagic config.go:728 payload semantics (verified
// during T.1 empirical recon).
//
// ReconcileFromDisk continues to call RecordCert (renewal=false)
// because the disk-state path has no signal to disambiguate; the
// cert_event row that would result from a reconcile-replay would
// be a no-op anyway because the listener handles fresh
// cert_obtained events directly.
func (t *Tracker) RecordCertWithRenewal(c *CertRuntimeInfo, renewal bool) {
	if c == nil {
		return
	}
	key := normalizeDomain(c.Domain)
	if key == "" {
		return
	}
	t.mu.Lock()
	e, ok := t.byDomain[key]
	if !ok {
		e = &entry{Domain: key}
		t.byDomain[key] = e
	}
	e.SANList = append([]string(nil), c.SANList...)
	e.Issuer = c.Issuer
	e.NotBefore = c.NotBefore
	e.NotAfter = c.NotAfter
	e.Source = c.Source
	// A fresh cert clears any prior failure — the domain just
	// succeeded, OBTAIN_FAILED is no longer accurate.
	e.LastError = ""
	e.LastErrorAt = time.Time{}
	t.mu.Unlock()

	// Forward-compat seam: fan out a synthetic Event so Subscribe
	// consumers (Step U.2 cert_event sink, future ACME log
	// consumers) see the obtain. IsRenewal reflects the
	// certmagic payload bit when the listener-side caller has
	// it; reconcile-from-disk passes renewal=false because the
	// disk-state path can't disambiguate.
	t.fanOut(Event{
		Kind:      EventCertObtained,
		Domain:    key,
		IsRenewal: renewal,
		Issuer:    c.Issuer,
		At:        t.now(),
	})
}

// RecordFailure annotates a domain with the most recent
// cert_failed payload, surfacing OBTAIN_FAILED status to the wire
// shape for the FailureFreshness window. The volatile failure
// fields are cleared by the next successful RecordCert call.
//
// If the domain has no prior entry (failure on first issuance,
// before any cert exists), a placeholder entry is created with
// zero-value cert metadata; List() will render Status=
// OBTAIN_FAILED with empty NotBefore/NotAfter, which the frontend
// renders by showing the error tooltip without expiry pill.
func (t *Tracker) RecordFailure(domain, errMsg string) {
	key := normalizeDomain(domain)
	if key == "" {
		return
	}
	now := t.now()
	t.mu.Lock()
	e, ok := t.byDomain[key]
	if !ok {
		e = &entry{Domain: key}
		t.byDomain[key] = e
	}
	e.LastError = errMsg
	e.LastErrorAt = now
	t.mu.Unlock()

	t.fanOut(Event{
		Kind:   EventCertFailed,
		Domain: key,
		Error:  errMsg,
		At:     now,
	})
}

// RecordObtaining is the informational "issuance has started"
// hook. The tracker itself doesn't change persistent state; the
// fan-out lets Subscribe consumers see the start signal (Step T+1
// will use it to record the issuance attempt in the events log
// before the outcome is known).
func (t *Tracker) RecordObtaining(domain string) {
	key := normalizeDomain(domain)
	if key == "" {
		return
	}
	t.fanOut(Event{
		Kind:   EventCertObtaining,
		Domain: key,
		At:     t.now(),
	})
}

// RecordRevoked is the OCSP-revocation hook (Step U.2). Mirror
// of RecordObtaining: fan-out only, NO state mutation. The
// cert may still serve requests until certmagic replaces it
// (per spec §3.6 — the tracker's Status enum has no REVOKED
// value because the cert remains operationally VALID from the
// reverse-proxy's POV). The signal is persisted as a
// security-relevant event in the cert_event table via the
// adapter that subscribes to the tracker's fan-out.
//
// Caddy v2.11.3 / certmagic v0.25.3 emit cert_ocsp_revoked at
// maintain.go:375 with payload {identifier, certificate};
// caddymgr's events subscription was extended in U.2 to
// include the event name, and listener.go dispatches to this
// method.
func (t *Tracker) RecordRevoked(domain string) {
	key := normalizeDomain(domain)
	if key == "" {
		return
	}
	t.fanOut(Event{
		Kind:   EventCertOCSPRevoked,
		Domain: key,
		At:     t.now(),
	})
}

// Remove purges a single entry from the in-memory cache and
// returns true when an entry was actually present. Called by the
// DELETE managed-domain API handler after a successful caddy reload
// so OBTAIN_FAILED ghost rows (for the apex that no longer exists
// in the managed-domain list) don't linger in /certs.
//
// Necessary because certmagic / Caddy v2.11.3 emit no cert-removal
// event (verified empirically against the vendored sources): the
// only paths into the tracker are the three Record* methods called
// from certmagic events, none of which trigger on a managed-domain
// removal. Without this hook the only way to clear a ghost was an
// Arenet restart, which is the recovery shape Step T was supposed
// to eliminate.
//
// Fans out an EventCertRemoved synthetic event so Step T+1's ACME
// events log captures the purge through the existing Subscribe
// seam, no separate hook needed.
func (t *Tracker) Remove(domain string) bool {
	key := normalizeDomain(domain)
	if key == "" {
		return false
	}
	t.mu.Lock()
	_, existed := t.byDomain[key]
	if existed {
		delete(t.byDomain, key)
	}
	t.mu.Unlock()
	if existed {
		t.fanOut(Event{
			Kind:   EventCertRemoved,
			Domain: key,
			At:     t.now(),
		})
	}
	return existed
}

// Subscribe attaches an EventHandler to the fan-out. Returns an
// unsubscribe function the caller invokes on shutdown — the
// tracker holds no lifecycle of its own beyond the subscriber
// list. Subscribers attached during T are forward-compat (no
// production consumer in T); the seam exists for T+1.
func (t *Tracker) Subscribe(h EventHandler) func() {
	if h == nil {
		return func() {}
	}
	t.subsMu.Lock()
	t.subs = append(t.subs, h)
	idx := len(t.subs) - 1
	t.subsMu.Unlock()
	return func() {
		t.subsMu.Lock()
		// Swap-with-last + truncate; order-preserving deletion
		// would be wasted work for the forward-compat seam.
		if idx >= 0 && idx < len(t.subs) {
			t.subs[idx] = nil
		}
		t.subsMu.Unlock()
	}
}

// fanOut dispatches an Event to every attached subscriber. Each
// handler runs synchronously; a panicking handler is recovered so
// one consumer's bug can't take down the tracker's main job.
func (t *Tracker) fanOut(e Event) {
	t.subsMu.RLock()
	handlers := make([]EventHandler, 0, len(t.subs))
	for _, h := range t.subs {
		if h != nil {
			handlers = append(handlers, h)
		}
	}
	t.subsMu.RUnlock()
	for _, h := range handlers {
		dispatch(h, e)
	}
}

// dispatch isolates the panic-recover boundary so a single handler
// crash doesn't take down the tracker's main goroutine. The
// recovered panic is silently dropped — Subscribe consumers are
// internal Arenet code, not user-supplied; a panic is a bug to
// fix in the consumer, not a runtime situation the tracker should
// react to.
func dispatch(h EventHandler, e Event) {
	defer func() {
		_ = recover()
	}()
	h.HandleCertEvent(e)
}

// SetNow injects a clock for tests. Production callers never need
// to touch this — NewTracker installs time.Now by default.
func (t *Tracker) SetNow(now func() time.Time) {
	t.mu.Lock()
	if now == nil {
		t.now = time.Now
	} else {
		t.now = now
	}
	t.mu.Unlock()
}

// normalizeDomain lowercases + trims so lookup/store keys are
// canonical. The certmagic event payload's "identifier" field
// is the literal subject from the cert request — typically
// already canonical, but a defensive trim costs nothing.
func normalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}
