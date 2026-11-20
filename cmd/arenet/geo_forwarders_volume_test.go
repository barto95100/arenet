// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/automation"
	"github.com/barto95100/arenet/internal/geo"
	"github.com/barto95100/arenet/internal/throttle"
	"github.com/barto95100/arenet/internal/waf"
)

// TestGeoForwardingWafSink_FeedsVolumeBlockOnly pins the v2.83.1 pre-LRU tap
// AND the v2.58.4 invariant at its new home: the WAF forwarder feeds the
// volume tracker for a BLOCK event but NOT for a DETECT event (detect mode
// lets the request through — counting it could ban a source the WAF chose not
// to block). bus/enricher/inner are nil (nil-safe); only the tap is exercised.
func TestGeoForwardingWafSink_FeedsVolumeBlockOnly(t *testing.T) {
	now := time.Now()
	tr := automation.NewVolumeTracker(func() time.Time { return now })
	sink := geoForwardingWafSink{volume: tr}

	// A DETECT event must NOT be observed.
	sink.Emit(waf.Event{
		Ts: now.Add(-time.Second), SrcIP: "9.9.9.9",
		Category: waf.CategoryRCE, Action: waf.ActionDetect, RuleID: "932160",
	})
	// A BLOCK event must be observed.
	sink.Emit(waf.Event{
		Ts: now.Add(-time.Second), SrcIP: "1.2.3.4",
		Category: waf.CategoryRCE, Action: waf.ActionBlock, RuleID: "932160",
	})

	got, err := tr.QueryWafEvents(context.Background(), automation.WafFilter{
		From: now.Add(-time.Minute), To: now,
	})
	if err != nil {
		t.Fatalf("QueryWafEvents: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("tracker holds %d events, want 1 (block only, detect excluded)", len(got))
	}
	if got[0].SrcIP != "1.2.3.4" || got[0].Source != automation.SourceWafRCE {
		t.Errorf("observed %+v, want the BLOCK event from 1.2.3.4 (waf-rce)", got[0])
	}
}

// TestGeoForwardingThrottleSink_FeedsVolume pins the throttle tap: every
// throttle event (all are refusals) is observed.
func TestGeoForwardingThrottleSink_FeedsVolume(t *testing.T) {
	now := time.Now()
	tr := automation.NewVolumeTracker(func() time.Time { return now })
	sink := geoForwardingThrottleSink{volume: tr}

	sink.Emit(throttle.Event{Ts: now.Add(-time.Second), Tier: 1, SrcIP: "1.2.3.4"})

	got, err := tr.QueryThrottleEvents(context.Background(), automation.ThrottleFilter{
		From: now.Add(-time.Minute), To: now,
	})
	if err != nil {
		t.Fatalf("QueryThrottleEvents: %v", err)
	}
	if len(got) != 1 || got[0].Source != automation.SourceThrottleTier1 {
		t.Fatalf("throttle tracker = %+v, want one throttle-tier1", got)
	}
}

// --- G7 (v2.84.0 dogfood regression guard) -----------------------------------
//
// The v2.84.0 dogfood on AreNET-test (geoip_mmdb=unset) saw 0 bans from a WAF
// burst, with the hypothesis that the D12 GeoEnricher refactor had starved the
// D11 volume feed. The unit guards (G1/G2) feed the tracker directly and use a
// FAKE enricher, so neither exercised the PRODUCTION chain with an unset-MMDB
// geo lookup. G7 closes that gap: it wires the real geoForwardingWafSink → the
// real VolumeTracker → the trigger engine → a writer, with NO MMDB (the
// production geoSourceEnricher over empty, reader-less geo.Lookup/ASNLookup —
// the exact degraded shape of an unset-MMDB boot), and asserts a 4-event RCE
// burst still fires exactly one ban. It fails if the forwarder stops feeding
// the tracker, if the degraded enricher ever short-circuits the push, or if the
// enrichment path panics on an empty lookup.

type g7Writer struct {
	mu     sync.Mutex
	alerts []automation.Alert
}

func (w *g7Writer) EnsureJWT(context.Context) (string, error) { return "jwt", nil }
func (w *g7Writer) PushAlert(_ context.Context, a automation.Alert) ([]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.alerts = append(w.alerts, a)
	return []string{"1"}, nil
}
func (w *g7Writer) LoginFailed() bool { return false }
func (w *g7Writer) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.alerts)
}
func (w *g7Writer) last() automation.Alert {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.alerts[len(w.alerts)-1]
}

// The burst is WAF-only; audit reader/emitter are no-op stubs.
type g7NoAuditReader struct{}

func (g7NoAuditReader) QueryAuthFailureEvents(context.Context, time.Time, time.Time, int) ([]automation.SourceEvent, error) {
	return nil, nil
}

type g7NoAuditEmitter struct{}

func (g7NoAuditEmitter) EmitDecisionPushed(string, string, string, int, int) {}

func TestAutomationChain_BansWithoutMMDB_EndToEnd(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	tr := automation.NewVolumeTracker(clock)

	// Real production WAF forwarder in the unset-MMDB shape: no bus, no
	// enricher, no inner sink — only the volume tap.
	sink := geoForwardingWafSink{volume: tr}
	for i := 0; i < 4; i++ {
		sink.Emit(waf.Event{
			Ts:       now.Add(-time.Duration(i+1) * time.Second),
			SrcIP:    "185.23.40.4",
			Category: waf.CategoryRCE,
			Action:   waf.ActionBlock,
			RuleID:   "932160",
		})
	}

	rs := automation.RuleSet{Rules: map[automation.Source]automation.Rule{
		automation.SourceWafRCE: {
			Enabled:   true,
			Threshold: 2,
			Window:    60 * time.Second,
			Duration:  time.Hour,
			Cooldown:  24 * time.Hour,
		},
	}}

	writer := &g7Writer{}
	e, err := automation.NewEngine(automation.EngineConfig{
		Waf:          tr,
		Throttle:     tr,
		Audit:        g7NoAuditReader{},
		Rules:        automation.NewRuleSetHolder(rs),
		Writer:       writer,
		AuditEmitter: g7NoAuditEmitter{},
		// The exact unset-MMDB production enricher: empty, reader-less lookups
		// (non-nil pointers, as main.go builds them when no MMDB is present).
		// LookupIP / LookupASN return the degraded empty result; buildAlert must
		// still push the ban.
		GeoEnricher:  geoSourceEnricher{geo: &geo.Lookup{}, asn: &geo.ASNLookup{}},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		TickInterval: 20 * time.Millisecond,
		Now:          clock,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go e.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && writer.count() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(120 * time.Millisecond) // expose a re-emit (D8 guard)
	cancel()
	<-e.Done()

	if writer.count() != 1 {
		t.Fatalf("alertCount=%d, want exactly 1 (4 RCE blocks through the real forwarder, no MMDB)", writer.count())
	}
	a := writer.last()
	if a.Scenario != "arenet/waf-rce" || a.Source.Value != "185.23.40.4" {
		t.Errorf("alert=%+v, want arenet/waf-rce from 185.23.40.4", a)
	}
	// D12 soft-fail: no MMDB → geo fields empty, and the ban still fired.
	if a.Source.Cn != "" || a.Source.AsNumber != "" || a.Source.AsName != "" {
		t.Errorf("geo fields should be empty without MMDB, got cn=%q as_number=%q as_name=%q",
			a.Source.Cn, a.Source.AsNumber, a.Source.AsName)
	}
}
