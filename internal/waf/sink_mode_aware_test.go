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

package waf

import (
	"context"
	"testing"
	"time"
)

// snapshot returns a flat copy of every event the inserter
// has received across all batches. Local helper on the
// recordingInserter type defined in sink_test.go; kept here
// (in the W.bugfix test file) so the new test surface stays
// scope-distinct from the pre-W.bugfix coverage.
func (r *recordingInserter) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, 0)
	for _, b := range r.batches {
		out = append(out, b...)
	}
	return out
}

// W.bugfix Fix #1 — mode-aware sink labels. Pre-fix the sink
// stamped no Action and the frontend hardcoded "BLOCK 403"
// labels regardless of mode. These tests pin the new contract:
// detect-mode events are persisted with Action="DETECT" and
// status=0 (so the frontend renders "—" for the upstream
// status that isn't known at WAF callback time), and the
// block-volume counter only bumps for ActionBlock events
// (detect-mode rule fires no longer inflate the dashboard's
// "WAF blocks per minute" tile).

// TestSinkEmit_DetectMode_PersistsActionDetect — a detect-mode
// event reaches the inserter with Action=DETECT + StatusCode=0
// (the frontend renders the latter as "—"). Pre-fix it would
// have reached with Action="" (zero value) and the frontend
// lied. The test asserts the post-fix contract end-to-end
// (Emit → absorb → flush → inserter).
func TestSinkEmit_DetectMode_PersistsActionDetect(t *testing.T) {
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Event{
		RouteID: "r1", SrcIP: "1.2.3.4", RuleID: "920420",
		Ts: time.Now(), Action: ActionDetect, StatusCode: 0,
	})
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-s.Done()

	all := rec.snapshot()
	if len(all) != 1 {
		t.Fatalf("inserter received %d events; want 1", len(all))
	}
	got := all[0]
	if got.Action != ActionDetect {
		t.Errorf("inserter event Action = %q; want %q", got.Action, ActionDetect)
	}
	if got.StatusCode != 0 {
		t.Errorf("inserter event StatusCode = %d; want 0 (detect = upstream status unknown at WAF time)", got.StatusCode)
	}
}

// TestSinkEmit_BlockMode_PersistsActionBlock — symmetric to
// the detect-mode test. Pin the block-mode contract:
// Action=BLOCK + StatusCode=403.
func TestSinkEmit_BlockMode_PersistsActionBlock(t *testing.T) {
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval: 20 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	s.Emit(Event{
		RouteID: "r1", SrcIP: "1.2.3.4", RuleID: "942100",
		Ts: time.Now(), Action: ActionBlock, StatusCode: 403,
	})
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-s.Done()

	all := rec.snapshot()
	if len(all) != 1 {
		t.Fatalf("inserter received %d events; want 1", len(all))
	}
	got := all[0]
	if got.Action != ActionBlock {
		t.Errorf("inserter event Action = %q; want %q", got.Action, ActionBlock)
	}
	if got.StatusCode != 403 {
		t.Errorf("inserter event StatusCode = %d; want 403", got.StatusCode)
	}
}

// TestSink_BlockCounter_DetectModeDoesNotBump — the dashboard's
// per-minute WAF block timeseries is the operator's signal for
// actual enforcement. Pre-fix every absorbed event bumped the
// counter, so detect-mode rule fires inflated the "blocks per
// minute" tile the same way the labels lied. Post-fix, only
// ActionBlock events bump.
func TestSink_BlockCounter_DetectModeDoesNotBump(t *testing.T) {
	rec := &recordingInserter{}
	counter := newRecordingCounter()
	s := NewSink(rec, counter, silentLogger(), SinkConfig{
		FlushInterval:  20 * time.Millisecond,
		FlushBatchSize: 1000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go s.Run(ctx)

	// 50 detect-mode events + 50 block-mode events. Counter
	// must reflect ONLY the 50 blocks.
	for i := 0; i < 50; i++ {
		s.Emit(Event{
			RouteID: "r1", SrcIP: "1.2.3.4", RuleID: "920420",
			Ts:     time.Now().Add(time.Duration(i) * time.Microsecond),
			Action: ActionDetect, StatusCode: 0,
		})
	}
	for i := 0; i < 50; i++ {
		s.Emit(Event{
			RouteID: "r1", SrcIP: "5.6.7.8", RuleID: "942100",
			Ts:     time.Now().Add(time.Duration(i) * time.Microsecond),
			Action: ActionBlock, StatusCode: 403,
		})
	}
	time.Sleep(200 * time.Millisecond)
	cancel()
	<-s.Done()

	if got := counter.total(); got != 50 {
		t.Errorf("BumpWafBlocks total = %d; want 50 (only ActionBlock events bump; detect-mode events do not inflate the block-volume timeseries)", got)
	}
}

// TestSinkEmit_PreservesRuleMetadataAcrossModes — Fix #1 must
// not regress the existing metadata capture. Pin that the
// rule_id, category, severity, src_ip, request_path,
// payload_sample all round-trip alongside the new Action +
// StatusCode fields. Pre-fix coverage existed for these
// fields but only on block-mode events.
func TestSinkEmit_PreservesRuleMetadataAcrossModes(t *testing.T) {
	for _, action := range []string{ActionBlock, ActionDetect} {
		t.Run(action, func(t *testing.T) {
			rec := &recordingInserter{}
			s := NewSink(rec, newRecordingCounter(), silentLogger(), SinkConfig{
				FlushInterval: 20 * time.Millisecond,
			})
			ctx, cancel := context.WithCancel(context.Background())
			go s.Run(ctx)

			statusCode := 0
			if action == ActionBlock {
				statusCode = 403
			}
			in := Event{
				RouteID:       "route-uuid",
				RuleID:        "920420",
				Category:      CategoryProtocol,
				Severity:      3,
				SrcIP:         "203.0.113.5",
				RequestMethod: "GET",
				RequestPath:   "/auth/login_flow",
				PayloadSample: "User-Agent: () { :; };",
				Ts:            time.Now(),
				Action:        action,
				StatusCode:    statusCode,
			}
			s.Emit(in)
			time.Sleep(60 * time.Millisecond)
			cancel()
			<-s.Done()

			all := rec.snapshot()
			if len(all) != 1 {
				t.Fatalf("inserter received %d events; want 1", len(all))
			}
			got := all[0]
			// Metadata must round-trip verbatim.
			checks := map[string]bool{
				"RouteID":       got.RouteID == in.RouteID,
				"RuleID":        got.RuleID == in.RuleID,
				"Category":      got.Category == in.Category,
				"Severity":      got.Severity == in.Severity,
				"SrcIP":         got.SrcIP == in.SrcIP,
				"RequestMethod": got.RequestMethod == in.RequestMethod,
				"RequestPath":   got.RequestPath == in.RequestPath,
				"PayloadSample": got.PayloadSample == in.PayloadSample,
				"Action":        got.Action == in.Action,
				"StatusCode":    got.StatusCode == in.StatusCode,
			}
			for field, ok := range checks {
				if !ok {
					t.Errorf("field %s did not round-trip", field)
				}
			}
		})
	}
}
