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
	"testing"
	"time"

	"github.com/barto95100/arenet/internal/automation"
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
