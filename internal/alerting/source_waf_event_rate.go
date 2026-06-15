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

package alerting

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/observability"
)

// AL.2.a — waf_event_rate Source.
//
// Counts waf_event rows matching the operator-supplied
// filter over a sliding window ending at "now". Returns
// the count as a SourceValue.Float so a ThresholdEvaluator
// can compare it against a per-rule limit.
//
// Reader audit (see commit body): the *observability.Store
// already exposes QueryWafEvents(ctx, WafEventFilter)
// returning []WafEvent. The Filter supports RouteID +
// Category + From + To + Limit but NOT Action — this
// source filters Action client-side post-query. The
// homelab tick volume (≤ a few hundred rows per minute on
// a busy day) keeps the in-memory filter cost trivial.

// WafEventRateParams is the Source.Read params shape.
type WafEventRateParams struct {
	// RouteID narrows the count to one route. Empty =
	// count across all routes.
	RouteID string `json:"routeId,omitempty"`
	// Category narrows by OWASP CRS category (operator
	// supplies "anomaly", "sqli", ...). Empty = all
	// categories.
	Category string `json:"category,omitempty"`
	// Action filters the rows post-query. Allowed:
	// "BLOCK" (count only block-mode events), "DETECT"
	// (count only detect-mode), "" (count all).
	Action string `json:"action,omitempty"`
	// WindowSecs is the lookback window in seconds. Range
	// [60, 86400]. Defaults to 300 (5 minutes) when zero.
	WindowSecs int `json:"windowSecs"`
}

const (
	wafEventRateDefaultWindowSecs = 300
	wafEventRateMinWindowSecs     = 60
	wafEventRateMaxWindowSecs     = 86400
	// wafEventRateQueryCap defensively bounds the rows
	// pulled back from QueryWafEvents. A busy homelab on
	// a 1h window may exceed the default cap; we raise it
	// to 10k here. A real "DDoS" window producing > 10k
	// rows in 1h is the threshold rule's point — the
	// count saturates at 10k but the rule still fires.
	// Surfacing this as a label on AlertEvent helps the
	// operator interpret the saturated count.
	wafEventRateQueryCap = 10000
)

// wafActions enumerates the allowed Action filter tokens.
var wafActions = []string{"", "BLOCK", "DETECT"}

// WafEventReader is the seam the source reads through.
// *observability.Store satisfies it via QueryWafEvents.
// Declared on the consumer side so the alerting package
// doesn't take a structural dep on the store's broader
// surface.
type WafEventReader interface {
	QueryWafEvents(ctx context.Context, filter observability.WafEventFilter) ([]observability.WafEvent, error)
}

// WafEventRateSource counts waf_event rows.
type WafEventRateSource struct {
	reader WafEventReader
	now    func() time.Time // injectable for tests
}

// NewWafEventRateSource constructs the source. reader may
// be nil — Read returns an error so the watcher records
// "observability disabled" rather than panicking. This
// matches the AC #13 degraded-observability contract.
func NewWafEventRateSource(reader WafEventReader) *WafEventRateSource {
	return &WafEventRateSource{
		reader: reader,
		now:    time.Now,
	}
}

// Name implements Source.
func (s *WafEventRateSource) Name() string { return "waf_event_rate" }

// ValidateParams implements Source.
func (s *WafEventRateSource) ValidateParams(raw json.RawMessage) error {
	var p WafEventRateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("waf_event_rate: params not valid JSON: %w", err)
	}
	if !stringInSlice(p.Action, wafActions) {
		return fmt.Errorf("waf_event_rate: action %q must be one of %v",
			p.Action, wafActions)
	}
	w := p.WindowSecs
	if w == 0 {
		w = wafEventRateDefaultWindowSecs
	}
	if w < wafEventRateMinWindowSecs || w > wafEventRateMaxWindowSecs {
		return fmt.Errorf("waf_event_rate: windowSecs %d out of range [%d, %d]",
			p.WindowSecs, wafEventRateMinWindowSecs, wafEventRateMaxWindowSecs)
	}
	return nil
}

// Read implements Source.
func (s *WafEventRateSource) Read(ctx context.Context, raw json.RawMessage) (SourceValue, error) {
	if s.reader == nil {
		return SourceValue{}, errors.New("waf_event_rate: observability reader not wired (boot-degraded)")
	}

	var p WafEventRateParams
	if err := json.Unmarshal(raw, &p); err != nil {
		return SourceValue{}, fmt.Errorf("waf_event_rate: params decode: %w", err)
	}
	if p.WindowSecs == 0 {
		p.WindowSecs = wafEventRateDefaultWindowSecs
	}

	now := s.now()
	filter := observability.WafEventFilter{
		RouteID:  p.RouteID,
		Category: p.Category,
		From:     now.Add(-time.Duration(p.WindowSecs) * time.Second),
		To:       now,
		Limit:    wafEventRateQueryCap,
	}
	events, err := s.reader.QueryWafEvents(ctx, filter)
	if err != nil {
		return SourceValue{}, fmt.Errorf("waf_event_rate: query: %w", err)
	}

	// Action filter applied client-side (the observability
	// filter has no Action column field). Empty Action =
	// count everything.
	count := 0
	wantAction := strings.ToUpper(p.Action)
	for _, e := range events {
		if wantAction != "" && strings.ToUpper(e.Action) != wantAction {
			continue
		}
		count++
	}

	labels := map[string]string{
		"window_secs": fmt.Sprintf("%d", p.WindowSecs),
	}
	if p.RouteID != "" {
		labels["route_id"] = p.RouteID
	}
	if p.Category != "" {
		labels["category"] = p.Category
	}
	if p.Action != "" {
		labels["action"] = p.Action
	}
	// Surface query-cap saturation so the operator knows
	// the count is a lower bound when the cap was hit.
	if len(events) >= wafEventRateQueryCap {
		labels["query_capped"] = "true"
	}

	v := FloatValue(float64(count))
	v.Labels = labels
	return v, nil
}
