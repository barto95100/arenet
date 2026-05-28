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

package observability

import "time"

// MetricBucket is one aggregated time window for one route.
// Persisted to SQLite; the same struct shape is used for both
// 1-minute and 1-hour buckets (the destination table tells them
// apart, not the struct).
//
// Note: LatencyP95Ms is stored as 0 when no samples landed in
// the bucket — the REST API projection layer maps that to JSON
// null per AC #5 (a "0 ms p95" would render as a fake latency
// dip on the timeline chart).
type MetricBucket struct {
	RouteID      string
	Ts           time.Time
	ReqCount     int64
	FourxxCount  int64
	FivexxCount  int64
	LatencyP95Ms int32
}

// Granularity selects the destination table for Insert / Query.
type Granularity int

const (
	// Granularity1m maps to bucket_1m (60-second windows).
	Granularity1m Granularity = iota
	// Granularity1h maps to bucket_1h (3600-second windows).
	Granularity1h
)

func (g Granularity) tableName() string {
	switch g {
	case Granularity1h:
		return "bucket_1h"
	default:
		return "bucket_1m"
	}
}

// Step returns the bucket size for this granularity.
func (g Granularity) Step() time.Duration {
	switch g {
	case Granularity1h:
		return time.Hour
	default:
		return time.Minute
	}
}
