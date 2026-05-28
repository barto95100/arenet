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

import (
	"math"
	"sync/atomic"
)

// histogramBuckets is the number of log-spaced buckets covering
// the realistic HTTP latency range. With histogramBaseMs=0.5 and
// 17 buckets, the top bucket has upper edge 0.5 * 2^17 = 65536 ms
// (~65 s) — past Caddy's default upstream timeout, so anything
// slower than that saturates the last bucket and is reported as
// "≥ 65 s". 17 * 8 bytes = 136 B per route, fits comfortably in
// two cache lines.
const histogramBuckets = 17

// histogramBaseMs is the lower edge of bucket 0. Anything below
// this latency saturates bucket 0; anything above the upper edge
// of bucket 63 saturates the last bucket.
const histogramBaseMs = 0.5

// LatencyHistogram is a fixed-bucket, lock-free latency
// distribution for one route. Bucket i covers
// [histogramBaseMs * 2^i, histogramBaseMs * 2^(i+1)) ms.
//
// Observe is allocation-free and lock-free (one atomic.AddUint64
// per call), making it safe to call from the Caddy request path
// without contention or I/O — the AC #13 invariant.
//
// P95 is read-side only and is called by the background flush
// goroutine, never by request handlers.
type LatencyHistogram struct {
	counts [histogramBuckets]uint64
}

// Observe records one request whose duration was durMs
// milliseconds. Safe for concurrent use from any number of
// goroutines.
func (h *LatencyHistogram) Observe(durMs float64) {
	idx := bucketIndex(durMs)
	atomic.AddUint64(&h.counts[idx], 1)
}

// P95 returns the upper edge of the bucket where the cumulative
// count first crosses 95 % of the total. Returns 0 when no
// observations have been recorded (caller decides whether to
// render that as null on the timeline per AC #5).
func (h *LatencyHistogram) P95() float64 {
	return h.percentile(0.95)
}

// Snapshot returns the current bucket counts and the total count.
// The returned array is a copy — safe to retain across resets.
func (h *LatencyHistogram) Snapshot() ([histogramBuckets]uint64, uint64) {
	var out [histogramBuckets]uint64
	var total uint64
	for i := range h.counts {
		c := atomic.LoadUint64(&h.counts[i])
		out[i] = c
		total += c
	}
	return out, total
}

// Reset clears all buckets. Called by the flush goroutine after
// snapshotting at the minute boundary.
func (h *LatencyHistogram) Reset() {
	for i := range h.counts {
		atomic.StoreUint64(&h.counts[i], 0)
	}
}

func (h *LatencyHistogram) percentile(p float64) float64 {
	snap, total := h.Snapshot()
	if total == 0 {
		return 0
	}
	threshold := uint64(math.Ceil(float64(total) * p))
	if threshold == 0 {
		threshold = 1
	}
	var cum uint64
	for i, c := range snap {
		cum += c
		if cum >= threshold {
			return bucketUpperEdgeMs(i)
		}
	}
	return bucketUpperEdgeMs(histogramBuckets - 1)
}

// bucketIndex maps a duration in ms to its bucket. Values below
// histogramBaseMs (including zero and negatives from a buggy
// clock) land in bucket 0; values past the top edge saturate the
// last bucket.
func bucketIndex(durMs float64) int {
	if durMs < histogramBaseMs {
		return 0
	}
	idx := int(math.Log2(durMs / histogramBaseMs))
	if idx < 0 {
		return 0
	}
	if idx >= histogramBuckets {
		return histogramBuckets - 1
	}
	return idx
}

// bucketUpperEdgeMs returns the upper edge of bucket i in ms.
func bucketUpperEdgeMs(i int) float64 {
	return histogramBaseMs * math.Pow(2, float64(i+1))
}
