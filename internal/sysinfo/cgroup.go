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

package sysinfo

import (
	"math"
	"strconv"
	"strings"
)

// limits is what the cgroup says this process may use, as opposed to
// what the machine has.
//
// Field semantics verified against the kernel's cgroup-v2 admin guide
// rather than recalled:
//   - memory.max      — bytes, or the literal "max" for no limit
//   - memory.current  — bytes in use by the cgroup and its children
//   - cpu.max         — "$MAX $PERIOD" in microseconds; "$MAX" is the
//     literal "max" when unlimited, default period
//     100000
//
// cgroup v1 spells the same three as memory.limit_in_bytes,
// memory.usage_in_bytes and cpu.cfs_quota_us / cpu.cfs_period_us, and
// signals "no limit" with a sentinel close to the 64-bit maximum
// rather than a keyword.
type limits struct {
	containerised bool
	memLimit      uint64
	memUsed       uint64
	// cpuCores is the quota expressed in whole-core equivalents,
	// rounded up: half a core still needs a core to run on, and
	// reporting 0 would read as "no CPU at all".
	cpuCores int
}

// cgroupV1NoLimit is how cgroup v1 spells "unlimited": a value near
// the 64-bit ceiling, page-aligned by the kernel. Anything at or
// above this is not a limit anybody set.
const cgroupV1NoLimit = uint64(math.MaxInt64) &^ 4095

func (r *Reader) cgroupLimits() limits {
	var l limits

	// Docker's marker file, and the cgroup path, are both weak on
	// their own — podman does not write /.dockerenv, and a bare
	// systemd service also lives in a named cgroup. A limit actually
	// being set is the signal that matters, so containerised is also
	// raised below whenever one is found.
	if _, ok := r.read(".dockerenv"); ok {
		l.containerised = true
	}
	if s, ok := r.read("proc/self/cgroup"); ok && strings.Contains(s, "/docker/") {
		l.containerised = true
	}

	if r.cgroupV2(&l) {
		return l
	}
	r.cgroupV1(&l)
	return l
}

// cgroupV2 reads the unified hierarchy. Returns false when this host
// is not on v2, so the caller can fall back.
func (r *Reader) cgroupV2(l *limits) bool {
	if _, ok := r.read("sys/fs/cgroup/cgroup.controllers"); !ok {
		return false
	}
	if s, ok := r.read("sys/fs/cgroup/memory.max"); ok {
		if v, unlimited := parseV2Limit(s); !unlimited && v > 0 {
			l.memLimit, l.containerised = v, true
		}
	}
	if s, ok := r.read("sys/fs/cgroup/memory.current"); ok {
		l.memUsed = parseUint(s)
	}
	if s, ok := r.read("sys/fs/cgroup/cpu.max"); ok {
		if cores, have := parseCPUMax(s); have {
			l.cpuCores, l.containerised = cores, true
		}
	}
	return true
}

func (r *Reader) cgroupV1(l *limits) {
	if s, ok := r.read("sys/fs/cgroup/memory/memory.limit_in_bytes"); ok {
		if v := parseUint(s); v > 0 && v < cgroupV1NoLimit {
			l.memLimit, l.containerised = v, true
		}
	}
	if s, ok := r.read("sys/fs/cgroup/memory/memory.usage_in_bytes"); ok {
		l.memUsed = parseUint(s)
	}
	quotaRaw, okQ := r.read("sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	periodRaw, okP := r.read("sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if okQ && okP {
		// A quota of -1 is v1's "no limit".
		quota, err := strconv.ParseInt(strings.TrimSpace(quotaRaw), 10, 64)
		period := parseUint(periodRaw)
		if err == nil && quota > 0 && period > 0 {
			l.cpuCores, l.containerised = coresFrom(uint64(quota), period), true
		}
	}
}

// parseV2Limit returns the byte value, or unlimited for "max".
func parseV2Limit(s string) (value uint64, unlimited bool) {
	t := strings.TrimSpace(s)
	if t == "max" {
		return 0, true
	}
	return parseUint(t), false
}

// parseCPUMax reads "$MAX $PERIOD", both in microseconds.
func parseCPUMax(s string) (int, bool) {
	f := strings.Fields(strings.TrimSpace(s))
	if len(f) != 2 || f[0] == "max" {
		return 0, false
	}
	quota, period := parseUint(f[0]), parseUint(f[1])
	if quota == 0 || period == 0 {
		return 0, false
	}
	return coresFrom(quota, period), true
}

// coresFrom turns a quota/period pair into whole cores, rounded up.
func coresFrom(quota, period uint64) int {
	cores := int((quota + period - 1) / period)
	if cores < 1 {
		cores = 1
	}
	return cores
}

func parseUint(s string) uint64 {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return v
}
