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

package sysinfo

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reader produces snapshots. It holds one piece of state — the
// previous CPU sample — because processor usage is a rate, and a rate
// needs two readings. Safe for concurrent use.
type Reader struct {
	// root is "/" in production and a fixture directory in tests, so
	// the parsers are exercised against known bytes rather than
	// against whichever machine runs the suite.
	root string
	// dataDir is the directory whose free space matters: the
	// database, the backups and the logs live there.
	dataDir   string
	startedAt time.Time

	mu       sync.Mutex
	prevCPU  cpuSample
	haveCPU  bool
	nowFn    func() time.Time
	hostname func() (string, error)
}

// cpuSample is one reading of /proc/stat's aggregate line.
type cpuSample struct {
	total uint64
	idle  uint64
}

// New returns a Reader rooted at the real filesystem.
func New(dataDir string) *Reader {
	return NewWithRoot("/", dataDir)
}

// NewWithRoot is New with the filesystem root overridden, for tests.
func NewWithRoot(root, dataDir string) *Reader {
	return &Reader{
		root:      root,
		dataDir:   dataDir,
		startedAt: time.Now(),
		nowFn:     time.Now,
		hostname:  os.Hostname,
	}
}

// Snapshot reads everything once.
//
// It never fails: a file that cannot be read leaves its fields empty
// rather than turning the whole page into an error. A supervision
// view that disappears when one number is missing is worse than one
// that shows the numbers it has.
func (r *Reader) Snapshot() Snapshot {
	snap := Snapshot{Timestamp: r.nowFn().UTC().Format(time.RFC3339)}
	snap.Process = r.process()

	if !r.procAvailable() {
		snap.Unsupported = "host metrics need /proc, which this platform does not provide; " +
			"Arenet's own figures below are still accurate"
		snap.Host.Arch = runtime.GOARCH
		if h, err := r.hostname(); err == nil {
			snap.Host.Hostname = h
		}
		snap.Disk = r.disk()
		return snap
	}

	limits := r.cgroupLimits()
	snap.Host = r.host(limits)
	snap.CPU = r.cpu(limits)
	snap.Memory = r.memory(limits)
	snap.Disk = r.disk()
	return snap
}

func (r *Reader) path(p string) string { return filepath.Join(r.root, p) }

func (r *Reader) read(p string) (string, bool) {
	b, err := os.ReadFile(r.path(p))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// procAvailable gates everything /proc-derived. Reading /proc/meminfo
// is the check rather than runtime.GOOS: a Linux binary in a sandbox
// without /proc must degrade the same way macOS does.
func (r *Reader) procAvailable() bool {
	_, ok := r.read("proc/meminfo")
	return ok
}

// --- host ------------------------------------------------------

func (r *Reader) host(l limits) Host {
	h := Host{Arch: runtime.GOARCH, Containerised: l.containerised}
	if name, err := r.hostname(); err == nil {
		h.Hostname = name
	}
	if s, ok := r.read("proc/sys/kernel/osrelease"); ok {
		h.Kernel = strings.TrimSpace(s)
	}
	if s, ok := r.read("etc/os-release"); ok {
		h.OS = prettyName(s)
	}
	if s, ok := r.read("proc/uptime"); ok {
		// "12345.67 98765.43" — seconds since boot, then idle time.
		if f := strings.Fields(s); len(f) > 0 {
			if v, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.UptimeSeconds = int64(v)
			}
		}
	}
	return h
}

// prettyName pulls PRETTY_NAME out of os-release, quotes stripped.
func prettyName(osRelease string) string {
	for _, line := range strings.Split(osRelease, "\n") {
		name, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found && name == "PRETTY_NAME" {
			return strings.Trim(strings.TrimSpace(value), `"`)
		}
	}
	return ""
}

// --- cpu -------------------------------------------------------

func (r *Reader) cpu(l limits) CPU {
	c := CPU{HostCores: runtime.NumCPU(), Cores: runtime.NumCPU(), Source: SourceHost}
	if s, ok := r.read("proc/cpuinfo"); ok {
		c.Model = cpuModel(s)
	}
	if l.cpuCores > 0 {
		// A quota is a smaller allowance, not a smaller machine, so
		// both numbers are reported and the source says which is the
		// binding one.
		c.Cores = l.cpuCores
		c.Source = SourceContainer
	}
	if s, ok := r.read("proc/loadavg"); ok {
		f := strings.Fields(s)
		if len(f) >= 3 {
			c.Load1, _ = strconv.ParseFloat(f[0], 64)
			c.Load5, _ = strconv.ParseFloat(f[1], 64)
			c.Load15, _ = strconv.ParseFloat(f[2], 64)
		}
	}
	if s, ok := r.read("proc/stat"); ok {
		if sample, valid := parseCPUSample(s); valid {
			if pct, have := r.usageSince(sample); have {
				c.UsagePercent = &pct
			}
		}
	}
	return c
}

func cpuModel(cpuinfo string) string {
	for _, line := range strings.Split(cpuinfo, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		// x86 says "model name"; arm64 has no such field and offers
		// "Model" on some boards. Both are reported as the model.
		case "model name", "Model":
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// parseCPUSample reads the aggregate "cpu " line of /proc/stat.
// Fields are jiffies: user nice system idle iowait irq softirq steal…
// Idle for our purposes is idle+iowait: a process waiting on disk is
// not using the processor, and counting iowait as busy would blame
// the CPU for a slow disk.
func parseCPUSample(stat string) (cpuSample, bool) {
	for _, line := range strings.Split(stat, "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		if len(fields) < 5 {
			return cpuSample{}, false
		}
		var s cpuSample
		for i, f := range fields {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return cpuSample{}, false
			}
			s.total += v
			if i == 3 || i == 4 { // idle, iowait
				s.idle += v
			}
		}
		return s, true
	}
	return cpuSample{}, false
}

// usageSince returns the percentage busy since the previous sample,
// and false when there is no previous sample to compare against.
func (r *Reader) usageSince(now cpuSample) (float64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	prev, had := r.prevCPU, r.haveCPU
	r.prevCPU, r.haveCPU = now, true
	if !had || now.total <= prev.total {
		return 0, false
	}
	totalDelta := float64(now.total - prev.total)
	idleDelta := float64(now.idle - prev.idle)
	pct := (totalDelta - idleDelta) / totalDelta * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct, true
}

// --- memory ----------------------------------------------------

func (r *Reader) memory(l limits) Memory {
	m := Memory{Source: SourceHost}
	if s, ok := r.read("proc/meminfo"); ok {
		total := meminfoValue(s, "MemTotal")
		avail := meminfoValue(s, "MemAvailable")
		m.TotalBytes, m.AvailableBytes = total, avail
		if total >= avail {
			m.UsedBytes = total - avail
		}
	}
	// The cgroup limit wins when there is one: it is the ceiling this
	// process is actually killed at.
	if l.memLimit > 0 {
		m.TotalBytes = l.memLimit
		m.UsedBytes = l.memUsed
		if l.memLimit >= l.memUsed {
			m.AvailableBytes = l.memLimit - l.memUsed
		}
		m.Source = SourceContainer
	}
	return m
}

// meminfoValue reads one "Key:  12345 kB" line, in bytes.
func meminfoValue(meminfo, key string) uint64 {
	for _, line := range strings.Split(meminfo, "\n") {
		name, value, found := strings.Cut(line, ":")
		if !found || name != key {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			return 0
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return 0
		}
		if len(fields) > 1 && strings.EqualFold(fields[1], "kB") {
			return v * 1024
		}
		return v
	}
	return 0
}

// --- process ---------------------------------------------------

func (r *Reader) process() Process {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	p := Process{
		HeapBytes:     ms.HeapAlloc,
		Goroutines:    runtime.NumGoroutine(),
		GoVersion:     runtime.Version(),
		UptimeSeconds: int64(r.nowFn().Sub(r.startedAt).Seconds()),
	}
	// /proc/self/statm field 2 is the resident set, in pages.
	if s, ok := r.read("proc/self/statm"); ok {
		if f := strings.Fields(s); len(f) >= 2 {
			if pages, err := strconv.ParseUint(f[1], 10, 64); err == nil {
				p.ResidentBytes = pages * uint64(os.Getpagesize())
			}
		}
	}
	return p
}
