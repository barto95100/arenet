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

// Package sysinfo reports what the machine under Arenet is doing.
//
// v2.45 — the Settings → System tab said how Arenet was, and nothing
// about the host it runs on. An operator watching a relay slow down
// had no way to tell, from Arenet, whether the machine was out of
// memory, out of CPU or out of disk.
//
// The one thing this package is careful about is telling the truth
// inside a container. /proc/meminfo and /proc/cpuinfo report the
// HOST: a container limited to 512 MiB shows the host's 64 GiB, a
// number that is literally correct and completely useless to whoever
// is trying to understand why Arenet keeps being OOM-killed. The real
// limits live in the cgroup, so every figure here carries the source
// it came from and the UI says which.
//
// Everything is read from the filesystem through a configurable root,
// so the parsers are tested against fixtures rather than against
// whichever machine happens to run the suite.
package sysinfo

// Source says where a figure came from, because in a container the
// two answers differ and only one of them is useful.
const (
	// SourceHost: read from /proc, describing the whole machine.
	SourceHost = "host"
	// SourceContainer: read from the cgroup, describing the limit
	// this process actually lives under.
	SourceContainer = "container"
)

// Host identifies the machine.
type Host struct {
	Hostname string `json:"hostname,omitempty"`
	// OS is the pretty name from /etc/os-release ("Debian GNU/Linux 12").
	OS string `json:"os,omitempty"`
	// Kernel is the release string ("6.1.0-18-amd64").
	Kernel string `json:"kernel,omitempty"`
	Arch   string `json:"arch,omitempty"`
	// UptimeSeconds is the machine's uptime, not Arenet's.
	UptimeSeconds int64 `json:"uptimeSeconds,omitempty"`
	// Containerised reports that Arenet runs confined. It does not
	// imply the limits below are set — a container may have none.
	Containerised bool `json:"containerised"`
}

// CPU is what the processor is doing, and how much of it this process
// is actually allowed to use.
type CPU struct {
	Model string `json:"model,omitempty"`
	// Cores is what this process may use: the cgroup quota when one
	// is set, the machine's core count otherwise.
	Cores int `json:"cores,omitempty"`
	// HostCores is the machine's count, reported alongside Cores so a
	// quota is visible as the restriction it is rather than as a
	// smaller machine.
	HostCores int `json:"hostCores,omitempty"`
	// UsagePercent is nil until two samples exist: the first call
	// after a restart has no baseline, and inventing a number there
	// would be worse than an empty field.
	UsagePercent *float64 `json:"usagePercent,omitempty"`
	Load1        float64  `json:"load1,omitempty"`
	Load5        float64  `json:"load5,omitempty"`
	Load15       float64  `json:"load15,omitempty"`
	Source       string   `json:"source,omitempty"`
}

// Memory is the ceiling this process lives under and how close to it
// things are.
type Memory struct {
	TotalBytes     uint64 `json:"totalBytes,omitempty"`
	UsedBytes      uint64 `json:"usedBytes,omitempty"`
	AvailableBytes uint64 `json:"availableBytes,omitempty"`
	Source         string `json:"source,omitempty"`
}

// Disk is the filesystem holding Arenet's data directory — the
// database, the backups and the logs. Not the root filesystem, which
// can be healthy while the one that matters is full.
type Disk struct {
	Path           string `json:"path,omitempty"`
	TotalBytes     uint64 `json:"totalBytes,omitempty"`
	UsedBytes      uint64 `json:"usedBytes,omitempty"`
	AvailableBytes uint64 `json:"availableBytes,omitempty"`
}

// Process is Arenet itself, kept separate from the host so a leak can
// be attributed rather than guessed at.
type Process struct {
	// HeapBytes is Go's own accounting of live heap.
	HeapBytes uint64 `json:"heapBytes,omitempty"`
	// ResidentBytes is what the OS says the process occupies. Absent
	// where the platform does not expose it.
	ResidentBytes uint64 `json:"residentBytes,omitempty"`
	Goroutines    int    `json:"goroutines,omitempty"`
	GoVersion     string `json:"goVersion,omitempty"`
	// UptimeSeconds is since this process started, not since boot.
	UptimeSeconds int64 `json:"uptimeSeconds,omitempty"`
}

// Snapshot is one reading of the whole thing.
type Snapshot struct {
	Host    Host    `json:"host"`
	CPU     CPU     `json:"cpu"`
	Memory  Memory  `json:"memory"`
	Disk    Disk    `json:"disk"`
	Process Process `json:"process"`
	// Unsupported carries the reason when the platform cannot answer
	// — macOS during development, say. The fields above are then
	// partly empty, and the UI says so instead of showing zeros as
	// though they were measurements.
	Unsupported string `json:"unsupported,omitempty"`
	// Timestamp is when this was read, RFC 3339 UTC.
	Timestamp string `json:"timestamp"`
}
