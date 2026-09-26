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
	"os"
	"path/filepath"
	"testing"
)

// v2.45 — host metrics.
//
// Everything is read through a configurable root, so these tests run
// against known bytes instead of against whichever machine happens to
// execute the suite. That matters twice over: the CI runner is a
// container, and the developer's machine is macOS — neither would
// exercise the paths that matter on a Debian host.
//
// What is pinned above all is the container case. /proc reports the
// HOST, so a container limited to 512 MiB would otherwise display the
// host's 64 GiB: a number that is literally correct and useless to
// whoever is working out why Arenet keeps being OOM-killed.

// fakeRoot writes a fixture filesystem and returns its path.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		full := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	return root
}

// A plain host: 8 GiB, four cores, no cgroup limits anywhere.
func hostFiles() map[string]string {
	return map[string]string{
		"proc/meminfo": "MemTotal:        8192000 kB\n" +
			"MemFree:         1024000 kB\n" +
			"MemAvailable:    4096000 kB\n",
		"proc/loadavg":              "0.52 0.41 0.38 2/512 12345\n",
		"proc/uptime":               "123456.78 987654.32\n",
		"proc/sys/kernel/osrelease": "6.1.0-18-amd64\n",
		"etc/os-release":            "NAME=\"Debian GNU/Linux\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\n",
		"proc/cpuinfo":              "processor\t: 0\nmodel name\t: Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz\n",
		"proc/stat":                 "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 25 0 12 200 12 0 0 0 0 0\n",
	}
}

func TestSnapshot_ReadsAPlainHost(t *testing.T) {
	r := NewWithRoot(fakeRoot(t, hostFiles()), t.TempDir())
	s := r.Snapshot()

	if s.Unsupported != "" {
		t.Fatalf("a host with /proc must be supported: %q", s.Unsupported)
	}
	if s.Host.OS != "Debian GNU/Linux 12 (bookworm)" {
		t.Errorf("OS: %q", s.Host.OS)
	}
	if s.Host.Kernel != "6.1.0-18-amd64" {
		t.Errorf("kernel: %q", s.Host.Kernel)
	}
	if s.Host.UptimeSeconds != 123456 {
		t.Errorf("uptime: %d", s.Host.UptimeSeconds)
	}
	if s.Host.Containerised {
		t.Error("no cgroup limit and no marker: this is not a container")
	}
	// meminfo is in kB; the wire is in bytes.
	if s.Memory.TotalBytes != 8192000*1024 {
		t.Errorf("total memory: %d", s.Memory.TotalBytes)
	}
	if s.Memory.UsedBytes != (8192000-4096000)*1024 {
		t.Errorf("used memory: %d", s.Memory.UsedBytes)
	}
	if s.Memory.Source != SourceHost {
		t.Errorf("source: %q", s.Memory.Source)
	}
	if s.CPU.Model != "Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz" {
		t.Errorf("model: %q", s.CPU.Model)
	}
	if s.CPU.Load1 != 0.52 || s.CPU.Load15 != 0.38 {
		t.Errorf("load: %+v", s.CPU)
	}
}

// The first reading has no baseline, so there is no rate to report.
// Inventing one would be worse than an empty field.
func TestCPUUsage_NeedsTwoSamples(t *testing.T) {
	files := hostFiles()
	root := fakeRoot(t, files)
	r := NewWithRoot(root, t.TempDir())

	if got := r.Snapshot().CPU.UsagePercent; got != nil {
		t.Fatalf("first sample cannot know a rate, got %v", *got)
	}

	// Second reading: 100 jiffies busy, 100 idle → 50%.
	if err := os.WriteFile(filepath.Join(root, "proc/stat"),
		[]byte("cpu  150 0 100 850 100 0 0 0 0 0\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := r.Snapshot().CPU.UsagePercent
	if got == nil {
		t.Fatal("second sample must produce a usage")
	}
	if *got < 49.9 || *got > 50.1 {
		t.Errorf("usage: got %v, want ~50", *got)
	}
}

// iowait is idle time: a process waiting on a slow disk is not using
// the processor, and counting it as busy blames the CPU for the disk.
func TestCPUUsage_IOWaitCountsAsIdle(t *testing.T) {
	files := hostFiles()
	files["proc/stat"] = "cpu  0 0 0 0 0 0 0 0 0 0\n"
	root := fakeRoot(t, files)
	r := NewWithRoot(root, t.TempDir())
	r.Snapshot()

	// 100 jiffies entirely in iowait: nothing ran.
	if err := os.WriteFile(filepath.Join(root, "proc/stat"),
		[]byte("cpu  0 0 0 0 100 0 0 0 0 0\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := r.Snapshot().CPU.UsagePercent
	if got == nil || *got != 0 {
		t.Fatalf("pure iowait must read as idle, got %v", got)
	}
}

// --- the container case, which is the reason this package is careful

func TestSnapshot_CgroupV2LimitsWinOverTheHost(t *testing.T) {
	files := hostFiles()
	files["sys/fs/cgroup/cgroup.controllers"] = "cpuset cpu io memory pids\n"
	files["sys/fs/cgroup/memory.max"] = "536870912\n"     // 512 MiB
	files["sys/fs/cgroup/memory.current"] = "268435456\n" // 256 MiB
	files["sys/fs/cgroup/cpu.max"] = "150000 100000\n"    // 1.5 cores

	s := NewWithRoot(fakeRoot(t, files), t.TempDir()).Snapshot()

	if !s.Host.Containerised {
		t.Error("a cgroup limit means confined, whatever the marker files say")
	}
	// The host has 8 GiB. Showing it here is the bug this test exists
	// to prevent.
	if s.Memory.TotalBytes != 536870912 {
		t.Errorf("the container limit must win: got %d", s.Memory.TotalBytes)
	}
	if s.Memory.UsedBytes != 268435456 {
		t.Errorf("used: %d", s.Memory.UsedBytes)
	}
	if s.Memory.AvailableBytes != 536870912-268435456 {
		t.Errorf("available: %d", s.Memory.AvailableBytes)
	}
	if s.Memory.Source != SourceContainer {
		t.Errorf("the figure must say where it came from: %q", s.Memory.Source)
	}
	// 1.5 cores rounds up: half a core still needs a core to run on.
	if s.CPU.Cores != 2 {
		t.Errorf("cores: got %d, want 2", s.CPU.Cores)
	}
	if s.CPU.Source != SourceContainer {
		t.Errorf("cpu source: %q", s.CPU.Source)
	}
	// The machine's real count stays visible, so a quota reads as a
	// restriction rather than as a smaller machine.
	if s.CPU.HostCores == 0 {
		t.Error("the host's core count must still be reported")
	}
}

// "max" is the kernel's word for no limit. Treating it as a number
// would report a ceiling of zero bytes.
func TestSnapshot_CgroupV2UnlimitedIsNotALimit(t *testing.T) {
	files := hostFiles()
	files["sys/fs/cgroup/cgroup.controllers"] = "memory\n"
	files["sys/fs/cgroup/memory.max"] = "max\n"
	files["sys/fs/cgroup/cpu.max"] = "max 100000\n"

	s := NewWithRoot(fakeRoot(t, files), t.TempDir()).Snapshot()

	if s.Memory.TotalBytes != 8192000*1024 {
		t.Errorf("no limit set: the host figure must stand, got %d", s.Memory.TotalBytes)
	}
	if s.Memory.Source != SourceHost {
		t.Errorf("source: %q", s.Memory.Source)
	}
	if s.Host.Containerised {
		t.Error("an unlimited cgroup is not a limit and must not read as one")
	}
}

func TestSnapshot_CgroupV1(t *testing.T) {
	files := hostFiles()
	files["sys/fs/cgroup/memory/memory.limit_in_bytes"] = "268435456\n"
	files["sys/fs/cgroup/memory/memory.usage_in_bytes"] = "134217728\n"
	files["sys/fs/cgroup/cpu/cpu.cfs_quota_us"] = "50000\n"
	files["sys/fs/cgroup/cpu/cpu.cfs_period_us"] = "100000\n"

	s := NewWithRoot(fakeRoot(t, files), t.TempDir()).Snapshot()

	if s.Memory.TotalBytes != 268435456 || s.Memory.Source != SourceContainer {
		t.Errorf("v1 limit ignored: %+v", s.Memory)
	}
	// Half a core still needs one core.
	if s.CPU.Cores != 1 {
		t.Errorf("cores: got %d, want 1", s.CPU.Cores)
	}
}

// v1 spells "no limit" as a sentinel near the 64-bit ceiling rather
// than a keyword. Read literally, it would claim 8 exabytes of RAM.
func TestSnapshot_CgroupV1SentinelIsNotALimit(t *testing.T) {
	files := hostFiles()
	files["sys/fs/cgroup/memory/memory.limit_in_bytes"] = "9223372036854771712\n"
	files["sys/fs/cgroup/cpu/cpu.cfs_quota_us"] = "-1\n"
	files["sys/fs/cgroup/cpu/cpu.cfs_period_us"] = "100000\n"

	s := NewWithRoot(fakeRoot(t, files), t.TempDir()).Snapshot()

	if s.Memory.TotalBytes != 8192000*1024 {
		t.Errorf("the sentinel is not a limit: got %d", s.Memory.TotalBytes)
	}
	if s.Host.Containerised {
		t.Error("no real limit: must not read as confined")
	}
}

// --- degradation ------------------------------------------------

// Without /proc the host figures are unknowable, and the page must
// say so rather than render zeros as though they were measurements.
func TestSnapshot_WithoutProcSaysSoAndStillReportsArenet(t *testing.T) {
	s := NewWithRoot(fakeRoot(t, map[string]string{}), t.TempDir()).Snapshot()

	if s.Unsupported == "" {
		t.Fatal("no /proc: the snapshot must say why it is empty")
	}
	if s.Memory.TotalBytes != 0 {
		t.Errorf("nothing was measured, so nothing must be reported: %d", s.Memory.TotalBytes)
	}
	// Arenet's own numbers come from the runtime and stay true.
	if s.Process.Goroutines == 0 || s.Process.GoVersion == "" {
		t.Errorf("the process figures must survive: %+v", s.Process)
	}
	if s.Host.Arch == "" {
		t.Error("the architecture is known without /proc")
	}
}

// The data directory is what fills up — the database, the backups and
// the logs live there. A healthy "/" says nothing about it.
func TestSnapshot_DiskMeasuresTheDataDirectory(t *testing.T) {
	dataDir := t.TempDir()
	s := NewWithRoot(fakeRoot(t, hostFiles()), dataDir).Snapshot()

	if s.Disk.Path != dataDir {
		t.Errorf("path: got %q, want %q", s.Disk.Path, dataDir)
	}
	if s.Disk.TotalBytes == 0 {
		t.Error("a real directory must produce a real size")
	}
	if s.Disk.AvailableBytes > s.Disk.TotalBytes {
		t.Errorf("available cannot exceed total: %+v", s.Disk)
	}
}
