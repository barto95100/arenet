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

//go:build linux || darwin

package sysinfo

import "syscall"

// disk measures the filesystem holding the data directory.
//
// Deliberately not the root filesystem: the database, the backups and
// the logs all live in the data directory, and on any install that
// puts it on its own volume a healthy "/" says nothing about whether
// the next backup will fit.
//
// Available is what a non-root process may use — Bavail, not Bfree —
// because the reserved blocks Bfree counts are not available to
// Arenet.
func (r *Reader) disk() Disk {
	d := Disk{Path: r.dataDir}
	if r.dataDir == "" {
		return d
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(r.dataDir, &st); err != nil {
		return d
	}
	// Bsize is int64 on Linux and uint32 on Darwin; the conversion
	// keeps one implementation for both.
	bs := uint64(st.Bsize)
	d.TotalBytes = st.Blocks * bs
	d.AvailableBytes = st.Bavail * bs
	if st.Blocks >= st.Bfree {
		d.UsedBytes = (st.Blocks - st.Bfree) * bs
	}
	return d
}
