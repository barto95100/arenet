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

package api

import (
	"net/http"

	"github.com/barto95100/arenet/internal/sysinfo"
)

// v2.45 — GET /system/info, the host behind Arenet.
//
// Unlike /system/health, this one sits INSIDE the auth middleware. It
// names the machine, its kernel, its load and its free disk — nothing
// catastrophic, but nothing an unauthenticated monitoring probe has
// any business reading either. Viewer scope: looking is not changing.

// SystemInfoReader is the seam cmd/arenet fills with a
// *sysinfo.Reader, so this package does not depend on the reader's
// construction — the same narrow-interface pattern as
// SystemHealthChecker above it.
type SystemInfoReader interface {
	Snapshot() sysinfo.Snapshot
}

// SetSystemInfoReader attaches the reader at boot. nil leaves the
// endpoint answering an honest "not wired" rather than a 500.
func (h *Handler) SetSystemInfoReader(r SystemInfoReader) { h.systemInfo = r }

func (h *Handler) getSystemInfo(w http.ResponseWriter, r *http.Request) {
	if h.systemInfo == nil {
		writeJSON(w, http.StatusOK, sysinfo.Snapshot{
			Unsupported: "system metrics are not wired on this build",
		})
		return
	}
	writeJSON(w, http.StatusOK, h.systemInfo.Snapshot())
}
