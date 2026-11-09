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
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/barto95100/arenet/internal/accesslog"
)

// v2.80 — read-only access-log viewer (admin-only).
//
// The error page prints a request id (= {http.request.uuid}); referencing
// that placeholder makes Caddy write the same id into the access log
// (verified: caddy modules/caddyhttp/replacer.go:207-215). Until now that
// id was only reachable over SSH. These two endpoints let an admin look
// it up — or an IP / path — from the UI, across the current log and its
// rotated/compressed siblings, always bounded.
//
// Both are wired INSIDE the admin-only group (RequireAdminMiddleware) under
// /admin/access-log/* — raw request logs are an admin surface, same posture
// as /admin/backup. The client sends only query params, never a path: the
// file is resolved server-side via the same resolver the config endpoint
// uses, so there is no traversal surface.
// See docs/superpowers/specs/2026-11-09-access-log-viewer-design.md.

// accessLogSearchTimeout bounds a cold search so decompressing many .gz
// files cannot hold the request open indefinitely.
const accessLogSearchTimeout = 10 * time.Second

// accessLogReason* are the explicit reasons a read returns empty cleanly
// rather than as an error, so the UI can explain the empty state.
const (
	accessLogReasonDisabled = "access log is disabled"
	accessLogReasonEmptyQ   = "no search term"
)

// accessLogEntry is a parsed, display-ready access-log line. The raw line
// is kept so the UI can show exactly what is on disk (already REDACTED).
type accessLogEntry struct {
	Ts       float64 `json:"ts"`
	Method   string  `json:"method"`
	URI      string  `json:"uri"`
	ClientIP string  `json:"clientIp"`
	Status   int     `json:"status"`
	UUID     string  `json:"uuid,omitempty"`
	Denied   string  `json:"denied,omitempty"`
	Raw      string  `json:"raw"`
}

// accessLogTailResponse is the GET /admin/access-log/tail body.
type accessLogTailResponse struct {
	Enabled bool             `json:"enabled"`
	Reason  string           `json:"reason,omitempty"`
	Path    string           `json:"path"`
	Lines   []accessLogEntry `json:"lines"`
}

// accessLogSearchResponse is the GET /admin/access-log/search body. The
// metadata block is reported honestly so the UI can say "searched 6 of 48
// files, also searched compressed, stopped at the limit".
type accessLogSearchResponse struct {
	Enabled            bool             `json:"enabled"`
	Reason             string           `json:"reason,omitempty"`
	Path               string           `json:"path"`
	Field              string           `json:"field"`
	Query              string           `json:"query"`
	Lines              []accessLogEntry `json:"lines"`
	FilesScanned       int              `json:"filesScanned"`
	BytesScanned       int64            `json:"bytesScanned"`
	Truncated          bool             `json:"truncated"`
	SearchedCompressed bool             `json:"searchedCompressed"`
	ElapsedMs          int64            `json:"elapsedMs"`
}

// getAccessLogTail returns the last N lines of the current access-log file.
func (h *Handler) getAccessLogTail(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetAccessLogConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the access log setting")
		return
	}
	path := h.resolveAccessLogPath(cfg)
	resp := accessLogTailResponse{Enabled: cfg.Enabled, Path: path, Lines: []accessLogEntry{}}
	if !cfg.Enabled {
		resp.Reason = accessLogReasonDisabled
		writeJSON(w, http.StatusOK, resp)
		return
	}

	lines := clampInt(r.URL.Query().Get("lines"), accesslog.DefaultTailLines, accesslog.MaxTailLines)
	raw, err := accesslog.Tail(path, lines)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the access log")
		return
	}
	resp.Lines = parseAccessLogLines(raw)
	writeJSON(w, http.StatusOK, resp)
}

// getAccessLogSearch searches for a uuid / ip / path across the current
// log and its rotated siblings, bounded, cold tier only on a hot miss.
func (h *Handler) getAccessLogSearch(w http.ResponseWriter, r *http.Request) {
	field := accesslog.Field(strings.TrimSpace(r.URL.Query().Get("field")))
	if !field.Valid() {
		writeError(w, http.StatusBadRequest, "field must be one of: uuid, ip, path")
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))

	cfg, err := h.store.GetAccessLogConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read the access log setting")
		return
	}
	path := h.resolveAccessLogPath(cfg)
	resp := accessLogSearchResponse{
		Enabled: cfg.Enabled, Path: path,
		Field: string(field), Query: q, Lines: []accessLogEntry{},
	}
	if !cfg.Enabled {
		resp.Reason = accessLogReasonDisabled
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if q == "" {
		resp.Reason = accessLogReasonEmptyQ
		writeJSON(w, http.StatusOK, resp)
		return
	}

	max := clampInt(r.URL.Query().Get("max"), accesslog.DefaultMaxResults, accesslog.MaxResults)
	res, err := accesslog.Search(path, q, field, max, accesslog.Caps{
		MaxBytes: accesslog.DefaultMaxBytes,
		Deadline: time.Now().Add(accessLogSearchTimeout),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to search the access log")
		return
	}
	resp.Lines = parseAccessLogLines(res.Lines)
	resp.FilesScanned = res.FilesScanned
	resp.BytesScanned = res.BytesScanned
	resp.Truncated = res.Truncated
	resp.SearchedCompressed = res.SearchedCompressed
	resp.ElapsedMs = res.ElapsedMs
	writeJSON(w, http.StatusOK, resp)
}

// caddyAccessLine is the subset of Caddy's JSON access-log line the UI
// shows. Only matched lines are decoded, never every scanned line.
type caddyAccessLine struct {
	Ts      float64 `json:"ts"`
	Status  int     `json:"status"`
	UUID    string  `json:"uuid"`
	Denied  string  `json:"arenet_denied"`
	Request struct {
		Method   string `json:"method"`
		URI      string `json:"uri"`
		ClientIP string `json:"client_ip"`
		RemoteIP string `json:"remote_ip"`
	} `json:"request"`
}

// parseAccessLogLines decodes each matched line for display, keeping the
// raw line. A line that is not valid JSON is still returned (raw only), so
// a malformed entry is shown rather than silently dropped.
func parseAccessLogLines(raw []string) []accessLogEntry {
	out := make([]accessLogEntry, 0, len(raw))
	for _, l := range raw {
		e := accessLogEntry{Raw: l}
		var c caddyAccessLine
		if json.Unmarshal([]byte(l), &c) == nil {
			e.Ts = c.Ts
			e.Status = c.Status
			e.UUID = c.UUID
			e.Denied = c.Denied
			e.Method = c.Request.Method
			e.URI = c.Request.URI
			e.ClientIP = c.Request.ClientIP
			if e.ClientIP == "" {
				e.ClientIP = c.Request.RemoteIP
			}
		}
		out = append(out, e)
	}
	return out
}

// clampInt parses a query value, falling back to def, and clamps to
// [1, max]. A missing, non-numeric, or out-of-range value is coerced
// rather than rejected — a read endpoint should not 400 on a sloppy N.
func clampInt(s string, def, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}
