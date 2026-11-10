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

// Package accesslog reads Caddy's HTTP access log and its rotated
// siblings for the UI, without ever loading a whole file.
//
// The access log can grow to roughly RollSizeMB * (RollKeep + 1) across
// up to ~101 files (internal/storage/access_log_config.go), mostly
// gzipped. Every read here is therefore bounded and streaming: Tail
// reads only the end of the current file, and Search walks the files in
// tiers, newest first, under a byte budget and a deadline.
//
// The package is deliberately free of any Caddy or storage import: it is
// pure file logic over a path the caller has already resolved, so it is
// unit-testable against a temp directory.
package accesslog

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Field is the access-log field a Search matches against. The three
// values are the operator-confirmed set (spec decision A8); anything
// else is rejected by the API layer before it reaches here.
type Field string

const (
	// FieldUUID matches the top-level "uuid" field Caddy writes when a
	// request evaluates {http.request.uuid} — which Arenet's error pages
	// do, so the id shown on an error page is the id in the log
	// (verified: caddy modules/caddyhttp/replacer.go:207-215). Unique per
	// request, so a search stops at the first hit.
	FieldUUID Field = "uuid"
	// FieldIP matches a client/remote IP anywhere in the line.
	FieldIP Field = "ip"
	// FieldPath matches the request URI (substring) anywhere in the line.
	FieldPath Field = "path"
)

// Valid reports whether f is one of the three accepted fields.
func (f Field) Valid() bool {
	switch f {
	case FieldUUID, FieldIP, FieldPath:
		return true
	}
	return false
}

// Tail / search bounds. Exported ones are the public contract the API
// clamps to; the unexported tail window is a var only so a test can
// shrink it to prove the read is bounded.
const (
	// DefaultTailLines is returned when the caller asks for 0 lines.
	DefaultTailLines = 200
	// MaxTailLines caps a tail request.
	MaxTailLines = 1000
	// DefaultMaxResults is the substring-search result cap when unset.
	DefaultMaxResults = 200
	// MaxResults caps how many matched lines a search returns.
	MaxResults = 1000
	// DefaultMaxBytes is the scan budget when the caller passes none.
	DefaultMaxBytes = int64(256 << 20) // 256 MiB of (decompressed) bytes
)

// tailByteCap is the window Tail reads from the end of the current file.
// A var, not a const, purely so the bounded-read test can lower it.
var tailByteCap int64 = 4 << 20 // 4 MiB

// LogFile is one access-log file on disk: the current file or a rotated
// sibling, with whether it is gzipped.
type LogFile struct {
	Path       string
	Compressed bool
}

// Caps bounds a Search so a cold query over many gzipped files cannot
// run unbounded. A zero MaxBytes means DefaultMaxBytes; a zero Deadline
// means no wall-clock limit.
type Caps struct {
	MaxBytes int64
	Deadline time.Time
}

// Result is a search outcome: the matched raw JSON lines plus honest
// metadata so the UI can explain a partial or cold search.
type Result struct {
	// Lines are the matched log lines, verbatim (already REDACTED on
	// disk), newest file first.
	Lines []string
	// FilesScanned is how many files were actually opened and read.
	FilesScanned int
	// BytesScanned is how many bytes were read (decompressed, for .gz).
	BytesScanned int64
	// Truncated is true when a cap (max results, bytes, or deadline) was
	// hit before the search was exhausted.
	Truncated bool
	// SearchedCompressed is true when the cold tier (.gz files) was
	// searched — i.e. the hot tier found nothing.
	SearchedCompressed bool
	// ElapsedMs is the wall-clock time the search took.
	ElapsedMs int64
}

// EnumerateFiles returns the current access-log file plus its rotated
// siblings, ordered so a tiered search can walk them newest→oldest:
// the current file first, then uncompressed rotated files, then gzipped
// rotated files, each group newest-first.
//
// Rotated files follow lumberjack's naming (verified against Caddy
// v2.11.4 → lumberjack v2.2.1): "<stem>-<timestamp><ext>" with an
// optional ".gz". The timestamp (2006-01-02T15-04-05.000) is
// lexicographically sortable, so a descending filename sort is
// newest-first with no per-file stat.
//
// A missing directory yields an empty list, not an error: "no log yet"
// is a normal state, not a failure.
func EnumerateFiles(resolvedPath string) ([]LogFile, error) {
	resolvedPath = strings.TrimSpace(resolvedPath)
	if resolvedPath == "" {
		return nil, nil
	}
	dir := filepath.Dir(resolvedPath)
	base := filepath.Base(resolvedPath)
	ext := filepath.Ext(base)             // ".log"
	stem := strings.TrimSuffix(base, ext) // "access"
	rotPrefix := stem + "-"
	gzSuffix := ext + ".gz"

	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	currentExists := false
	var uncompressed, compressed []LogFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case name == base:
			currentExists = true
		case strings.HasPrefix(name, rotPrefix) && strings.HasSuffix(name, gzSuffix):
			compressed = append(compressed, LogFile{Path: filepath.Join(dir, name), Compressed: true})
		case ext != "" && strings.HasPrefix(name, rotPrefix) && strings.HasSuffix(name, ext):
			uncompressed = append(uncompressed, LogFile{Path: filepath.Join(dir, name), Compressed: false})
		}
	}
	// Newest first: the timestamp in the name is lexically sortable.
	sort.Slice(uncompressed, func(i, j int) bool { return uncompressed[i].Path > uncompressed[j].Path })
	sort.Slice(compressed, func(i, j int) bool { return compressed[i].Path > compressed[j].Path })

	out := make([]LogFile, 0, len(uncompressed)+len(compressed)+1)
	if currentExists {
		out = append(out, LogFile{Path: resolvedPath, Compressed: false})
	}
	out = append(out, uncompressed...)
	out = append(out, compressed...)
	return out, nil
}

// Tail returns the last `lines` lines of the current access-log file
// only; it never opens a rotated file. It reads at most tailByteCap
// bytes from the end of the file, so a multi-gigabyte log is not loaded
// to answer "show me the latest".
//
// A missing file yields an empty slice, not an error.
func Tail(resolvedPath string, lines int) ([]string, error) {
	if lines <= 0 {
		lines = DefaultTailLines
	}
	if lines > MaxTailLines {
		lines = MaxTailLines
	}
	f, err := os.Open(resolvedPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var start int64
	if fi.Size() > tailByteCap {
		start = fi.Size() - tailByteCap
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(f) // bounded: at most tailByteCap bytes
	if err != nil {
		return nil, err
	}
	text := string(data)
	// When we started mid-file the first line is partial; drop it so the
	// tail is made of whole lines only.
	if start > 0 {
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			text = text[i+1:]
		} else {
			text = ""
		}
	}
	all := splitLines(text)
	if len(all) > lines {
		all = all[len(all)-lines:]
	}
	return all, nil
}

// Search walks the access-log files in two tiers and returns the matched
// lines with metadata. Tier 1 is the current file plus uncompressed
// rotated files (newest→oldest); Tier 2 (gzipped rotated files) is
// searched only when Tier 1 found nothing — operators usually report an
// incident quickly, so the hit is almost always in the hot tier (spec
// decision A3).
//
// For FieldUUID the search stops at the first match (a uuid is unique to
// one request). For FieldIP / FieldPath it collects up to `max` matches,
// bounded by caps.MaxBytes and caps.Deadline, reporting Truncated
// honestly. An unreadable individual file is skipped, not fatal.
func Search(resolvedPath, q string, field Field, max int, caps Caps) (Result, error) {
	begin := time.Now()
	var res Result
	q = strings.TrimSpace(q)
	if q == "" {
		res.ElapsedMs = time.Since(begin).Milliseconds()
		return res, nil
	}
	if max <= 0 {
		max = DefaultMaxResults
	}
	if max > MaxResults {
		max = MaxResults
	}
	if caps.MaxBytes <= 0 {
		caps.MaxBytes = DefaultMaxBytes
	}

	files, err := EnumerateFiles(resolvedPath)
	if err != nil {
		res.ElapsedMs = time.Since(begin).Milliseconds()
		return res, err
	}

	match := buildMatcher(q, field)
	stopAtFirst := field == FieldUUID

	// Tier 1 — hot: current + uncompressed rotated.
	done := searchTier(files, false, match, stopAtFirst, max, caps, &res)
	// Tier 2 — cold: gzipped rotated, only if the hot tier found nothing.
	if !done && len(res.Lines) == 0 {
		res.SearchedCompressed = true
		searchTier(files, true, match, stopAtFirst, max, caps, &res)
	}
	res.ElapsedMs = time.Since(begin).Milliseconds()
	return res, nil
}

// searchTier scans every file whose Compressed flag equals `compressed`,
// in the order EnumerateFiles produced them. It returns true when a hard
// stop was reached (first uuid hit, or `max` results), which tells the
// caller not to open the next tier.
func searchTier(files []LogFile, compressed bool, match func(string) bool, stopAtFirst bool, max int, caps Caps, res *Result) bool {
	for _, lf := range files {
		if lf.Compressed != compressed {
			continue
		}
		if res.BytesScanned >= caps.MaxBytes {
			res.Truncated = true
			return false
		}
		if !caps.Deadline.IsZero() && time.Now().After(caps.Deadline) {
			res.Truncated = true
			return false
		}
		stop, err := scanFile(lf, match, stopAtFirst, max, caps, res)
		if err != nil {
			// A single corrupt or unreadable file must not sink the whole
			// search; skip it and keep going.
			continue
		}
		res.FilesScanned++
		if stop {
			return true
		}
	}
	return false
}

// scanFile reads one file line by line (decompressing on the fly for a
// .gz), appending matches to res. It returns true to stop the search:
// the first hit for a uuid, or once `max` results are collected.
func scanFile(lf LogFile, match func(string) bool, stopAtFirst bool, max int, caps Caps, res *Result) (bool, error) {
	f, err := os.Open(lf.Path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var r io.Reader = f
	if lf.Compressed {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return false, err
		}
		defer gz.Close()
		r = gz
	}

	br := bufio.NewReaderSize(r, 64*1024)
	for {
		if res.BytesScanned >= caps.MaxBytes {
			res.Truncated = true
			return false, nil
		}
		line, readErr := br.ReadString('\n')
		res.BytesScanned += int64(len(line))
		if trimmed := strings.TrimRight(line, "\r\n"); trimmed != "" && match(trimmed) {
			res.Lines = append(res.Lines, trimmed)
			if stopAtFirst {
				return true, nil
			}
			if len(res.Lines) >= max {
				res.Truncated = true
				return true, nil
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return false, nil
			}
			return false, readErr
		}
	}
}

// buildMatcher returns the per-line predicate for a field. A uuid is
// matched as the whole quoted JSON value ("uuid":"<q>") so a partial id
// cannot hit a neighbouring one; ip and path are plain substring matches
// on the raw line (spec: substring for ip/path, anchored token for uuid).
func buildMatcher(q string, field Field) func(string) bool {
	if field == FieldUUID {
		needle := `"uuid":"` + q + `"`
		return func(line string) bool { return strings.Contains(line, needle) }
	}
	return func(line string) bool { return strings.Contains(line, q) }
}

// splitLines splits on newlines and drops empty lines, trimming a
// trailing CR so CRLF files behave.
func splitLines(text string) []string {
	raw := strings.Split(text, "\n")
	out := make([]string, 0, len(raw))
	for _, l := range raw {
		if l = strings.TrimRight(l, "\r"); l != "" {
			out = append(out, l)
		}
	}
	return out
}
