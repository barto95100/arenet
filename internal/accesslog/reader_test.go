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

package accesslog

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// line builds a minimal Caddy-style JSON access-log line carrying the
// fields this feature searches on.
func line(uuid, ip, uri string) string {
	return fmt.Sprintf(
		`{"level":"info","msg":"handled request","uuid":%q,"request":{"client_ip":%q,"uri":%q,"method":"GET"},"status":403}`,
		uuid, ip, uri)
}

func writeFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeGzFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// §7.1(a) — find a uuid in the current file.
func TestSearch_FindInCurrent(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	writeFile(t, cur,
		line("aaaaaaaa-0000-0000-0000-000000000001", "10.0.0.1", "/a"),
		line("11111111-2222-3333-4444-555555555555", "10.0.0.2", "/target"),
	)

	res, err := Search(cur, "11111111-2222-3333-4444-555555555555", FieldUUID, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "/target") {
		t.Fatalf("expected the one matching line, got %#v", res.Lines)
	}
	if res.SearchedCompressed {
		t.Fatalf("no .gz exists; SearchedCompressed must be false")
	}
}

// §7.1(b) — find a uuid in an uncompressed rotated file.
func TestSearch_FindInRotatedUncompressed(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	rot := filepath.Join(dir, "access-2026-11-09T10-00-00.000.log")
	writeFile(t, cur, line("cur-0000", "10.0.0.1", "/live"))
	writeFile(t, rot, line("22222222-aaaa-bbbb-cccc-000000000002", "10.0.0.9", "/rotated"))

	res, err := Search(cur, "22222222-aaaa-bbbb-cccc-000000000002", FieldUUID, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "/rotated") {
		t.Fatalf("expected the rotated line, got %#v", res.Lines)
	}
	if res.SearchedCompressed {
		t.Fatalf("hit was in an uncompressed file; SearchedCompressed must be false")
	}
}

// §7.1(c) — find a uuid only present in a gzipped rotated file.
func TestSearch_FindInGz(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	gz := filepath.Join(dir, "access-2026-11-08T09-00-00.000.log.gz")
	writeFile(t, cur, line("cur-0000", "10.0.0.1", "/live"))
	writeGzFile(t, gz, line("33333333-dddd-eeee-ffff-000000000003", "10.0.0.5", "/cold"))

	res, err := Search(cur, "33333333-dddd-eeee-ffff-000000000003", FieldUUID, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 || !strings.Contains(res.Lines[0], "/cold") {
		t.Fatalf("expected the gz line, got %#v", res.Lines)
	}
	if !res.SearchedCompressed {
		t.Fatalf("hit required the cold tier; SearchedCompressed must be true")
	}
}

// §7.2 — not found anywhere → clean empty result with SearchedCompressed.
func TestSearch_NotFound(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	gz := filepath.Join(dir, "access-2026-11-08T09-00-00.000.log.gz")
	writeFile(t, cur, line("cur-0000", "10.0.0.1", "/live"))
	writeGzFile(t, gz, line("old-0000", "10.0.0.2", "/old"))

	res, err := Search(cur, "does-not-exist", FieldUUID, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 0 {
		t.Fatalf("expected no matches, got %#v", res.Lines)
	}
	if !res.SearchedCompressed {
		t.Fatalf("a miss must have searched the cold tier too")
	}
}

// §7.3 — THE tier gate: a hit in the current file must not open any .gz.
// The .gz here carries the SAME uuid but a sentinel path; if Tier 2 were
// ever searched on a Tier-1 hit, the sentinel would leak into the result
// and SearchedCompressed would flip.
func TestSearch_Tier2SkippedOnTier1Hit(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	gz := filepath.Join(dir, "access-2026-11-08T09-00-00.000.log.gz")
	uuid := "44444444-1111-2222-3333-000000000004"
	writeFile(t, cur, line(uuid, "10.0.0.1", "/hot"))
	writeGzFile(t, gz, line(uuid, "10.0.0.1", "/SENTINEL-MUST-NOT-BE-SEARCHED"))

	res, err := Search(cur, uuid, FieldUUID, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 1 {
		t.Fatalf("expected exactly one hit (hot tier), got %d: %#v", len(res.Lines), res.Lines)
	}
	if strings.Contains(res.Lines[0], "SENTINEL") {
		t.Fatalf("cold tier was searched on a hot-tier hit")
	}
	if res.SearchedCompressed {
		t.Fatalf("SearchedCompressed must be false when the hot tier hit")
	}
}

// §7.4 — Tail reads only the end of the current file; a file far larger
// than the window is not fully read.
func TestTail_Bounded(t *testing.T) {
	old := tailByteCap
	tailByteCap = 256 // tiny window for the test
	defer func() { tailByteCap = old }()

	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	var lines []string
	for i := 0; i < 200; i++ {
		lines = append(lines, fmt.Sprintf(`{"n":%d,"marker":"line-%03d"}`, i, i))
	}
	writeFile(t, cur, lines...)

	got, err := Tail(cur, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 tail lines, got %d", len(got))
	}
	if !strings.Contains(got[2], "line-199") {
		t.Fatalf("last tail line should be the newest, got %q", got[2])
	}
	for _, l := range got {
		if strings.Contains(l, "line-000") {
			t.Fatalf("an early line was returned; the read was not bounded to the tail window")
		}
	}
}

// §7.5 — glob correctness: real rotated names match; unrelated files do not.
func TestEnumerateFiles_Glob(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	rot := filepath.Join(dir, "access-2026-11-09T10-00-00.000.log")
	gz := filepath.Join(dir, "access-2026-11-08T09-00-00.000.log.gz")
	for _, p := range []string{cur, rot, gz,
		filepath.Join(dir, "access.log.old"), // must NOT match
		filepath.Join(dir, "other-2026.log"), // different stem
		filepath.Join(dir, "access.log.1"),   // not the lumberjack scheme
	} {
		writeFile(t, p, `{"x":1}`)
	}

	files, err := EnumerateFiles(cur)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(files))
	for _, f := range files {
		got[filepath.Base(f.Path)] = f.Compressed
	}
	if len(got) != 3 {
		t.Fatalf("expected exactly 3 files, got %d: %v", len(got), got)
	}
	if _, ok := got["access.log"]; !ok {
		t.Fatalf("current file missing")
	}
	if c, ok := got["access-2026-11-09T10-00-00.000.log"]; !ok || c {
		t.Fatalf("uncompressed rotated file wrong: ok=%v compressed=%v", ok, c)
	}
	if c, ok := got["access-2026-11-08T09-00-00.000.log.gz"]; !ok || !c {
		t.Fatalf("gz rotated file wrong: ok=%v compressed=%v", ok, c)
	}
	// current file must be first (newest).
	if filepath.Base(files[0].Path) != "access.log" {
		t.Fatalf("current file must be first, got %q", filepath.Base(files[0].Path))
	}
}

// Substring fields collect up to max across the hot tier and do not open
// the cold tier when the hot tier already matched (spec A3).
func TestSearch_PathCollectsHotTierOnly(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "access.log")
	gz := filepath.Join(dir, "access-2026-11-08T09-00-00.000.log.gz")
	writeFile(t, cur,
		line("u1", "10.0.0.1", "/api/login"),
		line("u2", "10.0.0.2", "/api/login"),
	)
	writeGzFile(t, gz, line("u3", "10.0.0.3", "/api/login"))

	res, err := Search(cur, "/api/login", FieldPath, 0, Caps{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Lines) != 2 {
		t.Fatalf("expected 2 hot-tier matches, got %d", len(res.Lines))
	}
	if res.SearchedCompressed {
		t.Fatalf("hot tier matched; cold tier must not be searched")
	}
}
