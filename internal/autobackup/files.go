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

package autobackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	// filePrefix / fileSuffix frame every scheduled backup file; only
	// files matching fileNameRE are ever listed, served or deleted.
	filePrefix = "arenet-backup-auto-"
	fileSuffix = ".json"
	// fileStamp is the timestamp layout inside a file name (server
	// local time): names sort chronologically.
	fileStamp = "20060102-150405"
	// DefaultDirName is the default directory, inside the data dir.
	DefaultDirName = "backups"
	// fileMode / dirMode keep backups owner-only.
	fileMode = 0o600
	dirMode  = 0o700
)

// fileNameRE is the exact shape of a scheduled backup file name. It is
// the path-traversal guard of every endpoint taking a file name.
var fileNameRE = regexp.MustCompile(`^arenet-backup-auto-(\d{8}-\d{6})(?:-(\d+))?\.json$`)

// ErrInvalidName is returned for a name that is not a scheduled backup.
var ErrInvalidName = errors.New("autobackup: not a scheduled backup file name")

// ValidName reports whether name is a scheduled backup file name.
func ValidName(name string) bool { return fileNameRE.MatchString(name) }

// File is one scheduled backup in the directory.
type File struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
}

// ResolveDir returns the backup directory: dir, or <dataDir>/backups.
func ResolveDir(dir, dataDir string) string {
	if dir != "" {
		return dir
	}
	return filepath.Join(dataDir, DefaultDirName)
}

// CheckDir verifies Arenet can write into dir by creating and removing
// a probe file. create makes a missing dir (only for the default one:
// a custom path — typically a NAS mount — must already exist, so a
// missing mount is reported instead of silently filling the local disk).
func CheckDir(dir string, create bool) error {
	info, err := os.Stat(dir)
	switch {
	case err == nil && !info.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case errors.Is(err, os.ErrNotExist) && create:
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return fmt.Errorf("cannot create %s: %w", dir, err)
		}
	case err != nil:
		return fmt.Errorf("cannot access %s: %w", dir, err)
	}
	probe, err := os.CreateTemp(dir, ".arenet-write-probe-*")
	if err != nil {
		return fmt.Errorf("arenet cannot write in %s (check the mount and the permissions of the Arenet user — UID 65532 in Docker): %w", dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}

// writeAtomic writes data to dir/<name> through a temporary file and a
// rename, so a crash never leaves a truncated backup under a valid name.
// An existing file of the same name gets a numeric suffix.
func writeAtomic(dir string, now time.Time, data []byte) (string, error) {
	base := filePrefix + now.Format(fileStamp)
	name := base + fileSuffix
	for i := 1; ; i++ {
		if _, err := os.Stat(filepath.Join(dir, name)); errors.Is(err, os.ErrNotExist) {
			break
		}
		name = fmt.Sprintf("%s-%d%s", base, i, fileSuffix)
	}
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return "", fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	fail := func(err error) (string, error) {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Chmod(fileMode); err != nil {
		return fail(fmt.Errorf("chmod: %w", err))
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(fmt.Errorf("write: %w", err))
	}
	if err := tmp.Sync(); err != nil {
		return fail(fmt.Errorf("sync: %w", err))
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpName)
		return "", fmt.Errorf("rename: %w", err)
	}
	return name, nil
}

// List returns the scheduled backups of dir, newest first. A missing
// dir lists nothing.
func List(dir string) ([]File, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []File{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	out := []File{}
	for _, e := range entries {
		if !e.Type().IsRegular() || !ValidName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, File{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	slices.SortFunc(out, func(a, b File) int { return compareNames(b.Name, a.Name) })
	return out, nil
}

// compareNames orders scheduled backup names by the timestamp in the
// name, then by collision suffix. The name — not the file's mtime,
// which a NAS copy or a skewed clock can change — is authoritative.
func compareNames(a, b string) int {
	ma, mb := fileNameRE.FindStringSubmatch(a), fileNameRE.FindStringSubmatch(b)
	if c := strings.Compare(ma[1], mb[1]); c != 0 {
		return c
	}
	na, _ := strconv.Atoi(ma[2]) // "" → 0: the unsuffixed file comes first
	nb, _ := strconv.Atoi(mb[2])
	return na - nb
}

// prune deletes the scheduled backups beyond the keep newest. Only
// files matching the scheduled-backup name are ever touched, and
// justWritten never is.
func prune(dir string, keep int, justWritten string) (int, error) {
	files, err := List(dir)
	if err != nil {
		return 0, err
	}
	removed := 0
	for i := keep; i < len(files); i++ {
		if files[i].Name == justWritten {
			continue
		}
		if err := os.Remove(filepath.Join(dir, files[i].Name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, fmt.Errorf("remove %s: %w", files[i].Name, err)
		}
		removed++
	}
	return removed, nil
}

// Path returns the full path of a scheduled backup, refusing any name
// that is not one (path traversal guard).
func Path(dir, name string) (string, error) {
	if !ValidName(name) {
		return "", ErrInvalidName
	}
	return filepath.Join(dir, name), nil
}
