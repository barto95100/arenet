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

package auth

import (
	"bufio"
	"compress/gzip"
	"context"
	"embed"
	"log/slog"
	"strings"
	"sync"
)

// passwordHIBPChecker is the subset of the HIBP API ValidatePasswordSync
// depends on. Defined consumer-side so tests can inject a mock without
// constructing a full HIBPClient. *HIBPClient naturally satisfies it.
type passwordHIBPChecker interface {
	CheckPassword(ctx context.Context, password string) (string, error)
}

// ValidatePasswordSync runs the synchronous password validation gates
// from spec §7.5 in order:
//
//  1. Length (15..128) — fails fast before any allocation.
//  2. Top-10k embedded list — instant, offline, always active.
//  3. HIBP k-anonymity check — network, 5-second timeout, best-effort.
//
// Returns the HIBPStatus to persist on User.HIBPCheckStatus, and an
// error if the password is rejected. The status is meaningful only on
// nil error:
//
//   - clean    → password accepted, HIBP confirmed not in breach DB.
//   - pending  → password accepted, HIBP unreachable; deferred re-check
//     will run at next login (spec §7.6).
//   - skipped  → password accepted, HIBP disabled via env var.
//
// On a non-nil error the returned status is the zero string and the
// caller must NOT persist the user. Possible errors:
//
//   - ErrPasswordTooShort, ErrPasswordTooLong — length bounds (D6).
//   - ErrPasswordCommon — top-10k hit OR HIBP Compromised; same
//     sentinel for both sources by design (uniform UX, spec §7.5).
//
// Note: length validation is intentionally duplicated with
// UserStore.Create (Chunk 1). UserStore.Create enforces data integrity
// at the storage boundary (the store refuses invalid passwords even
// if a caller forgets the upstream validation). ValidatePasswordSync
// fails fast BEFORE the network call to HIBP and the ~100ms argon2id
// hash. Defense in depth, not a bug.
func ValidatePasswordSync(ctx context.Context, hibp passwordHIBPChecker, password string) (string, error) {
	if len(password) < PasswordMinLen {
		return "", ErrPasswordTooShort
	}
	if len(password) > PasswordMaxLen {
		return "", ErrPasswordTooLong
	}
	if isCommonPassword(password) {
		return "", ErrPasswordCommon
	}
	status, err := hibp.CheckPassword(ctx, password)
	if err != nil {
		// hibp.CheckPassword returns nil error on every operational
		// path (network, timeout, 5xx, parse). A non-nil error
		// indicates a programming bug (e.g., NewRequestWithContext
		// rejecting our URL). We treat it as a HIBP miss — same as
		// a network timeout — so the user-facing operation is not
		// blocked by our internal bug. A Warn log surfaces the bug
		// to operators; the deferred re-check at next login (spec
		// §7.6) will retry once the bug is fixed.
		slog.Default().Warn("auth: HIBP check returned an error (treating as pending)",
			slog.String("err", err.Error()),
		)
		return HIBPStatusPending, nil
	}
	if status == HIBPStatusCompromised {
		return "", ErrPasswordCommon
	}
	// HIBPStatusClean, HIBPStatusPending, HIBPStatusSkipped all
	// translate to "accepted"; the returned status tells the caller
	// what to record on User.HIBPCheckStatus.
	return status, nil
}

//go:embed data/common-passwords.txt.gz
var commonPasswordsFS embed.FS

// commonPasswordsPath is the embedded asset path used by loadCommonPasswords.
// Spec §7.4 + see internal/auth/data/README.md for provenance.
const commonPasswordsPath = "data/common-passwords.txt.gz"

var (
	// commonPasswords is the in-memory lookup table populated lazily
	// by loadCommonPasswords. Keys are lowercased password strings;
	// values are empty structs (set-semantics).
	commonPasswords     map[string]struct{}
	commonPasswordsOnce sync.Once
)

// loadCommonPasswords reads and decompresses the embedded top-10k
// list on first call. Subsequent calls are no-ops (sync.Once).
//
// Panics on failure: the embed.FS asset is bundled at compile time;
// a missing or corrupted file means the build is broken. Failing
// fast is correct — the application cannot meaningfully proceed
// without the list, and silently degrading to "accept all passwords"
// would be a security regression.
//
// The deduplication is case-insensitive: "Password" and "password"
// both reduce to the same lowercase key. The resulting map size is
// therefore slightly less than the file's line count (file has 10000
// lines, map typically has ~9900-9950 unique entries after
// case-folding). This is intentional: a password check should not
// distinguish between "Password" and "password".
func loadCommonPasswords() {
	commonPasswordsOnce.Do(func() {
		f, err := commonPasswordsFS.Open(commonPasswordsPath)
		if err != nil {
			panic("auth: cannot open embedded common-passwords list: " + err.Error())
		}
		defer f.Close()

		gz, err := gzip.NewReader(f)
		if err != nil {
			panic("auth: cannot decompress embedded common-passwords list: " + err.Error())
		}
		defer gz.Close()

		m := make(map[string]struct{}, 10000)
		scanner := bufio.NewScanner(gz)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				m[strings.ToLower(line)] = struct{}{}
			}
		}
		if err := scanner.Err(); err != nil {
			panic("auth: scanning common-passwords list: " + err.Error())
		}
		commonPasswords = m
	})
}

// isCommonPassword reports whether the given password (case-insensitive)
// is in the embedded top-10k list. Always available, never disabled:
// there is no scenario where allowing "password123" as an admin
// password is acceptable (spec §7.4).
func isCommonPassword(password string) bool {
	loadCommonPasswords()
	_, found := commonPasswords[strings.ToLower(password)]
	return found
}
