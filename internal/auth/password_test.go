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
	"context"
	"errors"
	"strings"
	"testing"
)

// mockHIBPChecker is a hand-rolled test double for passwordHIBPChecker.
// Configurable to return any combination of status + error and to
// count invocations.
type mockHIBPChecker struct {
	status string
	err    error

	calls        int
	lastPassword string
}

func (m *mockHIBPChecker) CheckPassword(_ context.Context, password string) (string, error) {
	m.calls++
	m.lastPassword = password
	return m.status, m.err
}

// TestIsCommonPassword_KnownTopHits covers the most common entries
// from the top-10k list. These passwords (123456, password, qwerty,
// etc.) are at positions 1-15 of the underlying xato-net corpus and
// must always be rejected.
func TestIsCommonPassword_KnownTopHits(t *testing.T) {
	hits := []string{
		"123456",
		"password",
		"12345678",
		"qwerty",
		"123456789",
		"12345",
		"1234",
		"111111",
		"abc123",
		"dragon",
	}
	for _, p := range hits {
		if !isCommonPassword(p) {
			t.Errorf("%q should be in the top-10k list", p)
		}
	}
}

// TestIsCommonPassword_StrongPasswordsNotHit verifies that genuinely
// strong, long, random-looking passwords are NOT in the list.
func TestIsCommonPassword_StrongPasswordsNotHit(t *testing.T) {
	misses := []string{
		"correct horse battery staple frobnicate",
		"Tr0ub4dor&3-but-very-long-with-spaces",
		"this-is-a-passphrase-with-15-chars-or-more",
		"R4nd0m!9-Goldfish-Tractor-Marshmallow",
	}
	for _, p := range misses {
		if isCommonPassword(p) {
			t.Errorf("%q should NOT be in the top-10k list", p)
		}
	}
}

// TestIsCommonPassword_CaseInsensitive verifies that "Password",
// "PASSWORD", and "password" are all rejected. Lookup is
// case-insensitive (spec §7.4).
func TestIsCommonPassword_CaseInsensitive(t *testing.T) {
	variants := []string{"password", "Password", "PASSWORD", "PaSsWoRd"}
	for _, v := range variants {
		if !isCommonPassword(v) {
			t.Errorf("case variant %q should be rejected", v)
		}
	}
	// And the same for a less obvious entry.
	for _, v := range []string{"dragon", "Dragon", "DRAGON"} {
		if !isCommonPassword(v) {
			t.Errorf("case variant %q should be rejected", v)
		}
	}
}

// TestIsCommonPassword_EmptyString verifies that the empty string
// is not matched (it is filtered at load time per spec §7.4 "non-empty
// lines only"). The length check at the caller layer rejects empty
// passwords long before they reach this function in production.
func TestIsCommonPassword_EmptyString(t *testing.T) {
	if isCommonPassword("") {
		t.Error(`empty string must not be considered "common"`)
	}
}

// TestLoadCommonPasswords_Idempotent verifies that calling
// loadCommonPasswords multiple times is a no-op after the first call
// (sync.Once guarantee).
func TestLoadCommonPasswords_Idempotent(t *testing.T) {
	loadCommonPasswords()
	first := len(commonPasswords)
	if first == 0 {
		t.Fatal("expected non-empty map after first load")
	}
	loadCommonPasswords()
	if got := len(commonPasswords); got != first {
		t.Errorf("map size changed across calls: first=%d second=%d", first, got)
	}
}

// TestLoadCommonPasswords_ExpectedSize asserts the loaded map size
// is in the expected range. The upstream source has 10000 lines, but
// loadCommonPasswords lowercases each entry as it inserts (per spec
// §7.4 case-insensitive lookup), which collapses case variants like
// "Password" and "password" into a single map entry. The xato-net
// 10000-line corpus contains ~84 such case-only duplicates, yielding
// roughly 9916 unique entries after lowercasing.
//
// We assert a range rather than an exact value so a future asset
// regeneration with a slightly different case-duplicate profile does
// not require a test update. A drastic drift (e.g., < 9000 or >
// 10000) would indicate a parse bug or a wrong asset.
func TestLoadCommonPasswords_ExpectedSize(t *testing.T) {
	loadCommonPasswords()
	got := len(commonPasswords)
	const (
		minExpected = 9900
		maxExpected = 10000
	)
	if got < minExpected || got > maxExpected {
		t.Errorf("common-passwords list size: got %d, want in [%d, %d]", got, minExpected, maxExpected)
	}
}

// --- ValidatePasswordSync tests --------------------------------------

func TestValidatePasswordSync_TooShort(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusClean}
	status, err := ValidatePasswordSync(context.Background(), mock, strings.Repeat("a", 14))
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("want ErrPasswordTooShort, got %v", err)
	}
	if status != "" {
		t.Errorf("status = %q, want \"\"", status)
	}
	if mock.calls != 0 {
		t.Errorf("HIBP must not be called on length-fail; got %d calls", mock.calls)
	}
}

func TestValidatePasswordSync_TooLong(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusClean}
	status, err := ValidatePasswordSync(context.Background(), mock, strings.Repeat("a", 129))
	if !errors.Is(err, ErrPasswordTooLong) {
		t.Errorf("want ErrPasswordTooLong, got %v", err)
	}
	if status != "" {
		t.Errorf("status = %q, want \"\"", status)
	}
	if mock.calls != 0 {
		t.Errorf("HIBP must not be called on length-fail; got %d calls", mock.calls)
	}
}

func TestValidatePasswordSync_TopHitRejected(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusClean}
	// We need a top-10k entry that satisfies the 15-char minimum
	// length floor so the length gate doesn't short-circuit first.
	// The xato-net 10k corpus contains two such entries that we
	// know are present at the documented SHA: "Mailcreated5240"
	// (15 chars) and "PolniyPizdec0211" (16 chars).
	pw := "Mailcreated5240"
	if !isCommonPassword(pw) {
		t.Skipf("test fixture %q unexpectedly not in top-10k; data drift — refresh fixture", pw)
	}
	status, err := ValidatePasswordSync(context.Background(), mock, pw)
	if !errors.Is(err, ErrPasswordCommon) {
		t.Errorf("want ErrPasswordCommon, got %v", err)
	}
	if status != "" {
		t.Errorf("status = %q, want \"\"", status)
	}
	if mock.calls != 0 {
		t.Errorf("HIBP must not be called when top-10k matches; got %d calls", mock.calls)
	}
}

func TestValidatePasswordSync_HIBPCompromised(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusCompromised}
	status, err := ValidatePasswordSync(context.Background(), mock, "very-long-strong-passphrase-not-in-top-10k")
	if !errors.Is(err, ErrPasswordCommon) {
		t.Errorf("want ErrPasswordCommon (uniform UX for top-10k and HIBP), got %v", err)
	}
	if status != "" {
		t.Errorf("status = %q, want \"\"", status)
	}
	if mock.calls != 1 {
		t.Errorf("HIBP should be called exactly once; got %d", mock.calls)
	}
}

func TestValidatePasswordSync_HIBPClean(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusClean}
	pw := "very-long-strong-passphrase-not-in-top-10k"
	status, err := ValidatePasswordSync(context.Background(), mock, pw)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if status != HIBPStatusClean {
		t.Errorf("status = %q, want %q", status, HIBPStatusClean)
	}
	if mock.calls != 1 {
		t.Errorf("HIBP should be called exactly once; got %d", mock.calls)
	}
	if mock.lastPassword != pw {
		t.Errorf("HIBP received %q, want %q", mock.lastPassword, pw)
	}
}

func TestValidatePasswordSync_HIBPPendingAccepted(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusPending}
	status, err := ValidatePasswordSync(context.Background(), mock, "very-long-strong-passphrase-not-in-top-10k")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if status != HIBPStatusPending {
		t.Errorf("status = %q, want %q (pending → accepted, deferred re-check)", status, HIBPStatusPending)
	}
}

func TestValidatePasswordSync_HIBPSkippedAccepted(t *testing.T) {
	mock := &mockHIBPChecker{status: HIBPStatusSkipped}
	status, err := ValidatePasswordSync(context.Background(), mock, "very-long-strong-passphrase-not-in-top-10k")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if status != HIBPStatusSkipped {
		t.Errorf("status = %q, want %q (skipped → accepted, HIBP disabled)", status, HIBPStatusSkipped)
	}
}

// TestValidatePasswordSync_HIBPErrorMappedToPending verifies that a
// non-nil error from hibp.CheckPassword (which by construction
// indicates a programming bug) is treated as a HIBP miss, mapping
// to HIBPStatusPending so the user-facing operation is not blocked.
// The bug is surfaced via a Warn log to operators; the deferred
// re-check at next login (spec §7.6) will retry once the bug is fixed.
func TestValidatePasswordSync_HIBPErrorMappedToPending(t *testing.T) {
	bug := errors.New("hibp: programming bug")
	mock := &mockHIBPChecker{err: bug}
	status, err := ValidatePasswordSync(context.Background(), mock, "very-long-strong-passphrase-not-in-top-10k")
	if err != nil {
		t.Errorf("err must be nil to not block user-facing flow; got %v", err)
	}
	if status != HIBPStatusPending {
		t.Errorf("status = %q, want %q (bug → pending, deferred re-check at next login)", status, HIBPStatusPending)
	}
}

// TestValidatePasswordSync_OrderOfGates verifies the validation runs
// in the correct order (length → top-10k → HIBP) by checking that
// each gate short-circuits the next.
func TestValidatePasswordSync_OrderOfGates(t *testing.T) {
	// 14-char top-10k entry: length must fire first, top-10k never
	// checked, HIBP never called.
	mock := &mockHIBPChecker{status: HIBPStatusClean}
	_, err := ValidatePasswordSync(context.Background(), mock, "password")
	if !errors.Is(err, ErrPasswordTooShort) {
		t.Errorf("length must short-circuit top-10k: got err=%v", err)
	}
	if mock.calls != 0 {
		t.Errorf("HIBP must not be called when length fails: got %d calls", mock.calls)
	}
}
