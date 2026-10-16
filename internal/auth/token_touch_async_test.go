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

package auth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// asyncFakeToucher implements APITokenLookup AND the optional
// asyncTokenToucher, recording which path the middleware helper used.
type asyncFakeToucher struct {
	syncCalls  atomic.Int32
	asyncCalls atomic.Int32
}

func (f *asyncFakeToucher) LookupToken(context.Context, string) (APIToken, error) {
	return APIToken{}, ErrAPITokenInvalid
}
func (f *asyncFakeToucher) TouchLastUsed(context.Context, string) error {
	f.syncCalls.Add(1)
	return nil
}
func (f *asyncFakeToucher) TouchLastUsedAsync(string) { f.asyncCalls.Add(1) }

// A store that offers the bounded async path must be driven through it,
// never through the per-request goroutine (F52).
func TestTouchLastUsedBestEffort_PrefersBoundedAsync(t *testing.T) {
	f := &asyncFakeToucher{}
	touchLastUsedBestEffort(f, "tok-1")
	if f.asyncCalls.Load() != 1 {
		t.Errorf("the bounded async path was not used: asyncCalls=%d", f.asyncCalls.Load())
	}
	if f.syncCalls.Load() != 0 {
		t.Errorf("the unbounded goroutine path ran despite an async toucher: syncCalls=%d", f.syncCalls.Load())
	}
}

// The store's single worker actually applies the update, so routing
// through it is not a silent drop of all touches.
func TestAPITokenStore_TouchLastUsedAsync_Writes(t *testing.T) {
	_, us, ts := newTokenTestDB(t)
	owner := createServiceUserForToken(t, us, "poller", UserRoleViewer)
	_, row, err := ts.CreateToken(context.Background(), owner.ID, "poll", "admin-uid", nil)
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if row.LastUsedAt != nil {
		t.Fatal("precondition: a fresh token has no LastUsedAt")
	}

	ts.TouchLastUsedAsync(row.ID)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := ts.GetByID(context.Background(), row.ID)
		if err == nil && got.LastUsedAt != nil {
			return // worker applied the touch
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("the async worker never applied LastUsedAt")
}
