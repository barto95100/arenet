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

package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// Step R — ErrorPageTemplate CRUD pinning tests. Mirror of the
// AlertRule round-trip + error-path coverage in alert_rule_test.go.

func sampleErrorTemplate(name string) ErrorPageTemplate {
	return ErrorPageTemplate{
		Name:        name,
		Description: "Brand-aligned error pages for worldgeekwide.fr",
		Pages: map[int]string{
			403: "<!doctype html><h1>403 Forbidden</h1>",
			404: "<!doctype html><h1>404 Not Found</h1>",
			502: "<!doctype html><h1>502 Bad Gateway</h1>",
		},
	}
}

func TestErrorTemplate_CreateGet(t *testing.T) {
	store := newStoreForTest(t)
	created, err := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("worldgeekwide"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected ID assigned at create time")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Errorf("expected timestamps set ; CreatedAt=%v UpdatedAt=%v", created.CreatedAt, created.UpdatedAt)
	}

	got, err := store.GetErrorPageTemplate(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "worldgeekwide" {
		t.Errorf("Name = %q ; want worldgeekwide", got.Name)
	}
	if got.Pages[403] != "<!doctype html><h1>403 Forbidden</h1>" {
		t.Errorf("page 403 round-trip lost: %q", got.Pages[403])
	}
	if len(got.Pages) != 3 {
		t.Errorf("expected 3 pages ; got %d", len(got.Pages))
	}
}

func TestErrorTemplate_GetNotFound(t *testing.T) {
	store := newStoreForTest(t)
	_, err := store.GetErrorPageTemplate(context.Background(), "no-such-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound ; got %v", err)
	}
}

func TestErrorTemplate_GetEmptyID(t *testing.T) {
	store := newStoreForTest(t)
	_, err := store.GetErrorPageTemplate(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "id must not be empty") {
		t.Errorf("expected id-empty error ; got %v", err)
	}
}

func TestErrorTemplate_List_SortedByCreatedAt(t *testing.T) {
	store := newStoreForTest(t)
	// Create 3 templates ; the storage layer auto-stamps CreatedAt to
	// time.Now() so the sequential creates land in chronological order.
	a, _ := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("first"))
	b, _ := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("second"))
	c, _ := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("third"))

	got, err := store.ListErrorPageTemplates(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 templates ; got %d", len(got))
	}
	if got[0].ID != a.ID || got[1].ID != b.ID || got[2].ID != c.ID {
		t.Errorf("List order = [%s, %s, %s] ; want [%s, %s, %s]",
			got[0].ID, got[1].ID, got[2].ID, a.ID, b.ID, c.ID)
	}
}

func TestErrorTemplate_Update_PreservesCreatedAt(t *testing.T) {
	store := newStoreForTest(t)
	created, _ := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("original"))
	createdAtSnap := created.CreatedAt

	created.Name = "renamed"
	created.Pages[500] = "<h1>500</h1>"
	updated, err := store.UpdateErrorPageTemplate(context.Background(), created)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !updated.CreatedAt.Equal(createdAtSnap) {
		t.Errorf("Update wiped CreatedAt: was %v, now %v", createdAtSnap, updated.CreatedAt)
	}
	if !updated.UpdatedAt.After(createdAtSnap) {
		t.Errorf("Update did not refresh UpdatedAt: %v vs %v", updated.UpdatedAt, createdAtSnap)
	}
	if updated.Name != "renamed" {
		t.Errorf("Update did not persist Name: %q", updated.Name)
	}
	if updated.Pages[500] != "<h1>500</h1>" {
		t.Errorf("Update did not persist new page 500: %q", updated.Pages[500])
	}
}

func TestErrorTemplate_Update_NotFound(t *testing.T) {
	store := newStoreForTest(t)
	t2 := sampleErrorTemplate("ghost")
	t2.ID = "no-such-id"
	_, err := store.UpdateErrorPageTemplate(context.Background(), t2)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound ; got %v", err)
	}
}

func TestErrorTemplate_Delete(t *testing.T) {
	store := newStoreForTest(t)
	created, _ := store.CreateErrorPageTemplate(context.Background(), sampleErrorTemplate("doomed"))

	if err := store.DeleteErrorPageTemplate(context.Background(), created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := store.GetErrorPageTemplate(context.Background(), created.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after Delete ; got %v", err)
	}
}

func TestErrorTemplate_Delete_NotFound(t *testing.T) {
	store := newStoreForTest(t)
	err := store.DeleteErrorPageTemplate(context.Background(), "no-such-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound ; got %v", err)
	}
}

func TestErrorTemplate_Validate_RejectsBadStatusCode(t *testing.T) {
	store := newStoreForTest(t)
	bad := sampleErrorTemplate("invalid")
	bad.Pages[418] = "<h1>I'm a teapot</h1>" // not in the supported set
	_, err := store.CreateErrorPageTemplate(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "unsupported status code 418") {
		t.Errorf("expected unsupported-code error ; got %v", err)
	}
}

func TestErrorTemplate_Validate_RejectsOversizedBody(t *testing.T) {
	store := newStoreForTest(t)
	bad := sampleErrorTemplate("huge")
	bad.Pages[500] = strings.Repeat("a", (1<<20)+1) // 1 MiB + 1
	_, err := store.CreateErrorPageTemplate(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Errorf("expected oversized-body error ; got %v", err)
	}
}

func TestErrorTemplate_Validate_AcceptsEmptyName_No(t *testing.T) {
	store := newStoreForTest(t)
	bad := sampleErrorTemplate("")
	_, err := store.CreateErrorPageTemplate(context.Background(), bad)
	if err == nil || !strings.Contains(err.Error(), "name must not be empty") {
		t.Errorf("expected empty-name error ; got %v", err)
	}
}

func TestErrorTemplate_Validate_NilPagesAcceptedAsEmpty(t *testing.T) {
	// nil Pages is operator-supplied "no overrides ; everything
	// falls back to default" — must round-trip cleanly without
	// nil-panic downstream.
	store := newStoreForTest(t)
	t2 := ErrorPageTemplate{Name: "nilpages"}
	created, err := store.CreateErrorPageTemplate(context.Background(), t2)
	if err != nil {
		t.Fatalf("Create with nil Pages: %v", err)
	}
	got, err := store.GetErrorPageTemplate(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Pages == nil || len(got.Pages) != 0 {
		t.Errorf("expected empty Pages map after round-trip ; got %v", got.Pages)
	}
}

func TestIsSupportedErrorStatusCode(t *testing.T) {
	for _, code := range SupportedErrorStatusCodes {
		if !IsSupportedErrorStatusCode(code) {
			t.Errorf("expected %d to be supported", code)
		}
	}
	for _, code := range []int{0, 200, 301, 418, 451, 999} {
		if IsSupportedErrorStatusCode(code) {
			t.Errorf("expected %d to be unsupported", code)
		}
	}
}

// v2.9.10 Bug 1 — catch-all default flag tests.

func TestErrorTemplate_IsCatchallDefault_Roundtrip(t *testing.T) {
	store := newStoreForTest(t)
	tmpl := sampleErrorTemplate("default-tmpl")
	tmpl.IsCatchallDefault = true
	created, err := store.CreateErrorPageTemplate(context.Background(), tmpl)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !created.IsCatchallDefault {
		t.Fatalf("IsCatchallDefault not preserved on create")
	}
	got, err := store.GetErrorPageTemplate(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.IsCatchallDefault {
		t.Errorf("IsCatchallDefault not preserved after round-trip")
	}
}

func TestErrorTemplate_MutualExclusion_CreateClearsPriorDefault(t *testing.T) {
	// Storage invariant: at most one template carries
	// IsCatchallDefault=true. Creating a 2nd template with the flag
	// must clear the flag on the previously-flagged template in the
	// same write transaction.
	store := newStoreForTest(t)
	ctx := context.Background()

	t1 := sampleErrorTemplate("t1")
	t1.IsCatchallDefault = true
	t1c, err := store.CreateErrorPageTemplate(ctx, t1)
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}

	t2 := sampleErrorTemplate("t2")
	t2.IsCatchallDefault = true
	t2c, err := store.CreateErrorPageTemplate(ctx, t2)
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}

	// t1 must now be un-flagged.
	t1got, err := store.GetErrorPageTemplate(ctx, t1c.ID)
	if err != nil {
		t.Fatalf("Get t1: %v", err)
	}
	if t1got.IsCatchallDefault {
		t.Errorf("t1 still flagged after t2 became default")
	}
	// t2 stays flagged.
	t2got, err := store.GetErrorPageTemplate(ctx, t2c.ID)
	if err != nil {
		t.Fatalf("Get t2: %v", err)
	}
	if !t2got.IsCatchallDefault {
		t.Errorf("t2 should be flagged")
	}
}

func TestErrorTemplate_MutualExclusion_UpdateClearsPriorDefault(t *testing.T) {
	store := newStoreForTest(t)
	ctx := context.Background()

	t1 := sampleErrorTemplate("t1")
	t1.IsCatchallDefault = true
	t1c, err := store.CreateErrorPageTemplate(ctx, t1)
	if err != nil {
		t.Fatalf("Create t1: %v", err)
	}
	t2 := sampleErrorTemplate("t2")
	t2c, err := store.CreateErrorPageTemplate(ctx, t2)
	if err != nil {
		t.Fatalf("Create t2: %v", err)
	}

	// Update t2 to set the flag — t1 must lose it.
	t2c.IsCatchallDefault = true
	if _, err := store.UpdateErrorPageTemplate(ctx, t2c); err != nil {
		t.Fatalf("Update t2: %v", err)
	}
	t1got, err := store.GetErrorPageTemplate(ctx, t1c.ID)
	if err != nil {
		t.Fatalf("Get t1: %v", err)
	}
	if t1got.IsCatchallDefault {
		t.Errorf("t1 still flagged after t2 update")
	}
}

func TestErrorTemplate_GetCatchallDefault_NotFoundWhenNoneFlagged(t *testing.T) {
	store := newStoreForTest(t)
	ctx := context.Background()
	if _, err := store.CreateErrorPageTemplate(ctx, sampleErrorTemplate("none-flagged")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	_, err := store.GetCatchallDefaultErrorPageTemplate(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestErrorTemplate_GetCatchallDefault_ReturnsFlagged(t *testing.T) {
	store := newStoreForTest(t)
	ctx := context.Background()

	if _, err := store.CreateErrorPageTemplate(ctx, sampleErrorTemplate("plain")); err != nil {
		t.Fatalf("Create plain: %v", err)
	}
	flagged := sampleErrorTemplate("flagged")
	flagged.IsCatchallDefault = true
	created, err := store.CreateErrorPageTemplate(ctx, flagged)
	if err != nil {
		t.Fatalf("Create flagged: %v", err)
	}

	got, err := store.GetCatchallDefaultErrorPageTemplate(ctx)
	if err != nil {
		t.Fatalf("GetCatchallDefault: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID = %q, want %q", got.ID, created.ID)
	}
	if !got.IsCatchallDefault {
		t.Errorf("returned template not flagged")
	}
}

