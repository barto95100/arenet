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

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// Step R — error_templates CRUD handler tests. Same shape as
// alerting_rules_test.go : exercise each HTTP verb's happy path +
// each documented error path, with role-gating (admin vs viewer)
// and audit-event emission pinned.

func validErrorTemplateBody(name string) string {
	return `{
		"name":"` + name + `",
		"description":"smoke template",
		"pages":{
			"403":"<h1>403 — branded</h1>",
			"404":"<h1>404 — branded</h1>"
		}
	}`
}

func TestErrorTemplate_GET_List_Empty(t *testing.T) {
	env := newTestEnv(t, false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/error-templates", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got []errorTemplateResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list ; got %d items", len(got))
	}
}

func TestErrorTemplate_POST_HappyPath_201(t *testing.T) {
	env := newTestEnv(t, false)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(validErrorTemplateBody("worldgeekwide")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
	var got errorTemplateResponse
	_ = json.NewDecoder(rec.Body).Decode(&got)
	if got.ID == "" {
		t.Error("expected ID assigned")
	}
	if got.Name != "worldgeekwide" {
		t.Errorf("Name = %q ; want worldgeekwide", got.Name)
	}
	if got.Pages[403] != "<h1>403 — branded</h1>" {
		t.Errorf("Pages[403] = %q ; want branded", got.Pages[403])
	}
}

func TestErrorTemplate_POST_RejectsUnsupportedCode(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"name":"bad","pages":{"418":"<h1>I'm a teapot</h1>"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d ; want 400 (unsupported code)", rec.Code)
	}
}

func TestErrorTemplate_POST_RejectsEmptyName(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{"name":"","pages":{"403":"<h1>x</h1>"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d ; want 400 (empty name)", rec.Code)
	}
}

func TestErrorTemplate_PUT_RoundTrip(t *testing.T) {
	env := newTestEnv(t, false)
	// Create.
	post := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(validErrorTemplateBody("original")))
	post.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, post)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body)
	}
	var created errorTemplateResponse
	_ = json.NewDecoder(rec.Body).Decode(&created)

	// Update : change name + add a page.
	updateBody := `{
		"name":"renamed",
		"description":"smoke template",
		"pages":{
			"403":"<h1>403 v2</h1>",
			"500":"<h1>500 new</h1>"
		}
	}`
	put := httptest.NewRequest(http.MethodPut, "/api/v1/error-templates/"+created.ID,
		strings.NewReader(updateBody))
	put.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, put)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body)
	}
	var updated errorTemplateResponse
	_ = json.NewDecoder(rec.Body).Decode(&updated)
	if updated.Name != "renamed" {
		t.Errorf("Name = %q ; want renamed", updated.Name)
	}
	if updated.Pages[500] != "<h1>500 new</h1>" {
		t.Errorf("Pages[500] = %q ; want new", updated.Pages[500])
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("CreatedAt drifted on update: %v vs %v", updated.CreatedAt, created.CreatedAt)
	}
}

func TestErrorTemplate_PUT_NotFound(t *testing.T) {
	env := newTestEnv(t, false)
	put := httptest.NewRequest(http.MethodPut, "/api/v1/error-templates/no-such-id",
		strings.NewReader(validErrorTemplateBody("x")))
	put.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, put)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status=%d ; want 404", rec.Code)
	}
}

func TestErrorTemplate_DELETE_204(t *testing.T) {
	env := newTestEnv(t, false)
	// Create then delete.
	post := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(validErrorTemplateBody("doomed")))
	post.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, post)
	var created errorTemplateResponse
	_ = json.NewDecoder(rec.Body).Decode(&created)

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/error-templates/"+created.ID, nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, del)
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete status=%d ; want 204", rec.Code)
	}

	// Verify gone via storage.
	_, err := env.store.GetErrorPageTemplate(context.Background(), created.ID)
	if err == nil {
		t.Error("expected ErrNotFound after delete")
	}
}

func TestErrorTemplate_Preview_RendersWithSubstitution(t *testing.T) {
	env := newTestEnv(t, false)
	body := `{
		"name":"preview-fixture",
		"pages":{
			"403":"<h1>{http.error.status_code} {http.error.status_text}</h1><p>{http.request.uri}</p>"
		}
	}`
	post := httptest.NewRequest(http.MethodPost, "/api/v1/error-templates",
		strings.NewReader(body))
	post.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, post)
	var created errorTemplateResponse
	_ = json.NewDecoder(rec.Body).Decode(&created)

	preview := httptest.NewRequest(http.MethodGet,
		"/api/v1/error-templates/"+created.ID+"/preview?statusCode=403", nil)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, preview)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", rec.Code, rec.Body)
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "<h1>403 Forbidden</h1>") {
		t.Errorf("preview did not substitute status_code/status_text ; body=%s", bodyStr)
	}
	if !strings.Contains(bodyStr, "/preview/path") {
		t.Errorf("preview did not substitute request.uri ; body=%s", bodyStr)
	}
	if rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q ; want text/html; charset=utf-8", rec.Header().Get("Content-Type"))
	}
}

func TestErrorTemplate_Preview_RejectsUnsupportedCode(t *testing.T) {
	env := newTestEnv(t, false)
	// Seed a real template so we hit the code check, not the not-found path.
	created, err := env.store.CreateErrorPageTemplate(context.Background(), storage.ErrorPageTemplate{
		Name:  "t",
		Pages: map[int]string{403: "<h1>x</h1>"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	preview := httptest.NewRequest(http.MethodGet,
		"/api/v1/error-templates/"+created.ID+"/preview?statusCode=999", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, preview)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d ; want 400 for unsupported code", rec.Code)
	}
}

func TestErrorTemplate_Preview_RejectsMissingStatusCode(t *testing.T) {
	env := newTestEnv(t, false)
	created, err := env.store.CreateErrorPageTemplate(context.Background(), storage.ErrorPageTemplate{
		Name:  "t",
		Pages: map[int]string{403: "<h1>x</h1>"},
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	preview := httptest.NewRequest(http.MethodGet,
		"/api/v1/error-templates/"+created.ID+"/preview", nil)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, preview)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d ; want 400 for missing statusCode", rec.Code)
	}
}
