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

func TestWatcherCredentials_Validate(t *testing.T) {
	cases := []struct {
		name    string
		c       WatcherCredentials
		wantErr string
	}{
		{
			name: "valid",
			c: WatcherCredentials{
				LAPIURL:   "http://127.0.0.1:8080/",
				MachineID: "arenet-writer",
				Password:  "secret",
			},
		},
		{
			name:    "empty lapi_url",
			c:       WatcherCredentials{MachineID: "m", Password: "p"},
			wantErr: "lapi_url must not be empty",
		},
		{
			name:    "empty machine_id",
			c:       WatcherCredentials{LAPIURL: "u", Password: "p"},
			wantErr: "machine_id must not be empty",
		},
		{
			name:    "empty password",
			c:       WatcherCredentials{LAPIURL: "u", MachineID: "m"},
			wantErr: "password must not be empty",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.c.validate()
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %q, want substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestWatcherCredentialsConfigured(t *testing.T) {
	if WatcherCredentialsConfigured(WatcherCredentials{}) {
		t.Error("empty credentials should report configured=false")
	}
	if !WatcherCredentialsConfigured(WatcherCredentials{
		LAPIURL: "u", MachineID: "m", Password: "p",
	}) {
		t.Error("full credentials should report configured=true")
	}
	if WatcherCredentialsConfigured(WatcherCredentials{
		LAPIURL: "u", MachineID: "m", // password missing
	}) {
		t.Error("missing password should report configured=false")
	}
}

func TestWatcherCredentials_PutGet_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	c := WatcherCredentials{
		LAPIURL:   "http://127.0.0.1:8080/",
		MachineID: "arenet-writer",
		Password:  "smoke-secret",
	}
	if err := s.PutWatcherCredentials(ctx, c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetWatcherCredentials(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != c {
		t.Errorf("roundtrip mismatch: got %+v, want %+v", got, c)
	}
}

func TestWatcherCredentials_Get_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetWatcherCredentials(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on fresh install, got %v", err)
	}
}

func TestWatcherCredentials_Put_RejectsPartial(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutWatcherCredentials(context.Background(), WatcherCredentials{
		// password missing — should be rejected by validate
		LAPIURL: "u", MachineID: "m",
	}); err == nil {
		t.Error("expected error on partial config, got nil")
	}
}

func TestWatcherCredentials_Delete_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Delete on missing row → nil (idempotent).
	if err := s.DeleteWatcherCredentials(ctx); err != nil {
		t.Errorf("delete on missing should return nil, got %v", err)
	}

	if err := s.PutWatcherCredentials(ctx, WatcherCredentials{
		LAPIURL: "u", MachineID: "m", Password: "p",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.DeleteWatcherCredentials(ctx); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetWatcherCredentials(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
	// Second delete on already-deleted row → nil.
	if err := s.DeleteWatcherCredentials(ctx); err != nil {
		t.Errorf("second delete should return nil, got %v", err)
	}
}

func TestAutomationRulesRaw_PutGet_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	raw := []byte(`{"rules":{"waf-sqli":{"enabled":true}}}`)
	if err := s.PutAutomationRulesRaw(ctx, raw); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetAutomationRulesRaw(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("roundtrip mismatch: got %s, want %s", got, raw)
	}
}

func TestAutomationRulesRaw_Get_NotFound(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.GetAutomationRulesRaw(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on fresh install, got %v", err)
	}
}

func TestAutomationRulesRaw_Put_RejectsEmpty(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutAutomationRulesRaw(context.Background(), nil); err == nil {
		t.Error("expected error on nil payload, got nil")
	}
	if err := s.PutAutomationRulesRaw(context.Background(), []byte{}); err == nil {
		t.Error("expected error on empty payload, got nil")
	}
}

func TestAutomationRulesRaw_Put_RejectsNonObject(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutAutomationRulesRaw(context.Background(), []byte("[1,2]")); err == nil {
		t.Error("expected error on array payload, got nil")
	}
	if err := s.PutAutomationRulesRaw(context.Background(), []byte(`"string"`)); err == nil {
		t.Error("expected error on string payload, got nil")
	}
}

func TestAutomationRulesRaw_Delete_Idempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.DeleteAutomationRulesRaw(ctx); err != nil {
		t.Errorf("delete on missing should be nil, got %v", err)
	}
	if err := s.PutAutomationRulesRaw(ctx, []byte(`{"rules":{}}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.DeleteAutomationRulesRaw(ctx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.GetAutomationRulesRaw(ctx); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}
