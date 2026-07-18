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
	"testing"
)

func TestMaintenancePageConfig_AbsentReturnsZero(t *testing.T) {
	s := newTestStore(t)
	got, err := s.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("get on fresh store: %v", err)
	}
	if got.HTML != "" {
		t.Errorf("HTML = %q; want empty (serve branded default)", got.HTML)
	}
}

func TestMaintenancePageConfig_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	if err := s.PutMaintenancePageConfig(context.Background(), MaintenancePageConfig{HTML: "<h1>Back soon</h1>"}); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HTML != "<h1>Back soon</h1>" {
		t.Errorf("HTML = %q; want the stored value", got.HTML)
	}
}

// v2.18.0 — the global maintenance Message field round-trips alongside
// HTML. Message is operator free text substituted into the maintenance
// body via {arenet.maintenance.message} at emission; it is stored
// verbatim (escaping happens at emission, not here).
func TestMaintenancePageConfig_MessageRoundtrip(t *testing.T) {
	s := newTestStore(t)
	want := MaintenancePageConfig{
		HTML:    "<h1>Back soon</h1>",
		Message: "DB migration in progress, back around 14:00.",
	}
	if err := s.PutMaintenancePageConfig(context.Background(), want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := s.GetMaintenancePageConfig(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.HTML != want.HTML {
		t.Errorf("HTML = %q; want %q", got.HTML, want.HTML)
	}
	if got.Message != want.Message {
		t.Errorf("Message = %q; want %q", got.Message, want.Message)
	}
}
