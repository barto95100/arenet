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
