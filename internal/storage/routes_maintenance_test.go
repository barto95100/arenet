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

func TestRoute_MaintenanceConfig_Roundtrip(t *testing.T) {
	s := newTestStore(t)
	r := minimalRoute("m.example.com", "http://u:1")
	r.MaintenanceConfig = &MaintenanceConfig{RetryAfterSeconds: 300, BypassIPs: []string{"192.168.1.0/24", "10.0.0.5"}}
	created, err := s.CreateRoute(context.Background(), r)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetRoute(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MaintenanceConfig == nil {
		t.Fatal("MaintenanceConfig nil after roundtrip; want non-nil")
	}
	if got.MaintenanceConfig.RetryAfterSeconds != 300 {
		t.Errorf("RetryAfterSeconds = %d; want 300", got.MaintenanceConfig.RetryAfterSeconds)
	}
	if len(got.MaintenanceConfig.BypassIPs) != 2 {
		t.Errorf("BypassIPs len = %d; want 2", len(got.MaintenanceConfig.BypassIPs))
	}
}

func TestRoute_MaintenanceConfig_NilByDefault(t *testing.T) {
	s := newTestStore(t)
	created, _ := s.CreateRoute(context.Background(), minimalRoute("plain.example.com", "http://u:1"))
	got, _ := s.GetRoute(context.Background(), created.ID)
	if got.MaintenanceConfig != nil {
		t.Errorf("MaintenanceConfig = %+v; want nil (zero value)", got.MaintenanceConfig)
	}
}

func TestMaintenanceConfig_Validate_BadIP(t *testing.T) {
	if err := (&MaintenanceConfig{BypassIPs: []string{"not-an-ip"}}).Validate(); err == nil {
		t.Error("want error for junk bypass IP")
	}
	if err := (&MaintenanceConfig{BypassIPs: []string{"10.0.0.0/8", "1.2.3.4"}}).Validate(); err != nil {
		t.Errorf("valid CIDR + IP rejected: %v", err)
	}
	if err := (&MaintenanceConfig{RetryAfterSeconds: -1}).Validate(); err == nil {
		t.Error("want error for negative RetryAfterSeconds")
	}
}
