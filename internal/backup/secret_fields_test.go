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

package backup

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// TestVisitSecrets_VisitsHealthCheckHeaders pins F48 for backups: a
// health-check probe credential (route-level and path-rule) must be run
// through the secret visitor, so it is redacted in a secrets-excluded
// export and sealed in an encrypted one rather than shipping in cleartext.
func TestVisitSecrets_VisitsHealthCheckHeaders(t *testing.T) {
	snap := &Snapshot{
		Routes: []storage.Route{{
			ID:   "r1",
			Host: "app.example.com",
			HealthCheck: storage.HealthCheck{
				Enabled: true, URI: "/healthz",
				Headers: map[string]string{"Authorization": "Bearer ROUTE-HC-SECRET"},
			},
			PathRules: []storage.PathRule{{
				PathPrefix: "/api",
				HealthCheck: &storage.HealthCheck{
					Enabled: true,
					Headers: map[string]string{"X-Api-Key": "PATH-HC-SECRET"},
				},
			}},
		}},
	}

	err := visitSecrets(snap, func(_ string, _ string) (string, error) { return "[redacted]", nil })
	if err != nil {
		t.Fatalf("visitSecrets: %v", err)
	}

	r := snap.Routes[0]
	if got := r.HealthCheck.Headers["Authorization"]; got != "[redacted]" {
		t.Errorf("route health-check credential not visited: %q", got)
	}
	if got := r.PathRules[0].HealthCheck.Headers["X-Api-Key"]; got != "[redacted]" {
		t.Errorf("path-rule health-check credential not visited: %q", got)
	}
}
