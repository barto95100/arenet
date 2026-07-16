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

package topology

import (
	"testing"

	"github.com/barto95100/arenet/internal/storage"
)

// stubMetrics / stubStatus are declared in builder_test.go — their
// zero values satisfy the builder's collaborators with no data,
// which is all this test needs (we only care about the Disabled
// pass-through, not metrics/status content).
func TestBuildRoute_PassesDisabledThrough(t *testing.T) {
	src := &storage.Route{ID: "r1", Host: "x.example.com", Disabled: true}
	out := buildRoute(src, stubMetrics{}, stubStatus{})
	if !out.Disabled {
		t.Error("buildRoute did not propagate Disabled=true to the wire struct")
	}

	src2 := &storage.Route{ID: "r2", Host: "y.example.com"}
	out2 := buildRoute(src2, stubMetrics{}, stubStatus{})
	if out2.Disabled {
		t.Error("enabled route reported Disabled=true")
	}
}
