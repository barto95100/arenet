// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package alerting

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/barto95100/arenet/internal/updatecheck"
)

func TestUpdateAvailableSource_ReadsStatus(t *testing.T) {
	src := NewUpdateAvailableSource(func() updatecheck.Status {
		return updatecheck.Status{UpdateAvailable: true, Latest: "v2.12.4", URL: "u", Current: "v2.12.3"}
	})
	if src.Name() != "update_available" {
		t.Fatalf("name=%q", src.Name())
	}
	v, err := src.Read(context.Background(), json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if v.String == nil || *v.String != "available" {
		t.Errorf("value=%+v; want state 'available'", v)
	}
	if v.Context["latest"] != "v2.12.4" {
		t.Errorf("context=%v; want latest v2.12.4", v.Context)
	}
}

func TestUpdateAvailableSource_UpToDate(t *testing.T) {
	src := NewUpdateAvailableSource(func() updatecheck.Status {
		return updatecheck.Status{UpdateAvailable: false}
	})
	v, _ := src.Read(context.Background(), json.RawMessage(`{}`))
	if v.String == nil || *v.String != "up_to_date" {
		t.Errorf("value=%+v; want 'up_to_date'", v)
	}
}

func TestUpdateAvailableSource_ValidateParams_AcceptsEmpty(t *testing.T) {
	src := NewUpdateAvailableSource(func() updatecheck.Status { return updatecheck.Status{} })
	if err := src.ValidateParams(json.RawMessage(`{}`)); err != nil {
		t.Errorf("ValidateParams: %v", err)
	}
}
