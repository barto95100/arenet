// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"context"
	"testing"
)

func TestUpdateCheckConfig_DefaultDisabled(t *testing.T) {
	s := newStoreForTest(t)
	got, err := s.GetUpdateCheckConfig(context.Background())
	if err != nil {
		t.Fatalf("GetUpdateCheckConfig on fresh store: %v", err)
	}
	if got.Enabled {
		t.Error("fresh install must default to Enabled=false (opt-in)")
	}
}

func TestUpdateCheckConfig_Roundtrip(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if err := s.PutUpdateCheckConfig(ctx, UpdateCheckConfig{Enabled: true, IntervalOverride: "12h"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetUpdateCheckConfig(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Enabled || got.IntervalOverride != "12h" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}
