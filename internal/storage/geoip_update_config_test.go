// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package storage

import (
	"context"
	"testing"
)

func TestGeoIPUpdateConfig_DefaultDisabled(t *testing.T) {
	s := newStoreForTest(t)
	got, err := s.GetGeoIPUpdateConfig(context.Background())
	if err != nil {
		t.Fatalf("GetGeoIPUpdateConfig on fresh store: %v", err)
	}
	if got.Enabled {
		t.Error("fresh install must default to Enabled=false (opt-in)")
	}
}

func TestGeoIPUpdateConfig_Roundtrip(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()
	if err := s.PutGeoIPUpdateConfig(ctx, GeoIPUpdateConfig{Enabled: true, IntervalOverride: "24h"}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.GetGeoIPUpdateConfig(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Enabled || got.IntervalOverride != "24h" {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

func TestGeoIPUpdateConfig_ToggleAndInterval(t *testing.T) {
	s := newStoreForTest(t)
	ctx := context.Background()

	if err := s.PutGeoIPUpdateConfig(ctx, GeoIPUpdateConfig{Enabled: true, IntervalOverride: "12h"}); err != nil {
		t.Fatalf("Put (enable): %v", err)
	}
	got, err := s.GetGeoIPUpdateConfig(ctx)
	if err != nil {
		t.Fatalf("Get (enable): %v", err)
	}
	if !got.Enabled || got.IntervalOverride != "12h" {
		t.Errorf("after enable: %+v", got)
	}

	if err := s.PutGeoIPUpdateConfig(ctx, GeoIPUpdateConfig{Enabled: false, IntervalOverride: "12h"}); err != nil {
		t.Fatalf("Put (disable): %v", err)
	}
	got, err = s.GetGeoIPUpdateConfig(ctx)
	if err != nil {
		t.Fatalf("Get (disable): %v", err)
	}
	if got.Enabled {
		t.Errorf("expected disabled after toggle: %+v", got)
	}
	if got.IntervalOverride != "12h" {
		t.Errorf("interval override should persist across toggle: %+v", got)
	}
}
