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
	"testing"
	"time"
)

func TestGetServerPosition_EmptyBucket_ReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetServerPosition(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPutServerPosition_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

	in := ServerPositionRecord{
		Lat:        48.8566,
		Lon:        2.3522,
		City:       "Paris",
		Country:    "FR",
		Mode:       "auto",
		SourceIP:   "203.0.113.42",
		DetectedAt: now,
	}
	if err := s.PutServerPosition(ctx, in); err != nil {
		t.Fatalf("PutServerPosition: %v", err)
	}

	got, err := s.GetServerPosition(ctx)
	if err != nil {
		t.Fatalf("GetServerPosition: %v", err)
	}
	if got.Lat != in.Lat || got.Lon != in.Lon {
		t.Errorf("lat/lon roundtrip: got %v/%v, want %v/%v",
			got.Lat, got.Lon, in.Lat, in.Lon)
	}
	if got.City != in.City || got.Country != in.Country {
		t.Errorf("city/country roundtrip: got %q/%q, want %q/%q",
			got.City, got.Country, in.City, in.Country)
	}
	if got.Mode != in.Mode {
		t.Errorf("mode: got %q, want %q", got.Mode, in.Mode)
	}
	if got.SourceIP != in.SourceIP {
		t.Errorf("sourceIP: got %q, want %q", got.SourceIP, in.SourceIP)
	}
	if !got.DetectedAt.Equal(in.DetectedAt) {
		t.Errorf("detectedAt: got %v, want %v", got.DetectedAt, in.DetectedAt)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be populated on Put")
	}
}

func TestPutServerPosition_Overwrites(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first := ServerPositionRecord{Lat: 48.8566, Lon: 2.3522, Mode: "auto", City: "Paris"}
	if err := s.PutServerPosition(ctx, first); err != nil {
		t.Fatalf("first put: %v", err)
	}

	second := ServerPositionRecord{Lat: 45.7640, Lon: 4.8357, Mode: "manual", City: "Lyon"}
	if err := s.PutServerPosition(ctx, second); err != nil {
		t.Fatalf("second put: %v", err)
	}

	got, err := s.GetServerPosition(ctx)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.City != "Lyon" || got.Mode != "manual" {
		t.Errorf("overwrite failed: %+v", got)
	}
}

func TestDeleteServerPosition_ClearsRecord(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.PutServerPosition(ctx, ServerPositionRecord{
		Lat: 48.8566, Lon: 2.3522, Mode: "manual",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	if err := s.DeleteServerPosition(ctx); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := s.GetServerPosition(ctx)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete, err = %v, want ErrNotFound", err)
	}
}

func TestDeleteServerPosition_NoRecord_NoError(t *testing.T) {
	s := newTestStore(t)
	if err := s.DeleteServerPosition(context.Background()); err != nil {
		t.Errorf("delete on empty bucket should be no-op, got: %v", err)
	}
}

func TestPutServerPosition_UpdatedAtRefreshes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.PutServerPosition(ctx, ServerPositionRecord{Lat: 1, Lon: 2, Mode: "auto"}); err != nil {
		t.Fatalf("first put: %v", err)
	}
	first, _ := s.GetServerPosition(ctx)

	time.Sleep(2 * time.Millisecond)
	if err := s.PutServerPosition(ctx, ServerPositionRecord{Lat: 3, Lon: 4, Mode: "manual"}); err != nil {
		t.Fatalf("second put: %v", err)
	}
	second, _ := s.GetServerPosition(ctx)

	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Errorf("UpdatedAt should refresh: first=%v second=%v", first.UpdatedAt, second.UpdatedAt)
	}
}
