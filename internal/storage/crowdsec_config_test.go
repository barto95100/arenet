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
	"time"
)

func TestGetCrowdSecConfig_EmptyBucket_ReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetCrowdSecConfig(context.Background())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestPutCrowdSecConfig_RoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	in := CrowdSecConfig{
		LAPIURL:        "http://127.0.0.1:8080",
		APIKey:         "ABCDEFGHIJ1234567890",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}
	if err := s.PutCrowdSecConfig(ctx, in); err != nil {
		t.Fatalf("PutCrowdSecConfig: %v", err)
	}

	got, err := s.GetCrowdSecConfig(ctx)
	if err != nil {
		t.Fatalf("GetCrowdSecConfig: %v", err)
	}
	if got.LAPIURL != in.LAPIURL {
		t.Errorf("LAPIURL: got %q, want %q", got.LAPIURL, in.LAPIURL)
	}
	if got.APIKey != in.APIKey {
		t.Errorf("APIKey: got %q, want %q", got.APIKey, in.APIKey)
	}
	if got.BouncerName != in.BouncerName {
		t.Errorf("BouncerName: got %q, want %q", got.BouncerName, in.BouncerName)
	}
	if got.TimeoutSeconds != in.TimeoutSeconds {
		t.Errorf("TimeoutSeconds: got %d, want %d", got.TimeoutSeconds, in.TimeoutSeconds)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be populated on Put")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be populated on Put")
	}
}

func TestPutCrowdSecConfig_PreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	first := CrowdSecConfig{
		LAPIURL:        "http://127.0.0.1:8080",
		APIKey:         "k1",
		BouncerName:    "arenet",
		TimeoutSeconds: 5,
	}
	if err := s.PutCrowdSecConfig(ctx, first); err != nil {
		t.Fatalf("first put: %v", err)
	}
	got1, _ := s.GetCrowdSecConfig(ctx)

	time.Sleep(2 * time.Millisecond)

	second := CrowdSecConfig{
		LAPIURL:        "http://192.168.99.10:8080",
		APIKey:         "k2",
		BouncerName:    "arenet-test",
		TimeoutSeconds: 10,
	}
	if err := s.PutCrowdSecConfig(ctx, second); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got2, _ := s.GetCrowdSecConfig(ctx)

	if !got2.CreatedAt.Equal(got1.CreatedAt) {
		t.Errorf("CreatedAt should be preserved across updates: got %v, want %v",
			got2.CreatedAt, got1.CreatedAt)
	}
	if !got2.UpdatedAt.After(got1.UpdatedAt) {
		t.Errorf("UpdatedAt should advance on second put: got1=%v got2=%v",
			got1.UpdatedAt, got2.UpdatedAt)
	}
	if got2.APIKey != "k2" || got2.LAPIURL != "http://192.168.99.10:8080" {
		t.Errorf("second put values not persisted: %+v", got2)
	}
}

func TestPutCrowdSecConfig_NormalisesDefaultsOnConfiguredRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// APIKey provided but LAPIURL + name + timeout left
	// blank — Put must fill from CrowdSecConfigDefaults so
	// downstream readers don't deal with sentinels.
	in := CrowdSecConfig{
		APIKey: "abc123",
	}
	if err := s.PutCrowdSecConfig(ctx, in); err != nil {
		t.Fatalf("PutCrowdSecConfig: %v", err)
	}
	got, err := s.GetCrowdSecConfig(ctx)
	if err != nil {
		t.Fatalf("GetCrowdSecConfig: %v", err)
	}
	if got.LAPIURL == "" {
		t.Error("blank LAPIURL on configured row should be normalised to default")
	}
	if got.BouncerName == "" {
		t.Error("blank BouncerName on configured row should be normalised to default")
	}
	if got.TimeoutSeconds == 0 {
		t.Error("zero TimeoutSeconds on configured row should be normalised to default")
	}
}

func TestPutCrowdSecConfig_EmptyKeyAccepted_NotConfiguredState(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// An all-empty row models the "Disable" / "Clear" UI
	// path. Validate must NOT reject it.
	in := CrowdSecConfig{}
	if err := s.PutCrowdSecConfig(ctx, in); err != nil {
		t.Fatalf("PutCrowdSecConfig (empty): %v", err)
	}
	got, err := s.GetCrowdSecConfig(ctx)
	if err != nil {
		t.Fatalf("GetCrowdSecConfig: %v", err)
	}
	if got.APIKey != "" {
		t.Errorf("APIKey should remain blank, got %q", got.APIKey)
	}
}

func TestCrowdSecConfig_Validate_RejectsBadURLScheme(t *testing.T) {
	c := CrowdSecConfig{
		LAPIURL:     "ftp://crowdsec/wat",
		APIKey:      "k",
		BouncerName: "arenet",
	}
	err := ValidateCrowdSecConfig(c)
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Errorf("err = %v, want scheme error", err)
	}
}

func TestCrowdSecConfig_Validate_RejectsBadURLHost(t *testing.T) {
	c := CrowdSecConfig{
		LAPIURL:     "http://",
		APIKey:      "k",
		BouncerName: "arenet",
	}
	err := ValidateCrowdSecConfig(c)
	if err == nil || !strings.Contains(err.Error(), "valid URL") {
		t.Errorf("err = %v, want valid-URL error", err)
	}
}

func TestCrowdSecConfig_Validate_RejectsTimeoutOutOfRange(t *testing.T) {
	for _, tt := range []struct {
		name  string
		val   int
		fails bool
	}{
		{"zero accepted (defaulted later)", 0, false},
		{"min boundary", 1, false},
		{"max boundary", 60, false},
		{"below min", -1, true},
		{"above max", 61, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := CrowdSecConfig{
				LAPIURL:        "http://127.0.0.1:8080",
				APIKey:         "k",
				BouncerName:    "arenet",
				TimeoutSeconds: tt.val,
			}
			err := ValidateCrowdSecConfig(c)
			if tt.fails && err == nil {
				t.Errorf("val=%d should have failed validation", tt.val)
			}
			if !tt.fails && err != nil {
				t.Errorf("val=%d should have passed validation, got %v", tt.val, err)
			}
		})
	}
}

func TestCrowdSecConfig_Validate_RejectsBadBouncerName(t *testing.T) {
	c := CrowdSecConfig{
		LAPIURL:     "http://127.0.0.1:8080",
		APIKey:      "k",
		BouncerName: "bad name with space",
	}
	err := ValidateCrowdSecConfig(c)
	if err == nil || !strings.Contains(err.Error(), "bouncer_name") {
		t.Errorf("err = %v, want bouncer_name error", err)
	}

	c.BouncerName = "way-too-long-" + strings.Repeat("x", 100)
	err = ValidateCrowdSecConfig(c)
	if err == nil || !strings.Contains(err.Error(), "exceeds 64") {
		t.Errorf("err = %v, want length error", err)
	}
}

func TestCrowdSecConfig_Validate_AcceptsDockerNetworkURL(t *testing.T) {
	// Deployment-agnostic acceptance: any http(s) URL the
	// operator's deployment exposes must validate. This pins
	// the case where Arenet + CrowdSec run as sibling
	// containers in the same docker-compose network.
	c := CrowdSecConfig{
		LAPIURL:     "http://crowdsec:8080",
		APIKey:      "k",
		BouncerName: "arenet",
	}
	if err := ValidateCrowdSecConfig(c); err != nil {
		t.Errorf("docker-network URL should validate: %v", err)
	}
}

func TestCrowdSecConfig_EverConfigured(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	ever, err := s.CrowdSecConfigEverConfigured(ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if ever {
		t.Error("EverConfigured on empty bucket = true, want false")
	}

	_ = s.PutCrowdSecConfig(ctx, CrowdSecConfig{
		LAPIURL: "http://127.0.0.1:8080", APIKey: "k", BouncerName: "arenet",
	})

	ever, err = s.CrowdSecConfigEverConfigured(ctx)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !ever {
		t.Error("EverConfigured after put = false, want true")
	}
}

func TestCrowdSecConfigDefaults_NonEmpty(t *testing.T) {
	d := CrowdSecConfigDefaults()
	if d.LAPIURL == "" || d.BouncerName == "" || d.TimeoutSeconds == 0 {
		t.Errorf("defaults look empty: %+v", d)
	}
}
