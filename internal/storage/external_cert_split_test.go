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
	"strings"
	"testing"
	"time"
)

// A "fullchain" pasted into the Certificate field (leaf + intermediates
// concatenated, the common CA download format regardless of vendor)
// must be split: the FIRST cert stays as the leaf, the rest move to the
// chain. Universal — no CA-specific logic.
func TestSplitLeafAndChain_FullchainInCert(t *testing.T) {
	now := time.Now()
	leaf, key := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), []string{"app.example.com"})
	inter, _ := genSelfSigned(t, "Intermediate CA", now.Add(-time.Hour), now.Add(time.Hour), nil)
	_ = key
	fullchain := leaf + inter // two CERTIFICATE blocks in the cert field

	gotLeaf, gotChain, err := SplitLeafAndChain(fullchain, "")
	if err != nil {
		t.Fatalf("split fullchain: %v", err)
	}
	if strings.Count(gotLeaf, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("leaf should have exactly 1 cert block; got %d", strings.Count(gotLeaf, "BEGIN CERTIFICATE"))
	}
	if strings.Count(gotChain, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("chain should carry the 1 intermediate; got %d", strings.Count(gotChain, "BEGIN CERTIFICATE"))
	}
}

// A single-cert Certificate field + a separate Chain field is the
// classic "separate files" upload — passed through untouched.
func TestSplitLeafAndChain_SeparateFields(t *testing.T) {
	now := time.Now()
	leaf, _ := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), []string{"app.example.com"})
	inter, _ := genSelfSigned(t, "Intermediate CA", now.Add(-time.Hour), now.Add(time.Hour), nil)

	gotLeaf, gotChain, err := SplitLeafAndChain(leaf, inter)
	if err != nil {
		t.Fatalf("split separate: %v", err)
	}
	if gotLeaf != strings.TrimSpace(leaf) && !strings.Contains(gotLeaf, "BEGIN CERTIFICATE") {
		t.Error("leaf changed unexpectedly")
	}
	if strings.Count(gotChain, "BEGIN CERTIFICATE") != 1 {
		t.Errorf("chain should be the passed intermediate; got %d", strings.Count(gotChain, "BEGIN CERTIFICATE"))
	}
}

// A fullchain in the Certificate field AND a non-empty Chain field is
// ambiguous (chain in two places) → explicit rejection.
func TestSplitLeafAndChain_ConflictRejected(t *testing.T) {
	now := time.Now()
	leaf, _ := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), []string{"app.example.com"})
	inter, _ := genSelfSigned(t, "Intermediate CA", now.Add(-time.Hour), now.Add(time.Hour), nil)
	fullchain := leaf + inter

	if _, _, err := SplitLeafAndChain(fullchain, inter); err == nil {
		t.Error("want error when fullchain in cert field AND chain field both carry a chain")
	}
}

// A single leaf, no chain, is the minimal valid case — untouched.
func TestSplitLeafAndChain_LeafOnly(t *testing.T) {
	now := time.Now()
	leaf, _ := genSelfSigned(t, "app.example.com", now.Add(-time.Hour), now.Add(time.Hour), []string{"app.example.com"})
	gotLeaf, gotChain, err := SplitLeafAndChain(leaf, "")
	if err != nil {
		t.Fatalf("leaf only: %v", err)
	}
	if strings.Count(gotLeaf, "BEGIN CERTIFICATE") != 1 {
		t.Error("leaf-only should stay 1 block")
	}
	if gotChain != "" {
		t.Errorf("leaf-only should yield empty chain; got %q", gotChain)
	}
}
