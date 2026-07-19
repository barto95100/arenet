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
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// ExternalCertificate is an operator-uploaded TLS cert served on a
// route via load_pem (v2.19.0). KeyPEM is a SECRET — redact-on-GET at
// the API layer, preserve-on-edit here (empty KeyPEM on update keeps
// the stored one), never logged, excluded from backup unless
// --include-secrets. Mirrors the DNSProviderConfig secret discipline.
type ExternalCertificate struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	CertPEM  string `json:"certPEM"`  // leaf (public)
	KeyPEM   string `json:"keyPEM"`   // SECRET
	ChainPEM string `json:"chainPEM"` // intermediates (public)

	Issuer             string    `json:"issuer"`
	Subject            string    `json:"subject"`
	SerialNumber       string    `json:"serialNumber"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	DNSNames           []string  `json:"dnsNames"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// ListExternalCertificates returns all stored certificates, unordered
// (bbolt iteration order).
func (s *Store) ListExternalCertificates(ctx context.Context) ([]ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := []ExternalCertificate{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketExternalCertificates)).ForEach(func(_, raw []byte) error {
			var c ExternalCertificate
			if err := json.Unmarshal(raw, &c); err != nil {
				return fmt.Errorf("unmarshal external cert: %w", err)
			}
			out = append(out, c)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetExternalCertificate returns the certificate with the given id,
// or ErrNotFound.
func (s *Store) GetExternalCertificate(ctx context.Context, id string) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out ExternalCertificate
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketExternalCertificates)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return out, nil
}

// CreateExternalCertificate assigns a fresh UUID and timestamps, and
// persists the given certificate as-is. Task 1 stores WITHOUT
// parsing/validation — Task 2 wires the parse/validate helper that
// populates the metadata fields (Issuer, Subject, NotBefore, ...)
// before calling this.
func (s *Store) CreateExternalCertificate(ctx context.Context, c ExternalCertificate) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	c.ID = uuid.NewString()
	now := time.Now().UTC()
	c.CreatedAt = now
	c.UpdatedAt = now
	buf, err := json.Marshal(c)
	if err != nil {
		return ExternalCertificate{}, fmt.Errorf("marshal external cert: %w", err)
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketExternalCertificates)).Put([]byte(c.ID), buf)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return c, nil
}

// UpdateExternalCertificate merges c over the stored row: empty KeyPEM
// preserves the stored key (secret preserve-on-edit); empty CertPEM /
// ChainPEM also preserve. Callers that re-parse metadata (API layer)
// overwrite the metadata fields before calling this. Returns ErrNotFound.
func (s *Store) UpdateExternalCertificate(ctx context.Context, id string, c ExternalCertificate) (ExternalCertificate, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	var out ExternalCertificate
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketExternalCertificates))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var existing ExternalCertificate
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal external cert: %w", err)
		}
		merged := c
		merged.ID = id
		merged.CreatedAt = existing.CreatedAt
		merged.UpdatedAt = time.Now().UTC()
		if merged.KeyPEM == "" {
			merged.KeyPEM = existing.KeyPEM
		}
		if merged.CertPEM == "" {
			merged.CertPEM = existing.CertPEM
		}
		buf, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshal external cert: %w", err)
		}
		out = merged
		return b.Put([]byte(id), buf)
	})
	if err != nil {
		return ExternalCertificate{}, err
	}
	return out, nil
}

// DeleteExternalCertificate removes the certificate with the given
// id, or returns ErrNotFound.
func (s *Store) DeleteExternalCertificate(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketExternalCertificates))
		if b.Get([]byte(id)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}
