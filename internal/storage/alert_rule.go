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
	"errors"
	"fmt"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Step AL.2.a — AlertRule BoltDB row + CRUD.
//
// The persisted shape is opaque to the storage layer
// (kind, severity, source, params blobs are all stored
// verbatim) so a forward-compat arenet that adds a new
// rule kind / source can round-trip rules written by an
// older version without a migration.
//
// AL.2.b (watcher) reads rows via ListAlertRules per
// polling tick + writes the LastFiredAt / LastEvalAt /
// LastError fields back via MarkAlertRuleEval*.
//
// AL.3b (CRUD HTTP layer) wires the operator-facing
// endpoints + audit emissions; the alert_rule_created /
// alert_rule_updated / alert_rule_deleted audit action
// constants land in internal/audit/actions.go in that
// commit alongside the count test bump.

// AlertRule is the persisted shape mirrored from
// alerting.AlertRule. Stored here as a flat row so the
// storage layer doesn't need to import internal/alerting
// (which would create a cycle: alerting depends on
// storage for the Channel CRUD it consumes).
//
// Field semantics are documented at
// internal/alerting/rule.go's AlertRule type. This row
// shape is the on-wire JSON the bucket stores; the
// alerting package converts to its typed AlertRule via
// the API CRUD adapter (AL.3b).
type AlertRule struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Enabled         bool            `json:"enabled"`
	Kind            string          `json:"kind"`
	Severity        int             `json:"severity"`
	Category        string          `json:"category"`
	Source          string          `json:"source"`
	SourceParams    json.RawMessage `json:"source_params"`
	EvalParams      json.RawMessage `json:"eval_params"`
	Channels        []string        `json:"channels"`
	CooldownSecs    int             `json:"cooldown_secs"`
	SubjectTemplate string          `json:"subject_template,omitempty"`
	BodyTemplate    string          `json:"body_template,omitempty"`

	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastFiredAt *time.Time `json:"last_fired_at,omitempty"`
	LastEvalAt  *time.Time `json:"last_eval_at,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	LastErrorAt *time.Time `json:"last_error_at,omitempty"`
}

// validate runs storage-layer last-line-of-defence
// checks. Operator-friendly validation (template compile,
// source registry lookup, channel existence) is the API
// CRUD layer's job — the storage layer only catches
// shape drift that would corrupt the bucket scan.
func (r *AlertRule) validate() error {
	if r.ID == "" {
		return errors.New("alert_rule: id must not be empty")
	}
	if r.Name == "" {
		return errors.New("alert_rule: name must not be empty")
	}
	if r.Kind == "" {
		return errors.New("alert_rule: kind must not be empty")
	}
	if r.Source == "" {
		return errors.New("alert_rule: source must not be empty")
	}
	if len(r.Channels) == 0 {
		return errors.New("alert_rule: channels must have at least one ID")
	}
	if r.CooldownSecs <= 0 {
		return errors.New("alert_rule: cooldown_secs must be > 0")
	}
	return nil
}

// CreateAlertRule persists a new rule. Returns ErrConflict
// on Name collision (any existing rule). Caller supplies
// Rule.ID (UUID v4) — same convention as CreateAlertChannel.
func (s *Store) CreateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := r.validate(); err != nil {
		return AlertRule{}, err
	}

	now := time.Now().UTC()
	r.CreatedAt = now
	r.UpdatedAt = now

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAlertRules))
		var conflict bool
		_ = b.ForEach(func(_, v []byte) error {
			var existing AlertRule
			if err := json.Unmarshal(v, &existing); err != nil {
				return nil
			}
			if existing.Name == r.Name {
				conflict = true
			}
			return nil
		})
		if conflict {
			return ErrConflict
		}
		if existing := b.Get([]byte(r.ID)); existing != nil {
			return ErrConflict
		}
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal alert_rule: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	})
	if err != nil {
		return AlertRule{}, err
	}
	return r, nil
}

// GetAlertRule returns the rule keyed by ID, or ErrNotFound.
func (s *Store) GetAlertRule(ctx context.Context, id string) (AlertRule, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return AlertRule{}, errors.New("alert_rule: id must not be empty")
	}
	var out AlertRule
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw := tx.Bucket([]byte(bucketAlertRules)).Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return AlertRule{}, err
	}
	return out, nil
}

// ListAlertRules returns every rule, sorted by CreatedAt
// ascending (mirrors ListAlertChannels). The watcher
// (AL.2.b) calls this once per polling tick; a homelab
// at < 100 rules keeps the per-tick cost trivial. If the
// rule count ever exceeds ~1k, a watcher-side cache +
// invalidate-on-write is the natural V2 move.
func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	var out []AlertRule
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketAlertRules)).ForEach(func(_, v []byte) error {
			var r AlertRule
			if err := json.Unmarshal(v, &r); err != nil {
				return fmt.Errorf("unmarshal alert_rule row: %w", err)
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// UpdateAlertRule persists changes to an existing rule.
// Returns ErrNotFound on missing ID, ErrConflict on Name
// collision with a different row. CreatedAt is preserved
// from the stored row; UpdatedAt is bumped; the watcher-
// owned fields (LastFiredAt / LastEvalAt / LastError /
// LastErrorAt) are preserved from the stored row IF the
// caller leaves them zero — the API CRUD layer always
// sends zero (those fields are watcher-private), so this
// preserves them implicitly.
func (s *Store) UpdateAlertRule(ctx context.Context, r AlertRule) (AlertRule, error) {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if err := r.validate(); err != nil {
		return AlertRule{}, err
	}

	now := time.Now().UTC()
	r.UpdatedAt = now

	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAlertRules))
		raw := b.Get([]byte(r.ID))
		if raw == nil {
			return ErrNotFound
		}
		var existing AlertRule
		if err := json.Unmarshal(raw, &existing); err != nil {
			return fmt.Errorf("unmarshal stored alert_rule: %w", err)
		}
		r.CreatedAt = existing.CreatedAt
		// Preserve watcher-owned fields when caller didn't
		// set them (zero-value test) — operator-facing PUT
		// must never blow away the live telemetry.
		if r.LastFiredAt == nil {
			r.LastFiredAt = existing.LastFiredAt
		}
		if r.LastEvalAt == nil {
			r.LastEvalAt = existing.LastEvalAt
		}
		if r.LastError == "" && r.LastErrorAt == nil {
			r.LastError = existing.LastError
			r.LastErrorAt = existing.LastErrorAt
		}

		var conflict bool
		_ = b.ForEach(func(k, v []byte) error {
			if string(k) == r.ID {
				return nil
			}
			var other AlertRule
			if err := json.Unmarshal(v, &other); err != nil {
				return nil
			}
			if other.Name == r.Name {
				conflict = true
			}
			return nil
		})
		if conflict {
			return ErrConflict
		}

		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal alert_rule: %w", err)
		}
		return b.Put([]byte(r.ID), buf)
	})
	if err != nil {
		return AlertRule{}, err
	}
	return r, nil
}

// DeleteAlertRule removes the row keyed by ID.
func (s *Store) DeleteAlertRule(ctx context.Context, id string) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("alert_rule: id must not be empty")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAlertRules))
		if existing := b.Get([]byte(id)); existing == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(id))
	})
}

// MarkAlertRuleEval updates the watcher-owned telemetry
// fields after a polling tick. fired=true bumps
// LastFiredAt; evalErr != nil records LastError +
// LastErrorAt; LastEvalAt always bumps as a heartbeat
// (operators reading the rule UI see "last evaluated 8s
// ago" — meaningful even when the rule didn't fire and
// has no error).
//
// Called by AL.2.b's watcher; AL.2.a ships it now so the
// watcher commit lands as a pure additive without
// reaching back into storage.
func (s *Store) MarkAlertRuleEval(ctx context.Context, id string, fired bool, evalErr error) error {
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	if id == "" {
		return errors.New("alert_rule: id must not be empty")
	}
	now := time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := tx.Bucket([]byte(bucketAlertRules))
		raw := b.Get([]byte(id))
		if raw == nil {
			return ErrNotFound
		}
		var r AlertRule
		if err := json.Unmarshal(raw, &r); err != nil {
			return fmt.Errorf("unmarshal alert_rule: %w", err)
		}
		r.LastEvalAt = &now
		if fired {
			r.LastFiredAt = &now
		}
		if evalErr != nil {
			r.LastError = evalErr.Error()
			r.LastErrorAt = &now
		} else {
			r.LastError = ""
			r.LastErrorAt = nil
		}
		r.UpdatedAt = now
		buf, err := json.Marshal(r)
		if err != nil {
			return fmt.Errorf("marshal alert_rule: %w", err)
		}
		return b.Put([]byte(id), buf)
	})
}
