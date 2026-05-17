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

// Package audit persists immutable records of authentication events and
// route mutations into the BoltDB "audit" bucket. Events are keyed by
// UUID v7, providing natural chronological ordering via cursor iteration.
package audit

import (
	"encoding/json"
	"time"
)

// Event is a single audit log entry.
//
// Events are immutable once written. UUID v7 keys provide natural
// chronological ordering via BoltDB cursor iteration, so no secondary
// time index is needed.
//
// Security rule: BeforeJSON and AfterJSON MUST NOT contain secrets
// (password hashes, session tokens, etc.). Producers strip sensitive
// fields before serializing.
type Event struct {
	ID                    string          `json:"id"`                      // UUID v7 (hyphenated)
	Timestamp             time.Time       `json:"timestamp"`               // redundant with v7 but explicit
	ActorUserID           string          `json:"actor_user_id,omitempty"` // "" for unauthenticated events
	ActorUsernameSnapshot string          `json:"actor_username_snapshot,omitempty"`
	Action                string          `json:"action"`                // see actions.go enum
	TargetType            string          `json:"target_type,omitempty"` // "route" | "user" | "session" | ""
	TargetID              string          `json:"target_id,omitempty"`
	BeforeJSON            json.RawMessage `json:"before_json,omitempty"` // nil for create / login / ...
	AfterJSON             json.RawMessage `json:"after_json,omitempty"`  // nil for delete / login_failure / ...
	Message               string          `json:"message,omitempty"`     // free text (login_failure reason, etc.)
	IP                    string          `json:"ip,omitempty"`
	UserAgent             string          `json:"user_agent,omitempty"`
}

// Filter narrows the events returned by List. Zero values mean "no
// filter on this field". Limit defaults to 50 if zero or negative,
// and is silently clamped to 200 if exceeded. Cursor is the opaque
// token returned by the previous List call (a hyphenated UUID v7
// internally; callers MUST NOT parse it).
type Filter struct {
	ActorUserID string
	Action      string
	TargetType  string
	TargetID    string
	From        time.Time // inclusive
	To          time.Time // exclusive
	Limit       int       // default 50, max 200 (clamped silently)
	Cursor      string    // opaque, from previous List call
}

// Default and maximum page sizes for List. Exposed as constants so
// callers and tests can reference them without re-hardcoding.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)
