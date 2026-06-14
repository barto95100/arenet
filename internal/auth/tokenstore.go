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

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

// Phase 4 — service-account bearer tokens.
//
// Token format on the wire: "arn_<43-char-base64url>" — 256
// bits of crypto-random entropy, base64url-encoded (no
// padding), with a stable "arn_" prefix so leaked tokens are
// easy to grep / regex-scan in logs, git history, and Slack
// messages. Pattern is intentionally aligned with GitHub
// (ghp_), Stripe (sk_live_), GitLab (glpat-) so generic
// secret-scanners pick it up.
//
// Hash on disk: SHA-256(plain) hex (64 chars). The plain
// token's 256-bit entropy makes argon2id-style stretching
// unnecessary (slow hashing exists to compensate for low-
// entropy human passwords). Validation is ~1 µs per call
// instead of ~100 ms — critical for n8n / Home Assistant /
// monitoring scripts that poll endpoints at high rate.
//
// Constant-time comparison via crypto/subtle protects against
// pathological timing side-channels even though the entropy
// budget makes them practically unexploitable here.

const (
	apiTokensBucketName = "api_tokens"

	// APITokenPrefix identifies an arenet API token on sight.
	// Operators grep for this in CI logs / pastebins; secret
	// scanners (GitHub, gitleaks, trufflehog) can register the
	// pattern as a custom rule.
	APITokenPrefix = "arn_"

	// apiTokenRandomBytes is the crypto-random suffix length.
	// 32 bytes → 256 bits of entropy → 43 base64url chars
	// (no padding). Total token length: 4 + 43 = 47 chars.
	apiTokenRandomBytes = 32
)

// APIToken is the on-disk shape stored in the "api_tokens"
// bucket, keyed by ID. The plain token value is NEVER stored —
// only its SHA-256 hex digest.
type APIToken struct {
	ID              string     `json:"id"`                          // UUID v4
	Name            string     `json:"name"`                        // operator-visible label (e.g. "n8n-prod")
	UserID          string     `json:"user_id"`                     // links to the service-account User row
	TokenHash       string     `json:"token_hash"`                  // SHA-256(plain) hex; 64 chars
	CreatedAt       time.Time  `json:"created_at"`
	CreatedByUserID string     `json:"created_by_user_id"`          // human admin who issued the token
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`      // nullable — set best-effort on every Bearer call
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`        // nullable — no-expiry by default
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`        // soft-delete flag
	RevokedByUserID *string    `json:"revoked_by_user_id,omitempty"` // who rotated / revoked
}

// IsActive returns true when the token is neither revoked
// nor expired at the given moment. Centralised so the Validate
// path and any UI rendering of "Actif" / "Expiré" / "Révoqué"
// stay in sync.
func (t APIToken) IsActive(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !t.ExpiresAt.After(now) {
		return false
	}
	return true
}

// Token validation errors. Each is mapped 1-1 to an HTTP 401
// response with a distinct operator-readable message by the
// API layer.
var (
	ErrAPITokenInvalid = errors.New("auth: api token invalid")
	ErrAPITokenRevoked = errors.New("auth: api token revoked")
	ErrAPITokenExpired = errors.New("auth: api token expired")
	ErrAPITokenNotFound = errors.New("auth: api token not found")
)

// APITokenStore persists API tokens in the "api_tokens" BoltDB
// bucket. Safe for concurrent use (bbolt single-writer model).
type APITokenStore struct {
	db *bolt.DB
}

// NewAPITokenStore returns a store backed by the given bbolt
// handle. Ownership of the handle is retained by the caller.
func NewAPITokenStore(db *bolt.DB) *APITokenStore {
	if db == nil {
		panic("auth.NewAPITokenStore: db is nil")
	}
	return &APITokenStore{db: db}
}

// generatePlainToken builds a fresh "arn_<base64url>" token.
// Returns the plain string + the SHA-256 hex digest of that
// plain. The plain MUST be returned to the caller via the API
// response and never persisted.
func generatePlainToken() (plain, hash string, err error) {
	buf := make([]byte, apiTokenRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("auth: crypto/rand: %w", err)
	}
	plain = APITokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	hash = hex.EncodeToString(sum[:])
	return plain, hash, nil
}

// CreateToken issues a new token for the given service-account
// user. Returns the plain string (to be displayed ONCE in the
// API response) plus the stored APIToken row.
//
// expiresAt is optional: nil → no expiry (homelab set-and-
// forget); non-nil → token expires at the given UTC instant.
//
// createdByUserID is the human admin who pressed the button —
// recorded for audit attribution.
func (s *APITokenStore) CreateToken(
	ctx context.Context,
	userID, name, createdByUserID string,
	expiresAt *time.Time,
) (plain string, row APIToken, err error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return "", APIToken{}, errors.New("auth: CreateToken: userID empty")
	}

	plain, hash, err := generatePlainToken()
	if err != nil {
		return "", APIToken{}, err
	}

	now := time.Now().UTC()
	row = APIToken{
		ID:              uuid.NewString(),
		Name:            strings.TrimSpace(name),
		UserID:          userID,
		TokenHash:       hash,
		CreatedAt:       now,
		CreatedByUserID: createdByUserID,
		ExpiresAt:       expiresAt,
	}

	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		v, err := json.Marshal(row)
		if err != nil {
			return fmt.Errorf("auth: marshal token: %w", err)
		}
		return b.Put([]byte(row.ID), v)
	}); err != nil {
		return "", APIToken{}, err
	}
	return plain, row, nil
}

// GetByID returns the token row with the given ID.
func (s *APITokenStore) GetByID(ctx context.Context, id string) (APIToken, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if id == "" {
		return APIToken{}, ErrAPITokenNotFound
	}
	var out APIToken
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrAPITokenNotFound
		}
		return json.Unmarshal(v, &out)
	})
	return out, err
}

// ListByUser returns every token row owned by the given user,
// including revoked and expired tokens (for audit display).
func (s *APITokenStore) ListByUser(ctx context.Context, userID string) ([]APIToken, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if userID == "" {
		return nil, errors.New("auth: ListByUser: userID empty")
	}
	var out []APIToken
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			var t APIToken
			if err := json.Unmarshal(v, &t); err != nil {
				slog.Default().Warn("auth: corrupted api_token row, skipping",
					slog.String("key", string(k)),
					slog.String("err", err.Error()),
				)
				return nil
			}
			if t.UserID == userID {
				out = append(out, t)
			}
			return nil
		})
	})
	return out, err
}

// FindActiveByUser returns the single active (non-revoked,
// non-expired) token owned by the given user, or
// ErrAPITokenNotFound. V1 invariant: at most one active token
// per service account, so the first match wins; the API layer
// must rotate (Revoke + Create) rather than stack tokens.
func (s *APITokenStore) FindActiveByUser(ctx context.Context, userID string) (APIToken, error) {
	tokens, err := s.ListByUser(ctx, userID)
	if err != nil {
		return APIToken{}, err
	}
	now := time.Now().UTC()
	for _, t := range tokens {
		if t.IsActive(now) {
			return t, nil
		}
	}
	return APIToken{}, ErrAPITokenNotFound
}

// LookupToken hashes the plain token, walks the bucket, and
// returns the matching token row (active OR not — caller
// inspects RevokedAt / ExpiresAt). ErrAPITokenInvalid signals
// either a wrong-prefix string or a hash miss; this lets the
// API layer return a 401 without leaking whether the token
// existed-but-was-revoked vs never-existed for unauthenticated
// callers.
//
// Splitting Lookup from full validation keeps the
// apiTokenStore interface free of any *UserStore dependency,
// so the middleware can mock token validation independently of
// user lookups.
func (s *APITokenStore) LookupToken(ctx context.Context, plain string) (APIToken, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	if !strings.HasPrefix(plain, APITokenPrefix) {
		return APIToken{}, ErrAPITokenInvalid
	}

	sum := sha256.Sum256([]byte(plain))
	wantHash := hex.EncodeToString(sum[:])

	var matched APIToken
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			var t APIToken
			if err := json.Unmarshal(v, &t); err != nil {
				return nil
			}
			// Constant-time compare — defence-in-depth even
			// though a 256-bit token makes timing attacks
			// impractical.
			if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(wantHash)) == 1 {
				matched = t
				found = true
			}
			return nil
		})
	})
	if err != nil {
		return APIToken{}, err
	}
	if !found {
		return APIToken{}, ErrAPITokenInvalid
	}
	return matched, nil
}

// ValidateAuthToken is the high-level convenience that calls
// LookupToken + applies the revoked/expired checks + resolves
// the owning user. The API layer / handler tests call this;
// the middleware calls LookupToken directly so it can keep the
// apiTokenStore interface free of UserStore.
func (s *APITokenStore) ValidateAuthToken(
	ctx context.Context,
	users *UserStore,
	plain string,
) (APIToken, User, error) {
	matched, err := s.LookupToken(ctx, plain)
	if err != nil {
		return APIToken{}, User{}, err
	}
	if matched.RevokedAt != nil {
		return matched, User{}, ErrAPITokenRevoked
	}
	now := time.Now().UTC()
	if matched.ExpiresAt != nil && !matched.ExpiresAt.After(now) {
		return matched, User{}, ErrAPITokenExpired
	}
	user, err := users.GetByID(ctx, matched.UserID)
	if err != nil {
		return matched, User{}, fmt.Errorf("auth: token references missing user %q: %w", matched.UserID, err)
	}
	return matched, user, nil
}

// TouchLastUsed updates LastUsedAt to now. Best-effort: the
// middleware calls it from a goroutine and ignores failures so
// a transient bbolt write contention never blocks an
// authenticated request.
func (s *APITokenStore) TouchLastUsed(ctx context.Context, id string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	now := time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrAPITokenNotFound
		}
		var t APIToken
		if err := json.Unmarshal(v, &t); err != nil {
			return fmt.Errorf("auth: unmarshal token: %w", err)
		}
		t.LastUsedAt = &now
		out, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("auth: marshal token: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// RevokeToken sets RevokedAt to now + records the revoking
// user. Idempotent: revoking an already-revoked token is a
// no-op (preserves the original RevokedAt for audit fidelity).
func (s *APITokenStore) RevokeToken(ctx context.Context, id, revokedByUserID string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	now := time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		v := b.Get([]byte(id))
		if v == nil {
			return ErrAPITokenNotFound
		}
		var t APIToken
		if err := json.Unmarshal(v, &t); err != nil {
			return fmt.Errorf("auth: unmarshal token: %w", err)
		}
		if t.RevokedAt != nil {
			return nil
		}
		t.RevokedAt = &now
		uid := revokedByUserID
		t.RevokedByUserID = &uid
		out, err := json.Marshal(t)
		if err != nil {
			return fmt.Errorf("auth: marshal token: %w", err)
		}
		return b.Put([]byte(id), out)
	})
}

// RevokeAllByUser sets RevokedAt on every non-revoked token of
// the given user. Used by the service-account DELETE handler
// (cascade) so the soft-deleted user's tokens cannot keep
// authenticating after the account is gone.
func (s *APITokenStore) RevokeAllByUser(ctx context.Context, userID, revokedByUserID string) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	now := time.Now().UTC()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(apiTokensBucketName))
		if b == nil {
			return fmt.Errorf("auth: bucket %q missing", apiTokensBucketName)
		}
		return b.ForEach(func(k, v []byte) error {
			var t APIToken
			if err := json.Unmarshal(v, &t); err != nil {
				return nil
			}
			if t.UserID != userID || t.RevokedAt != nil {
				return nil
			}
			t.RevokedAt = &now
			uid := revokedByUserID
			t.RevokedByUserID = &uid
			out, err := json.Marshal(t)
			if err != nil {
				return fmt.Errorf("auth: marshal token: %w", err)
			}
			return b.Put(k, out)
		})
	})
}
