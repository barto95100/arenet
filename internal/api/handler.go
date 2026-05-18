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

package api

import (
	"context"
	"log/slog"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// timestampFormat is RFC 3339 with millisecond precision, trailing zeros
// stripped. Matches the wire shape defined in spec §5.2.
const timestampFormat = "2006-01-02T15:04:05.999Z07:00"

// CaddyReloader is the subset of internal/caddymgr the API depends on. Defined
// here (consumer side) so tests can inject a fake without booting Caddy.
type CaddyReloader interface {
	ReloadFromStore(ctx context.Context) error
}

// AuditAppender is the subset of internal/audit the API depends on. Defined
// here (consumer side, decision D4) so tests can inject a fake without
// booting bbolt. *audit.Store naturally satisfies this interface.
type AuditAppender interface {
	Append(ctx context.Context, evt audit.Event) error
}

// Handler owns the storage + caddy reloader + audit appender + logger and
// exposes the HTTP handlers for the admin API.
type Handler struct {
	store  *storage.Store
	caddy  CaddyReloader
	audit  AuditAppender
	logger *slog.Logger
}

// NewHandler constructs a Handler. All arguments must be non-nil.
func NewHandler(store *storage.Store, caddy CaddyReloader, auditAppender AuditAppender, logger *slog.Logger) *Handler {
	switch {
	case store == nil:
		panic("api.NewHandler: store is nil")
	case caddy == nil:
		panic("api.NewHandler: caddy is nil")
	case auditAppender == nil:
		panic("api.NewHandler: audit is nil")
	case logger == nil:
		panic("api.NewHandler: logger is nil")
	}
	return &Handler{store: store, caddy: caddy, audit: auditAppender, logger: logger}
}

// routeRequest is the wire shape accepted by POST and PUT /routes. JSON tags
// are camelCase per the spec.
type routeRequest struct {
	Host        string `json:"host"`
	UpstreamURL string `json:"upstreamUrl"`
	TLSEnabled  bool   `json:"tlsEnabled"`
	WAFEnabled  bool   `json:"wafEnabled"`
}

// routeResponse is the wire shape returned by GET / POST / PUT /routes. The
// JSON tags must match routeRequest's camelCase scheme.
type routeResponse struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	UpstreamURL string `json:"upstreamUrl"`
	TLSEnabled  bool   `json:"tlsEnabled"`
	WAFEnabled  bool   `json:"wafEnabled"`
	CreatedAt   string `json:"createdAt"`
	UpdatedAt   string `json:"updatedAt"`
}

// toResponse converts a storage.Route to its API wire form (RFC 3339 with
// millisecond precision, UTC).
func toResponse(r storage.Route) routeResponse {
	return routeResponse{
		ID:          r.ID,
		Host:        r.Host,
		UpstreamURL: r.UpstreamURL,
		TLSEnabled:  r.TLSEnabled,
		WAFEnabled:  r.WAFEnabled,
		CreatedAt:   r.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:   r.UpdatedAt.UTC().Format(timestampFormat),
	}
}
