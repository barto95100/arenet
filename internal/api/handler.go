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
	"time"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/auth"
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
//
// The interface exposes both Append (used by handlers post-success) and
// List (used by /audit endpoint, Commit C). The name AuditAppender is
// kept for Step C/Chunk 3 backwards compatibility despite now covering
// reads as well; a future rename to AuditStore is out of scope for Step D.
type AuditAppender interface {
	Append(ctx context.Context, evt audit.Event) error
	List(ctx context.Context, f audit.Filter) ([]audit.Event, string, error)
}

// Handler owns every dependency the admin API needs (storage, Caddy
// reload, audit, auth stores, HIBP, rate limiter, setup token) and
// exposes the HTTP handlers.
type Handler struct {
	store       *storage.Store
	caddy       CaddyReloader
	audit       AuditAppender
	users       *auth.UserStore
	sessions    *auth.SessionStore
	hibp        *auth.HIBPClient
	rateLimiter *auth.RateLimiter
	setupToken  *SetupTokenHolder
	devMode     bool
	logger      *slog.Logger
	// startTime is captured at NewHandler-time and reported by the
	// /healthz endpoint as uptime_seconds (Step H.3). Read-only after
	// construction.
	startTime time.Time
}

// NewHandler constructs a Handler. All non-bool arguments must be non-nil.
func NewHandler(
	store *storage.Store,
	caddy CaddyReloader,
	auditAppender AuditAppender,
	users *auth.UserStore,
	sessions *auth.SessionStore,
	hibp *auth.HIBPClient,
	rateLimiter *auth.RateLimiter,
	setupToken *SetupTokenHolder,
	devMode bool,
	logger *slog.Logger,
) *Handler {
	switch {
	case store == nil:
		panic("api.NewHandler: store is nil")
	case caddy == nil:
		panic("api.NewHandler: caddy is nil")
	case auditAppender == nil:
		panic("api.NewHandler: audit is nil")
	case users == nil:
		panic("api.NewHandler: users is nil")
	case sessions == nil:
		panic("api.NewHandler: sessions is nil")
	case hibp == nil:
		panic("api.NewHandler: hibp is nil")
	case rateLimiter == nil:
		panic("api.NewHandler: rateLimiter is nil")
	case setupToken == nil:
		panic("api.NewHandler: setupToken is nil")
	case logger == nil:
		panic("api.NewHandler: logger is nil")
	}
	return &Handler{
		store:       store,
		caddy:       caddy,
		audit:       auditAppender,
		users:       users,
		sessions:    sessions,
		hibp:        hibp,
		rateLimiter: rateLimiter,
		setupToken:  setupToken,
		devMode:     devMode,
		logger:      logger,
		startTime:   time.Now(),
	}
}

// upstreamReq is the per-element wire shape inside the routeRequest
// upstreams pool. Mirrors storage.Upstream verbatim (URL + Weight)
// but lives in the api package so the wire layer is decoupled from
// the storage struct — pattern Step I established for routeRequest
// vs storage.Route. createRoute / updateRoute map upstreamReq slices
// to storage.Upstream slices before validation; the API materialises
// Weight=0 → 1 in that mapping (§5.1, §1.3 decision 1).
type upstreamReq struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// routeRequest is the wire shape accepted by POST and PUT /routes. JSON tags
// are camelCase per the spec.
type routeRequest struct {
	Host string `json:"host"`
	// Step J.1 — pool of backends. Replaces the pre-J.1 single
	// UpstreamURL string. At least one element; per-element URL is
	// validated by validateUpstreamURL (the existing Step I logic,
	// applied per element). Per-element Weight defaults to 1 if
	// omitted/zero — materialised by the API before the storage
	// write so the storage validate() rule weight >= 1 is satisfied.
	Upstreams []upstreamReq `json:"upstreams"`
	// Step J.1 — LB selection policy. One of the six storage
	// .LBPolicy* values. Empty on POST is normalised to
	// "round_robin" (the default per §5.1, materialised before
	// validation so the storage row carries the explicit value).
	// Empty on PUT means "preserve the previously stored value",
	// same UX as WAFMode below.
	LBPolicy        string   `json:"lbPolicy"`
	TLSEnabled      bool     `json:"tlsEnabled"`
	RedirectToHTTPS bool     `json:"redirectToHttps"`
	Aliases         []string `json:"aliases"`
	// Step I.5 — Basic Auth. BasicAuthPassword is the PLAIN
	// password; write-only on the wire (the response never echoes
	// it, the storage layer holds only the argon2id PHC hash). On
	// Edit, leaving this empty means "keep the existing hash" —
	// see updateRoute.
	BasicAuthEnabled  bool   `json:"basicAuthEnabled"`
	BasicAuthUsername string `json:"basicAuthUsername"`
	BasicAuthPassword string `json:"basicAuthPassword"`
	// Step I.6 — custom headers applied to the proxied request /
	// response. Map[name → value] (single value per name in v1.0).
	// Validation rejects CR/LF/control characters and hop-by-hop /
	// framing-critical names — see validateHeaders.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	// On POST, empty string is normalized to "detect" (the FortiWeb
	// safe-shadow default, L6). On PUT, empty string MEANS "preserve
	// the previously stored value" — mirrors the I.5 password
	// preserve UX so admins can flip unrelated fields without
	// re-typing the WAF mode every time.
	WAFMode string `json:"wafMode"`
}

// upstreamResp is the per-element wire shape inside the routeResponse
// upstreams pool. Symmetric to upstreamReq — URL + Weight.
type upstreamResp struct {
	URL    string `json:"url"`
	Weight int    `json:"weight"`
}

// routeResponse is the wire shape returned by GET / POST / PUT /routes. The
// JSON tags must match routeRequest's camelCase scheme.
type routeResponse struct {
	ID   string `json:"id"`
	Host string `json:"host"`
	// Step J.1 — pool surfaced on the wire. Always at least one
	// element on a stored route (storage.validate guarantees it).
	Upstreams []upstreamResp `json:"upstreams"`
	// Step J.1 — LB selection policy. Always a non-empty enum value
	// on a stored route (storage.validate guarantees it).
	LBPolicy        string `json:"lbPolicy"`
	TLSEnabled      bool   `json:"tlsEnabled"`
	RedirectToHTTPS bool   `json:"redirectToHttps"`
	// Aliases (Step I.3) is normalized to an empty slice (never nil)
	// so the JSON wire shape is consistently `"aliases": []` rather
	// than `"aliases": null` — frontend callers can read .length
	// without a null check.
	Aliases []string `json:"aliases"`
	// Step I.5 — Basic Auth response surface. The plaintext password
	// is NEVER echoed; the hash is NEVER echoed either. Instead,
	// BasicAuthPasswordSet is a boolean derived from "is the hash
	// non-empty?" so the UI can render the placeholder
	// "••• set" hint in Edit mode without ever seeing the secret.
	BasicAuthEnabled     bool   `json:"basicAuthEnabled"`
	BasicAuthUsername    string `json:"basicAuthUsername"`
	BasicAuthPasswordSet bool   `json:"basicAuthPasswordSet"`
	// Step I.6 — custom headers, normalized to empty maps (never
	// nil) so the JSON wire shape is always {} and frontend can
	// iterate without a null check.
	RequestHeaders  map[string]string `json:"requestHeaders"`
	ResponseHeaders map[string]string `json:"responseHeaders"`
	// Step I.4 — WAF mode, one of "off" / "detect" / "block".
	WAFMode   string `json:"wafMode"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// toResponse converts a storage.Route to its API wire form (RFC 3339 with
// millisecond precision, UTC).
func toResponse(r storage.Route) routeResponse {
	aliases := r.Aliases
	if aliases == nil {
		aliases = []string{} // S6: never emit `"aliases": null` on the wire.
	}
	// Step I.6 — normalize nil maps to empty so the wire JSON never
	// emits `null`. Frontend reads .length / Object.keys safely.
	reqHeaders := r.RequestHeaders
	if reqHeaders == nil {
		reqHeaders = map[string]string{}
	}
	respHeaders := r.ResponseHeaders
	if respHeaders == nil {
		respHeaders = map[string]string{}
	}
	// Step J.1 — surface the upstream pool 1:1 from storage.
	// storage.validate() guarantees at least one element, so the
	// returned slice is always non-empty for a stored route.
	upstreamsResp := make([]upstreamResp, len(r.Upstreams))
	for i, u := range r.Upstreams {
		upstreamsResp[i] = upstreamResp{URL: u.URL, Weight: u.Weight}
	}
	return routeResponse{
		ID:                   r.ID,
		Host:                 r.Host,
		Upstreams:            upstreamsResp,
		LBPolicy:             r.LBPolicy,
		TLSEnabled:           r.TLSEnabled,
		RedirectToHTTPS:      r.RedirectToHTTPS,
		Aliases:              aliases,
		BasicAuthEnabled:     r.BasicAuthEnabled,
		BasicAuthUsername:    r.BasicAuthUsername,
		BasicAuthPasswordSet: r.BasicAuthPasswordHash != "",
		RequestHeaders:       reqHeaders,
		ResponseHeaders:      respHeaders,
		WAFMode:              r.WAFMode,
		CreatedAt:            r.CreatedAt.UTC().Format(timestampFormat),
		UpdatedAt:            r.UpdatedAt.UTC().Format(timestampFormat),
	}
}
