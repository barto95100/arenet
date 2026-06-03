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

package topology

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// caddyAdminURL is Caddy v2's auto-default admin endpoint when the
// emitted JSON omits the `admin` key (which Arenet does — see
// internal/caddymgr). The endpoint is localhost-only and not
// reachable over the network unless explicitly reconfigured. We
// hardcode the path here because changing the bind would also
// require changing every caddymgr emit; if/when Arenet decides to
// expose the Caddy admin externally, this constant moves to the
// config layer.
const caddyAdminURL = "http://127.0.0.1:2019/reverse_proxy/upstreams"

// caddyProbeTimeout caps the probe call. The admin endpoint is
// in-process loopback so 200 ms is generous; a slower response
// likely means Caddy itself is wedged, in which case "unknown" is
// the right thing to return upstream of us.
const caddyProbeTimeout = 200 * time.Millisecond

// caddyUpstreamStatus mirrors the JSON shape returned by
// /reverse_proxy/upstreams. See Caddy v2.11.3
// modules/caddyhttp/reverseproxy/admin.go for the source-of-truth
// fields. Arenet only reads Address and Fails; NumRequests is
// kept for future use (e.g. cross-check our per-route counter).
type caddyUpstreamStatus struct {
	Address     string `json:"address"`
	NumRequests int    `json:"num_requests"`
	Fails       int    `json:"fails"`
}

// CaddyStatusProber polls Caddy's admin endpoint and exposes a
// per-address health lookup. The prober is cheap (one HTTP GET,
// JSON of length ≈ N upstreams × 80 bytes) so callers re-probe
// once per topology emit; a memoised cache would be premature.
//
// The prober is goroutine-safe — concurrent Status() calls are
// fine, but only one Refresh runs at a time (held under mu during
// the HTTP call).
type CaddyStatusProber struct {
	mu     sync.Mutex
	client *http.Client
	url    string

	// statuses is the last-known address → fails count. Refresh
	// overwrites the whole map atomically (under mu). A nil map
	// means "never refreshed" or "last refresh failed" — Status
	// returns StatusUnknown in that case.
	statuses map[string]int
}

// NewCaddyStatusProber returns a prober configured for the
// auto-default Caddy admin endpoint. Tests pass NewCaddyStatusProberWithURL
// to point at a httptest.Server.
func NewCaddyStatusProber() *CaddyStatusProber {
	return NewCaddyStatusProberWithURL(caddyAdminURL)
}

// NewCaddyStatusProberWithURL is the test/customisation seam. The
// HTTP client is local to the prober — we don't share with the
// rest of Arenet because the admin endpoint is loopback-only and
// we don't want shared keepalive pools leaking unrelated state.
func NewCaddyStatusProberWithURL(url string) *CaddyStatusProber {
	return &CaddyStatusProber{
		client: &http.Client{Timeout: caddyProbeTimeout},
		url:    url,
	}
}

// Refresh hits the Caddy admin endpoint and updates the internal
// per-address cache. Failures are silent — Status returns
// StatusUnknown when the cache is empty, which is the correct
// behaviour during Caddy startup (the admin endpoint isn't ready
// until apps.http has been provisioned) and during transient
// admin-endpoint issues.
//
// Refresh respects ctx for cancellation; a cancelled context
// drops the in-flight request without erroring louder.
func (p *CaddyStatusProber) Refresh(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, caddyProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, p.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "arenet-topology-probe")
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var out []caddyUpstreamStatus
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return
	}
	m := make(map[string]int, len(out))
	for _, u := range out {
		m[u.Address] = u.Fails
	}
	p.mu.Lock()
	p.statuses = m
	p.mu.Unlock()
}

// Status returns the cached status for an upstream URL.
//
// upstreamURL is the storage form (e.g. "http://10.0.4.12:8080").
// Caddy's admin endpoint reports the dial form ("10.0.4.12:8080"),
// so we strip scheme prefix before lookup. Trailing path / query
// is stripped too — Caddy keys on host:port only.
//
// Returns:
//   - StatusHealthy   when the address is in the cache with fails == 0
//   - StatusUnhealthy when fails > 0
//   - StatusUnknown   when the address is absent (zero-traffic
//     upstream, or Caddy not yet probed) OR the cache is empty
//
// StatusDraining is reserved for Phase 2.1 and never returned
// here.
func (p *CaddyStatusProber) Status(upstreamURL string) string {
	addr := normalizeUpstreamAddr(upstreamURL)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.statuses == nil {
		return StatusUnknown
	}
	fails, ok := p.statuses[addr]
	if !ok {
		return StatusUnknown
	}
	if fails > 0 {
		return StatusUnhealthy
	}
	return StatusHealthy
}

// normalizeUpstreamAddr strips scheme prefix and any path so
// "http://10.0.4.12:8080/v1/" becomes "10.0.4.12:8080" — matching
// the key Caddy emits in /reverse_proxy/upstreams.
//
// Defensive: zero-input returns zero-output; we don't validate
// further because Caddy itself will have rejected malformed URLs
// at route-create time (storage validation §5.1).
func normalizeUpstreamAddr(raw string) string {
	s := raw
	for _, p := range []string{"http://", "https://", "h2c://", "h2://"} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			break
		}
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}
