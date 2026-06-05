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

package certinfo

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// CaddyModuleID is the identifier the Caddy registry uses for the
// arenet_cert_info handler. The "events.handlers." namespace is
// the one the events App looks in when resolving Subscription
// `handlers` array entries.
//
// Mirrors the caddyhc handler's naming convention (events.handlers.
// arenet_topology_hc — commit 1926f78). Two distinct handler
// modules so the caddymgr config can subscribe each to its own
// origin-module filter (caddyhc → "http.handlers.reverse_proxy",
// arenet_cert_info → "tls").
const CaddyModuleID = "events.handlers.arenet_cert_info"

// init registers the handler module with the Caddy registry. Caddy
// only sees module IDs that have been registered by import time;
// the caddymgr package side-effect-imports this package so the
// registration happens before any caddy.Load call.
func init() {
	caddy.RegisterModule(CaddyEventHandler{})
}

// trackerSingleton is the package-level pointer the handler module
// delegates into. Set once at process start by main via
// SetTracker. The singleton is necessary because the handler is
// instantiated by Caddy (via JSON unmarshal during Provision) and
// there is no JSON-config path to inject a Go reference — the
// module body is empty JSON.
var (
	trackerMu        sync.RWMutex
	trackerSingleton *Tracker
)

// SetTracker installs the process-wide tracker the event handler
// module delegates into. Called from cmd/arenet during init,
// BEFORE the caddymgr emits a config that references the
// arenet_cert_info handler.
//
// Passing nil clears the singleton — useful for test isolation.
// The handler treats a nil singleton as "no tracker available,
// drop event silently" rather than returning an error: a missing
// tracker should not break Caddy's event dispatch.
func SetTracker(t *Tracker) {
	trackerMu.Lock()
	trackerSingleton = t
	trackerMu.Unlock()
}

// getTracker returns the current singleton (may be nil).
func getTracker() *Tracker {
	trackerMu.RLock()
	defer trackerMu.RUnlock()
	return trackerSingleton
}

// CaddyEventHandler is the caddyevents.Handler module that translates
// certmagic events into Tracker state changes.
//
// Empty-state struct apart from the logger captured during
// Provision (mirror of the caddyhc handler shape — same
// rationale: the logger field lets future debug logging
// re-enable without restructuring). Pointer receivers throughout
// because Provision mutates the struct.
type CaddyEventHandler struct {
	logger *zap.Logger
}

// CaddyModule satisfies caddy.Module so RegisterModule accepts us.
func (CaddyEventHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  CaddyModuleID,
		New: func() caddy.Module { return new(CaddyEventHandler) },
	}
}

// Provision captures the Caddy-context logger for future
// diagnostics. Tracker singleton is installed by main before
// caddy.Load runs, so it's reliably non-nil by the time Provision
// fires.
func (h *CaddyEventHandler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.logger == nil {
		h.logger = zap.NewNop()
	}
	return nil
}

// Handle is invoked once per matching event. The caddyevents App
// calls Handle synchronously from its dispatch goroutine — we
// must NOT block. State mutation goes through the tracker's
// internal RWMutex which is well within "don't block" tolerances;
// the cert-file read on cert_obtained is a synchronous disk read
// but the file is local and tiny (single PEM bundle).
//
// Returning an error from Handle causes the events App to log it
// but does not stop subsequent handlers. We return nil even on
// missing/malformed payload because event-source contracts can
// shift with Caddy versions and we'd rather degrade silently
// than spam Caddy's error log on every probe.
func (h *CaddyEventHandler) Handle(_ context.Context, e caddy.Event) error {
	t := getTracker()
	if t == nil {
		return nil
	}
	switch e.Name() {
	case "cert_obtaining":
		domain, ok := extractString(e.Data, "identifier")
		if !ok {
			return nil
		}
		t.RecordObtaining(domain)

	case "cert_obtained":
		domain, ok := extractString(e.Data, "identifier")
		if !ok {
			return nil
		}
		// Re-read the on-disk leaf to pick up the freshly-issued
		// metadata (NotBefore, NotAfter, SAN list, issuer). The
		// event payload's certificate_path is the canonical
		// pointer to the new file.
		certPath, _ := extractString(e.Data, "certificate_path")
		issuerKey, _ := extractString(e.Data, "issuer")
		info := buildCertInfoFromEvent(domain, certPath, issuerKey, h.logger)
		if info != nil {
			t.RecordCert(info)
		} else {
			// We know the cert obtained successfully but failed to
			// read the metadata back from disk (transient I/O,
			// concurrent rotation, etc.). Record a minimal entry so
			// the tracker at least knows the domain exists; the
			// next List() will surface Status=UNKNOWN until reconcile
			// or a future event fills in metadata.
			t.RecordCert(&CertRuntimeInfo{
				Domain: domain,
				Issuer: decodeIssuerLabel(issuerKey),
				Source: inferSourceFromSubject(domain),
			})
		}

	case "cert_failed":
		domain, ok := extractString(e.Data, "identifier")
		if !ok {
			return nil
		}
		errMsg := extractError(e.Data)
		t.RecordFailure(domain, errMsg)

	default:
		// Subscription filters on these three names. Defensive
		// no-op for any unexpected event name (cached_managed_cert
		// etc. flow past us without state change).
	}
	return nil
}

// buildCertInfoFromEvent re-reads the on-disk leaf at certPath and
// returns a populated CertRuntimeInfo. Returns nil when the file
// can't be opened or the PEM doesn't parse — caller decides the
// degraded-state fallback.
func buildCertInfoFromEvent(domain, certPath, issuerKey string, logger *zap.Logger) *CertRuntimeInfo {
	if certPath == "" {
		return nil
	}
	// Note: certmagic's storage_path / certificate_path event
	// fields are storage KEYS, not absolute filesystem paths.
	// On a FileStorage backend they happen to resolve directly
	// against the storage root; the caddymgr default storage is
	// caddy.AppDataDir() (Linux: $HOME/.local/share/caddy). The
	// event itself doesn't carry the storage root because the
	// emitting cfg may use any certmagic.Storage implementation.
	//
	// For T.1 we assume FileStorage with the default root. If a
	// future Caddy config swaps storage to S3 / GCS / etc., the
	// event-driven cache populates with degraded entries (Status
	// UNKNOWN) until a future Step adds a storage abstraction
	// indirection. Documented limitation; current AreNET config
	// always uses FileStorage.
	resolved := resolveStoragePath(certPath)
	pemBytes, err := os.ReadFile(resolved)
	if err != nil {
		if logger != nil {
			logger.Debug("certinfo: cannot read cert file after cert_obtained event",
				zap.String("domain", domain),
				zap.String("path", resolved),
				zap.Error(err))
		}
		return nil
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	primary := pickPrimaryDomain(leaf, "")
	if primary == "" {
		primary = domain
	}
	return &CertRuntimeInfo{
		Domain:    primary,
		SANList:   append([]string(nil), leaf.DNSNames...),
		Issuer:    decodeIssuerLabel(issuerKey),
		NotBefore: leaf.NotBefore,
		NotAfter:  leaf.NotAfter,
		Source:    inferSourceFromSubject(primary),
	}
}

// resolveStoragePath prefixes a certmagic storage key with the
// Caddy default data dir when the key isn't already an absolute
// filesystem path. certmagic emits storage-relative keys; the
// FileStorage backend prefixes them with its configured Path
// before reading. Since we don't have a handle to the
// FileStorage instance here, we approximate with the same
// AppDataDir() the Caddy default storage uses.
//
// Tests inject CERTINFO_STORAGE_DIR to override this lookup
// without touching environment defaults; production reads
// $HOME/.local/share/caddy.
func resolveStoragePath(key string) string {
	if len(key) > 0 && key[0] == '/' {
		return key
	}
	root := os.Getenv("CERTINFO_STORAGE_DIR")
	if root == "" {
		root = caddy.AppDataDir()
	}
	return fmt.Sprintf("%s/%s", root, key)
}

// extractString reads a string-typed field from the event data
// map. Returns ("", false) when the field is missing or not a
// string — defensive against future payload-shape changes the
// way Stage B's extractHost handles it.
func extractString(data map[string]any, key string) (string, bool) {
	if data == nil {
		return "", false
	}
	raw, ok := data[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// extractError pulls the error message out of a cert_failed
// payload. certmagic stores the error as the literal `error` Go
// value (not stringified — verified at config.go:697 and :988),
// so we use fmt.Sprintf to coerce whatever shape it has into a
// readable string. Returns empty when the field is missing.
func extractError(data map[string]any) string {
	if data == nil {
		return ""
	}
	raw, ok := data["error"]
	if !ok {
		return ""
	}
	if raw == nil {
		return ""
	}
	if s, ok := raw.(string); ok {
		return s
	}
	if e, ok := raw.(error); ok {
		return e.Error()
	}
	return fmt.Sprintf("%v", raw)
}

// Compile-time interface guards. Same pattern as caddyhc — we
// avoid importing modules/caddyevents just for the type assertion.
type handlerLike interface {
	Handle(context.Context, caddy.Event) error
}

var (
	_ handlerLike       = (*CaddyEventHandler)(nil)
	_ caddy.Provisioner = (*CaddyEventHandler)(nil)
)
