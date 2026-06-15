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

package main

import (
	"context"
	"errors"

	"github.com/barto95100/arenet/internal/certinfo"
	"github.com/barto95100/arenet/internal/observability"
	"github.com/barto95100/arenet/internal/storage"
	"github.com/barto95100/arenet/internal/systemhealth"
)

// Step AL.3a wiring adapters. The systemhealth package
// declares narrow interfaces (RoutesCounter,
// CrowdSecConfigReader, CertInfoLister, MetricsProber) to
// stay free of the concrete storage / observability /
// certinfo deps; this file bridges those interfaces to the
// production singletons constructed in main.go.

// boltdbRoutesCounter adapts *storage.Store.ListRoutes into
// the systemhealth.RoutesCounter signature. The check only
// needs the count, not the full slice — but we pay the
// allocation cost because Arenet's typical route count is
// small (<50 in homelab; <500 in v2 multi-tenant). A
// dedicated CountRoutes bbolt-stat call is a micro-
// optimisation for V2.
type boltdbRoutesCounter struct {
	store *storage.Store
}

func (c *boltdbRoutesCounter) CountRoutes(ctx context.Context) (int, error) {
	routes, err := c.store.ListRoutes(ctx)
	if err != nil {
		return 0, err
	}
	return len(routes), nil
}

// crowdsecConfigAdapter adapts *storage.Store.GetCrowdSecConfig
// into the systemhealth.CrowdSecConfigReader signature.
// "Configured" is true when both the LAPI URL and API key
// are populated — same gate as the existing crowdsec
// bouncer wiring (cmd/arenet/main.go:237+).
type crowdsecConfigAdapter struct {
	store *storage.Store
}

func (c *crowdsecConfigAdapter) GetCrowdSecConfig(ctx context.Context) (lapiURL, apiKey string, configured bool, err error) {
	cfg, err := c.store.GetCrowdSecConfig(ctx)
	if err != nil {
		// ErrNotFound is the "never been configured" path
		// for a fresh install — surface as "not configured"
		// rather than an error so the check returns the
		// degraded shape with a clean message.
		if errors.Is(err, storage.ErrNotFound) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	configured = cfg.LAPIURL != "" && cfg.APIKey != ""
	return cfg.LAPIURL, cfg.APIKey, configured, nil
}

// certInfoListerAdapter adapts *certinfo.Tracker.List into
// the systemhealth.CertInfoLister signature, projecting the
// CertRuntimeInfo records into the minimal CertEntry shape
// the systemhealth package needs (NotAfter + two status
// booleans). Keeps the systemhealth package import-free of
// certinfo.
type certInfoListerAdapter struct {
	tracker *certinfo.Tracker
}

func (a *certInfoListerAdapter) ListCertEntries() []systemhealth.CertEntry {
	if a.tracker == nil {
		return nil
	}
	raw := a.tracker.List()
	out := make([]systemhealth.CertEntry, 0, len(raw))
	for _, c := range raw {
		out = append(out, systemhealth.CertEntry{
			Domain:             c.Domain,
			NotAfter:           c.NotAfter,
			StatusValid:        c.Status == certinfo.StatusValid,
			StatusObtainFailed: c.Status == certinfo.StatusObtainFailed,
		})
	}
	return out
}

// metricsProberAdapter adapts *observability.Store.SchemaVersion
// into the systemhealth.MetricsProber signature. Nil-tolerant
// wrapper: if the boot-degraded observability path left
// obsStore nil, the systemhealth check sees a nil Prober and
// surfaces "store not configured (degraded mode)" — the
// adapter never returns a non-nil but stub-y interface.
type metricsProberAdapter struct {
	store *observability.Store
}

func (a *metricsProberAdapter) SchemaVersion(ctx context.Context) (int, error) {
	if a.store == nil {
		// Should never happen in practice — boot wiring
		// avoids constructing this adapter when obsStore is
		// nil. Defensive return so a misuse from a future
		// caller surfaces cleanly.
		return 0, errors.New("observability store not configured")
	}
	return a.store.SchemaVersion(ctx)
}
