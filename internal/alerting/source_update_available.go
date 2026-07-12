// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package alerting

import (
	"context"
	"encoding/json"

	"github.com/barto95100/arenet/internal/updatecheck"
)

// UpdateAvailableSource is a STATE source (v2.12.3): it emits the string
// "available" when a newer stable release exists, "up_to_date"
// otherwise. An operator rule of kind state (expected == "available") at
// severity Info surfaces the update — a new version is never an
// operational emergency (D4), so it stays informational.
//
// It reads a live snapshot via statusFn so it stays decoupled from the
// checker's goroutine (mirrors how cert sources read a tracker).
type UpdateAvailableSource struct {
	statusFn func() updatecheck.Status
}

// NewUpdateAvailableSource wires the source to a status provider (the
// running *updatecheck.Checker's Status method).
func NewUpdateAvailableSource(statusFn func() updatecheck.Status) *UpdateAvailableSource {
	return &UpdateAvailableSource{statusFn: statusFn}
}

// Name returns the stable source identifier referenced by AlertRule.Source.
func (s *UpdateAvailableSource) Name() string { return "update_available" }

// ValidateParams accepts any (this source takes no params).
func (s *UpdateAvailableSource) ValidateParams(_ json.RawMessage) error {
	return nil
}

// Read returns the current update state. On "available" it attaches the
// current/latest/url as Context for downstream alert consumers.
func (s *UpdateAvailableSource) Read(_ context.Context, _ json.RawMessage) (SourceValue, error) {
	st := s.statusFn()
	if st.UpdateAvailable {
		v := StringValue("available")
		v.Context = map[string]any{"current": st.Current, "latest": st.Latest, "url": st.URL}
		return v, nil
	}
	return StringValue("up_to_date"), nil
}
