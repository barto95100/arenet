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

	"github.com/barto95100/arenet/internal/alerting"
	"github.com/barto95100/arenet/internal/observability"
)

// AL.4.a — translates the dispatcher's typed
// AlertEventRecord into the observability layer's row
// shape. Tiny stateless wrapper; lives here so neither
// package needs to import the other.
type alertEventInserterAdapter struct {
	store *observability.Store
}

// InsertAlertEvent satisfies alerting.AlertEventInserter.
func (a *alertEventInserterAdapter) InsertAlertEvent(ctx context.Context, rec alerting.AlertEventRecord) error {
	return a.store.InsertAlertEvent(ctx, observability.AlertEvent{
		EventID:            rec.EventID,
		Ts:                 rec.Ts,
		RuleID:             rec.RuleID,
		RuleName:           rec.RuleName,
		Severity:           rec.Severity,
		Category:           rec.Category,
		Subject:            rec.Subject,
		Body:               rec.Body,
		ContextJSON:        rec.ContextJSON,
		LabelsJSON:         rec.LabelsJSON,
		ChannelsFiredJSON:  rec.ChannelsFiredJSON,
		ChannelsFailedJSON: rec.ChannelsFailedJSON,
	})
}
