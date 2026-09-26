// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
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

package geoipupdate

import (
	"context"
	"strings"
	"sync"
	"time"
)

// Group drives several Updaters (v2.28: GeoLite2-City + GeoLite2-ASN)
// behind the single-updater surface the admin API and the scheduler
// already use: one "update now", one status, one loop.
type Group struct {
	members []*Updater
}

// NewGroup returns a Group over the non-nil updaters, in order.
func NewGroup(updaters ...*Updater) *Group {
	g := &Group{}
	for _, u := range updaters {
		if u != nil {
			g.members = append(g.members, u)
		}
	}
	return g
}

// UpdateOnce runs every member in order and returns the combined
// result.
func (g *Group) UpdateOnce(ctx context.Context) UpdateResult {
	results := make([]UpdateResult, 0, len(g.members))
	for _, u := range g.members {
		results = append(results, u.UpdateOnce(ctx))
	}
	return g.combine(results)
}

// Status returns the combined last result of every member.
func (g *Group) Status() UpdateResult {
	results := make([]UpdateResult, 0, len(g.members))
	for _, u := range g.members {
		results = append(results, u.Status())
	}
	return g.combine(results)
}

// Run runs every member's scheduler loop until ctx is cancelled.
// Blocks like Updater.Run.
func (g *Group) Run(ctx context.Context, interval time.Duration) {
	var wg sync.WaitGroup
	for _, u := range g.members {
		wg.Add(1)
		go func(u *Updater) {
			defer wg.Done()
			u.Run(ctx, interval)
		}(u)
	}
	wg.Wait()
}

// statusRank orders statuses from least to most noteworthy; the
// combined status is the highest-ranked member status.
var statusRank = map[string]int{
	"":             0,
	StatusNoCreds:  1,
	StatusUpToDate: 2,
	StatusUpdated:  3,
	StatusError:    4,
}

// combine folds member results: the most noteworthy status wins,
// errors are prefixed with their database kind and joined, and the
// latest timestamps are kept.
func (g *Group) combine(results []UpdateResult) UpdateResult {
	var out UpdateResult
	var errs []string
	for i, r := range results {
		if statusRank[r.Status] > statusRank[out.Status] {
			out.Status = r.Status
		}
		if r.Status == StatusError && r.Error != "" {
			errs = append(errs, g.members[i].kind+": "+r.Error)
		}
		if r.LastModified.After(out.LastModified) {
			out.LastModified = r.LastModified
		}
		if r.At.After(out.At) {
			out.At = r.At
		}
	}
	out.Error = strings.Join(errs, "; ")
	return out
}
