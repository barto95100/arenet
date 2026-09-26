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

package geo

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// v2.28 — MaxMind GeoLite2-ASN support for the country-block ASN
// rules and the route form's ASN search.

// ASNInfo is one autonomous system: its number and organisation name.
type ASNInfo struct {
	ASN  uint32 `json:"asn"`
	Name string `json:"name"`
}

// asnRecord mirrors the GeoLite2-ASN record fields Arenet reads.
type asnRecord struct {
	Number uint32 `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// asnState is one loaded database: the reader serves per-IP lookups
// immediately; the name index is built in the background and
// published once complete (index == nil while building).
type asnState struct {
	reader *maxminddb.Reader
	index  atomic.Pointer[asnIndex]
}

// asnIndex maps every ASN in the database to its organisation, plus
// the same entries sorted by number for deterministic search output.
type asnIndex struct {
	names  map[uint32]string
	sorted []ASNInfo
}

// ASNLookup wraps a MaxMind GeoLite2-ASN database. Same concurrency
// and degraded-mode contract as Lookup: a nil or empty *ASNLookup is
// a valid receiver whose lookups find nothing, and Reload swaps a new
// database in without a lock on the lookup hot path.
type ASNLookup struct {
	state atomic.Pointer[asnState]

	pathMu sync.Mutex
	path   string
}

// ErrNotASNDatabase is returned when an MMDB is not an ASN edition.
var ErrNotASNDatabase = errors.New("geo: database is not an ASN edition")

// NewASNLookup opens the GeoLite2-ASN MMDB at path and starts
// building its name index in the background.
func NewASNLookup(path string) (*ASNLookup, error) {
	l := &ASNLookup{}
	if err := l.Reload(path); err != nil {
		return nil, err
	}
	return l, nil
}

// VerifyASNMMDB reports whether the MMDB at path is an ASN edition
// (e.g. "GeoLite2-ASN"). Used by the updater's edition guard.
func VerifyASNMMDB(path string) error {
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("open mmdb: %w", err)
	}
	defer r.Close()
	return checkASNType(r)
}

func checkASNType(r *maxminddb.Reader) error {
	if !strings.Contains(r.Metadata.DatabaseType, "ASN") {
		return fmt.Errorf("%w: type %q", ErrNotASNDatabase, r.Metadata.DatabaseType)
	}
	return nil
}

// Reload opens the ASN MMDB at path and swaps it in. The previous
// reader is closed after closeGracePeriod. On error the current
// database stays active.
func (l *ASNLookup) Reload(path string) error {
	if l == nil {
		return errors.New("geo: reload on nil ASNLookup")
	}
	if path == "" {
		return errors.New("geo: asn mmdb path is empty")
	}
	r, err := maxminddb.Open(path)
	if err != nil {
		return fmt.Errorf("geo: open asn mmdb %q: %w", path, err)
	}
	if err := checkASNType(r); err != nil {
		_ = r.Close()
		return err
	}
	st := &asnState{reader: r}
	old := l.state.Swap(st)
	l.pathMu.Lock()
	l.path = path
	l.pathMu.Unlock()
	go st.buildIndex()
	if old != nil {
		go func(o *asnState) {
			time.Sleep(closeGracePeriod)
			_ = o.reader.Close()
		}(old)
	}
	return nil
}

// buildIndex walks every network of the database once. Errors leave
// an empty index: search then returns nothing, lookups still work.
func (st *asnState) buildIndex() {
	idx := &asnIndex{names: map[uint32]string{}}
	nets := st.reader.Networks(maxminddb.SkipAliasedNetworks)
	for nets.Next() {
		var rec asnRecord
		if _, err := nets.Network(&rec); err != nil || rec.Number == 0 {
			continue
		}
		// Some networks carry an empty organisation: keep the first
		// non-empty name seen for a number.
		if name, seen := idx.names[rec.Number]; !seen || (name == "" && rec.Org != "") {
			idx.names[rec.Number] = rec.Org
		}
	}
	idx.sorted = make([]ASNInfo, 0, len(idx.names))
	for n, name := range idx.names {
		idx.sorted = append(idx.sorted, ASNInfo{ASN: n, Name: name})
	}
	sort.Slice(idx.sorted, func(i, j int) bool { return idx.sorted[i].ASN < idx.sorted[j].ASN })
	st.index.Store(idx)
}

// Loaded reports whether an ASN database is active.
func (l *ASNLookup) Loaded() bool {
	return l != nil && l.state.Load() != nil
}

// IndexReady reports whether the name index of the active database
// has been built (search results are complete).
func (l *ASNLookup) IndexReady() bool {
	if l == nil {
		return false
	}
	st := l.state.Load()
	return st != nil && st.index.Load() != nil
}

// Path returns the active database path ("" when none).
func (l *ASNLookup) Path() string {
	if l == nil {
		return ""
	}
	l.pathMu.Lock()
	defer l.pathMu.Unlock()
	return l.path
}

// LookupASN returns the autonomous system of ip, or a zero ASNInfo
// when the database is missing, the IP is private or not found.
func (l *ASNLookup) LookupASN(ip net.IP) ASNInfo {
	if l == nil || ip == nil || isLAN(ip) {
		return ASNInfo{}
	}
	st := l.state.Load()
	if st == nil {
		return ASNInfo{}
	}
	var rec asnRecord
	if err := st.reader.Lookup(ip, &rec); err != nil {
		return ASNInfo{}
	}
	return ASNInfo{ASN: rec.Number, Name: rec.Org}
}

// maxASNSearchResults caps Search's limit.
const maxASNSearchResults = 50

// SearchASN returns up to limit systems matching q: a number (with or
// without an "AS" prefix) matches by number prefix, anything else by
// case-insensitive substring of the organisation name. Empty until
// the index is built.
func (l *ASNLookup) SearchASN(q string, limit int) []ASNInfo {
	idx := l.index()
	q = strings.TrimSpace(q)
	if idx == nil || q == "" {
		return []ASNInfo{}
	}
	if limit <= 0 || limit > maxASNSearchResults {
		limit = maxASNSearchResults
	}
	num := strings.TrimPrefix(strings.ToUpper(q), "AS")
	_, numErr := strconv.ParseUint(num, 10, 32)
	byNumber := numErr == nil
	needle := strings.ToLower(q)

	out := make([]ASNInfo, 0, limit)
	for _, e := range idx.sorted {
		var hit bool
		if byNumber {
			hit = strings.HasPrefix(strconv.FormatUint(uint64(e.ASN), 10), num)
		} else {
			hit = strings.Contains(strings.ToLower(e.Name), needle)
		}
		if hit {
			out = append(out, e)
			if len(out) == limit {
				break
			}
		}
	}
	return out
}

// NamesASN resolves the organisation names of the given numbers
// (unknown numbers get an empty name). Used to label saved rules.
func (l *ASNLookup) NamesASN(asns []uint32) []ASNInfo {
	idx := l.index()
	out := make([]ASNInfo, 0, len(asns))
	for _, n := range asns {
		info := ASNInfo{ASN: n}
		if idx != nil {
			info.Name = idx.names[n]
		}
		out = append(out, info)
	}
	return out
}

func (l *ASNLookup) index() *asnIndex {
	if l == nil {
		return nil
	}
	st := l.state.Load()
	if st == nil {
		return nil
	}
	return st.index.Load()
}

// Close releases the database. Safe on nil and when called twice.
func (l *ASNLookup) Close() error {
	if l == nil {
		return nil
	}
	if st := l.state.Swap(nil); st != nil {
		return st.reader.Close()
	}
	return nil
}
