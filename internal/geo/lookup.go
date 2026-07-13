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

// Package geo provides GeoIP lookup capabilities backed by a MaxMind
// GeoLite2-City database file. It is the foundation for event
// enrichment (V.2) and server position detection (V.1, V.4).
//
// Per Step V spec §3.1 (locked decision: oschwald/geoip2-golang as the
// MMDB reader) and §3.2 (MMDB lifecycle: default path
// /var/lib/arenet/GeoLite2-City.mmdb, overridable via ARENET_GEOIP_MMDB).
// Operator-supplied MMDB; absence is non-fatal (§3.7 degraded mode).
package geo

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/geoip2-golang"
)

// Location is the GeoIP resolution result for a single IP address.
// Country is the ISO 3166-1 alpha-2 code (e.g. "FR", "US"). The
// sentinel value "LAN" marks an RFC1918 / loopback / link-local
// address — V.2 enrichment will key off it for §3.8 RFC1918 handling.
// Lat/Lon are 0.0 when Found=false; callers must check Found before
// rendering coordinates.
type Location struct {
	Country     string  `json:"country"`
	CountryName string  `json:"countryName"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Found       bool    `json:"found"`
}

// Lookup wraps a MaxMind GeoLite2-City reader. Safe for concurrent
// use: the underlying reader is a read-only mmap (goroutine-safe for
// reads), published via an atomic pointer so Reload can swap it in at
// runtime without a lock on the lookup hot path.
//
// A nil *Lookup is a valid degraded-mode receiver: LookupIP returns
// Location{Found: false} and Close/Reload are safe.
type Lookup struct {
	reader atomic.Pointer[geoip2.Reader]

	// pathMu guards path, updated by Reload off the hot path.
	pathMu sync.Mutex
	path   string
}

// closeGracePeriod is how long Reload waits before closing the previous
// reader, so concurrent in-flight lookups (each a microsecond-scale
// City() call) finish against the old mmap before it is unmapped.
const closeGracePeriod = 5 * time.Second

// NewLookup opens the MMDB file at the given path. Returns an error
// if the path is empty, the file is missing, or the file is not a
// valid MMDB. The caller is responsible for path selection (env-var
// override resolution lives in cmd/arenet). The caller may proceed
// with a nil *Lookup on error — every method tolerates a nil receiver.
func NewLookup(mmdbPath string) (*Lookup, error) {
	if mmdbPath == "" {
		return nil, errors.New("geo: mmdb path is empty")
	}
	reader, err := geoip2.Open(mmdbPath)
	if err != nil {
		return nil, fmt.Errorf("geo: open mmdb %q: %w", mmdbPath, err)
	}
	l := &Lookup{path: mmdbPath}
	l.reader.Store(reader)
	return l, nil
}

// Path returns the MMDB file path this Lookup was opened against.
// Returns "" on a nil receiver. Useful for boot-log diagnostics.
func (l *Lookup) Path() string {
	if l == nil {
		return ""
	}
	l.pathMu.Lock()
	defer l.pathMu.Unlock()
	return l.path
}

// LookupIP returns the location for the given IP.
//
// Contract:
//   - nil receiver (degraded mode) → Location{Found: false}.
//   - nil or unspecified ip → Location{Found: false}.
//   - RFC1918 / loopback / link-local ip → Location{Country: "LAN", Found: false}.
//     V.2 uses Country=="LAN" as the marker for §3.8 LAN traffic handling.
//   - IP not in the MMDB → Location{Found: false}.
//   - MMDB lookup error → Location{Found: false} (logged at caller's discretion).
//   - Successful lookup → fully populated Location with Found=true.
//
// Country name resolution prefers English ("en") for stable wire shape;
// the frontend handles its own localization layer.
func (l *Lookup) LookupIP(ip net.IP) Location {
	if l == nil {
		return Location{Found: false}
	}
	if ip == nil || ip.IsUnspecified() {
		return Location{Found: false}
	}
	if isLAN(ip) {
		return Location{Country: "LAN", Found: false}
	}
	r := l.reader.Load()
	if r == nil {
		return Location{Found: false}
	}
	rec, err := r.City(ip)
	if err != nil || rec == nil {
		return Location{Found: false}
	}
	loc := Location{
		Country:     rec.Country.IsoCode,
		CountryName: rec.Country.Names["en"],
		City:        rec.City.Names["en"],
		Lat:         rec.Location.Latitude,
		Lon:         rec.Location.Longitude,
	}
	loc.Found = loc.Country != "" || loc.Lat != 0 || loc.Lon != 0
	return loc
}

// Reload opens the MMDB at newPath and atomically swaps it in as the
// active reader. In-flight lookups continue against whichever reader
// they already loaded; the previous reader is closed after a grace
// period so those lookups finish first.
//
// On open error the current reader is left in place — a failed download
// or corrupt file never degrades a working lookup. A nil receiver or
// empty path returns an error.
func (l *Lookup) Reload(newPath string) error {
	if l == nil {
		return errors.New("geo: reload on nil Lookup")
	}
	if newPath == "" {
		return errors.New("geo: reload path is empty")
	}
	nr, err := geoip2.Open(newPath)
	if err != nil {
		return fmt.Errorf("geo: reload open mmdb %q: %w", newPath, err)
	}
	old := l.reader.Swap(nr)
	l.pathMu.Lock()
	l.path = newPath
	l.pathMu.Unlock()
	if old != nil {
		go func(r *geoip2.Reader) {
			time.Sleep(closeGracePeriod)
			_ = r.Close()
		}(old)
	}
	return nil
}

// Close releases the MMDB file handle. Safe to call on nil, safe to
// call multiple times.
func (l *Lookup) Close() error {
	if l == nil {
		return nil
	}
	if r := l.reader.Swap(nil); r != nil {
		return r.Close()
	}
	return nil
}

// rfc1918Ranges + loopback + link-local CIDR set used by isLAN.
// Compiled once at init() rather than re-parsed on every call.
//
// Per Step V spec §3.8 — RFC1918 traffic is enriched with the "LAN"
// country sentinel rather than dropped or geolocated to the server's
// own position, because the MMDB doesn't cover private ranges and
// silent fallback would misattribute homelab traffic.
var (
	lanRanges []*net.IPNet
	lanInit   sync.Once
)

func initLANRanges() {
	cidrs := []string{
		"10.0.0.0/8",     // RFC1918 class A
		"172.16.0.0/12",  // RFC1918 class B
		"192.168.0.0/16", // RFC1918 class C
		"127.0.0.0/8",    // IPv4 loopback
		"169.254.0.0/16", // IPv4 link-local (RFC3927)
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local (RFC4193)
	}
	lanRanges = make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			lanRanges = append(lanRanges, n)
		}
	}
}

// isLAN reports whether ip belongs to a private / loopback / link-local
// range that should not be geolocated against the public MMDB.
func isLAN(ip net.IP) bool {
	if ip == nil {
		return false
	}
	lanInit.Do(initLANRanges)
	for _, n := range lanRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
