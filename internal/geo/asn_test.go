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

package geo

import (
	"errors"
	"net"
	"testing"
	"time"
)

const (
	testASNDB  = "../geoipupdate/testdata/asn.mmdb"
	testCityDB = "../geoipupdate/testdata/city.mmdb"
)

func loadTestASN(t *testing.T) *ASNLookup {
	t.Helper()
	l, err := NewASNLookup(testASNDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	deadline := time.Now().Add(5 * time.Second)
	for !l.IndexReady() {
		if time.Now().After(deadline) {
			t.Fatal("asn name index not built in 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return l
}

func TestASNLookup_LookupAndIndex(t *testing.T) {
	l := loadTestASN(t)
	if got := l.LookupASN(net.ParseIP("1.0.0.1")); got.ASN != 15169 || got.Name != "Google Inc." {
		t.Errorf("1.0.0.1 = %+v, want 15169 Google Inc.", got)
	}
	if got := l.LookupASN(net.ParseIP("192.168.1.1")); got.ASN != 0 {
		t.Errorf("LAN IP must not resolve: %+v", got)
	}
	// AT&T appears on several networks, some with an empty name.
	names := l.NamesASN([]uint32{7018, 4294967295})
	if names[0].Name != "AT&T Services" || names[1].Name != "" {
		t.Errorf("NamesASN = %+v", names)
	}
}

func TestASNLookup_Search(t *testing.T) {
	l := loadTestASN(t)
	has := func(res []ASNInfo, n uint32) bool {
		for _, r := range res {
			if r.ASN == n {
				return true
			}
		}
		return false
	}
	if res := l.SearchASN("google", 10); !has(res, 15169) {
		t.Errorf("name search: %+v", res)
	}
	if res := l.SearchASN("AS1516", 10); !has(res, 15169) {
		t.Errorf("AS-prefixed number search: %+v", res)
	}
	if res := l.SearchASN("7018", 10); len(res) == 0 || res[0].ASN != 7018 {
		t.Errorf("number search: %+v", res)
	}
	if res := l.SearchASN("china", 1); len(res) != 1 {
		t.Errorf("limit not applied: %+v", res)
	}
	if res := l.SearchASN("   ", 10); len(res) != 0 {
		t.Errorf("blank query must return nothing: %+v", res)
	}
}

func TestASNLookup_RejectsNonASNAndKeepsCurrent(t *testing.T) {
	l := loadTestASN(t)
	if err := l.Reload(testCityDB); !errors.Is(err, ErrNotASNDatabase) {
		t.Fatalf("Reload(city) err = %v, want ErrNotASNDatabase", err)
	}
	if l.LookupASN(net.ParseIP("1.0.0.1")).ASN != 15169 {
		t.Error("a rejected reload must keep the working database")
	}
	if err := VerifyASNMMDB(testCityDB); !errors.Is(err, ErrNotASNDatabase) {
		t.Errorf("VerifyASNMMDB(city) = %v", err)
	}
	if err := VerifyASNMMDB(testASNDB); err != nil {
		t.Errorf("VerifyASNMMDB(asn) = %v", err)
	}
}

func TestASNLookup_NilAndEmptySafe(t *testing.T) {
	var l *ASNLookup
	if l.Loaded() || l.IndexReady() || l.LookupASN(net.ParseIP("1.0.0.1")).ASN != 0 ||
		len(l.SearchASN("x", 5)) != 0 || l.Close() != nil {
		t.Error("nil ASNLookup must be a safe degraded receiver")
	}
	empty := &ASNLookup{}
	if empty.Loaded() || len(empty.NamesASN([]uint32{1})) != 1 {
		t.Error("empty ASNLookup must be a safe degraded receiver")
	}
}
