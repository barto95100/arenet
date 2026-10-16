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
	"net"
	"sync"
	"testing"
	"time"
)

// Publish must not send on a subscriber channel that unsubscribe has
// closed (F49). Before the fix Publish released the lock and then fanned
// out, so a concurrent unsubscribe could close the channel in between —
// a send-on-closed panic that aborts the publishing goroutine (on the
// CrowdSec arm, permanently). Run under -race; a tight subscribe/publish
// churn surfaces both the data race and the panic without the fix.
func TestBus_PublishDoesNotRaceUnsubscribe(t *testing.T) {
	b := NewBus(16)
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				b.Publish(GeoEvent{SourceCountry: "FR"})
			}
		}
	}()

	for i := 0; i < 3000; i++ {
		_, unsub := b.Subscribe(1)
		b.Publish(GeoEvent{SourceCountry: "DE"})
		unsub()
	}
	close(stop)
	wg.Wait()
}

// Close must wait for in-flight lookups before it unmaps the reader
// (F55). Before the fix Close munmapped immediately, so a traversal in
// flight faulted on unmapped memory — a runtime fault that kills the
// process. Run under -race with a real MMDB; concurrent LookupIP + Close
// faults without the fix and completes cleanly with it.
func TestLookup_CloseWaitsForInFlightLookups(t *testing.T) {
	l, err := NewLookup(testCityDB)
	if err != nil {
		t.Fatalf("open test MMDB %s: %v", testCityDB, err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip := net.ParseIP("8.8.8.8")
			for {
				select {
				case <-stop:
					return
				default:
					l.LookupIP(ip)
				}
			}
		}()
	}

	time.Sleep(10 * time.Millisecond) // let lookups get in flight
	if err := l.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	time.Sleep(10 * time.Millisecond) // lookups now hit the nil reader, safely
	close(stop)
	wg.Wait()
}
