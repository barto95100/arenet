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

package alerting

import (
	"net/http"
	"time"

	"github.com/barto95100/arenet/internal/netguard"
)

// guardedHTTPClient returns the http.Client the URL-based channel senders
// (webhook, Discord) use. Its dialer refuses link-local / cloud-metadata
// addresses (SSRF guard, internal/netguard) while leaving private
// addresses reachable — a homelab webhook is often one. The same guard
// backs the operator Test button, which dispatches through these senders.
//
// The dialer is the only change from a default client: the transport is a
// clone of http.DefaultTransport so proxy, TLS and keep-alive behaviour
// are unchanged, and timeout bounds the whole request as before.
func guardedHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = netguard.NewDialer(timeout).DialContext
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
}
