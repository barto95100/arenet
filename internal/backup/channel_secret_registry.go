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

package backup

import (
	"slices"

	"github.com/barto95100/arenet/internal/storage"
)

// Which config keys of an alert channel hold a credential (v2.73).
//
// This replaces a switch over the channel kind that handled email and
// webhook and silently did nothing for anything else. The Discord kind
// shipped in v2.53 with its credential in a field named webhookUrl —
// not url, which is the generic webhook kind's name — so it matched no
// branch, and its live webhook URL was written in cleartext into every
// backup artifact: the "no-secrets" export an operator is told is safe
// to attach to a ticket, the passphrase-encrypted export whose own
// header declares it encrypted, and every scheduled backup file,
// including the ones mailed as SMTP attachments under covering text
// that says the secrets are encrypted.
//
// A map keyed by kind, rather than a switch, so the exhaustiveness
// test below can walk storage.AlertChannelKinds and fail when a new
// kind arrives without declaring its secrets. A switch cannot be
// audited that way, which is exactly how this one went wrong.

// channelSecretStringFields names the string-valued config keys that
// hold a credential, per channel kind.
//
// A kind with no credential at all declares an empty slice rather
// than being absent: "this kind was considered and has none" and
// "nobody thought about this kind" must not look the same.
var channelSecretStringFields = map[string][]string{
	storage.ChannelKindEmail:   {cfgKeySMTPPassword},
	storage.ChannelKindWebhook: {cfgKeyURL},
	storage.ChannelKindDiscord: {cfgKeyWebhookURL},
}

// channelSecretMapFields names the map-valued config keys whose VALUES
// are credentials. Only the generic webhook kind has one: its
// operator-supplied auth headers.
var channelSecretMapFields = map[string][]string{
	storage.ChannelKindWebhook: {cfgKeyHeaders},
}

// allChannelSecretStringFields is every string key any kind can carry,
// used by the restore path, which resolves sentinels without knowing
// the kind. Trying a key the kind does not have is a no-op, so the
// union is both correct and the shape least likely to miss one.
func allChannelSecretStringFields() []string {
	seen := map[string]bool{}
	out := make([]string, 0, 4)
	for _, keys := range channelSecretStringFields {
		for _, k := range keys {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	// Sorted: a map walk is randomised, and a security-relevant helper
	// returning a different order on each call is a needless source of
	// non-reproducible behaviour. Order does not affect the result —
	// each key resolves independently — which is exactly why it costs
	// nothing to pin.
	slices.Sort(out)
	return out
}
