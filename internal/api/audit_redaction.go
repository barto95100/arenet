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

package api

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/barto95100/arenet/internal/audit"
	"github.com/barto95100/arenet/internal/storage"
)

// auditRedacted replaces a secret value in an audit payload; the key
// stays so the operator still sees what was configured.
const auditRedacted = "[redacted]"

// Audit target types whose payloads older versions stored with
// secrets (v2.30 scrub).
const (
	auditTargetRoute          = "route"
	auditTargetAlertChannel   = "alerting_channel"
	auditRoutePasswordHashKey = "password_hash"
)

// redactWebhookURL keeps the scheme and host of a webhook URL — enough
// to audit where alerts go — and drops the path and query, which carry
// the credential for Discord / Slack style webhooks.
func redactWebhookURL(raw string) string {
	if raw == "" || raw == auditRedacted {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return auditRedacted
	}
	return u.Scheme + "://" + u.Host + "/" + auditRedacted
}

// redactSensitiveHeaders returns a copy of h with the values of
// credential-bearing headers replaced (nil stays nil).
func redactSensitiveHeaders(h map[string]string) map[string]string {
	if h == nil {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if v != "" && storage.IsSensitiveHeader(k) {
			v = auditRedacted
		}
		out[k] = v
	}
	return out
}

// ScrubAuditSecrets removes from the stored audit events the secrets
// that versions before v2.30 recorded: webhook URLs and header
// values, SMTP passwords, sensitive route header values and Basic
// Auth hashes (route and path rules). Idempotent; returns the number
// of events rewritten.
func ScrubAuditSecrets(ctx context.Context, store *audit.Store) (int, error) {
	return store.Redact(ctx, func(evt *audit.Event) bool {
		var scrub func(map[string]json.RawMessage) bool
		switch evt.TargetType {
		case auditTargetRoute:
			scrub = scrubRouteAuditPayload
		case auditTargetAlertChannel:
			scrub = scrubChannelAuditPayload
		default:
			return false
		}
		changed := false
		for _, p := range []*json.RawMessage{&evt.BeforeJSON, &evt.AfterJSON} {
			if out, ok := scrubPayload(*p, scrub); ok {
				*p = out
				changed = true
			}
		}
		return changed
	})
}

// scrubPayload applies scrub to a JSON object payload, re-encoding it
// only when something changed. Non-object payloads are left alone.
func scrubPayload(raw json.RawMessage, scrub func(map[string]json.RawMessage) bool) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return raw, false
	}
	if !scrub(m) {
		return raw, false
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw, false
	}
	return out, true
}

func scrubRouteAuditPayload(m map[string]json.RawMessage) bool {
	changed := false
	for _, key := range []string{"request_headers", "response_headers"} {
		changed = editObject(m, key, func(h map[string]json.RawMessage) bool {
			c := false
			for name := range h {
				if storage.IsSensitiveHeader(name) {
					c = setString(h, name, func(v string) string {
						if v == "" {
							return v
						}
						return auditRedacted
					}) || c
				}
			}
			return c
		}) || changed
	}
	changed = editObject(m, "basic_auth", blankPasswordHash) || changed
	if raw, ok := m["path_rules"]; ok {
		var rules []map[string]json.RawMessage
		if json.Unmarshal(raw, &rules) == nil {
			rc := false
			for _, r := range rules {
				rc = editObject(r, "basic_auth", blankPasswordHash) || rc
			}
			if rc {
				if b, err := json.Marshal(rules); err == nil {
					m["path_rules"] = b
					changed = true
				}
			}
		}
	}
	return changed
}

func scrubChannelAuditPayload(m map[string]json.RawMessage) bool {
	return editObject(m, "config", func(cfg map[string]json.RawMessage) bool {
		c := setString(cfg, "url", redactWebhookURL)
		c = setString(cfg, "smtpPassword", func(string) string { return "" }) || c
		c = editObject(cfg, "headers", func(h map[string]json.RawMessage) bool {
			hc := false
			for name := range h {
				hc = setString(h, name, func(v string) string {
					if v == "" {
						return v
					}
					return auditRedacted
				}) || hc
			}
			return hc
		}) || c
		return c
	})
}

func blankPasswordHash(ba map[string]json.RawMessage) bool {
	return setString(ba, auditRoutePasswordHashKey, func(string) string { return "" })
}

// editObject decodes m[key] as an object, applies fn and stores it
// back when fn reports a change.
func editObject(m map[string]json.RawMessage, key string, fn func(map[string]json.RawMessage) bool) bool {
	raw, ok := m[key]
	if !ok {
		return false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return false
	}
	if !fn(obj) {
		return false
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return false
	}
	m[key] = b
	return true
}

// setString replaces the string m[key] with fn(value) when it differs.
func setString(m map[string]json.RawMessage, key string, fn func(string) string) bool {
	raw, ok := m[key]
	if !ok {
		return false
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	nv := fn(v)
	if nv == v {
		return false
	}
	b, err := json.Marshal(nv)
	if err != nil {
		return false
	}
	m[key] = b
	return true
}
