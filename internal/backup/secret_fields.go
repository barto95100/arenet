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

package backup

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/barto95100/arenet/internal/secrets"
	"github.com/barto95100/arenet/internal/storage"
)

// secretFn maps one secret value. path names the value and its row
// ("routes/<id>/basic_auth.password_hash"); it is the AAD when the
// value is sealed, so a sealed value cannot be moved to another row
// or field. fn is only called for non-empty values.
type secretFn func(path, value string) (string, error)

// visitSecrets applies fn to every secret value of the snapshot — the
// single list of secret fields shared by redaction (sentinel), sealing
// (passphrase backup) and opening. Slices, maps and pointers are
// cloned before being written, so values shared with the caller (the
// live store's rows) are never mutated.
//
// Adding a secret field anywhere in the snapshot REQUIRES adding it
// here, or exports leak it.
func visitSecrets(s *Snapshot, fn secretFn) error {
	apply := func(path string, v *string) error {
		if *v == "" {
			return nil
		}
		nv, err := fn(path, *v)
		if err != nil {
			return err
		}
		*v = nv
		return nil
	}

	for i := range s.Routes {
		r := &s.Routes[i]
		base := "routes/" + r.ID + "/"
		if err := apply(base+"basic_auth.password_hash", &r.BasicAuth.PasswordHash); err != nil {
			return err
		}
		if len(r.PathRules) > 0 {
			rules := slices.Clone(r.PathRules)
			for j := range rules {
				if ba := rules[j].BasicAuth; ba != nil {
					cp := *ba
					if err := apply(base+pathRuleHashField(rules[j].PathPrefix), &cp.PasswordHash); err != nil {
						return err
					}
					rules[j].BasicAuth = &cp
				}
			}
			r.PathRules = rules
		}
		var err error
		if r.RequestHeaders, err = visitHeaders(base+"request_headers", r.RequestHeaders, fn); err != nil {
			return err
		}
		if r.ResponseHeaders, err = visitHeaders(base+"response_headers", r.ResponseHeaders, fn); err != nil {
			return err
		}
	}
	for i := range s.Users {
		if err := apply("users/"+s.Users[i].ID+"/password_hash", &s.Users[i].PasswordHash); err != nil {
			return err
		}
	}
	for i := range s.DNSProviders {
		d := &s.DNSProviders[i]
		d.Credentials = maps.Clone(d.Credentials)
		secret := storage.SecretKeys(d.Type)
		for k, v := range d.Credentials {
			if !slices.Contains(secret, k) && !secrets.IsSealed(v) {
				continue
			}
			if err := apply("dns_providers/"+d.ID+"/credentials."+k, &v); err != nil {
				return err
			}
			d.Credentials[k] = v
		}
	}
	for i := range s.ForwardAuthProviders {
		p := &s.ForwardAuthProviders[i]
		if err := apply("forward_auth_providers/"+p.Name+"/client_secret", &p.ClientSecret); err != nil {
			return err
		}
	}
	if err := apply("oidc_config/client_secret", &s.OIDCConfig.ClientSecret); err != nil {
		return err
	}
	if s.MaxMindConfig != nil {
		cp := *s.MaxMindConfig
		if err := apply("maxmind_config/license_key", &cp.LicenseKey); err != nil {
			return err
		}
		s.MaxMindConfig = &cp
	}
	for i := range s.ExternalCertificates {
		c := &s.ExternalCertificates[i]
		if err := apply("external_certificates/"+c.ID+"/keyPEM", &c.KeyPEM); err != nil {
			return err
		}
	}
	return visitExtrasSecrets(s.Extras, apply, fn)
}

func visitExtrasSecrets(ex *SnapshotExtras, apply func(string, *string) error, fn secretFn) error {
	if ex == nil {
		return nil
	}
	channels := slices.Clone(ex.AlertChannels)
	for i := range channels {
		cfg, err := visitChannelConfig(entityAlertChannels+"/"+channels[i].ID+"/", channels[i].Kind, channels[i].Config, fn)
		if err != nil {
			return err
		}
		channels[i].Config = cfg
	}
	ex.AlertChannels = channels
	if ex.CrowdSecConfig != nil {
		cp := *ex.CrowdSecConfig
		if err := apply(entityCrowdSec+"/api_key", &cp.APIKey); err != nil {
			return err
		}
		ex.CrowdSecConfig = &cp
	}
	if ex.WatcherCredentials != nil {
		cp := *ex.WatcherCredentials
		if err := apply(entityWatcher+"/password", &cp.Password); err != nil {
			return err
		}
		ex.WatcherCredentials = &cp
	}
	tokens := slices.Clone(ex.APITokens)
	for i := range tokens {
		if err := apply(entityAPITokens+"/"+tokens[i].ID+"/token_hash", &tokens[i].TokenHash); err != nil {
			return err
		}
	}
	ex.APITokens = tokens
	return nil
}

// visitHeaders applies fn to the values of credential-bearing headers
// (and to any already sealed value) of a copy of h.
func visitHeaders(base string, h map[string]string, fn secretFn) (map[string]string, error) {
	if h == nil {
		return nil, nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if v != "" && (storage.IsSensitiveHeader(k) || secrets.IsSealed(v)) {
			nv, err := fn(base+"["+k+"]", v)
			if err != nil {
				return nil, err
			}
			v = nv
		}
		out[k] = v
	}
	return out, nil
}

// visitChannelConfig applies fn to the secret values of a channel
// config: SMTP password (email), URL and header values (webhook). A
// config that is not a JSON object is handled whole, as a JSON string.
func visitChannelConfig(base, kind string, raw json.RawMessage, fn secretFn) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	m := decodeConfig(raw)
	if m == nil {
		var whole string
		if json.Unmarshal(raw, &whole) != nil {
			whole = string(raw)
		}
		nv, err := fn(base+"config", whole)
		if err != nil {
			return nil, err
		}
		if json.Valid([]byte(nv)) && !secrets.IsSealed(nv) && nv != SentinelLiteral {
			return json.RawMessage(nv), nil // opened back to the original JSON
		}
		b, err := json.Marshal(nv)
		return b, err
	}
	str := func(key string) error {
		v, ok := m[key].(string)
		if !ok || v == "" {
			return nil
		}
		nv, err := fn(base+"config."+key, v)
		if err != nil {
			return err
		}
		m[key] = nv
		return nil
	}
	switch kind {
	case storage.ChannelKindEmail:
		if err := str(cfgKeySMTPPassword); err != nil {
			return nil, err
		}
	case storage.ChannelKindWebhook:
		if err := str(cfgKeyURL); err != nil {
			return nil, err
		}
		if h, ok := m[cfgKeyHeaders].(map[string]any); ok {
			for k, v := range h {
				s, ok := v.(string)
				if !ok || s == "" {
					continue
				}
				nv, err := fn(base+"config."+cfgKeyHeaders+"["+k+"]", s)
				if err != nil {
					return nil, err
				}
				h[k] = nv
			}
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode channel config: %w", err)
	}
	return b, nil
}
