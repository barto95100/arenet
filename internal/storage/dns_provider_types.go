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

package storage

import "strings"

// v2.26 — DNS provider type registry. Each entry describes one Caddy
// `dns.providers.<Type>` module: the credential fields it accepts,
// which of them are secrets, which are required. The registry is the
// single source of truth for validation (storage), Caddy emission
// (caddymgr), redaction (api, backup, caddymgr) and the settings form
// (served verbatim by GET /settings/dns-providers/types).
//
// Field Keys are the JSON keys of the upstream module's Provider
// struct, read from source (spec 2026-09-21 §Faits empiriques #2).
// Caddy decodes module config strictly, so a Key that drifts from
// upstream fails caddy.Validate — pinned by
// TestBuildConfigJSON_LoadsCleanly_AllDNSProviderTypes.

// DNSProviderField describes one credential field of a provider type.
type DNSProviderField struct {
	// Key is the JSON key emitted into the Caddy provider block.
	Key string `json:"key"`
	// Label is the default (English) form label; the frontend
	// translates by key and falls back to this.
	Label string `json:"label"`
	// Secret fields are never returned by the API and are redacted
	// in audit rows, backup exports and error strings.
	Secret bool `json:"secret"`
	// Required fields must be non-empty for the provider to be
	// considered configured.
	Required bool `json:"required"`
	// Enum, when non-empty, is the closed set of accepted values.
	Enum []string `json:"enum,omitempty"`
	// Default is the value the form pre-fills on create.
	Default string `json:"default,omitempty"`
}

// DNSProviderType describes one supported DNS provider.
type DNSProviderType struct {
	// Type is the stored type value and the suffix of the Caddy
	// module ID (dns.providers.<Type>).
	Type string `json:"type"`
	// Label is the provider's display name.
	Label string `json:"label"`
	// DocsURL points at the provider page where the operator creates
	// the credentials.
	DocsURL string `json:"docsUrl"`
	// Fields lists the credential fields, in form order.
	Fields []DNSProviderField `json:"fields"`
}

// Stored Type values. DNSProviderTypeOVH predates the registry and is
// referenced by the legacy migrations.
const (
	DNSProviderTypeOVH          = "ovh"
	DNSProviderTypeCloudflare   = "cloudflare"
	DNSProviderTypeDigitalOcean = "digitalocean"
	DNSProviderTypeGandi        = "gandi"
	DNSProviderTypeHetzner      = "hetzner"
	DNSProviderTypeInfomaniak   = "infomaniak"
	DNSProviderTypePorkbun      = "porkbun"
	DNSProviderTypeRoute53      = "route53"
	DNSProviderTypeScaleway     = "scaleway"
)

// OVHEndpoints lists the seven endpoint identifiers accepted by the
// go-ovh SDK (see github.com/ovh/go-ovh@v1.7.0/ovh/ovh.go:40-48).
// Raw endpoint URLs (also accepted by go-ovh) are a backlog item.
var OVHEndpoints = []string{
	"ovh-eu",
	"ovh-ca",
	"ovh-us",
	"kimsufi-eu",
	"kimsufi-ca",
	"soyoustart-eu",
	"soyoustart-ca",
}

// Legacy OVH credential keys, stored flat on DNSProviderConfig before
// v2.26. They are also the OVH registry Keys, which is what makes the
// fold-in of legacy rows lossless.
const (
	ovhKeyEndpoint          = "endpoint"
	ovhKeyApplicationKey    = "application_key"
	ovhKeyApplicationSecret = "application_secret"
	ovhKeyConsumerKey       = "consumer_key"
)

// route53DefaultRegion is pre-filled on create. Route53 is a global
// service; the SDK only needs a region to sign requests.
const route53DefaultRegion = "us-east-1"

// dnsProviderRegistry is ordered: OVH first (the reference provider),
// then alphabetical by Type.
var dnsProviderRegistry = []DNSProviderType{
	{
		Type:    DNSProviderTypeOVH,
		Label:   "OVHcloud",
		DocsURL: "https://www.ovh.com/auth/api/createToken",
		Fields: []DNSProviderField{
			{Key: ovhKeyEndpoint, Label: "Endpoint", Required: true, Enum: OVHEndpoints, Default: "ovh-eu"},
			{Key: ovhKeyApplicationKey, Label: "Application key", Secret: true, Required: true},
			{Key: ovhKeyApplicationSecret, Label: "Application secret", Secret: true, Required: true},
			{Key: ovhKeyConsumerKey, Label: "Consumer key", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypeCloudflare,
		Label:   "Cloudflare",
		DocsURL: "https://dash.cloudflare.com/profile/api-tokens",
		Fields: []DNSProviderField{
			{Key: "api_token", Label: "API token (Zone.DNS:Edit)", Secret: true, Required: true},
			{Key: "zone_token", Label: "Zone token (Zone:Read, optional)", Secret: true},
		},
	},
	{
		Type:    DNSProviderTypeDigitalOcean,
		Label:   "DigitalOcean",
		DocsURL: "https://cloud.digitalocean.com/account/api/tokens",
		Fields: []DNSProviderField{
			{Key: "auth_token", Label: "API token", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypeGandi,
		Label:   "Gandi",
		DocsURL: "https://admin.gandi.net/organizations/account/pat",
		Fields: []DNSProviderField{
			{Key: "bearer_token", Label: "Personal access token", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypeHetzner,
		Label:   "Hetzner",
		DocsURL: "https://docs.hetzner.cloud/reference/cloud#authentication",
		Fields: []DNSProviderField{
			{Key: "api_token", Label: "Hetzner Cloud API token", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypeInfomaniak,
		Label:   "Infomaniak",
		DocsURL: "https://manager.infomaniak.com/v3/ng/accounts/token/list",
		Fields: []DNSProviderField{
			{Key: "api_token", Label: "API token", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypePorkbun,
		Label:   "Porkbun",
		DocsURL: "https://porkbun.com/account/api",
		Fields: []DNSProviderField{
			{Key: "api_key", Label: "API key", Secret: true, Required: true},
			{Key: "api_secret_key", Label: "Secret API key", Secret: true, Required: true},
		},
	},
	{
		Type:    DNSProviderTypeRoute53,
		Label:   "Amazon Route 53",
		DocsURL: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
		Fields: []DNSProviderField{
			{Key: "region", Label: "AWS region", Required: true, Default: route53DefaultRegion},
			{Key: "access_key_id", Label: "Access key ID", Required: true},
			{Key: "secret_access_key", Label: "Secret access key", Secret: true, Required: true},
			{Key: "hosted_zone_id", Label: "Hosted zone ID (optional)"},
		},
	},
	{
		Type:    DNSProviderTypeScaleway,
		Label:   "Scaleway",
		DocsURL: "https://console.scaleway.com/iam/api-keys",
		Fields: []DNSProviderField{
			{Key: "secret_key", Label: "Secret key", Secret: true, Required: true},
			{Key: "organization_id", Label: "Organization ID", Required: true},
		},
	},
}

// DNSProviderTypesList returns a copy of the registry in display order.
func DNSProviderTypesList() []DNSProviderType {
	out := make([]DNSProviderType, len(dnsProviderRegistry))
	copy(out, dnsProviderRegistry)
	return out
}

// DNSProviderTypeByName returns the registry entry for t.
func DNSProviderTypeByName(t string) (DNSProviderType, bool) {
	for _, pt := range dnsProviderRegistry {
		if pt.Type == t {
			return pt, true
		}
	}
	return DNSProviderType{}, false
}

// field returns the field with the given key.
func (pt DNSProviderType) field(key string) (DNSProviderField, bool) {
	for _, f := range pt.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return DNSProviderField{}, false
}

// SecretKeys returns the keys of the secret fields of type t (nil for
// an unknown type).
func SecretKeys(t string) []string {
	pt, ok := DNSProviderTypeByName(t)
	if !ok {
		return nil
	}
	var out []string
	for _, f := range pt.Fields {
		if f.Secret {
			out = append(out, f.Key)
		}
	}
	return out
}

// ProviderConfigured reports whether c has a known type and every
// required field non-empty — the bar for emitting a DNS-01 ACME policy
// that won't fail Caddy's Provision.
func ProviderConfigured(c DNSProviderConfig) bool {
	pt, ok := DNSProviderTypeByName(c.Type)
	if !ok {
		return false
	}
	for _, f := range pt.Fields {
		if f.Required && c.Credentials[f.Key] == "" {
			return false
		}
	}
	return true
}

// SecretValues returns the non-empty secret credential values of c,
// for redaction of error strings.
func SecretValues(c DNSProviderConfig) []string {
	var out []string
	for _, k := range SecretKeys(c.Type) {
		if v := c.Credentials[k]; v != "" {
			out = append(out, v)
		}
	}
	return out
}

// WithoutSecrets returns a copy of c whose secret credential values are
// removed. Used for audit rows and anywhere a config is echoed. Values
// of an unknown type, or keys the type does not declare, are dropped
// too: only fields the registry positively marks non-secret survive.
func WithoutSecrets(c DNSProviderConfig) DNSProviderConfig {
	pt, _ := DNSProviderTypeByName(c.Type)
	creds := make(map[string]string, len(c.Credentials))
	for k, v := range c.Credentials {
		if f, ok := pt.field(k); ok && !f.Secret {
			creds[k] = v
		}
	}
	c.Credentials = creds
	return c
}

// redactedPlaceholder replaces secret values in redacted strings.
const redactedPlaceholder = "[REDACTED]"

// minRedactLen is the shortest secret value RedactDNSSecrets replaces.
// Shorter values (test fixtures, typos) would shred unrelated text and
// carry no real credential.
const minRedactLen = 4

// RedactDNSSecrets replaces every secret credential value of the given
// providers found in msg with "[REDACTED]". Some DNS modules echo the
// credential in their Provision error (caddy-dns/cloudflare@v0.2.4:
// "API token '<token>' appears invalid"), and those errors travel
// through caddy.Load into logs and API responses.
func RedactDNSSecrets(msg string, providers ...DNSProviderConfig) string {
	for _, p := range providers {
		for _, v := range SecretValues(p) {
			if len(v) >= minRedactLen {
				msg = strings.ReplaceAll(msg, v, redactedPlaceholder)
			}
		}
	}
	return msg
}
