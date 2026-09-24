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

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/barto95100/arenet/internal/secrets"
	bolt "go.etcd.io/bbolt"
)

// RestoreSnapshotInput is the wire shape the backup package hands to
// the storage layer. Each section carries pre-serialised JSON per
// row; the storage layer does NOT validate (the backup package owns
// validation + sentinel resolution). The bucket keys carry the
// correct identity per spec §5.3 (route id, user id, "ovh", forward-
// auth name, "default").
//
// All six sections are applied in a single bbolt write transaction.
// On any error, the entire transaction is rolled back — the BoltDB
// is left untouched. This is the spec §5.3 "all-or-nothing" property
// enforced at the storage layer.
type RestoreSnapshotInput struct {
	// Routes maps route ID → JSON-marshalled storage.Route.
	Routes map[string][]byte
	// Users maps user ID → JSON-marshalled auth.User.
	Users map[string][]byte
	// DNSProviders maps dns provider key (e.g. "ovh") → JSON-marshalled
	// storage.DNSProviderConfig. nil or empty clears the bucket.
	DNSProviders map[string][]byte
	// ForwardAuthProviders maps provider name → JSON-marshalled
	// storage.ForwardAuthProvider. nil or empty clears the bucket.
	ForwardAuthProviders map[string][]byte
	// OIDCConfig is the JSON-marshalled storage.OIDCConfig for the
	// "default" key, or nil/empty to clear the OIDC bucket.
	OIDCConfig []byte
	// MaxMindConfig is the JSON-marshalled storage.MaxMindConfig for
	// the "default" key, or nil/empty to clear the maxmind_config
	// bucket (mirrors the OIDCConfig single-record convention).
	MaxMindConfig []byte
	// ExternalCertificates maps external cert ID → JSON-marshalled
	// storage.ExternalCertificate (v2.19.0). nil or empty clears the
	// bucket.
	ExternalCertificates map[string][]byte

	// Extras (v2.29) are the config areas the 1.0.0 backup format did
	// not carry. nil → none of their buckets is touched (restoring a
	// pre-v2.29 backup keeps the live values); non-nil → every one of
	// them is replaced by its content.
	Extras *RestoreExtras
}

// RestoreExtras is the v2.29 part of a restore. Singletons left nil
// are deleted (except ServerPosition); empty slices clear their
// bucket.
type RestoreExtras struct {
	ManagedDomains     []ManagedDomain
	ErrorTemplates     []ErrorPageTemplate
	TCPServices        []TCPService
	MaintenancePage    *MaintenancePageConfig
	AlertChannels      []Channel
	AlertRules         []AlertRule
	CrowdSecConfig     *CrowdSecConfig
	WatcherCredentials *WatcherCredentials
	// AutomationRules is the opaque automation rule set (nil = none).
	AutomationRules json.RawMessage
	UpdateCheck     *UpdateCheckConfig
	GeoIPUpdate     *GeoIPUpdateConfig
	// ServerPosition nil leaves the live row untouched: only a manual
	// position is exported, an auto-detected one belongs to the host.
	ServerPosition *ServerPositionRecord
	// BackupSchedule (v2.33) nil deletes the config; the runtime status
	// row is cleared either way.
	BackupSchedule *BackupScheduleConfig
	// RouteCheck (v2.35) nil deletes the row (back to the enabled
	// default).
	RouteCheck *RouteCheckConfig
	// APITokens are pre-marshalled auth.APIToken rows keyed by token
	// ID (storage does not import auth). nil leaves the api_tokens
	// bucket untouched (the exporter had no token store).
	APITokens map[string][]byte
}

// ListAPITokenRows returns the raw api_tokens rows keyed by token ID,
// for the backup export (v2.29). The rows are auth.APIToken JSON;
// storage owns the bucket but not the type (auth imports storage).
func (s *Store) ListAPITokenRows(ctx context.Context) (map[string][]byte, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("storage: nil store")
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()
	out := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return tx.Bucket([]byte(bucketAPITokens)).ForEach(func(k, v []byte) error {
			// Copy: bbolt-owned bytes die with the transaction.
			out[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("storage: list api tokens: %w", err)
	}
	return out, nil
}

// rows marshals the typed extras into bucket → key → JSON rows.
func (e *RestoreExtras) rows() (map[string]map[string][]byte, error) {
	out := map[string]map[string][]byte{}
	put := func(bucket, key string, v any) error {
		if out[bucket] == nil {
			out[bucket] = map[string][]byte{}
		}
		if raw, ok := v.(json.RawMessage); ok {
			out[bucket][key] = raw
			return nil
		}
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("marshal %s/%s: %w", bucket, key, err)
		}
		out[bucket][key] = b
		return nil
	}
	for _, b := range []string{bucketManagedDomains, bucketErrorTemplates, bucketMaintenancePage,
		bucketAlertingChannels, bucketAlertRules, bucketCrowdSecConfig, bucketAutomation,
		bucketUpdateCheck, bucketGeoIPUpdate, bucketBackupSchedule, bucketRouteCheck,
		bucketTCPServices} {
		out[b] = map[string][]byte{}
	}
	for _, md := range e.ManagedDomains {
		if err := put(bucketManagedDomains, md.Apex, md); err != nil {
			return nil, err
		}
	}
	for _, t := range e.ErrorTemplates {
		if err := put(bucketErrorTemplates, t.ID, t); err != nil {
			return nil, err
		}
	}
	for _, svc := range e.TCPServices {
		if err := put(bucketTCPServices, svc.ID, svc); err != nil {
			return nil, err
		}
	}
	for _, c := range e.AlertChannels {
		if err := put(bucketAlertingChannels, c.ID, c); err != nil {
			return nil, err
		}
	}
	for _, r := range e.AlertRules {
		if err := put(bucketAlertRules, r.ID, r); err != nil {
			return nil, err
		}
	}
	singletons := []struct {
		bucket, key string
		v           any
		set         bool
	}{
		{bucketMaintenancePage, maintenancePageKey, e.MaintenancePage, e.MaintenancePage != nil},
		{bucketCrowdSecConfig, crowdSecConfigKey, e.CrowdSecConfig, e.CrowdSecConfig != nil},
		{bucketAutomation, automationKeyCredentials, e.WatcherCredentials, e.WatcherCredentials != nil},
		{bucketAutomation, automationKeyRules, e.AutomationRules, len(e.AutomationRules) > 0},
		{bucketUpdateCheck, updateCheckKey, e.UpdateCheck, e.UpdateCheck != nil},
		{bucketGeoIPUpdate, geoIPUpdateKey, e.GeoIPUpdate, e.GeoIPUpdate != nil},
		{bucketServerPosition, serverPositionKey, e.ServerPosition, e.ServerPosition != nil},
		{bucketBackupSchedule, backupScheduleKey, e.BackupSchedule, e.BackupSchedule != nil},
		{bucketRouteCheck, routeCheckKey, e.RouteCheck, e.RouteCheck != nil},
	}
	for _, sg := range singletons {
		if sg.set {
			if err := put(sg.bucket, sg.key, sg.v); err != nil {
				return nil, err
			}
		}
	}
	if e.APITokens != nil {
		out[bucketAPITokens] = e.APITokens
	}
	return out, nil
}

// RestoreSnapshot atomically replaces the contents of the six
// backup-relevant buckets with the supplied input. Every bucket is
// cleared first then refilled inside the same transaction; a bbolt
// commit failure rolls back to the prior state.
//
// SECURITY: this method MUST only be called by the
// internal/backup.Import path. It bypasses every domain validator
// (CreateRoute / UpdateUser / PutDNSProvider). The backup package
// is responsible for validating the entire snapshot BEFORE calling
// this, and for clearing fields explicitly when the operator has
// opted into --allow-incomplete-restore.
func (s *Store) RestoreSnapshot(ctx context.Context, in RestoreSnapshotInput) error {
	if s == nil || s.db == nil {
		return errors.New("storage: nil store")
	}
	var extraRows map[string]map[string][]byte
	if in.Extras != nil {
		rows, err := in.Extras.rows()
		if err != nil {
			return fmt.Errorf("storage: restore extras: %w", err)
		}
		extraRows = rows
	}
	ctx, cancel := withTimeout(ctx)
	defer cancel()

	kr := s.keyring()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := resetAndFill(tx, kr, bucketRoutes, in.Routes); err != nil {
			return fmt.Errorf("restore routes: %w", err)
		}
		if err := resetAndFill(tx, kr, bucketUsers, in.Users); err != nil {
			return fmt.Errorf("restore users: %w", err)
		}
		if err := resetAndFill(tx, kr, bucketDNSProviders, in.DNSProviders); err != nil {
			return fmt.Errorf("restore dns_providers: %w", err)
		}
		if err := resetAndFill(tx, kr, bucketForwardAuthProviders, in.ForwardAuthProviders); err != nil {
			return fmt.Errorf("restore forward_auth_providers: %w", err)
		}
		oidcRows := map[string][]byte{}
		if len(in.OIDCConfig) > 0 {
			oidcRows["default"] = in.OIDCConfig
		}
		if err := resetAndFill(tx, kr, bucketOIDCConfig, oidcRows); err != nil {
			return fmt.Errorf("restore oidc_config: %w", err)
		}
		maxMindRows := map[string][]byte{}
		if len(in.MaxMindConfig) > 0 {
			maxMindRows[maxMindConfigKey] = in.MaxMindConfig
		}
		if err := resetAndFill(tx, kr, bucketMaxMindConfig, maxMindRows); err != nil {
			return fmt.Errorf("restore maxmind_config: %w", err)
		}
		if err := resetAndFill(tx, kr, bucketExternalCertificates, in.ExternalCertificates); err != nil {
			return fmt.Errorf("restore external_certificates: %w", err)
		}
		if in.Extras != nil {
			for bucket, rows := range extraRows {
				if err := resetAndFill(tx, kr, bucket, rows); err != nil {
					return fmt.Errorf("restore %s: %w", bucket, err)
				}
			}
		}
		return nil
	})
}

// resetAndFill clears every key in the bucket then re-inserts every
// row in rows. Bucket must already exist (NewStore creates them).
// Done inside the caller's transaction so the reset + fill are
// atomic with the rest of the restore.
// Secret fields are sealed with kr on the way in (nil = encryption
// off), so a restore never writes a secret in clear.
func resetAndFill(tx *bolt.Tx, kr *secrets.Keyring, bucketName string, rows map[string][]byte) error {
	b := tx.Bucket([]byte(bucketName))
	if b == nil {
		return fmt.Errorf("bucket %q missing", bucketName)
	}
	// Collect keys first, then delete — modifying a bucket while
	// iterating it is undefined behaviour in bbolt.
	var keys [][]byte
	if err := b.ForEach(func(k, _ []byte) error {
		copyk := make([]byte, len(k))
		copy(copyk, k)
		keys = append(keys, copyk)
		return nil
	}); err != nil {
		return err
	}
	for _, k := range keys {
		if err := b.Delete(k); err != nil {
			return fmt.Errorf("delete %q: %w", string(k), err)
		}
	}
	for k, v := range rows {
		v, _, err := sealRow(kr, bucketName, v)
		if err != nil {
			return fmt.Errorf("seal %q: %w", k, err)
		}
		if err := b.Put([]byte(k), v); err != nil {
			return fmt.Errorf("put %q: %w", k, err)
		}
	}
	return nil
}
