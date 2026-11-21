// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  The Arenet Authors
// Licensed under the GNU AGPL v3 or later. See LICENSE.

package main

import (
	"os"
	"regexp"
	"time"
)

// zeroTailRe matches a trailing "0s", or a trailing "0m0s"/"0m", as
// WHOLE components (a leading non-digit boundary ensures we don't chop
// the "0m" out of "30m"). Applied once, it turns 12h0m0s → 12h,
// 1h30m0s → 1h30m, 90m0s → 90m.
var zeroTailRe = regexp.MustCompile(`(\D)(0m)?0s$`)

// humanizeDuration renders a duration without the trailing zero
// components that time.Duration.String() emits, so the boot log echoes
// ~what the operator typed.
func humanizeDuration(d time.Duration) string {
	return zeroTailRe.ReplaceAllString(d.String(), "$1")
}

// effectiveConfigLogAttrs builds the slog key/value attrs for the
// one-line "effective config" boot log (v2.12.3). It reports the
// EFFECTIVE value of the operator-facing knobs — the value that was
// actually applied, whether it came from an env var / .env file or the
// built-in default — so an operator can confirm at a glance that their
// override was picked up.
//
// Secret-bearing vars (API keys) are reported as "set"/"unset" only —
// never their value. Presence-only env vars (contact email, trusted
// proxies) are likewise "set"/"unset" since the value isn't needed to
// confirm it was read.
func effectiveConfigLogAttrs(
	adminBind, dataDir, httpPort, httpsPort string,
	updateEnabled bool,
	updateInterval string,
	logFormat string,
	geoipMMDB, geoipASNMMDB string,
) []any {
	updateCheck := "disabled"
	if updateEnabled {
		updateCheck = "enabled"
	}
	attrs := []any{
		"admin_bind", adminBind,
		"data_dir", dataDir,
		"http", httpPort,
		"https", httpsPort,
		// #358 — the effective log output format (text|json), so an operator
		// can confirm ARENET_LOG_FORMAT took effect (it was a phantom knob
		// before v2.84.4). log_level is on the "Arenet starting" line.
		"log_format", logFormat,
		"update_check", updateCheck,
		"update_interval", updateInterval,
		"acme_email", setUnset("ARENET_ACME_EMAIL"),
		"trusted_proxies", setUnset("ARENET_TRUSTED_PROXIES"),
		"crowdsec_api_url", setUnset("ARENET_CROWDSEC_API_URL"),
		"crowdsec_api_key", setUnset("ARENET_CROWDSEC_API_KEY"),
		// #356 — the EFFECTIVE MMDB path (env var, or the built-in default it
		// fell back to), or "disabled" when none loaded. Before v2.84.4 these
		// reported set/unset from the env var alone, so a DB opened from the
		// default path logged "unset" even though Country/AS enrichment worked.
		"geoip_mmdb", geoipMMDB,
		"geoip_asn_mmdb", geoipASNMMDB,
		"secret_key_file", setUnset(envSecretKeyFile),
	}
	return attrs
}

// geoipMMDBDescriptor renders the effective MMDB descriptor for the boot
// "effective config" line (#356). Precedence mirrors run()'s resolution:
// ARENET_GEOIP_MMDB (envValue) when set, else the built-in default path. When
// a DB actually opened it reports that path — suffixed "(default)" when the
// path came from the fallback rather than the env var — so the log matches
// what enrichment really uses. When no DB loaded it reports "disabled", never a
// misleading "unset" that hides a working fallback.
func geoipMMDBDescriptor(envValue, resolvedPath string, loaded bool) string {
	if !loaded {
		return "disabled"
	}
	if envValue == "" {
		return resolvedPath + " (default)"
	}
	return resolvedPath
}

// setUnset returns "set" when the env var is present and non-empty,
// "unset" otherwise. Used for secret / presence-only vars so the log
// confirms the var was read without ever printing its value.
func setUnset(envKey string) string {
	if os.Getenv(envKey) != "" {
		return "set"
	}
	return "unset"
}
