// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// v2.42 — service presets.
//
// A layer-4 relay is a handful of fields, but the ones that matter
// are the ones an operator has to KNOW: which port a protocol lives
// on, whether it is TCP or UDP, and — the part people get wrong —
// whether exposing it to the whole internet is reasonable.
//
// So a preset carries more than a port number: it says, per service,
// whether the source should be restricted by default. A database on
// the open internet is the mistake this list exists to prevent; mail
// is the opposite case, where restricting would break the service.

import type { ProxyProtocolVersion, TCPServiceProtocol } from '$lib/api/tcp-services';

export interface ServicePreset {
	/** Stable key; the label and note are resolved through i18n. */
	id: string;
	/** Suggested service name, also the i18n key suffix. */
	name: string;
	protocol: TCPServiceProtocol;
	port: number;
	proxyProtocol: ProxyProtocolVersion;
	/**
	 * true when the service should NOT be reachable from anywhere by
	 * default. The form pre-arms the source-IP filter and says why.
	 */
	restrictByDefault: boolean;
	/** Active health check makes sense (TCP only, and not for mail MX). */
	healthCheck: boolean;
	group: 'mail' | 'data' | 'remote' | 'network';
}

export const SERVICE_PRESETS: ServicePreset[] = [
	// --- Mail. The whole point is to be reachable; restricting the
	// source would mean refusing mail from the internet.
	{ id: 'smtp', name: 'smtp', protocol: 'tcp', port: 25, proxyProtocol: 'v2', restrictByDefault: false, healthCheck: false, group: 'mail' },
	{ id: 'submissions', name: 'submissions', protocol: 'tcp', port: 465, proxyProtocol: 'v2', restrictByDefault: false, healthCheck: false, group: 'mail' },
	{ id: 'submission', name: 'submission', protocol: 'tcp', port: 587, proxyProtocol: 'v2', restrictByDefault: false, healthCheck: false, group: 'mail' },
	{ id: 'imaps', name: 'imaps', protocol: 'tcp', port: 993, proxyProtocol: 'v2', restrictByDefault: false, healthCheck: false, group: 'mail' },
	{ id: 'managesieve', name: 'managesieve', protocol: 'tcp', port: 4190, proxyProtocol: 'v2', restrictByDefault: true, healthCheck: false, group: 'mail' },

	// --- Databases and caches. Never open to the world.
	{ id: 'postgresql', name: 'postgresql', protocol: 'tcp', port: 5432, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'data' },
	{ id: 'mysql', name: 'mysql', protocol: 'tcp', port: 3306, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'data' },
	{ id: 'redis', name: 'redis', protocol: 'tcp', port: 6379, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'data' },
	{ id: 'mongodb', name: 'mongodb', protocol: 'tcp', port: 27017, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'data' },

	// --- Remote access. Reachable on purpose, but worth a filter.
	{ id: 'ssh', name: 'ssh', protocol: 'tcp', port: 22, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'remote' },
	{ id: 'rdp', name: 'rdp', protocol: 'tcp', port: 3389, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'remote' },
	{ id: 'vnc', name: 'vnc', protocol: 'tcp', port: 5900, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'remote' },

	// --- Network services. Mostly UDP, where an active health check
	// is refused by the API anyway.
	{ id: 'wireguard', name: 'wireguard', protocol: 'udp', port: 51820, proxyProtocol: '', restrictByDefault: false, healthCheck: false, group: 'network' },
	{ id: 'dns', name: 'dns', protocol: 'udp', port: 53, proxyProtocol: '', restrictByDefault: true, healthCheck: false, group: 'network' },
	{ id: 'syslog', name: 'syslog', protocol: 'udp', port: 514, proxyProtocol: '', restrictByDefault: true, healthCheck: false, group: 'network' },
	{ id: 'mqtt', name: 'mqtt', protocol: 'tcp', port: 1883, proxyProtocol: '', restrictByDefault: true, healthCheck: true, group: 'network' },
	{ id: 'minecraft', name: 'minecraft', protocol: 'tcp', port: 25565, proxyProtocol: '', restrictByDefault: false, healthCheck: true, group: 'network' }
];

/** Presets grouped for the picker, in the order they are shown. */
export const PRESET_GROUPS: ServicePreset['group'][] = ['mail', 'data', 'remote', 'network'];

export function presetsOf(group: ServicePreset['group']): ServicePreset[] {
	return SERVICE_PRESETS.filter((p) => p.group === group);
}
