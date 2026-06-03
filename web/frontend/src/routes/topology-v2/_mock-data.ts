// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

/**
 * Mock topology routes for Phase 1 visual development.
 *
 * Five routes cover the cases we want the canvas to render
 * convincingly before the live data feed lands:
 *
 *   1. api.arenet.fr       round_robin, 3 healthy backends (Go)
 *   2. app.arenet.fr       least_conn, 2 healthy backends (Next.js)
 *   3. ws.arenet.fr        ip_hash (sticky), 2 healthy backends (Node)
 *   4. admin.arenet.fr     SINGLE backend (SPOF warning), high p99
 *   5. billing.arenet.fr   SINGLE backend, 5xx errors (bad tier)
 *
 * Numbers mirror the mock screenshots so the visual diff is easy
 * to spot if a component drifts.
 */

import type { TopologyRoute } from './_types';

export const mockRoutes: TopologyRoute[] = [
        // ---------- 1. api.arenet.fr — round-robin, 3/3 healthy ----------
        {
                id: 'api',
                host: 'api.arenet.fr',
                aliases: ['admin.arenet.fr'],
                lbPolicy: 'round_robin',
                reqPerSec: 624,
                p99LatencyMs: 38,
                errorRate5xx: 0,
                tlsEnabled: true,
                wafLevel: 'block',
                rateLimited: true,
                upstreams: [
                        {
                                id: 'api-v2-01',
                                url: '10.0.4.12:8080',
                                runtime: 'Go',
                                status: 'healthy',
                                reqPerSec: 220,
                                p99LatencyMs: 38,
                                fairnessRatio: 0.35,
                        },
                        {
                                id: 'api-v2-02',
                                url: '10.0.4.13:8080',
                                runtime: 'Go',
                                status: 'healthy',
                                reqPerSec: 198,
                                p99LatencyMs: 35,
                                fairnessRatio: 0.32,
                        },
                        {
                                id: 'api-v2-03',
                                url: '10.0.4.14:8080',
                                runtime: 'Go',
                                status: 'healthy',
                                reqPerSec: 206,
                                p99LatencyMs: 41,
                                fairnessRatio: 0.33,
                        },
                ],
        },

        // ---------- 2. app.arenet.fr — least_conn, 2/2 healthy ----------
        {
                id: 'app',
                host: 'app.arenet.fr',
                lbPolicy: 'least_conn',
                reqPerSec: 298,
                p99LatencyMs: 24,
                errorRate5xx: 0,
                tlsEnabled: true,
                wafLevel: 'detect',
                upstreams: [
                        {
                                id: 'app-fe-01',
                                url: '10.0.4.21:3000',
                                runtime: 'Next.js 15',
                                status: 'healthy',
                                reqPerSec: 148,
                                p99LatencyMs: 22,
                                fairnessRatio: 0.50,
                        },
                        {
                                id: 'app-fe-02',
                                url: '10.0.4.22:3000',
                                runtime: 'Next.js 15',
                                status: 'healthy',
                                reqPerSec: 150,
                                p99LatencyMs: 25,
                                fairnessRatio: 0.50,
                        },
                ],
        },

        // ---------- 3. ws.arenet.fr — ip_hash (sticky), 2/2 healthy ----------
        {
                id: 'ws',
                host: 'ws.arenet.fr',
                lbPolicy: 'ip_hash',
                reqPerSec: 84,
                p99LatencyMs: 18,
                errorRate5xx: 0,
                tlsEnabled: true,
                upstreams: [
                        {
                                id: 'ws-rt-01',
                                url: '10.0.4.30:9001',
                                runtime: 'Node 22',
                                status: 'healthy',
                                reqPerSec: 45,
                                p99LatencyMs: 16,
                                fairnessRatio: 0.55,
                        },
                        {
                                id: 'ws-rt-02',
                                url: '10.0.4.31:9001',
                                runtime: 'Node 22',
                                status: 'healthy',
                                reqPerSec: 39,
                                p99LatencyMs: 19,
                                fairnessRatio: 0.45,
                        },
                ],
        },

        // ---------- 4. admin.arenet.fr — SINGLE, SPOF + high p99 ----------
        {
                id: 'admin',
                host: 'admin.arenet.fr',
                lbPolicy: 'first',
                reqPerSec: 182,
                p99LatencyMs: 410,   // > 300 -> warn tier on edges
                errorRate5xx: 0,
                tlsEnabled: true,
                mtlsRequired: true,
                upstreams: [
                        {
                                id: 'api-auth-01',
                                url: '10.0.4.18:8081',
                                runtime: 'OIDC',
                                status: 'healthy',
                                reqPerSec: 182,
                                p99LatencyMs: 410,
                                fairnessRatio: 1.0,
                        },
                ],
        },

        // ---------- 5. billing.arenet.fr — SINGLE, 5xx errors ----------
        {
                id: 'billing',
                host: 'billing.arenet.fr',
                lbPolicy: 'first',
                reqPerSec: 38,
                p99LatencyMs: 280,
                errorRate5xx: 14,    // > 0 -> bad tier on edges
                tlsEnabled: true,
                upstreams: [
                        {
                                id: 'billing-svc-01',
                                url: '10.0.4.18:8090',
                                runtime: 'Python 3.12',
                                status: 'unhealthy',
                                reqPerSec: 38,
                                p99LatencyMs: 280,
                                fairnessRatio: 1.0,
                        },
                ],
        },
];
