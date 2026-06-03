<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  TopologySidebar — right-side companion to the topology canvas.

  Three stacked panels matching the mock:
   1. Légende des flux  — visual key tying each FlowTier to its
      particle styling (count/glow/color). Reads the same tier
      thresholds as the canvas so they never drift apart.
   2. Top flux           — live list of routes sorted by req/s desc,
      with a per-row tier-colored progress bar relative to the
      busiest route. Surfaces warn/bad badges (p99 spike, 5xx %).
   3. Actions rapides   — quick operator actions. Buttons are
      cosmetic placeholders for Phase 1; wiring lands in Phase 2.
-->
<script lang="ts">
        import type { TopologyRoute, FlowTier } from '../_types';
        import { resolveFlowTier } from '../_types';

        let { routes }: { routes: TopologyRoute[] } = $props();

        // Sort by req/s desc so the busiest route is on top.
        let sortedRoutes = $derived([...routes].sort((a, b) => b.reqPerSec - a.reqPerSec));

        // Tier for each route's aggregate flow — reuses the canvas resolver.
        function routeTier(r: TopologyRoute): FlowTier {
                return resolveFlowTier({
                        kind: 'flow',
                        reqPerSec: r.reqPerSec,
                        p99LatencyMs: r.p99LatencyMs,
                        errorRate5xx: r.errorRate5xx,
                });
        }

        function formatRate(rps: number): string {
                if (rps >= 1000) return `${(rps / 1000).toFixed(1)}k r/s`;
                return `${Math.round(rps)} r/s`;
        }

        // "→ {cluster} · {ip}" subtitle of each top-flux row.
        function firstUpstreamLabel(r: TopologyRoute): string {
                if (r.upstreams.length === 0) return '(no upstream)';
                const cluster = r.clusterLabel ?? r.host.split('.')[0];
                return `${cluster} · ${r.upstreams[0].url}`;
        }

        // Optional inline badge surfaced next to the upstream label
        // when something operationally interesting needs flagging.
        function topfluxBadge(r: TopologyRoute): string | null {
                if (r.errorRate5xx > 0) return `5xx ${r.errorRate5xx}%`;
                if (r.p99LatencyMs > 300) return `p99 ${r.p99LatencyMs} ms`;
                return null;
        }

        // Progress bar widths are relative to the busiest route in
        // the list — preserves the visual ranking when absolute rps
        // values cover a wide range.
        let maxRps = $derived(Math.max(1, ...sortedRoutes.map((r) => r.reqPerSec)));

        // Each tier's "dots" preview in the legend. Inline 4-circle
        // SVG so the per-tier color + glow filter can apply via CSS.
        const LEGEND_ROWS: { tier: FlowTier; label: string }[] = [
                { tier: 'high', label: '≥ 400 req/s — flux principal' },
                { tier: 'mid', label: '150 – 400 req/s' },
                { tier: 'low', label: '20 – 150 req/s' },
                { tier: 'idle', label: '< 20 req/s — quasi-inactif' },
                { tier: 'warn', label: 'latence élevée (p99 > 300 ms)' },
                { tier: 'bad', label: 'erreurs upstream (5xx ou timeout)' },
        ];
</script>

<aside class="topo-sidebar" aria-label="Panneau latéral topology">
        <!-- =========================================================
             Panel 1 — Légende des flux
        ========================================================= -->
        <section class="panel">
                <h3>Légende des flux</h3>
                <ul class="legend-list">
                        {#each LEGEND_ROWS as row (row.tier)}
                                <li>
                                        <svg
                                                class="dots tier-{row.tier}"
                                                viewBox="0 0 56 8"
                                                width="56"
                                                height="8"
                                                aria-hidden="true"
                                        >
                                                <circle cx="4" cy="4" r="2" fill="currentColor" />
                                                <circle cx="18" cy="4" r="2" fill="currentColor" />
                                                <circle cx="32" cy="4" r="2" fill="currentColor" />
                                                <circle cx="46" cy="4" r="2" fill="currentColor" />
                                        </svg>
                                        <span class="legend-label">{row.label}</span>
                                </li>
                        {/each}
                </ul>
                <p class="legend-note">
                        L'épaisseur est calculée sur la moyenne glissante des 60 dernières
                        secondes. L'animation pointe dans le sens du trafic dominant —
                        requêtes entrantes vers les services.
                </p>
        </section>

        <!-- =========================================================
             Panel 2 — Top flux (live list)
        ========================================================= -->
        <section class="panel">
                <header class="panel-head">
                        <h3>Top flux</h3>
                        <span class="live-pill">live</span>
                </header>
                <ul class="topflux-list">
                        {#each sortedRoutes as route (route.id)}
                                {@const tier = routeTier(route)}
                                {@const badge = topfluxBadge(route)}
                                <li class="topflux-row" data-tier={tier}>
                                        <div class="topflux-line-1">
                                                <span class="host">{route.host}</span>
                                                <span class="rps">{formatRate(route.reqPerSec)}</span>
                                        </div>
                                        <div class="topflux-line-2">
                                                <span class="up-label">→ {firstUpstreamLabel(route)}</span>
                                                {#if badge}
                                                        <span class="badge">{badge}</span>
                                                {/if}
                                        </div>
                                        <div class="topflux-bar" aria-hidden="true">
                                                <div
                                                        class="topflux-bar-fill"
                                                        style:width="{(route.reqPerSec / maxRps) * 100}%"
                                                ></div>
                                        </div>
                                </li>
                        {/each}
                </ul>
        </section>

        <!-- =========================================================
             Panel 3 — Actions rapides
        ========================================================= -->
        <section class="panel">
                <h3>Actions rapides</h3>
                <ul class="actions-list">
                        <li><button type="button" class="action-btn">Drainer un upstream…</button></li>
                        <li><button type="button" class="action-btn">Recharger la config Caddy</button></li>
                        <li><button type="button" class="action-btn">Snapshot topology (JSON)</button></li>
                </ul>
        </section>
</aside>

<style>
        .topo-sidebar {
                flex: 0 0 280px;
                display: flex;
                flex-direction: column;
                gap: 14px;
                overflow-y: auto;
                min-height: 0;
                padding-right: 2px;
        }

        .panel {
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                padding: 14px 14px 12px 14px;
        }

        .panel h3 {
                font-size: 13px;
                font-weight: 600;
                margin: 0 0 12px 0;
                color: var(--fg, oklch(96% 0.005 250));
        }

        .panel-head {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
        }

        .panel-head h3 {
                margin: 0;
        }

        .live-pill {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10px;
                padding: 2px 6px;
                border-radius: 4px;
                background: var(--accent-soft, oklch(68% 0.21 255 / 0.14));
                color: var(--accent, oklch(68% 0.21 255));
                text-transform: uppercase;
                letter-spacing: 0.05em;
        }

        /* ---------- Legend ---------- */
        .legend-list {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                gap: 6px;
        }

        .legend-list li {
                display: flex;
                align-items: center;
                gap: 10px;
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .dots {
                flex: 0 0 auto;
        }

        .tier-idle {
                color: oklch(60% 0.01 250);
                opacity: 0.55;
        }

        .tier-low {
                color: var(--accent, oklch(68% 0.21 255));
                opacity: 0.6;
        }

        .tier-mid {
                color: var(--accent, oklch(68% 0.21 255));
                opacity: 0.85;
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .tier-high {
                color: var(--accent, oklch(68% 0.21 255));
                filter: drop-shadow(0 0 2px currentColor);
        }

        .tier-warn {
                color: var(--warn, oklch(80% 0.14 85));
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .tier-bad {
                color: var(--bad, oklch(66% 0.20 25));
                filter: drop-shadow(0 0 1.5px currentColor);
        }

        .legend-label {
                line-height: 1.4;
        }

        .legend-note {
                font-size: 11px;
                line-height: 1.55;
                color: var(--fg-dim, oklch(54% 0.011 250));
                margin: 12px 0 0 0;
                padding-top: 10px;
                border-top: 1px solid var(--border, oklch(28% 0.009 250));
        }

        /* ---------- Top flux ---------- */
        .topflux-list {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
        }

        .topflux-row {
                padding: 9px 0;
                border-bottom: 1px solid var(--border, oklch(28% 0.009 250));
        }

        .topflux-row:last-child {
                border-bottom: none;
                padding-bottom: 0;
        }

        .topflux-row:first-child {
                padding-top: 0;
        }

        .topflux-line-1 {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                margin-bottom: 3px;
        }

        .topflux-line-1 .host {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11.5px;
                font-weight: 500;
                color: var(--fg, oklch(96% 0.005 250));
        }

        .topflux-line-1 .rps {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 11px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                white-space: nowrap;
        }

        .topflux-line-2 {
                display: flex;
                justify-content: space-between;
                align-items: baseline;
                gap: 8px;
                margin-bottom: 6px;
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
        }

        .topflux-line-2 .up-label {
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .topflux-line-2 .badge {
                flex: 0 0 auto;
                color: var(--warn, oklch(80% 0.14 85));
        }

        .topflux-row[data-tier='bad'] .topflux-line-2 .badge {
                color: var(--bad, oklch(66% 0.20 25));
        }

        .topflux-bar {
                width: 100%;
                height: 3px;
                background: var(--border, oklch(28% 0.009 250));
                border-radius: 2px;
                overflow: hidden;
        }

        .topflux-bar-fill {
                height: 100%;
                background: var(--accent, oklch(68% 0.21 255));
                border-radius: 2px;
                transition: width 0.4s ease;
        }

        .topflux-row[data-tier='warn'] .topflux-bar-fill {
                background: var(--warn, oklch(80% 0.14 85));
        }

        .topflux-row[data-tier='bad'] .topflux-bar-fill {
                background: var(--bad, oklch(66% 0.20 25));
        }

        /* ---------- Actions ---------- */
        .actions-list {
                list-style: none;
                margin: 0;
                padding: 0;
                display: flex;
                flex-direction: column;
                gap: 6px;
        }

        .action-btn {
                width: 100%;
                padding: 8px 10px;
                background: var(--surface-2, oklch(22% 0.007 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 6px;
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                text-align: left;
                cursor: pointer;
                font-family: inherit;
                transition: background 0.15s ease, border-color 0.15s ease;
        }

        .action-btn:hover {
                background: var(--surface-hi, oklch(26% 0.008 250));
                border-color: var(--border-hi, oklch(34% 0.011 250));
        }
</style>
