<!--
  FQDNNode — Col 1 of the Service→Backend view.

  Represents a primary host (api.arenet.fr, app.arenet.fr…) fed by
  upstream consumers and forwarding to Caddy. Declares both handles
  so edges can attach on the right protocol.

  C16 (2026-06-03): WAF indicator. Route-level attribute carried
  via data.wafLevel. Off → no glyph. Detect → Lucide Shield (muted
  gray). Block → Lucide ShieldCheck (accent blue). Coherent with
  the UpstreamNode icon language: Activity = HC monitored,
  Lock = upstream TLS, Shield = WAF.

  C17 (2026-06-04): aliases tooltip. When the route has aliases,
  the meta line (e.g. "2 hosts") gets a `title` listing the full
  hostnames — primary first, then aliases. Operator can hover to
  see the real names without expanding the node. The "h2 · h3"
  protocol suffix was dropped from the protocols line in _layout.ts
  because the backend doesn't expose real ALPN data yet (see
  #R-TOPO-alpn).
-->
<script lang="ts">
        import { Handle, Position, type NodeProps } from '@xyflow/svelte';
        import type { FQDNNodeData } from '../../_types';

        let { data }: NodeProps & { data: FQDNNodeData } = $props();

        // Hosts tooltip — primary host first, then aliases, comma-
        // separated. Empty string when the route has no aliases (the
        // count alone is already "1 host"; the hostname is right
        // above, no need to repeat it in a tooltip).
        let hostsTooltip = $derived.by(() => {
                if (!data.aliases || data.aliases.length === 0) return '';
                return [data.host, ...data.aliases].join(', ');
        });
</script>

<div class="fqdn-node">
        <Handle type="target" position={Position.Left} />

        <div class="host-row">
                <span class="host">{data.host}</span>
                {#if data.wafLevel === 'detect'}
                        <svg
                                class="ico ico-waf ico-waf-detect"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                aria-label="WAF · Mode détection"
                        >
                                <title>WAF · Mode détection</title>
                                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                        </svg>
                {:else if data.wafLevel === 'block'}
                        <svg
                                class="ico ico-waf ico-waf-block"
                                viewBox="0 0 24 24"
                                fill="none"
                                stroke="currentColor"
                                stroke-width="2"
                                stroke-linecap="round"
                                stroke-linejoin="round"
                                aria-label="WAF · Mode blocage"
                        >
                                <title>WAF · Mode blocage</title>
                                <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                                <path d="m9 12 2 2 4-4" />
                        </svg>
                {/if}
        </div>
        <div class="protocols">{data.protocols}</div>
        <div class="meta" title={hostsTooltip}>{data.meta}</div>

        <Handle type="source" position={Position.Right} />
</div>

<style>
        .fqdn-node {
                width: 200px;
                padding: 10px 12px;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 8px;
                font-family: var(--font-display, system-ui, sans-serif);
                color: var(--fg, oklch(96% 0.005 250));
                font-size: 12px;
                box-shadow: 0 1px 0 rgb(0 0 0 / 0.4);
        }

        .host-row {
                display: flex;
                align-items: center;
                gap: 6px;
                margin-bottom: 3px;
        }

        .host {
                flex: 1 1 auto;
                font-size: 13px;
                font-weight: 600;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
        }

        .ico {
                flex: 0 0 auto;
                width: 14px;
                height: 14px;
        }

        /* Detect = muted gray, block = accent blue. Same hue family as
           the UpstreamNode icons so the security indicators read as one
           visual language. */
        .ico-waf-detect {
                color: var(--fg-muted, oklch(68% 0.012 250));
        }
        .ico-waf-block {
                color: var(--accent, oklch(68% 0.21 255));
        }

        .protocols {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-muted, oklch(68% 0.012 250));
                margin-bottom: 4px;
        }

        .meta {
                font-family: var(--font-mono, ui-monospace, monospace);
                font-size: 10.5px;
                color: var(--fg-dim, oklch(54% 0.011 250));
        }

        :global(.svelte-flow__node-fqdn) {
                padding: 0;
                background: transparent;
                border: none;
                box-shadow: none;
                color: inherit;
        }
</style>
