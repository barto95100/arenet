<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  ViewToggle — segmented control to switch between the two topology
  views. Stateless; the parent owns the current value and reacts to
  onChange to rebuild the graph.
-->
<script lang="ts">
        import type { TopologyViewMode } from '../_types';

        let {
                value,
                onChange,
        }: {
                value: TopologyViewMode;
                onChange: (v: TopologyViewMode) => void;
        } = $props();
</script>

<div class="view-toggle" role="tablist" aria-label="Sélection de la vue topology">
        <button
                role="tab"
                aria-selected={value === 'protocol'}
                class="seg"
                data-active={value === 'protocol'}
                onclick={() => onChange('protocol')}
                type="button"
        >
                Vue protocole
        </button>
        <button
                role="tab"
                aria-selected={value === 'service-to-backend'}
                class="seg"
                data-active={value === 'service-to-backend'}
                onclick={() => onChange('service-to-backend')}
                type="button"
        >
                Vue service → backend
        </button>
</div>

<style>
        .view-toggle {
                display: inline-flex;
                background: var(--surface, oklch(19% 0.006 250));
                border: 1px solid var(--border, oklch(28% 0.009 250));
                border-radius: 6px;
                padding: 2px;
                gap: 2px;
        }

        .seg {
                background: transparent;
                border: none;
                padding: 6px 14px;
                font-size: 12px;
                font-weight: 500;
                color: var(--fg-muted, oklch(68% 0.012 250));
                cursor: pointer;
                border-radius: 4px;
                font-family: inherit;
                transition: background 0.15s ease, color 0.15s ease;
        }

        .seg:hover {
                color: var(--fg, oklch(96% 0.005 250));
        }

        .seg[data-active='true'] {
                background: var(--surface-hi, oklch(26% 0.008 250));
                color: var(--fg, oklch(96% 0.005 250));
        }

        .seg:focus-visible {
                outline: 2px solid var(--accent, oklch(68% 0.21 255));
                outline-offset: 1px;
        }
</style>
