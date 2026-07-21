<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Sujet 2 (2026-06-17) — operator-facing badge that surfaces the
  parsed Route.effectiveCertSource shape, including the covering
  apex when the route is served by a managed-domain wildcard.

  Pre-Sujet-2 the routes list (src/routes/routes/+page.svelte:1623)
  rendered a generic "wildcard" badge with the apex hidden in the
  title attribute. Operators with multiple managed domains could
  not tell at a glance WHICH wildcard covered a route. This
  component closes the gap by surfacing the apex directly on the
  badge label ("Couvert par *.example.com") and keeping a longer
  RFC-6125 tooltip for the explainability the title attribute
  already carried.

  Used in :
    - routes list table (col TLS) — primary surface.

  Backward-compat : when effectiveCertSource is undefined / empty
  (no TLS, pre-O routes) the badge renders nothing, same as the
  legacy inline check.
-->
<script lang="ts">
        import Badge from './Badge.svelte';
        import {
                parseEffectiveCertSource,
                certSourceLabel,
                certSourceTooltip,
                type ParsedCertSource,
        } from '$lib/utils/effective-cert-source';

        interface Props {
                /** Raw wire string from Route.effectiveCertSource. */
                source: string | undefined | null;
                /**
                 * Display name for a manual cert (kind "manual"), resolved by
                 * the caller from route.cert_id — the cert's name, or
                 * "*.<apex>" for a wildcard. Ignored for every other kind.
                 * The backend's effectiveCertSource string carries no name,
                 * so it must be injected here.
                 */
                certName?: string;
        }

        let { source, certName }: Props = $props();

        let parsed: ParsedCertSource = $derived.by(() => {
                const p = parseEffectiveCertSource(source);
                return p.kind === 'manual' ? { ...p, certName } : p;
        });
        let label = $derived(certSourceLabel(parsed));
        let tooltip = $derived(certSourceTooltip(parsed));

        // Variant policy mirrors the route table's pre-Sujet-2
        // colour assignments :
        //   - managed-domain → "current" (accent — this is the
        //     "live, inherited" state, same visual weight as the
        //     existing wildcard badge).
        //   - per-route-acme → "neutral" (low-key — operator-
        //     declared specifics don't need a colour).
        //   - per-route-internal → "neutral" with the "internal"
        //     wording carrying the meaning.
        let variant = $derived.by(() => {
                switch (parsed.kind) {
                        case 'managed-domain':
                                return 'current' as const;
                        default:
                                return 'neutral' as const;
                }
        });
</script>

{#if parsed.kind !== 'none'}
        <span title={tooltip} data-cert-kind={parsed.kind}>
                <Badge {variant}>{label}</Badge>
        </span>
{/if}
