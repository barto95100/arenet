<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Phase 3.e HOTFIX harness component (2026-06-17). Mirrors the
  page-level $effect contract from +page.svelte exactly so an
  effect_update_depth_exceeded loop is reproduced at vitest time
  rather than at operator-eyeball time.

  Shape :
    - Subscribes to collapsedRoutes.collapsed (the tracked trigger).
    - Calls a rebuildLike() function INSIDE untrack() that both
      READS and WRITES local $state.raw nodes (mirrors the real
      rebuildGraph's $state read+write pattern that caused the
      original loop).
    - Records the effect run count in a $state. The test reads
      this count after toggling the store and asserts it doesn't
      exceed a small bound (loop would push it past Svelte's
      effect-depth ceiling, which fires the runtime error).

  If a future change removes the untrack() wrapper in +page.svelte
  (or duplicates the pattern elsewhere without untrack), this
  harness reproduces the loop and the corresponding test fails.
-->
<script lang="ts">
        import { untrack } from 'svelte';
        import { collapsedRoutes } from './_collapsed.svelte';

        // Mirror of +page.svelte's nodes / edges : $state.raw arrays
        // that the effect both reads (for the diff path) and writes
        // (for the first-build path). The dual access through the
        // SAME $state is what creates the loop opportunity.
        let nodes = $state.raw<string[]>([]);
        // Non-reactive run counter — a $state counter would itself
        // be a read+write inside the effect (write of runCount =>
        // re-fire because we also read it implicitly via the +=
        // operator), which trips Svelte's depth guard for an
        // unrelated reason. Plain `let` keeps the bookkeeping
        // outside the reactive graph so we measure only the loop we
        // care about.
        let runCount = 0;

        function rebuildLike(): void {
                // READ then WRITE the same $state — same shape as
                // rebuildGraph's nodes.length === 0 check followed
                // by nodes = graph.nodes assignment.
                if (nodes.length === 0) {
                        nodes = ['n1', 'n2'];
                        return;
                }
                // Steady state : keep rewriting so we stress the
                // re-run path. Without untrack the effect would
                // re-fire on every write.
                nodes = [...nodes];
        }

        $effect(() => {
                // Tracked dep — the trigger.
                void collapsedRoutes.collapsed;
                runCount += 1;
                // The fix : untrack the body so nodes' reads/writes
                // don't enter the effect's reactive graph.
                untrack(() => {
                        rebuildLike();
                });
        });

        // Export the run counter so the test can assert.
        export function getRunCount(): number {
                return runCount;
        }
        export function getNodes(): string[] {
                return nodes;
        }
</script>
