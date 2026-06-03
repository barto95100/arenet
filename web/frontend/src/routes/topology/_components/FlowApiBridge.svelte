<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  FlowApiBridge — calls useSvelteFlow() from inside a <SvelteFlow>
  subtree and bubbles the API up to the parent page via a callback.

  Why this exists: useSvelteFlow() must be invoked from a component
  that is a *descendant* of <SvelteFlow>, because the Svelte context
  it reads is established by <SvelteFlow>'s setup phase. The parent
  page that mounts <SvelteFlow> cannot call useSvelteFlow() in its
  own <script> — the context is empty there. So we render this
  tiny child inside <SvelteFlow> purely to pluck the flow API out
  and pass it back upward.

  No DOM output — just a side-effect on mount.
-->
<script lang="ts">
        import { onMount } from 'svelte';
        import { useSvelteFlow, type Node, type Edge } from '@xyflow/svelte';

        type FlowApi = ReturnType<typeof useSvelteFlow<Node, Edge>>;

        let props: { onReady: (api: FlowApi) => void } = $props();

        // useSvelteFlow() reads from Svelte context — must run during
        // component init, not in a tick callback. The cast widens the
        // generic so the parent page can call updateNodeData/updateEdge
        // without re-stating the topology Node/Edge types here.
        const flow = useSvelteFlow();

        // Defer to onMount so we read the latest prop value rather
        // than the init snapshot — Svelte 5 warns about reading a
        // prop directly during script init (state_referenced_locally)
        // because the prop is reactive and the read won't be tracked
        // here. onMount runs after the parent has finished its setup,
        // and we only ever fire the callback once.
        onMount(() => {
                props.onReady(flow as unknown as FlowApi);
        });
</script>
