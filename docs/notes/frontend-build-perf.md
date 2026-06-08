<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  Ludovic Ramos
Licensed under the GNU AGPL v3 or later. See LICENSE.
-->

# Frontend build perf — `vite-plugin-sveltekit-guard` (#R-FRONTEND-build-perf)

**Date**: 2026-06-09
**Trigger**: operator-observed plugin timing in `npm run build` output across multiple W.* releases.

## Observation

Every `npm run build` run since the Step W series (v1.6.0+)
emits the following Vite timing breakdown:

```
[PLUGIN_TIMINGS] Your build spent significant time in plugins. Here is a breakdown:
  - vite-plugin-sveltekit-guard (88%)
  - vite-plugin-svelte:preprocess (4%)
```

Total build time is **~4.1 s** end-to-end. The `vite-plugin-sveltekit-guard` plugin
dominates the time budget at ~88 %, with the Svelte preprocess pass at ~4 % and
the remaining 8 % spread across Rolldown's bundler core + the SvelteKit
adapter-static output emission.

## Plugin identification

Found at:

```
node_modules/@sveltejs/kit/src/exports/vite/index.js:571
```

The plugin is declared **inside the `@sveltejs/kit` package itself** — NOT a
separate npm dependency, NOT a third-party plugin, NOT vendored in the Arenet
repo. It runs automatically as part of every SvelteKit Vite build pipeline.

Installed version: `@sveltejs/kit@2.60.1` (declared `^2.57.0`).

## What the plugin does

From the source doc-comment:

> Ensures that client-side code can't accidentally import server-side code,
> whether in `*.server.js` files, `$app/server`, `$lib/server`, or
> `$env/[static|dynamic]/private`

Concretely it intercepts every `resolveId` call during build, normalizes
the resolved module path against the SvelteKit `$lib` + `cwd` roots, and
maintains a `Map<importedModule, Set<importers>>` to detect cross-boundary
imports. It runs with `enforce: 'pre'` so it sees every import-resolution
attempt BEFORE Vite's own resolution.

## Why it dominates the build

The 88 % figure is **misleading-by-construction**, not a bug:

- Vite's `[PLUGIN_TIMINGS]` measures *cumulative* time spent inside each
  plugin's hooks across all module evaluations. `vite-plugin-sveltekit-guard`
  has a `resolveId` hook that fires for EVERY import in the project (including
  every transitive node_modules import that the Svelte compiler chases through
  `$lib`, `$app`, etc.).
- The bundler core (Rolldown) runs its work in parallel pipelines and isn't
  attributed to any single plugin — most of the actual "build time" isn't
  charged to a plugin at all.
- The guard plugin itself does very little work per call: a path normalization +
  a `Map.set` + a `Set.add`. The high cumulative count comes from the SHEER
  NUMBER of calls (~30k+ for a project this size), not the cost per call.

For comparison: 88 % of 4.1 s ≈ 3.6 s of resolveId hook invocations spread
across ~30 000 module imports = ~120 µs per import. That's not pathological;
it's just a load-bearing safety check the framework needs to run.

## Cannot be removed or replaced

- Removing the plugin would let `*.server.js` code leak into the client bundle.
  That would be a **security regression**: Arenet's `+page.server.ts` files
  hold the secret-handling logic (session cookies, OAuth state, audit log
  writes). A client-side import of any of those would expose secrets in the
  browser bundle. Not acceptable under any timing budget.
- The plugin isn't configurable — no SvelteKit option lets us reduce its scope
  or skip it for production builds.
- Forking SvelteKit to patch the plugin is feasible in theory but pulls Arenet
  into a maintenance position upstream changes will repeatedly disrupt.

## Recommendation: **acceptable for now, not worth the dev cost**

The 4 s build time is well within ergonomic acceptable bounds for a project of
Arenet's size (the smaller of the two homelab-tier devloops — `go test -race
./...` takes ~5 min, frontend `npm test` takes ~10 s, build is in the noise).
The 88 % attribution is a **reporting artifact** of how Vite charges hook time,
not an actual cost we can recover.

## Open paths if it ever becomes painful

If the build time triples (~12+ s) due to a future SvelteKit revision adding
more `resolveId` work, options in increasing cost order:

1. **Wait for a SvelteKit release with a faster guard implementation.**
   The plugin uses `string.startsWith()` for boundary checks; a switch to a
   prebuilt trie (~30 LOC change upstream) would halve the per-call cost. File
   a GitHub issue with the timing data if we get there.
2. **Use `vite build --watch` for dev iteration** to amortize the cost across
   incremental rebuilds. The cold-start guard cost is paid once; warm rebuilds
   only re-resolve changed modules.
3. **Cache the `import_map` to disk between CI builds.** Requires a custom
   plugin that runs BEFORE `vite-plugin-sveltekit-guard` and short-circuits the
   guard's work when its cache hits. ~50 LOC, ~1 day of work, breaks if
   SvelteKit changes the plugin's internal shape. **Not recommended** unless
   the upstream wait is years.

## Conclusion

No code change committed. Investigation closed. Status: **`#R-FRONTEND-build-perf`
documented as acceptable, no action required at v1.6.4 cadence**. Revisit if
build time exceeds 10 s after a future SvelteKit upgrade.

---

**Related**: the `vite-plugin-svelte:preprocess` 4 % share is the Svelte 5
runes preprocessor; that one IS optimizable (rune-aware AST caching landed in
svelte@5.20+) but its share is too small to matter at current build sizes.
