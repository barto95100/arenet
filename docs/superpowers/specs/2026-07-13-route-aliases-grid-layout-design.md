# Route Aliases — Auto-fit Grid Layout — Design

**Date:** 2026-07-13
**Status:** Approved (design validated by operator)

## Goal

In the route create/edit form, the alias hostname inputs currently stack
vertically (one full-width row per alias). With several aliases this pushes
the rest of the form down, forcing the operator to scroll to reach the
remaining fields. Lay the alias inputs out in a **responsive auto-fit
grid** so multiple aliases sit side by side, wrapping to the available
width — cutting the vertical space they consume.

## Non-Goals (YAGNI)

- No change to the alias data model, `bind:value`, `addAlias`/`removeAlias`
  logic, wildcard validation, or i18n.
- No change to the shared `Input` component.
- Not switching to a tags/chips input (a heavier interaction rework the
  operator explicitly did not choose).

## Current state

`web/frontend/src/routes/routes/+page.svelte`, the alias repeater (~lines
2336-2348):

```svelte
<!-- Step I.3: alias hostnames repeater. -->
<div class="flex flex-col gap-2">
  <div class="flex items-center justify-between">
    <span class="text-sm text-secondary">{...aliasesLabel}</span>
    <Button variant="ghost" size="sm" onclick={addAlias} ...>{...aliasesAdd}</Button>
  </div>
  {#each formData.aliases as _, i (i)}
    <div class="flex items-center gap-2">
      <Input bind:value={formData.aliases[i]} placeholder={...} />
      <Button variant="ghost" size="sm" onclick={() => removeAlias(i)} ...>×</Button>
    </div>
  {/each}
</div>
```

The outer `flex flex-col gap-2` stacks each `[Input ×]` row vertically.

## Design

Wrap the `{#each}` rows in a **responsive auto-fit grid** instead of
stacking them. The header row (label + "Add" button) stays full-width above
the grid, unchanged.

```svelte
<div class="flex flex-col gap-2">
  <div class="flex items-center justify-between">
    <span class="text-sm text-secondary">{...aliasesLabel}</span>
    <Button variant="ghost" size="sm" onclick={addAlias} ...>{...aliasesAdd}</Button>
  </div>
  <div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2" data-testid="alias-grid">
    {#each formData.aliases as _, i (i)}
      <div class="flex items-center gap-2">
        <div class="flex-1">
          <Input bind:value={formData.aliases[i]} placeholder={...} />
        </div>
        <Button variant="ghost" size="sm" onclick={() => removeAlias(i)} ...>×</Button>
      </div>
    {/each}
  </div>
</div>
```

Behavior:
- `grid-cols-[repeat(auto-fit,minmax(200px,1fr))]` — each alias cell is at
  least 200px wide; the grid packs as many columns as the form width
  allows (≈2 on a narrow modal, 3-4 on a wide viewport) and wraps
  automatically. This is a Tailwind arbitrary value; the codebase already
  uses responsive grids (e.g. `grid gap-3 sm:grid-cols-2` at ~line 3039),
  so this stays consistent with existing patterns.
- The `Input` is wrapped in a `<div class="flex-1">` so it fills the width
  left of the `×` button. See the component-boundary note below for why the
  wrapper (not a `class` prop on `Input`) is used.
- `data-testid="alias-grid"` — anchor for the regression guard test.

Rationale for auto-fit over fixed columns: the operator chose "as many as
fit" for density; `minmax(200px, …)` keeps hostnames readable while
adapting to whatever width the modal/viewport gives.

## Component boundary check (resolved)

`lib/components/Input.svelte` **`Omit`s `'class'`** from its `Props`
(`Omit<HTMLInputAttributes, 'class' | 'value'>`) and never applies a
caller-supplied class — so passing `class="flex-1"` to `<Input>` would not
work (and is type-rejected). Therefore the alias input is wrapped in an
outer `<div class="flex-1">`, as shown above. **Do not modify `Input`.**

One detail to verify at implementation time: `Input`'s root is a
`flex flex-col` wrapper and its `<input>` has no explicit `w-full`. Inside
the `flex-1` cell the wrapper should stretch, and the `<input>` fills it
via the flex-column default (`align-items: stretch`). Confirm the input
visually spans its cell during runtime verification; if a stray narrow
input appears, the minimal fix is adding `w-full` to the wrapper `<div>`
around `Input` — still no change to the shared `Input` component.

## Testing

`web/frontend/src/routes/routes/page.test.ts` (existing):
- **Regression guard:** render the form, add ≥2 aliases via the "Add"
  control, assert the alias container has the auto-fit grid class (query by
  `data-testid="alias-grid"`, assert its `class` contains
  `grid-cols-[repeat(auto-fit,minmax(200px,1fr))]`). This fails if someone
  reverts the grid to a vertical stack.
- **Behavior unchanged:** assert add appends an empty input and remove
  drops the right one (if not already covered by existing tests — reuse
  existing coverage where present rather than duplicating).

## Verification (runtime)

Build the frontend + binary, open the route create form, add 3-4 aliases,
and confirm at two viewport widths:
- Wide: aliases sit 3-4 per row, wrapping; the fields below the alias block
  are visible without scrolling (for a small alias count).
- Narrow (modal / small window): aliases collapse to ~2 or 1 per row,
  still readable, `×` buttons aligned.

## Files summary

| Action | File |
| --- | --- |
| Modify | `web/frontend/src/routes/routes/+page.svelte` (alias repeater container → auto-fit grid, `data-testid`, `Input` fills cell) |
| Modify | `web/frontend/src/routes/routes/page.test.ts` (grid-class regression guard) |

## Global constraints (from CLAUDE.md)

- TypeScript strict; no CSS framework beyond Tailwind; interactive elements
  keep their ARIA/labels; user-facing text via `t()` (unchanged here).
- AGPL header already present on both touched files (no new files).
