# Route Aliases Auto-fit Grid — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay the route form's alias inputs out in a responsive auto-fit grid so they sit side by side and wrap to the available width, instead of stacking vertically and pushing the rest of the form down.

**Architecture:** A single layout change in the route form's alias repeater — wrap the `{#each}` rows in a `grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))]` container, and wrap each `Input` in a `flex-1` div (the shared `Input` component ignores a `class` prop, so it is left untouched). Plus a regression-guard test.

**Tech Stack:** SvelteKit / Svelte 5 runes, Tailwind (arbitrary grid value), vitest + @testing-library/svelte + @testing-library/user-event.

**Spec:** `docs/superpowers/specs/2026-07-13-route-aliases-grid-layout-design.md`

## Global Constraints

- Tailwind only (no other CSS framework); the arbitrary value `grid-cols-[repeat(auto-fit,minmax(200px,1fr))]` is allowed and consistent with existing responsive grids in the file.
- Do NOT modify `lib/components/Input.svelte` (it `Omit`s `class` from its props — pass layout via an outer wrapper `<div>` instead).
- Do NOT change alias data/state (`formData.aliases`, `addAlias`, `removeAlias`), wildcard validation, or i18n.
- AGPL headers already present on both touched files (no new files).
- Run frontend tests with: `cd web/frontend && npm run test -- <path>` (vitest). Typecheck: `npm run check`.

---

### Task 1: Alias repeater → auto-fit grid + regression guard

**Files:**
- Modify: `web/frontend/src/routes/routes/+page.svelte` (alias repeater, ~lines 2336-2348)
- Modify: `web/frontend/src/routes/routes/page.test.ts` (add grid-class guard test)

**Interfaces:**
- Consumes: existing `formData.aliases`, `addAlias()`, `removeAlias(i)`, the `Input`/`Button` components, and the i18n keys `routes.form.aliasesLabel` / `aliasesAdd` / `aliasesPlaceholder` — all unchanged.
- Produces: the alias rows rendered inside a container with `data-testid="alias-grid"` carrying the auto-fit grid class.

- [ ] **Step 1: Write the failing test**

In `web/frontend/src/routes/routes/page.test.ts`, add a new `describe` block near the other repeater suites. It opens the create form, adds two aliases, and asserts the alias container is an auto-fit grid (not a vertical stack). Uses the existing `render(Page)` + `openCreateForm()` + `userEvent` helpers already in the file.

```ts
describe('Routes page — aliases layout', () => {
	it('lays alias inputs out in an auto-fit grid (not a vertical stack)', async () => {
		render(Page);
		await openCreateForm();
		const addAlias = screen.getByRole('button', { name: /\+\s*Add alias/i });
		await userEvent.click(addAlias);
		await userEvent.click(addAlias);
		await tick();
		// two alias inputs now present (by their placeholder)
		expect(screen.getAllByPlaceholderText('alt.example.com')).toHaveLength(2);
		// and they live inside the auto-fit grid container
		const grid = screen.getByTestId('alias-grid');
		expect(grid.className).toContain('grid-cols-[repeat(auto-fit,minmax(200px,1fr))]');
	});
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd web/frontend && npm run test -- src/routes/routes/page.test.ts -t "auto-fit grid"`
Expected: FAIL — `getByTestId('alias-grid')` throws "Unable to find an element by: [data-testid="alias-grid"]" (the container doesn't exist yet). This confirms the test targets the new markup.

- [ ] **Step 3: Apply the layout change**

In `web/frontend/src/routes/routes/+page.svelte`, replace the alias repeater block (currently, ~lines 2336-2348):

```svelte
					<!-- Step I.3: alias hostnames repeater. -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<span class="text-sm text-secondary">{language.current && t('routes.form.aliasesLabel')}</span>
							<Button variant="ghost" size="sm" onclick={addAlias} type="button">{language.current && t('routes.form.aliasesAdd')}</Button>
						</div>
						{#each formData.aliases as _, i (i)}
							<div class="flex items-center gap-2">
								<Input bind:value={formData.aliases[i]} placeholder={language.current && t('routes.form.aliasesPlaceholder')} />
								<Button variant="ghost" size="sm" onclick={() => removeAlias(i)} type="button">×</Button>
							</div>
						{/each}
					</div>
```

with the grid version (header row unchanged; the `{#each}` rows move into a grid container, and each `Input` gets a `flex-1` wrapper div):

```svelte
					<!-- Step I.3: alias hostnames repeater. Auto-fit grid so
					     multiple aliases sit side by side and wrap to width
					     instead of stacking and pushing the form down. -->
					<div class="flex flex-col gap-2">
						<div class="flex items-center justify-between">
							<span class="text-sm text-secondary">{language.current && t('routes.form.aliasesLabel')}</span>
							<Button variant="ghost" size="sm" onclick={addAlias} type="button">{language.current && t('routes.form.aliasesAdd')}</Button>
						</div>
						<div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2" data-testid="alias-grid">
							{#each formData.aliases as _, i (i)}
								<div class="flex items-center gap-2">
									<div class="flex-1">
										<Input bind:value={formData.aliases[i]} placeholder={language.current && t('routes.form.aliasesPlaceholder')} />
									</div>
									<Button variant="ghost" size="sm" onclick={() => removeAlias(i)} type="button">×</Button>
								</div>
							{/each}
						</div>
					</div>
```

Do NOT touch `addAlias`, `removeAlias`, `formData.aliases`, or the `Input` component.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd web/frontend && npm run test -- src/routes/routes/page.test.ts -t "auto-fit grid"`
Expected: PASS. Then run the whole file to confirm no regression in the existing alias/upstream/validation tests: `cd web/frontend && npm run test -- src/routes/routes/page.test.ts` → all pass.

- [ ] **Step 5: Typecheck**

Run: `cd web/frontend && npm run check`
Expected: 0 errors (the change adds only markup + a wrapper div; no type surface changes).

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/routes/routes/+page.svelte web/frontend/src/routes/routes/page.test.ts
git commit -m "feat(routes): lay alias inputs out in an auto-fit grid

Alias inputs stacked vertically (one full-width row each), pushing the
rest of the route form down and forcing a scroll. Wrap them in a
responsive auto-fit grid (minmax(200px,1fr)) so they sit side by side
and wrap to the available width. Input is wrapped in a flex-1 div (the
shared Input component ignores a class prop, so it stays untouched).
Alias state/logic/validation unchanged. Regression guard added."
```

---

### Task 2: Runtime verification

**Files:** none (observation only).

- [ ] **Step 1: Build**

Run: `cd web/frontend && npm run build && cd ../.. && go build -o arenet ./cmd/arenet`
Expected: clean build.

- [ ] **Step 2: Drive the form (verify skill)**

Run the binary, log in, open the route **create** form, add 3-4 aliases, and confirm:
- Wide viewport: aliases sit 3-4 per row and wrap; fields below the alias block are visible without scrolling for a small alias count.
- Narrow (modal / small window): aliases collapse to ~2 or 1 per row, still readable, `×` buttons aligned, each input fills its cell (no stray narrow input — if one appears, apply the spec's fallback: add `w-full` to the wrapper div).

- [ ] **Step 3: Capture evidence + report PASS/FAIL** per the verify skill (screenshot of the form with several aliases at a wide and a narrow width).

---

## Self-Review

**Spec coverage:** grid container + auto-fit class → Task 1 Step 3. Input wrapped in flex-1 (no Input change) → Task 1 Step 3. Regression guard → Task 1 Steps 1-2. Runtime check at two widths → Task 2. All spec sections covered.

**Placeholder scan:** No TBD/TODO; full before/after markup given. The only conditional is Task 2's `w-full` fallback, which is a real spec-defined contingency, not a placeholder.

**Type consistency:** No new types or signatures. The test uses helpers (`openCreateForm`, `render`, `screen`, `userEvent`, `tick`) already imported in `page.test.ts`. The `data-testid` string matches between the markup (Task 1 Step 3) and the test assertion (Task 1 Step 1).
