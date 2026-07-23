# Country flags in the GeoIP selector — Design

**Status:** brainstormed with user 2026-07-23, 4 decisions locked. Small
frontend-only UX polish. Branch `feature/country-flags`.

**One-line:** Show the country **flag** (SVG) instead of the raw ISO code in
the GeoIP / country-block selector — both the selected chips and the search
dropdown — for a cleaner look (like FortiWeb), while keeping name/code search.

## Decisions (Q1–Q4)
| # | Decision | Why |
|---|----------|-----|
| Q1 | **SVG flags** (not emoji regional-indicators) | Emoji flags don't render on Windows (show "FR" boxes); SVG renders identically everywhere — the whole point. |
| Q2 | **`flag-icons` npm lib** (v7.5.0, MIT, local SVG) | Offline-first (no CDN — Arenet embeds its frontend), tree-shakeable, `fi fi-fr` CSS class, 4:3 SVGs. Vite bundles them locally. |
| Q3 | Chip = **[flag] France [×]** — flag replaces the ISO code, name stays | Flag alone is ambiguous (look-alike flags); the name disambiguates and keeps it accessible. |
| Q4 | Flag in **both the search dropdown AND the chips** | Full visual consistency; one reusable `Flag` component both places. |

## Architecture

**New reusable `Flag.svelte`** (`web/frontend/src/lib/components/Flag.svelte`):
- Prop `code: string` (ISO alpha-2).
- Renders `<span class="fi fi-{code.toLowerCase()}" role="img" aria-label={countryName(code)}>`.
- Fallback: an empty/unknown code renders a neutral placeholder span (no broken
  flag), mirroring the fallback discipline in `$lib/data/countries.ts`.
- Single source of truth for flag rendering, reused at both sites.

**Dependency:** add `flag-icons` to `web/frontend/package.json`; import its CSS
once (in the root `+layout.svelte` or a global stylesheet). Vite bundles the
referenced SVGs locally → no network call, compatible with `adapter-static` +
the Go `embed.FS`. CSP is fine (same-origin assets; this is Arenet's own
frontend, not a CSP-strict Artifact).

**Selector changes** (`web/frontend/src/routes/routes/+page.svelte`,
country-block section):
- **Chip** (~line 4037): replace `<span class="cb-chip__code">{code}</span>`
  with `<Flag {code} />`; keep `<span class="cb-chip__name">{countryName(code)}</span>`.
  Adjust the `.cb-chip__code` CSS (~line 4670) — repurpose/replace for flag sizing.
- **Dropdown** (~line 4100): replace `<span class="cb-dropdown__code">{match.code}</span>`
  with `<Flag code={match.code} />` before the name.

## Unchanged
- Business logic (mode allowlist/denylist, `countryList`, add/remove) — untouched.
- `matchCountries` / `countryName` — untouched (search by code AND name still works: type "fr" or "france").
- Backend — nothing (country stays an ISO code in storage; the flag is pure presentation).
- Applies to both allowlist and denylist modes automatically (same component).

## Testing
- `Flag.svelte`: renders `fi fi-fr` for "FR", `aria-label` == countryName, a
  neutral fallback for an unknown/empty code.
- Country-block selector: chips + dropdown render the `Flag` component (light
  integration assertion; update existing country-block tests if they asserted
  on the raw code text — the code text is gone from the chip, replaced by the flag).
- `svelte-check --threshold error` clean; full frontend suite green.
- **Visual check (this is a VISUAL feature):** run the frontend, screenshot the
  country-block selector with a few countries selected + the search dropdown open,
  confirm flags render (and would render on Windows since they're SVG).

## Process
LIGHT — frontend-only, ~3 files (new Flag component, package.json + CSS import,
the selector edits). Direct implementation + inline review + visual check.
