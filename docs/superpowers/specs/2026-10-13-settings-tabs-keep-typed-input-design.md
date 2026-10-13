<!-- Arenet — design spec. AGPL-3.0-or-later. See LICENSE. -->

# A settings tab does not discard what was typed in it

**Target version:** v2.72.0
**Status:** design locked, implementation in progress
**Decided:** 2026-10-13, operator chose the confirm-on-leave option

## The behaviour today

`routes/settings/+page.svelte:754` and its four siblings render each
tab's content behind `{#if activeTab === '<id>'}`. Switching tabs
unmounts the section, so every `$state` in it is destroyed. There is no
prompt and no toast: an operator who had typed an OIDC client secret,
a CrowdSec LAPI key or a set of scheduled-backup fields and clicked
another tab to check something comes back to an empty form.

The unmount is also what reloads the section from the API on return, so
the form is not merely blank — it is repopulated with the stored
values, which makes the loss look like a successful save.

## Decision

Confirm before leaving a tab that holds unsaved input. Rejected
alternative: keep all ten sections mounted and hide them with CSS. It
is one line per tab and needs no instrumentation, but it mounts every
section on page load, so all ten fetch their data even for tabs the
operator never opens. The settings page would go from one or two
requests to roughly ten on every visit.

| # | Decision | Rationale |
| --- | --- | --- |
| D1 | A section declares its own dirtiness | Only the section knows when it last saved. A generic DOM diff over the panel cannot tell "typed" from "saved and reloaded", and a false "unsaved changes" prompt after a successful save is worse than the current behaviour. |
| D2 | Registration is scoped by mounting | A section registers its predicate while mounted and unregisters on destroy. Since the inactive tabs are unmounted, the registry only ever holds the active tab's sections — no per-tab bookkeeping. |
| D3 | `Tabs` gains a veto hook | `canLeave?: (next) => boolean`. `select()` returns early when it refuses, so the page can show its dialog and apply the switch itself. Optional prop: the other five call sites are untouched. |
| D4 | Discarding is the confirm action | The dialog's confirm switches tabs, which unmounts the section and drops the state. That is the operator's explicit choice at that point, so no extra save path is needed. |
| D5 | Dirtiness is a snapshot comparison | Each section keeps a baseline string of its form fields, refreshed after a load and after a successful save. `isDirty()` compares the current snapshot to the baseline, so reverting a field by hand clears the warning. |
| D6 | Redacted secret fields count as dirty when non-empty | A password or API-key field is deliberately blank when a value is stored, so there is nothing to compare against: any content is unsaved input. |

## Non-goals

- Guarding browser navigation (`beforeunload`) or SvelteKit route
  changes. This spec covers the tab strip only; closing the window is
  outside it and would need a separate decision about how intrusive a
  native prompt should be.
- Guarding modals that carry their own state
  (`DNSProvidersSection`'s provider dialog). A modal is already a
  deliberate open/close, and its Cancel button is the discard control.
- Saving on leave. The operator asked for a confirmation, not an
  autosave, and an autosave would push half-filled credentials to the
  API.

## Scope — which sections carry a form

Counted, not assumed: `bind:value` / `bind:checked` occurrences per
section, then read to see whether the bindings feed a persisted form or
a one-shot action.

| Section | Bindings | In scope |
| --- | --- | --- |
| `OIDCSettingsSection` | 11 | yes — the largest form in settings, and it holds a client secret |
| `ScheduledBackupsSection` | 10 | yes |
| `CrowdSecSettingsSection` | 4 | yes — holds the bouncer API key |
| `ServerPositionSection` | 4 | yes |
| `GeoIPSettingsSection` | 2 | yes — holds the MaxMind licence key |
| `DNSProvidersSection` | 4 | no — the bindings live in the provider modal (non-goal above) |
| `BackupSection` | 5 | no — export options for an immediate action, nothing persisted |
| `SystemInfoSection`, `UpdatesSection`, `RouteCheckSection` | 0 | no form |

The account tab's inline profile and appearance forms are deferred:
appearance applies immediately and the profile form needs its own read
before it is instrumented.

## Empirical validation gates

1. A component test proves the current behaviour first: type into a
   section, switch tab, switch back, assert the field is empty. It is
   the before-state this spec exists to change.
2. The registry's predicate is consulted for the **outgoing** tab, not
   the incoming one — asserted by registering a dirty predicate and
   checking the dialog appears when leaving, not when arriving.
3. Saving clears dirtiness: type, save, then leave — no dialog. This is
   the gate that rules out crying wolf, which D1 exists to prevent.
4. Reverting by hand clears dirtiness (D5): type, undo the typing,
   leave — no dialog.
5. The five untouched `Tabs` call sites keep switching with no veto
   prop — their existing tests are the instrument.
