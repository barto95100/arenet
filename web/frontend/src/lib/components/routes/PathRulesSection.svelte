<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  PathRulesSection (path-based-rules Task 8). Collapsed-by-default
  editor for a route's path-scoped rules: a list of cards, each with
  a path-prefix input, an optional basic-auth override (username +
  password), and an embedded IPFilterFields (Task 7) scoped to that
  prefix. Mirrors the request/response-headers <details> disclosure
  pattern from routes/+page.svelte (collapsed <details>/<summary>,
  count badge in the summary, Button variant="ghost" size="sm" for
  add/remove) rather than inventing a new collapsible affordance.

  IMPORTANT: unlike the route-level basic auth (which has a
  `passwordSet` flag driving a "already set" placeholder), the
  backend does NOT emit `passwordSet` for path-rule basic-auth. Do
  NOT build that affordance here — the password field is a plain
  password input, no placeholder-on-edit trick.

  Two-way bound via Svelte 5 `$bindable` — the parent owns the
  PathRule[] array (route-level formData.pathRules) and this
  component mutates it in place (push/splice), mirroring the
  aliases/upstreams repeaters in routes/+page.svelte.

  Public API (add-only; do not rename/remove props):

    value — the bound PathRule[] list.
-->
<script lang="ts">
	import type { PathRule } from '$lib/api/types';
	import { t } from '$lib/i18n';
	import { language } from '$lib/stores/language.svelte';
	import Button from '$lib/components/Button.svelte';
	import Input from '$lib/components/Input.svelte';
	import IPFilterFields from './IPFilterFields.svelte';

	interface Props {
		value: PathRule[];
	}

	let { value = $bindable() }: Props = $props();

	function addRule(): void {
		value = [...value, { pathPrefix: '', ipFilter: { mode: 'off' } }];
	}

	function removeRule(i: number): void {
		value = value.filter((_, idx) => idx !== i);
	}

	function toggleBasicAuth(i: number, enabled: boolean): void {
		if (enabled) {
			value[i].basicAuth = { username: '', password: '' };
		} else {
			value[i].basicAuth = undefined;
		}
	}

	// IPFilterFields expects a non-optional IPFilter, but PathRule.ipFilter
	// is optional (rules loaded from the API may predate the field). This
	// getter/setter pair lazily materializes an "off" default on first
	// write, without mutating rules that are only being read/rendered.
	function ipFilterValue(rule: PathRule): NonNullable<PathRule['ipFilter']> {
		return rule.ipFilter ?? { mode: 'off' };
	}
	function setIpFilterValue(rule: PathRule, next: NonNullable<PathRule['ipFilter']>): void {
		rule.ipFilter = next;
	}
</script>

<details class="rounded border border-border-subtle" data-testid="path-rules-section">
	<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
		{language.current && t('routes.pathRules.sectionLabel')}
		{#if value.length > 0}
			<span class="ml-1 text-xs text-muted">({value.length})</span>
		{/if}
	</summary>
	<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
		<p class="text-xs text-muted">
			{language.current && t('routes.pathRules.sectionHelp')}
		</p>

		{#each value as rule, i (i)}
			<div
				class="flex flex-col gap-3 rounded-md border border-border-default bg-surface p-3"
				data-testid="path-rule-card"
			>
				<div class="flex items-start gap-2">
					<div class="flex-1">
						<Input
							label={language.current && t('routes.pathRules.prefixLabel')}
							bind:value={rule.pathPrefix}
							placeholder={language.current && t('routes.pathRules.prefixPlaceholder')}
							data-testid="path-rule-prefix-{i}"
						/>
						<p class="text-xs text-muted mt-1">
							{language.current && t('routes.pathRules.prefixHelp')}
						</p>
					</div>
					<Button
						variant="ghost"
						size="sm"
						onclick={() => removeRule(i)}
						type="button"
						data-testid="path-rule-remove-{i}"
						aria-label={language.current && t('routes.pathRules.remove')}
					>
						×
					</Button>
				</div>

				<div class="flex flex-col gap-2">
					<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
						<input
							type="checkbox"
							class="accent-cyan"
							checked={!!rule.basicAuth}
							onchange={(e) => toggleBasicAuth(i, (e.currentTarget as HTMLInputElement).checked)}
							data-testid="path-rule-basicauth-toggle-{i}"
						/>
						{language.current && t('routes.pathRules.basicAuthLabel')}
					</label>
					{#if rule.basicAuth}
						<div class="ml-6 flex flex-col gap-2">
							<Input
								label={language.current && t('routes.pathRules.basicAuthUsernameLabel')}
								bind:value={rule.basicAuth.username}
								placeholder={language.current && t('routes.pathRules.basicAuthUsernamePlaceholder')}
								data-testid="path-rule-basicauth-username-{i}"
							/>
							<div>
								<label
									for="path-rule-basicauth-password-{i}"
									class="text-sm font-medium text-secondary block mb-1"
								>
									{language.current && t('routes.pathRules.basicAuthPasswordLabel')}
								</label>
								<input
									id="path-rule-basicauth-password-{i}"
									type="password"
									bind:value={
										() => rule.basicAuth?.password ?? '',
										(v) => {
											if (rule.basicAuth) rule.basicAuth.password = v;
										}
									}
									data-testid="path-rule-basicauth-password-{i}"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								/>
							</div>
						</div>
					{/if}
				</div>

				<div>
					<span class="text-xs font-medium text-secondary block mb-1">
						{language.current && t('routes.pathRules.ipFilterLabel')}
					</span>
					<IPFilterFields
						bind:value={
							() => ipFilterValue(rule),
							(next) => setIpFilterValue(rule, next)
						}
					/>
				</div>
			</div>
		{/each}

		<Button variant="ghost" size="sm" onclick={addRule} type="button" data-testid="path-rules-add">
			{language.current && t('routes.pathRules.add')}
		</Button>
	</div>
</details>
