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

	// Task 6 (per-path upstream routing) — the upstream pool, lbPolicy
	// and healthCheck are all optional/absent on a PathRule that
	// inherits the route's upstream. We only materialise them on
	// first operator interaction so a pool-less rule stays pool-less
	// on submit (sanitizePathRules on the backend drops empty
	// upstream pools; we mirror that "don't create until asked"
	// discipline client-side too).
	// Each mutator writes through the existing rule object in place
	// (mirrors toggleBasicAuth/setIpFilterValue above, and keeps the
	// object identity the parent/test holds intact) and then
	// reassigns `value = value` — a no-op replacement of the
	// top-level bindable array — to force Svelte to re-evaluate the
	// #each block. Plain in-place nested mutation alone triggers a
	// `binding_property_non_reactive` warning and the DOM does not
	// update reliably when `value` was not itself created via
	// `$state` on the caller's side (e.g. a bare array literal passed
	// in tests), because $bindable does not deep-proxy values it did
	// not create.
	function touch(): void {
		value = [...value];
	}

	function addBackend(i: number): void {
		const rule = value[i];
		if (!rule.upstreams) rule.upstreams = [];
		rule.upstreams.push({ url: '', weight: 1 });
		if (!rule.lbPolicy) rule.lbPolicy = 'round_robin';
		touch();
	}

	function removeBackend(i: number, j: number): void {
		const rule = value[i];
		if (!rule.upstreams) return;
		rule.upstreams = rule.upstreams.filter((_, idx) => idx !== j);
		touch();
	}

	function updateBackend(i: number, j: number, patch: Partial<{ url: string; weight: number }>): void {
		const rule = value[i];
		if (!rule.upstreams?.[j]) return;
		Object.assign(rule.upstreams[j], patch);
		touch();
	}

	function setLbPolicy(i: number, lbPolicy: PathRule['lbPolicy']): void {
		value[i].lbPolicy = lbPolicy;
		touch();
	}

	function toggleHealthCheck(i: number, enabled: boolean): void {
		if (enabled) {
			value[i].healthCheck = {
				enabled: true,
				uri: '',
				method: 'GET',
				interval: '10s',
				timeout: '5s',
				expectStatus: 0,
				expectBody: '',
				passes: 1,
				fails: 1
			};
		} else {
			value[i].healthCheck = undefined;
		}
		touch();
	}

	function updateHealthCheckUri(i: number, uri: string): void {
		const rule = value[i];
		if (!rule.healthCheck) return;
		rule.healthCheck.uri = uri;
		touch();
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

				<!-- Task 6 (per-path upstream routing) — collapsed-by-default
				     disclosure mirroring the route-level health-check <details>
				     idiom. Only forced open when the rule already carries a
				     non-empty pool on mount (mirrors open={formData.healthCheck.enabled}
				     at routes/+page.svelte:4189). -->
				<details
					class="rounded border border-border-subtle"
					open={(rule.upstreams?.length ?? 0) > 0}
					data-testid="path-rule-upstream-disclosure-{i}"
				>
					<summary class="px-3 py-2 text-sm text-secondary cursor-pointer select-none">
						{language.current && t('routes.pathRules.upstreamLabel')}
						{#if rule.upstreams && rule.upstreams.length > 0}
							<span
								class="ml-1 text-xs text-muted"
								data-testid="path-rule-backends-badge-{i}"
							>
								{language.current &&
									t('routes.pathRules.upstreamBackendsBadge', {
										count: rule.upstreams.length
									})}
							</span>
						{/if}
					</summary>
					<div class="p-3 flex flex-col gap-3 border-t border-border-subtle">
						<p class="text-xs text-muted">
							{language.current && t('routes.pathRules.upstreamInheritHint')}
						</p>

						{#if rule.upstreams}
							{#each rule.upstreams as _backend, j (j)}
								<div class="flex items-start gap-2">
									<div class="flex-1">
										<Input
											bind:value={
												() => rule.upstreams?.[j]?.url ?? '',
												(v) => updateBackend(i, j, { url: v })
											}
											placeholder={language.current &&
												t('routes.pathRules.upstreamUrlPlaceholder')}
											data-testid="path-rule-upstream-url-{i}-{j}"
										/>
									</div>
									<div class="w-24">
										<label for="path-rule-upstream-weight-{i}-{j}" class="sr-only">
											{language.current && t('routes.pathRules.upstreamWeightLabel')}
										</label>
										<input
											id="path-rule-upstream-weight-{i}-{j}"
											type="number"
											min="1"
											value={rule.upstreams?.[j]?.weight ?? 1}
											oninput={(e) =>
												updateBackend(i, j, {
													weight: Number((e.currentTarget as HTMLInputElement).value) || 1
												})}
											placeholder={language.current &&
												t('routes.pathRules.upstreamWeightLabel')}
											data-testid="path-rule-upstream-weight-{i}-{j}"
											class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
										/>
									</div>
									<Button
										variant="ghost"
										size="sm"
										onclick={() => removeBackend(i, j)}
										type="button"
										data-testid="path-rule-upstream-remove-{i}-{j}"
										aria-label={language.current &&
											t('routes.pathRules.upstreamRemoveBackend')}
									>
										×
									</Button>
								</div>
							{/each}
						{/if}

						<Button
							variant="ghost"
							size="sm"
							onclick={() => addBackend(i)}
							type="button"
							data-testid="path-rule-upstream-add-{i}"
						>
							{language.current && t('routes.pathRules.upstreamAddBackend')}
						</Button>

						{#if rule.upstreams && rule.upstreams.length > 0}
							<div>
								<label for="path-rule-lb-{i}" class="text-sm font-medium text-secondary block mb-1">
									{language.current && t('routes.pathRules.upstreamLbLabel')}
								</label>
								<select
									id="path-rule-lb-{i}"
									value={rule.lbPolicy ?? 'round_robin'}
									onchange={(e) =>
										setLbPolicy(i, (e.currentTarget as HTMLSelectElement).value as PathRule['lbPolicy'])}
									data-testid="path-rule-lb-{i}"
									class="w-full bg-surface border border-border-default rounded-md px-3 py-2 text-sm text-primary"
								>
									<option value="round_robin"
										>{language.current && t('routes.form.lbRoundRobin')}</option
									>
									<option value="weighted_round_robin"
										>{language.current && t('routes.form.lbWeightedRoundRobin')}</option
									>
									<option value="least_conn"
										>{language.current && t('routes.form.lbLeastConn')}</option
									>
									<option value="ip_hash"
										>{language.current && t('routes.form.lbIPHash')}</option
									>
									<option value="random">{language.current && t('routes.form.lbRandom')}</option>
									<option value="first">{language.current && t('routes.form.lbFirst')}</option>
								</select>
							</div>
						{/if}

						<div class="flex flex-col gap-2">
							<label class="inline-flex items-center gap-2 text-sm text-secondary cursor-pointer">
								<input
									type="checkbox"
									class="accent-cyan"
									checked={!!rule.healthCheck?.enabled}
									onchange={(e) =>
										toggleHealthCheck(i, (e.currentTarget as HTMLInputElement).checked)}
									data-testid="path-rule-hc-toggle-{i}"
								/>
								{language.current && t('routes.pathRules.upstreamHealthCheckLabel')}
							</label>
							{#if rule.healthCheck?.enabled}
								<div class="ml-6">
									<Input
										bind:value={
											() => rule.healthCheck?.uri ?? '',
											(v) => updateHealthCheckUri(i, v)
										}
										placeholder={language.current &&
											t('routes.pathRules.upstreamHealthCheckUriPlaceholder')}
										data-testid="path-rule-hc-uri-{i}"
									/>
								</div>
							{/if}
						</div>
					</div>
				</details>
			</div>
		{/each}

		<Button variant="ghost" size="sm" onclick={addRule} type="button" data-testid="path-rules-add">
			{language.current && t('routes.pathRules.add')}
		</Button>
	</div>
</details>
