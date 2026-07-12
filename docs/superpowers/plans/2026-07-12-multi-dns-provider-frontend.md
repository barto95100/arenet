# Multi-config DNS providers — Frontend (v2.12.1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expose the multi-config DNS provider backend in the UI: a dynamic provider dropdown in the Wildcard apex wizard, a DNS Providers table CRUD in /settings, the collection client API, and EN/FR i18n — no hardcoded strings.

**Architecture:** Mirror the existing `forwardAuthProviders` collection pattern in `settings.ts`. The wizard's hardcoded `<select><option>OVH</option>` becomes a dynamic dropdown fed by `listDNSProviders()` sending `providerId`. The /settings singleton OVH form becomes a table + add/edit modal. `ApiError` gains `params` so the backend's structured `{code, params}` errors (409 provider_in_use, 400 invalid_*) render translated.

**Tech Stack:** SvelteKit (Svelte 5 runes), TypeScript strict, Tailwind, vitest + @testing-library/svelte, the project i18n `t()` bundles (en.json / fr.json).

**Depends on:** Backend v2.12.0 (PR #3) merged. Wire contract: `GET/POST/GET{id}/PUT{id}/DELETE{id} /api/v1/settings/dns-providers`; view `{id,label,type,endpoint,configured,usedBy[]}` (no secrets); errors `{error,code,params}` — 409 `provider_in_use` +`params.wildcards`, 404 `provider_not_found` +`params.id`, 400 `invalid_dns_provider`/`invalid_label`/`invalid_type`/`invalid_endpoint`/`invalid_provider_id` (+`params`). Managed-domains create/update accepts `providerId`.

## Global Constraints

- AGPL header (// comment block) on every new .ts/.svelte file.
- TypeScript strict; components PascalCase; API client centralized in `lib/api/`.
- ALL user-facing strings via `t()` — EN + FR. Zero hardcoded FR/EN. This is a blocking gate (see §i18n).
- Strings staying EN in both locales: acronyms (DNS, OVH, ACME, API, UUID, TLS), type/endpoint identifiers (`ovh`, `ovh-eu`…), future provider names.
- Secrets never displayed; edit form uses preserve-on-edit (blank = keep).
- Accessibility: interactive elements have ARIA labels (project rule).

---

## File Structure

- `web/frontend/src/lib/api/types.ts` — new `DNSProvider`/`DNSProviderRequest` types; `ManagedDomain(Request).providerId`; `ApiError.params` (MODIFY).
- `web/frontend/src/lib/api/client.ts` — read `errBody.params` into `ApiError` (MODIFY).
- `web/frontend/src/lib/api/settings.ts` — collection methods (MODIFY).
- `web/frontend/src/lib/components/certs/WildcardApexWizard.svelte` — dynamic provider dropdown + empty state (MODIFY).
- `web/frontend/src/lib/components/settings/DNSProvidersSection.svelte` — table + add/edit modal (CREATE).
- The /settings page that currently hosts the OVH form — swap in `DNSProvidersSection` (MODIFY; grep for `getDNSProviderOVH`/`DNSProviderOVH` usage).
- `web/frontend/src/lib/i18n/locales/en.json` + `fr.json` — new keys (MODIFY).

---

### Task 2a: Client API — types + collection methods + ApiError.params

**Files:**
- Modify: `web/frontend/src/lib/api/types.ts`
- Modify: `web/frontend/src/lib/api/client.ts`
- Modify: `web/frontend/src/lib/api/settings.ts`
- Test: `web/frontend/src/lib/api/settings.test.ts` (or the existing api test file — grep `settingsApi` in `*.test.ts`)

**Interfaces:**
- Produces:
  - `interface DNSProvider { id: string; label: string; type: string; endpoint: string; configured: boolean; usedBy: string[] }`
  - `interface DNSProviderRequest { label: string; type: string; endpoint: string; applicationKey?: string; applicationSecret?: string; consumerKey?: string }`
  - `settingsApi.listDNSProviders/getDNSProvider/createDNSProvider/updateDNSProvider/deleteDNSProvider`
  - `ApiError.params?: Record<string, unknown>`
  - `ManagedDomainRequest.providerId?: string` (+ keep `provider?` for back-compat typing) and `ManagedDomain.providerId: string`.

- [ ] **Step 1: Write failing test for the client methods (method + path + body)**

Find the existing auth/settings client test pattern (grep `requestMock` in `web/frontend/src/lib/api/*.test.ts`). Add:

```ts
it('listDNSProviders GETs /settings/dns-providers', async () => {
	requestMock.mockResolvedValue([]);
	await settingsApi.listDNSProviders();
	expect(requestMock).toHaveBeenCalledWith('GET', '/settings/dns-providers');
});

it('createDNSProvider POSTs the body', async () => {
	requestMock.mockResolvedValue({});
	const body = { label: 'OVH perso', type: 'ovh', endpoint: 'ovh-eu', applicationKey: 'ak', applicationSecret: 'as', consumerKey: 'ck' };
	await settingsApi.createDNSProvider(body);
	expect(requestMock).toHaveBeenCalledWith('POST', '/settings/dns-providers', body);
});

it('updateDNSProvider PUTs to the id path', async () => {
	requestMock.mockResolvedValue({});
	await settingsApi.updateDNSProvider('id-1', { label: 'x', type: 'ovh', endpoint: 'ovh-eu' });
	expect(requestMock).toHaveBeenCalledWith('PUT', '/settings/dns-providers/id-1', { label: 'x', type: 'ovh', endpoint: 'ovh-eu' });
});

it('deleteDNSProvider DELETEs the id path', async () => {
	requestMock.mockResolvedValue(undefined);
	await settingsApi.deleteDNSProvider('id-1');
	expect(requestMock).toHaveBeenCalledWith('DELETE', '/settings/dns-providers/id-1');
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd web/frontend && npx vitest run src/lib/api/settings.test.ts`
Expected: FAIL — `settingsApi.listDNSProviders is not a function`.

- [ ] **Step 3: Add the types**

In `types.ts`, add (near the existing `DNSProviderOVH`, which you may leave or remove — grep other usages first; if only the settings section uses it, remove it in Task 2c):

```ts
export interface DNSProvider {
	id: string;
	label: string;
	type: string;
	endpoint: string;
	configured: boolean;
	usedBy: string[];
}

export interface DNSProviderRequest {
	label: string;
	type: string;
	endpoint: string;
	applicationKey?: string;
	applicationSecret?: string;
	consumerKey?: string;
}
```

Change `ManagedDomain` / `ManagedDomainRequest`:

```ts
// in ManagedDomain: replace `provider: ManagedDomainProvider;` with
	providerId: string;
// in ManagedDomainRequest: replace `provider?: ManagedDomainProvider;` with
	providerId?: string;
```

- [ ] **Step 4: Add `params` to ApiError + read it in client.ts**

In `types.ts` `ApiError`, add a field + constructor param:

```ts
	params?: Record<string, unknown>;
	// constructor: add `params?: Record<string, unknown>` after `code`
	// and `this.params = params;`
```

In `client.ts` where it builds the error (~line 150-158):

```ts
			const code = typeof errBody?.code === 'string' ? errBody.code : undefined;
			const params =
				errBody && typeof errBody.params === 'object' && errBody.params !== null
					? (errBody.params as Record<string, unknown>)
					: undefined;
			const kind = res.status >= 500 ? 'system' : 'validation';
			throw new ApiError(msg, res.status, kind, undefined, code, params);
```

- [ ] **Step 5: Add the collection methods to settings.ts**

Replace `getDNSProviderOVH`/`putDNSProviderOVH` with (mirror `forwardAuthProviders`):

```ts
	listDNSProviders: (): Promise<DNSProvider[]> =>
		request<DNSProvider[]>('GET', '/settings/dns-providers'),
	getDNSProvider: (id: string): Promise<DNSProvider> =>
		request<DNSProvider>('GET', `/settings/dns-providers/${encodeURIComponent(id)}`),
	createDNSProvider: (r: DNSProviderRequest): Promise<DNSProvider> =>
		request<DNSProvider>('POST', '/settings/dns-providers', r),
	updateDNSProvider: (id: string, r: DNSProviderRequest): Promise<DNSProvider> =>
		request<DNSProvider>('PUT', `/settings/dns-providers/${encodeURIComponent(id)}`, r),
	deleteDNSProvider: (id: string): Promise<void> =>
		request<void>('DELETE', `/settings/dns-providers/${encodeURIComponent(id)}`),
```

Update the `import type { ... }` line to include `DNSProvider`, `DNSProviderRequest` and drop `DNSProviderOVH`/`DNSProviderOVHRequest` if no longer referenced.

- [ ] **Step 6: Run tests to verify green + typecheck**

Run: `cd web/frontend && npx vitest run src/lib/api/settings.test.ts && npm run check 2>&1 | tail -5`
Expected: tests PASS; `svelte-check` will show errors in the wizard/settings that still use `.provider` — those are fixed in 2b/2c. If it errors ONLY there, that's expected; proceed and they resolve by 2c. (If you prefer green-at-each-step, stub the wizard/settings `.provider`→`.providerId` minimally now.)

- [ ] **Step 7: Commit**

```bash
git add web/frontend/src/lib/api/types.ts web/frontend/src/lib/api/client.ts web/frontend/src/lib/api/settings.ts web/frontend/src/lib/api/settings.test.ts
git commit -m "feat(web): DNS provider collection client API + ApiError.params"
```

---

### Task 2b: WildcardApexWizard — dynamic provider dropdown

**Files:**
- Modify: `web/frontend/src/lib/components/certs/WildcardApexWizard.svelte`
- Test: `web/frontend/src/lib/components/certs/WildcardApexWizard.test.ts` (grep existing test file name; the certs tests exist)

**Interfaces:**
- Consumes: `settingsApi.listDNSProviders`, `DNSProvider`, `settingsApi.createManagedDomain` (now `providerId`).
- Produces: wizard sends `{apex, includeApex, providerId}`.

- [ ] **Step 1: Write failing tests**

```ts
it('populates the provider dropdown from listDNSProviders', async () => {
	listDNSProvidersMock.mockResolvedValue([
		{ id: 'id-1', label: 'OVH perso', type: 'ovh', endpoint: 'ovh-eu', configured: true, usedBy: [] },
		{ id: 'id-2', label: 'OVH pro', type: 'ovh', endpoint: 'ovh-ca', configured: true, usedBy: [] },
	]);
	const { getByText } = render(WildcardApexWizard, { props: { open: true, onClose(){}, } });
	await waitFor(() => expect(getByText('OVH perso')).toBeInTheDocument());
	expect(getByText('OVH pro')).toBeInTheDocument();
});

it('sends providerId on submit', async () => {
	listDNSProvidersMock.mockResolvedValue([{ id: 'id-1', label: 'OVH perso', type: 'ovh', endpoint: 'ovh-eu', configured: true, usedBy: [] }]);
	createManagedDomainMock.mockResolvedValue({});
	const { getByLabelText, getByTestId } = render(WildcardApexWizard, { props: { open: true, onClose(){}, } });
	await waitFor(() => expect(createManagedDomainMock).not.toHaveBeenCalled());
	// fill apex + submit
	await fireEvent.input(getByLabelText(/apex/i), { target: { value: 'example.com' } });
	await fireEvent.submit(getByTestId('wildcard-wizard-form'));
	await waitFor(() => expect(createManagedDomainMock).toHaveBeenCalledWith(
		expect.objectContaining({ apex: 'example.com', providerId: 'id-1' })
	));
});

it('shows an empty-state CTA when no provider is configured', async () => {
	listDNSProvidersMock.mockResolvedValue([]);
	const { getByText } = render(WildcardApexWizard, { props: { open: true, onClose(){}, } });
	await waitFor(() => expect(getByText(/configure.*dns provider|configurer.*provider/i)).toBeInTheDocument());
});
```

> Adapt mock wiring to the existing test file's `vi.mock('$lib/api/settings', …)` pattern. Confirm the form has a `data-testid` — the wizard currently has `<form>`; add `data-testid="wildcard-wizard-form"` (the certs page test already references `wildcard-wizard-form`, so it likely exists — grep first).

- [ ] **Step 2: Run to verify fail**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/WildcardApexWizard.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement the dynamic dropdown**

In the `<script>`: replace `let provider = $state<ManagedDomainProvider>('ovh');` with:

```ts
	let providers = $state<DNSProvider[]>([]);
	let providerId = $state<string>('');
	let providersLoading = $state(true);

	$effect(() => {
		if (open) {
			providersLoading = true;
			settingsApi.listDNSProviders()
				.then((list) => {
					providers = list;
					if (list.length > 0 && providerId === '') providerId = list[0].id;
				})
				.catch(() => { providers = []; })
				.finally(() => { providersLoading = false; });
		}
	});
```

Update `resetForm` (`provider = 'ovh'` → `providerId = providers[0]?.id ?? ''`) and `handleSubmit` to send `providerId` instead of `provider`. Guard submit when `providers.length === 0`.

In the markup, replace the single-option `<select>` with a dropdown listing providers (label + a small type badge/icon per Q2 design), plus an empty-state block when `providers.length === 0` linking to /settings:

```svelte
{#if providersLoading}
	<Spinner />
{:else if providers.length === 0}
	<div class="wizard-empty" role="alert">
		<p>{t('certs.wildcardWizard.dnsProvider.emptyState.message')}</p>
		<a href="/settings#dns-providers">{t('certs.wildcardWizard.dnsProvider.emptyState.ctaLabel')}</a>
	</div>
{:else}
	<label for="wz-provider">{t('certs.wildcardWizard.dnsProvider.label')}</label>
	<select id="wz-provider" bind:value={providerId} disabled={submitting}>
		{#each providers as p (p.id)}
			<option value={p.id}>{p.label} · {p.type.toUpperCase()}</option>
		{/each}
	</select>
{/if}
```

- [ ] **Step 4: Run tests + typecheck**

Run: `cd web/frontend && npx vitest run src/lib/components/certs/WildcardApexWizard.test.ts && npm run check 2>&1 | tail -5`
Expected: PASS; svelte-check clean for this file.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/components/certs/WildcardApexWizard.svelte web/frontend/src/lib/components/certs/WildcardApexWizard.test.ts
git commit -m "feat(web): dynamic DNS provider dropdown in wildcard wizard"
```

---

### Task 2c: /settings DNS Providers section — table + add/edit modal

**Files:**
- Create: `web/frontend/src/lib/components/settings/DNSProvidersSection.svelte`
- Modify: the /settings page hosting the old OVH form (grep `DNSProviderOVH`/`getDNSProviderOVH` under `src/routes` and `src/lib/components`)
- Test: `web/frontend/src/lib/components/settings/DNSProvidersSection.test.ts` (CREATE)

**Interfaces:**
- Consumes: all `settingsApi` DNS methods; `DNSProvider`, `DNSProviderRequest`; `OVH_ENDPOINTS`; existing `Card`, `Modal`, `Button`, `pushToast`, `t`.
- Produces: a self-contained section mounted in /settings.

- [ ] **Step 1: Write failing tests**

```ts
it('renders a row per provider with label, endpoint, usedBy', async () => {
	listMock.mockResolvedValue([
		{ id: 'id-1', label: 'OVH perso', type: 'ovh', endpoint: 'ovh-eu', configured: true, usedBy: ['a.com'] },
	]);
	const { getByText } = render(DNSProvidersSection);
	await waitFor(() => expect(getByText('OVH perso')).toBeInTheDocument());
	expect(getByText('ovh-eu')).toBeInTheDocument();
});

it('shows the empty state when no providers', async () => {
	listMock.mockResolvedValue([]);
	const { getByText } = render(DNSProvidersSection);
	await waitFor(() => expect(getByText(/add.*first provider|premier provider/i)).toBeInTheDocument());
});

it('surfaces the wildcard names on a 409 delete', async () => {
	listMock.mockResolvedValue([{ id: 'id-1', label: 'OVH', type: 'ovh', endpoint: 'ovh-eu', configured: true, usedBy: ['a.com'] }]);
	deleteMock.mockRejectedValue(new ApiError('in use', 409, 'validation', undefined, 'provider_in_use', { wildcards: ['a.com', 'b.org'] }));
	const { getByTestId } = render(DNSProvidersSection);
	await waitFor(() => getByTestId('dns-provider-delete-id-1'));
	await fireEvent.click(getByTestId('dns-provider-delete-id-1'));
	// confirm dialog → confirm → toast carrying the wildcard names
	// (adapt to your ConfirmDialog interaction)
	await waitFor(() => expect(pushToastMock).toHaveBeenCalledWith(
		expect.stringContaining('a.com'), expect.anything()
	));
});
```

- [ ] **Step 2: Run to verify fail**

Run: `cd web/frontend && npx vitest run src/lib/components/settings/DNSProvidersSection.test.ts`
Expected: FAIL (component doesn't exist).

- [ ] **Step 3: Implement the section**

Create `DNSProvidersSection.svelte` (AGPL header). Structure: load `listDNSProviders()` on mount; render a table (Label | Type | Endpoint | Status | Used by | actions ✎ 🗑) with `data-testid="dns-provider-row-{id}"` and `dns-provider-delete-{id}`; an "+ Add" button opening a `Modal` with the form (label, endpoint `<select>` from `OVH_ENDPOINTS`, 3 secret inputs); edit reuses the modal (preserve-on-edit: secret placeholders indicate "leave blank to keep"); delete goes through `ConfirmDialog`. On a caught `ApiError` with `code==='provider_in_use'`, build the toast from `t('settings.dnsProviders.delete.error409', { wildcards: (err.params?.wildcards as string[])?.join(', ') })`. Empty state → "+ Add your first provider". All strings via `t()`.

> Follow the `forwardAuth` settings section if one exists as a structural reference; otherwise follow the existing OVH form + the managed-domains list styling.

- [ ] **Step 4: Mount it in /settings + remove the old OVH form**

Replace the singleton OVH form usage with `<DNSProvidersSection />`. Remove now-dead `getDNSProviderOVH`/`DNSProviderOVH` references. Give the section an `id="dns-providers"` anchor (the wizard empty-state links to `/settings#dns-providers`).

- [ ] **Step 5: Run tests + typecheck + build**

Run: `cd web/frontend && npx vitest run src/lib/components/settings/DNSProvidersSection.test.ts && npm run check 2>&1 | tail -5 && npm run build 2>&1 | tail -3`
Expected: tests PASS, svelte-check 0 errors, build OK.

- [ ] **Step 6: Commit**

```bash
git add web/frontend/src/lib/components/settings/DNSProvidersSection.svelte web/frontend/src/lib/components/settings/DNSProvidersSection.test.ts web/frontend/src/routes/<settings-page>
git commit -m "feat(web): DNS providers table CRUD in /settings"
```

---

### Task 2d: i18n bundles (EN + FR)

**Files:**
- Modify: `web/frontend/src/lib/i18n/locales/en.json`
- Modify: `web/frontend/src/lib/i18n/locales/fr.json`
- Test: the existing i18n parity test (grep `en.json`/`fr.json` in `*.test.ts`; there is a bundle-parity checker)

**Interfaces:** all keys referenced by 2b/2c must exist in both locales.

- [ ] **Step 1: Write/confirm the failing parity test**

If a bundle-parity test exists (keys in en.json === keys in fr.json), it will FAIL once 2b/2c reference keys you haven't added. Run it: `cd web/frontend && npx vitest run -t "i18n" 2>&1 | tail -10`. If none exists, add one asserting every key used under `settings.dnsProviders.*` and `certs.wildcardWizard.dnsProvider.*` is present in both files.

- [ ] **Step 2: Add the keys to en.json**

Under `settings`:

```json
"dnsProviders": {
  "title": "DNS Providers",
  "subtitle": "DNS accounts used to issue wildcard certificates (ACME DNS-01).",
  "table": { "label": "Label", "type": "Type", "endpoint": "Endpoint", "status": "Status", "usedBy": "Used by", "actions": "Actions",
    "emptyTitle": "No DNS provider configured", "emptyText": "Add an OVH account to issue wildcard certificates.", "emptyCta": "+ Add your first provider" },
  "modal": { "addTitle": "Add DNS provider", "editTitle": "Edit DNS provider", "labelField": "Label", "endpointField": "Endpoint",
    "appKey": "Application key", "appSecret": "Application secret", "consumerKey": "Consumer key",
    "secretsKeepHint": "Leave blank to keep the current value.", "add": "Add", "save": "Save" },
  "validation": { "labelRequired": "Label is required.", "endpointRequired": "Endpoint is required." },
  "delete": { "confirmTitle": "Delete DNS provider", "confirmText": "This cannot be undone.", "confirm": "Delete",
    "error409": "Provider is in use by: {wildcards}. Reassign or remove those wildcards first." },
  "toast": { "created": "DNS provider added.", "updated": "DNS provider updated.", "deleted": "DNS provider deleted." },
  "badge": { "configured": "configured", "notConfigured": "not configured" }
}
```

Under `certs`, add:

```json
"wildcardWizard": {
  "dnsProvider": {
    "label": "DNS provider",
    "emptyState": { "message": "No DNS provider configured yet.", "ctaLabel": "Configure a DNS provider in Settings" }
  }
}
```

- [ ] **Step 3: Add the FR translations to fr.json**

Same structure, French values (acronyms/type/endpoint identifiers stay as-is):

```json
"dnsProviders": {
  "title": "Fournisseurs DNS",
  "subtitle": "Comptes DNS utilisés pour émettre les certificats wildcard (ACME DNS-01).",
  "table": { "label": "Libellé", "type": "Type", "endpoint": "Endpoint", "status": "Statut", "usedBy": "Utilisé par", "actions": "Actions",
    "emptyTitle": "Aucun fournisseur DNS configuré", "emptyText": "Ajoutez un compte OVH pour émettre des certificats wildcard.", "emptyCta": "+ Ajouter votre premier fournisseur" },
  "modal": { "addTitle": "Ajouter un fournisseur DNS", "editTitle": "Modifier le fournisseur DNS", "labelField": "Libellé", "endpointField": "Endpoint",
    "appKey": "Application key", "appSecret": "Application secret", "consumerKey": "Consumer key",
    "secretsKeepHint": "Laisser vide pour conserver la valeur actuelle.", "add": "Ajouter", "save": "Enregistrer" },
  "validation": { "labelRequired": "Le libellé est requis.", "endpointRequired": "L'endpoint est requis." },
  "delete": { "confirmTitle": "Supprimer le fournisseur DNS", "confirmText": "Cette action est irréversible.", "confirm": "Supprimer",
    "error409": "Fournisseur utilisé par : {wildcards}. Réassignez ou supprimez ces wildcards d'abord." },
  "toast": { "created": "Fournisseur DNS ajouté.", "updated": "Fournisseur DNS mis à jour.", "deleted": "Fournisseur DNS supprimé." },
  "badge": { "configured": "configuré", "notConfigured": "non configuré" }
}
```

```json
"wildcardWizard": {
  "dnsProvider": {
    "label": "Fournisseur DNS",
    "emptyState": { "message": "Aucun fournisseur DNS configuré pour l'instant.", "ctaLabel": "Configurer un fournisseur DNS dans les Réglages" }
  }
}
```

- [ ] **Step 4: Run parity + full suite + typecheck + build**

Run:
```bash
cd web/frontend && npx vitest run 2>&1 | tail -6 && npm run check 2>&1 | tail -3 && npm run build 2>&1 | tail -3
```
Expected: all tests PASS, svelte-check 0 errors / 0 warnings, build OK.

- [ ] **Step 5: Commit**

```bash
git add web/frontend/src/lib/i18n/locales/en.json web/frontend/src/lib/i18n/locales/fr.json
git commit -m "feat(i18n): DNS providers + wildcard wizard bundles (EN/FR)"
```

---

### Task 2e: Empirical smoke (real app, both locales)

**Files:** none (verification).

- [ ] **Step 1: Build + run the app**

```bash
cd web/frontend && npm run build && cd ../.. && go build -o /tmp/arenet-2e ./cmd/arenet
DD=$(mktemp -d); ARENET_HIBP_DISABLED=true ARENET_ADMIN_BIND=127.0.0.1:8001 /tmp/arenet-2e --dev --data-dir "$DD" >/tmp/2e.log 2>&1 &
```

- [ ] **Step 2: Drive via browser (Claude in Chrome) — EN then FR**

Complete /setup, then:
1. Settings → DNS Providers: empty state shows "+ Add your first provider". Add "OVH perso" (ovh-eu) + "OVH pro" (ovh-ca). Table shows 2 rows, secrets not shown, usedBy empty.
2. Certs → "+ Wildcard apex": the DNS provider dropdown lists both by label; create `*.a.com` on perso.
3. Back to Settings: "OVH perso" now shows usedBy `a.com`. Try delete → confirm → toast names the wildcard (409 rendered translated, not a raw code).
4. Toggle language FR: repeat a screen; verify no raw keys, no EN/FR mix on the same screen.
5. Screenshot each locale's DNS Providers table + the wizard dropdown.

- [ ] **Step 3: Clean up**

```bash
pkill -f arenet-2e; rm -rf /tmp/arenet-2e /tmp/2e.log "$DD"
```

- [ ] **Step 4: Report** — screenshots + any raw-key/mix findings. GO/NO-GO for tag v2.12.1.

---

## Rollback / failure handling

- Frontend-only; no data migration. A bad build is reverted by reverting the branch commit; backend is untouched.
- If the collection API contract differs from what 2a assumes (e.g. field name), fix 2a's types first — all later tasks derive from it.

## Self-Review

- **Spec coverage** (spec §3.6 + §3.7): client API → 2a; wizard dropdown + empty state → 2b; settings table + modal + 409 toast → 2c; i18n EN/FR + parity gate → 2d; empirical both-locales → 2e. `ApiError.params` (needed for translated 409) → 2a. ✓
- **Placeholder scan**: all steps carry real code; the "grep the exact file name" notes are verification instructions (test/route file names vary), not code placeholders. ✓
- **Type consistency**: `DNSProvider`, `DNSProviderRequest`, `providerId`, `settingsApi.{list,get,create,update,delete}DNSProvider`, `ApiError.params` — consistent across 2a→2c. ✓
- **i18n gate**: 2d's parity test blocks a merge with a missing FR/EN key — the guard against residual strings. ✓
