<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R Phase 2.a — /settings/error-pages

  Operator-facing CRUD for custom HTML error-page templates.
  State-driven (no sub-routes) : `view` toggles between
  'list' (DataTable of templates with row actions) and
  'edit' (8 status-code tabs + CodeMirror + iframe preview
  + Variables panel + Save/Cancel).

  Backend reference : POST/GET/PUT/DELETE /api/v1/error-
  templates + GET /api/v1/error-templates/{id}/preview
  (commit f51167c Phase 1).

  3-layer resolution at serve time (caddymgr-side, Phase 1) :
    1. Route.ErrorPageOverrides[code]
    2. Template.Pages[code]
    3. Built-in Arenet branded default
  This page only manages templates (layer 2) ; the per-route
  override layer (1) lives in the RouteForm "Pages d'erreur"
  section (R.2.b sibling work).
-->

<script lang="ts">
	import { onMount } from 'svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import HtmlEditor from '$lib/components/HtmlEditor.svelte';
	import {
		errorTemplatesApi,
		BUILTIN_TEMPLATE_ID,
		SUPPORTED_ERROR_STATUS_CODES,
		ERROR_PAGE_PLACEHOLDERS,
		type ErrorTemplate,
		type SupportedErrorStatusCode
	} from '$lib/api/error-templates';
	import { pushToast } from '$lib/stores/toast';
	import { ApiError } from '$lib/api/types';

	// --- View state ---------------------------------------

	type View = 'list' | 'edit';
	let view = $state<View>('list');

	// --- List state ---------------------------------------

	let templates = $state<ErrorTemplate[]>([]);
	let loading = $state(true);
	let loadError = $state<string | null>(null);

	async function loadTemplates(): Promise<void> {
		loading = true;
		loadError = null;
		try {
			templates = await errorTemplatesApi.list();
		} catch (err) {
			// Surface ApiError.message verbatim ; for plain Error
			// (network down, abort, etc.) use .message too rather
			// than a generic "failed to load" so the operator sees
			// the actual cause without opening DevTools.
			loadError =
				err instanceof ApiError
					? err.message
					: err instanceof Error
						? err.message
						: 'failed to load templates';
			templates = [];
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		void loadTemplates();
	});

	// --- Editor state -------------------------------------

	// Null when creating a new template, populated when editing.
	let editingId = $state<string | null>(null);
	// Step R Phase 2.1 — when the operator opens the virtual
	// builtin for inspection, the editor runs in read-only
	// mode : Save is hidden, Delete is hidden, the only
	// available action is Duplicate. The flag distinguishes
	// "editing a real DB template" (false) from "previewing
	// the builtin to decide whether to duplicate" (true).
	let editingBuiltin = $state(false);
	let editName = $state('');
	let editDescription = $state('');
	// Sparse Pages map ; codes absent fall back to template-side
	// default at serve time. Active tab governs which buffer is
	// shown in the CodeMirror editor.
	let editPages = $state<Record<number, string>>({});
	let activeCode = $state<SupportedErrorStatusCode>(403);
	let saving = $state(false);
	let editorRef = $state<HtmlEditor | undefined>();

	// Two-way bound to the editor : reads the active code's
	// body from editPages, writes back on user typing. Mirrored
	// into editPages on every change (Svelte 5 $effect).
	let activeBuffer = $state('');

	// When the active tab changes, snap activeBuffer to the
	// corresponding editPages entry. When activeBuffer changes
	// (user typed), write back to editPages.
	//
	// $state(activeCode) for the previous-tab snapshot so the
	// effect re-reads it reactively (Svelte 5 warns when a
	// top-level `let x = activeCode` is referenced inside an
	// effect because it captures the initial value only — the
	// $state wrapper makes the comparison reactive).
	let lastActiveCode = $state<SupportedErrorStatusCode>(403);
	$effect(() => {
		if (activeCode !== lastActiveCode) {
			activeBuffer = editPages[activeCode] ?? '';
			lastActiveCode = activeCode;
		}
	});
	$effect(() => {
		// Only write back when editing (not during reset).
		if (view !== 'edit') return;
		editPages[activeCode] = activeBuffer;
	});

	function startCreate(): void {
		editingId = null;
		editingBuiltin = false;
		editName = '';
		editDescription = '';
		editPages = {};
		activeCode = 403;
		activeBuffer = '';
		previewHtml = '';
		view = 'edit';
	}

	function startEdit(t: ErrorTemplate): void {
		editingId = t.id;
		editingBuiltin = t.isBuiltin === true;
		editName = t.name;
		editDescription = t.description ?? '';
		// Cast key strings back to numbers (server returns
		// Record<string, string> by JSON convention).
		const pages: Record<number, string> = {};
		for (const [k, v] of Object.entries(t.pages)) {
			pages[Number(k)] = v;
		}
		editPages = pages;
		activeCode = 403;
		activeBuffer = pages[403] ?? '';
		previewHtml = '';
		view = 'edit';
	}

	// Step R Phase 2.1 — duplicate flow.
	//
	// Operator clicks "Dupliquer" on the builtin card (or on
	// any editable row's hypothetical future Duplicate
	// button) → we create a fresh DB template with the source
	// content + a unique-among-existing name following the
	// macOS Finder pattern: "Copy of X", "Copy of X (2)",
	// "Copy of X (3)" ... Backend has no name uniqueness
	// constraint (Phase 1 storage validate) so the suffix
	// strategy is pure UX hygiene ; collisions would be
	// silently accepted server-side, but the operator
	// shouldn't see two rows with the same name.
	//
	// On success : reload list, switch to editing the new
	// (now editable) row so the operator can immediately
	// customise.
	async function duplicateTemplate(source: ErrorTemplate): Promise<void> {
		const baseName = `Copy of ${source.name}`;
		const uniqueName = computeUniqueCopyName(baseName, templates);
		const pages: Record<string, string> = { ...source.pages };
		try {
			const created = await errorTemplatesApi.create({
				name: uniqueName,
				description: source.description,
				pages
			});
			pushToast(`Template "${uniqueName}" créé`, 'success');
			await loadTemplates();
			startEdit(created);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'failed to duplicate template';
			pushToast(msg, 'danger');
		}
	}

	// macOS Finder-style copy naming. Returns baseName if no
	// row already uses it ; otherwise appends "(N)" with the
	// smallest N >= 2 that resolves the conflict.
	//
	// Exported via export shim at the bottom of the script so
	// the page.test.ts can pin the algorithm without going
	// through the full duplicate-and-create round-trip.
	function computeUniqueCopyName(baseName: string, existing: ErrorTemplate[]): string {
		const names = new Set(existing.map((t) => t.name));
		if (!names.has(baseName)) return baseName;
		for (let n = 2; n < 1000; n++) {
			const candidate = `${baseName} (${n})`;
			if (!names.has(candidate)) return candidate;
		}
		// Operator has somehow created 998 copies of the same
		// template ; degrade with a timestamp rather than loop
		// forever. Genuinely never reached in practice.
		return `${baseName} (${Date.now()})`;
	}

	function cancelEdit(): void {
		view = 'list';
		previewHtml = '';
	}

	async function saveTemplate(): Promise<void> {
		// Phase 2.1 — the read-only builtin path : the Save
		// button is hidden in the template (see {#if !editingBuiltin}
		// guard around the actions snippet) so this branch
		// should be unreachable. Defence-in-depth in case a
		// future refactor surfaces the button :
		if (editingBuiltin) {
			pushToast('Le template « Arenet default » est en lecture seule ; utilisez « Dupliquer ».', 'danger');
			return;
		}
		if (!editName.trim()) {
			pushToast('Le nom du template est requis', 'danger');
			return;
		}
		saving = true;
		try {
			// Strip empty bodies before submit — the operator
			// "cleared this code's override" gesture should not
			// persist as an explicit empty-string entry.
			const cleanPages: Record<number, string> = {};
			for (const [code, body] of Object.entries(editPages)) {
				if (body.trim()) cleanPages[Number(code)] = body;
			}
			const req = {
				name: editName.trim(),
				description: editDescription.trim() || undefined,
				pages: Object.fromEntries(
					Object.entries(cleanPages).map(([k, v]) => [String(k), v])
				)
			};
			if (editingId === null) {
				await errorTemplatesApi.create(req);
				pushToast(`Template "${editName}" créé`, 'success');
			} else {
				await errorTemplatesApi.update(editingId, req);
				pushToast(`Template "${editName}" mis à jour`, 'success');
			}
			await loadTemplates();
			view = 'list';
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'failed to save template';
			pushToast(msg, 'danger');
		} finally {
			saving = false;
		}
	}

	// --- Delete with confirmation -------------------------

	let deleteTarget = $state<ErrorTemplate | null>(null);
	let deleting = $state(false);

	function askDelete(t: ErrorTemplate): void {
		deleteTarget = t;
	}

	async function confirmDelete(): Promise<void> {
		if (!deleteTarget) return;
		const target = deleteTarget;
		deleting = true;
		try {
			await errorTemplatesApi.delete(target.id);
			pushToast(`Template "${target.name}" supprimé`, 'success');
			deleteTarget = null;
			await loadTemplates();
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : 'failed to delete template';
			pushToast(msg, 'danger');
		} finally {
			deleting = false;
		}
	}

	// --- Preview pane -------------------------------------

	// Held outside the active-code reactive chain so it only
	// updates on debounced keystrokes (300ms idle). iframe srcdoc
	// rerender on every char would flicker badly and trigger
	// excessive backend preview round-trips.
	let previewHtml = $state('');
	let previewLoading = $state(false);
	let previewError = $state<string | null>(null);
	let previewTimer: ReturnType<typeof setTimeout> | null = null;

	const PREVIEW_DEBOUNCE_MS = 300;

	function schedulePreview(): void {
		if (previewTimer !== null) {
			clearTimeout(previewTimer);
		}
		previewTimer = setTimeout(() => {
			void renderPreview();
			previewTimer = null;
		}, PREVIEW_DEBOUNCE_MS);
	}

	async function renderPreview(): Promise<void> {
		// The preview endpoint needs a persisted template ID.
		// For a freshly-created (unsaved) template, we fall
		// back to a client-side substitution mirror of the
		// backend's previewSubstitute() helper.
		previewError = null;
		previewLoading = true;
		try {
			if (editingId !== null && editPages[activeCode]) {
				// Persisted template : use server-side preview
				// (matches what'll render in prod via the same
				// placeholder substitution path).
				previewHtml = await errorTemplatesApi.preview(editingId, activeCode);
			} else {
				// Unsaved template : substitute client-side
				// using the same fixture values as the backend.
				previewHtml = clientSidePreview(activeBuffer, activeCode);
			}
		} catch (err) {
			previewError = err instanceof Error ? err.message : 'preview failed';
			previewHtml = '';
		} finally {
			previewLoading = false;
		}
	}

	// Trigger preview render on activeBuffer change (debounced)
	// and immediately on tab switch.
	$effect(() => {
		if (view !== 'edit') return;
		// Read activeBuffer to register dependency.
		activeBuffer;
		schedulePreview();
	});

	// Client-side preview substitution. Mirror of the Go
	// previewSubstitute() in internal/api/error_templates.go.
	// Kept narrow + literal for transparency : operator sees
	// the same SHAPE they'll see in prod for these specific
	// tokens. Unknown placeholders pass through untouched.
	function clientSidePreview(body: string, code: number): string {
		const statusText: Record<number, string> = {
			401: 'Unauthorized',
			403: 'Forbidden',
			404: 'Not Found',
			429: 'Too Many Requests',
			500: 'Internal Server Error',
			502: 'Bad Gateway',
			503: 'Service Unavailable',
			504: 'Gateway Timeout'
		};
		const replacements: Record<string, string> = {
			'{http.error.status_code}': String(code),
			'{http.error.status_text}': statusText[code] ?? '',
			'{http.error.id}': 'preview-error-id-0000',
			'{http.error.message}': statusText[code] ?? '',
			'{http.reverse_proxy.status_code}': String(code),
			'{http.request.method}': 'GET',
			'{http.request.host}': 'preview.example.com',
			'{http.request.uri}': '/preview/path',
			'{http.request.uri.path}': '/preview/path',
			'{http.request.uuid}': '00000000-0000-4000-8000-000000000000',
			'{http.request.remote.host}': '203.0.113.42',
			'{time.now.year}': String(new Date().getFullYear()),
			'{system.hostname}': 'arenet-preview'
		};
		let out = body;
		for (const [k, v] of Object.entries(replacements)) {
			out = out.split(k).join(v);
		}
		return out;
	}

	// --- Variables panel ---------------------------------

	function insertPlaceholder(token: string): void {
		editorRef?.insertAtCursor(token);
	}

	// --- Helpers -----------------------------------------

	function codeHasContent(code: number): boolean {
		return Boolean(editPages[code]?.trim());
	}

	function formatDate(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleDateString('fr-FR', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	}
</script>

<svelte:head>
	<title>Pages d'erreur · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Réglages · Pages d'erreur"
	title={view === 'list'
		? "Pages d'erreur personnalisées"
		: editingBuiltin
			? 'Aperçu : Arenet default'
			: editingId
				? 'Modifier le template'
				: 'Nouveau template'}
	subtitle="Templates HTML servis par Caddy pour les codes 401/403/404/429/500/502/503/504. Sans template attaché à une route, le défaut Arenet branded s'applique automatiquement."
>
	{#snippet actions()}
		{#if view === 'list'}
			<button class="tb-btn primary" onclick={startCreate}>+ Nouveau template</button>
		{:else if editingBuiltin}
			<!-- Read-only mode : no Save. Operator returns to
			     list or duplicates to customise. -->
			<button class="tb-btn" onclick={cancelEdit}>Retour</button>
			<button
				class="tb-btn primary"
				onclick={() => {
					// Materialise a synthetic ErrorTemplate from the
					// current edit buffer to feed the duplicate flow.
					// Same content as what was loaded ; the duplicate
					// will lift it to a real editable template.
					const pages: Record<string, string> = {};
					for (const [k, v] of Object.entries(editPages)) {
						if (v) pages[String(k)] = v;
					}
					void duplicateTemplate({
						id: BUILTIN_TEMPLATE_ID,
						name: editName,
						description: editDescription,
						pages,
						createdAt: '',
						updatedAt: '',
						isBuiltin: true
					});
				}}
			>
				Dupliquer pour customiser
			</button>
		{:else}
			<button class="tb-btn" onclick={cancelEdit} disabled={saving}>Annuler</button>
			<button class="tb-btn primary" onclick={() => void saveTemplate()} disabled={saving}>
				{saving ? 'Enregistrement…' : 'Enregistrer'}
			</button>
		{/if}
	{/snippet}
</PageHeader>

{#if view === 'list'}
	<div class="card">
		{#if loading}
			<div class="loading-wrap"><Spinner /></div>
		{:else if loadError}
			<div class="empty-state">
				<p class="error">{loadError}</p>
				<button class="tb-btn" onclick={() => void loadTemplates()}>Réessayer</button>
			</div>
		{:else if templates.length === 0}
			<div class="empty-state">
				<h3>Aucun template personnalisé</h3>
				<p>
					Toutes les routes reçoivent actuellement le défaut Arenet branded.
					Créez un template pour personnaliser les pages d'erreur d'une route ou plusieurs.
				</p>
				<button class="tb-btn primary" onclick={startCreate}>+ Créer le premier template</button>
			</div>
		{:else}
			<table class="tpl-table">
				<thead>
					<tr>
						<th>Nom</th>
						<th>Description</th>
						<th class="num">Codes configurés</th>
						<th>Mis à jour</th>
						<th class="actions">Actions</th>
					</tr>
				</thead>
				<tbody>
					{#each templates as t (t.id)}
						<tr class:builtin-row={t.isBuiltin}>
							<td>
								<strong>{t.name}</strong>
								{#if t.isBuiltin}
									<span class="builtin-badge" title="Template Arenet par défaut, lecture seule">
										Built-in
									</span>
								{/if}
							</td>
							<td class="dim">{t.description || '—'}</td>
							<td class="num mono">{Object.keys(t.pages).length} / 8</td>
							<td class="dim">
								{t.isBuiltin ? '—' : formatDate(t.updatedAt)}
							</td>
							<td class="actions">
								{#if t.isBuiltin}
									<!-- Read-only : Inspect goes to the editor in
									     read-only mode ; Duplicate creates an
									     editable copy. No Modifier / Supprimer. -->
									<button class="tb-btn sm" onclick={() => startEdit(t)}>
										Aperçu
									</button>
									<button
										class="tb-btn sm primary"
										onclick={() => void duplicateTemplate(t)}
										title="Créer un nouveau template à partir du défaut"
									>
										Dupliquer
									</button>
								{:else}
									<button class="tb-btn sm" onclick={() => startEdit(t)}>Modifier</button>
									<button
										class="tb-btn sm"
										onclick={() => void duplicateTemplate(t)}
										title="Créer un nouveau template à partir de celui-ci"
									>
										Dupliquer
									</button>
									<button class="tb-btn sm danger" onclick={() => askDelete(t)}>
										Supprimer
									</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		{/if}
	</div>
{:else}
	<!-- Editor view -->
	<div class="editor-grid">
		{#if editingBuiltin}
			<!-- Step R Phase 2.1 — read-only banner. Makes
			     the inputs-disabled state operator-obvious so
			     the absence of a Save button isn't perceived
			     as a UI bug. -->
			<div class="card builtin-banner">
				<strong>Lecture seule</strong>
				— ce template est le défaut Arenet. Cliquez sur
				« Dupliquer pour customiser » en haut à droite pour
				créer une copie éditable.
			</div>
		{/if}
		<!-- Top : name + description -->
		<div class="card meta-card">
			<label>
				<span class="meta-label">Nom du template</span>
				<input
					type="text"
					bind:value={editName}
					placeholder="ex: WGW Branding"
					class="meta-input"
					maxlength="100"
					readonly={editingBuiltin}
				/>
			</label>
			<label>
				<span class="meta-label">Description (optionnel)</span>
				<input
					type="text"
					bind:value={editDescription}
					placeholder="Pages d'erreur brandées pour worldgeekwide.fr"
					class="meta-input"
					maxlength="500"
					readonly={editingBuiltin}
				/>
			</label>
		</div>

		<!-- Status code tabs -->
		<div class="card tabs-card">
			<div class="code-tabs" role="tablist" aria-label="Status codes">
				{#each SUPPORTED_ERROR_STATUS_CODES as code (code)}
					<button
						role="tab"
						aria-selected={activeCode === code}
						class="code-tab"
						class:active={activeCode === code}
						class:filled={codeHasContent(code)}
						onclick={() => (activeCode = code)}
					>
						{code}
						{#if codeHasContent(code)}<span class="dot">●</span>{/if}
					</button>
				{/each}
			</div>
		</div>

		<!-- Main editor + preview + variables -->
		<div class="card editor-card">
			<div class="editor-pane">
				<div class="pane-label">Éditeur HTML — code {activeCode}</div>
				<HtmlEditor
					bind:this={editorRef}
					bind:value={activeBuffer}
					label="HTML body for status code {activeCode}"
					placeholder="<!doctype html>..."
					minHeight={360}
					readonly={editingBuiltin}
				/>
			</div>
			<div class="preview-pane">
				<div class="pane-label">
					Prévisualisation
					{#if previewLoading}<span class="dim">(chargement…)</span>{/if}
				</div>
				{#if previewError}
					<div class="preview-error">{previewError}</div>
				{:else}
					<iframe
						title="Aperçu HTML du template (sandbox)"
						sandbox=""
						srcdoc={previewHtml}
						class="preview-frame"
					></iframe>
				{/if}
			</div>
		</div>

		<!-- Variables panel -->
		<div class="card vars-card">
			<details open>
				<summary>
					Variables Caddy disponibles
					{#if !editingBuiltin}(cliquez pour insérer){/if}
				</summary>
				<div class="vars-grid">
					{#each ERROR_PAGE_PLACEHOLDERS as p (p.token)}
						<button
							class="var-btn"
							title={editingBuiltin
								? `Exemple : ${p.example} (lecture seule)`
								: `Exemple : ${p.example}`}
							onclick={() => insertPlaceholder(p.token)}
							disabled={editingBuiltin}
						>
							<code>{p.token}</code>
							<span class="var-label">{p.label}</span>
						</button>
					{/each}
				</div>
				<p class="vars-help">
					Ces placeholders sont remplacés par Caddy au moment de la requête
					(pas dans la prévisualisation, qui utilise des valeurs fictives).
				</p>
			</details>
		</div>
	</div>
{/if}

<!-- Delete confirmation -->
{#if deleteTarget}
	<div class="modal-backdrop" onclick={() => (deleteTarget = null)} role="presentation">
		<!-- svelte-ignore a11y_click_events_have_key_events -->
		<div
			class="modal"
			role="dialog"
			aria-modal="true"
			aria-labelledby="delete-modal-title"
			tabindex="-1"
			onclick={(e) => e.stopPropagation()}
		>
			<h3 id="delete-modal-title">Supprimer le template ?</h3>
			<p>
				Supprimer « <strong>{deleteTarget.name}</strong> » est irréversible.
				Les routes qui le référencent reviendront au défaut Arenet branded.
			</p>
			<div class="modal-actions">
				<button class="tb-btn" onclick={() => (deleteTarget = null)} disabled={deleting}>
					Annuler
				</button>
				<button
					class="tb-btn danger"
					onclick={() => void confirmDelete()}
					disabled={deleting}
				>
					{deleting ? 'Suppression…' : 'Supprimer'}
				</button>
			</div>
		</div>
	</div>
{/if}

<style>
	.card {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 16px;
	}

	.loading-wrap {
		display: flex;
		justify-content: center;
		padding: 48px;
	}
	.empty-state {
		text-align: center;
		padding: 48px 24px;
		color: var(--fg-dim);
	}
	.empty-state h3 {
		color: var(--fg);
		font-size: 16px;
		margin: 0 0 8px;
	}
	.empty-state p {
		margin: 0 auto 16px;
		max-width: 520px;
		font-size: 13px;
	}
	.error { color: var(--status-down); }

	/* List view */
	/* Step R Phase 2.1 — builtin row + badge + read-only banner. */
	.tpl-table .builtin-row {
		background: color-mix(in oklch, var(--accent-cyan) 3%, transparent);
	}
	.builtin-badge {
		display: inline-block;
		margin-left: 8px;
		padding: 1px 7px;
		border-radius: 999px;
		background: color-mix(in oklch, var(--accent-cyan) 16%, transparent);
		color: var(--accent-cyan);
		font-family: var(--font-mono);
		font-size: 10px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		vertical-align: middle;
	}
	.builtin-banner {
		padding: 10px 14px;
		font-size: 12.5px;
		color: var(--fg);
		background: color-mix(in oklch, var(--accent-cyan) 8%, transparent);
		border-left: 3px solid var(--accent-cyan);
	}
	.builtin-banner strong {
		color: var(--accent-cyan);
	}

	.tpl-table {
		width: 100%;
		border-collapse: collapse;
		font-size: 13px;
	}
	.tpl-table th {
		text-align: left;
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-dim);
		padding: 8px 12px;
		border-bottom: 1px solid var(--border);
	}
	.tpl-table th.num,
	.tpl-table td.num { text-align: right; }
	.tpl-table th.actions,
	.tpl-table td.actions { text-align: right; }
	.tpl-table td {
		padding: 10px 12px;
		border-bottom: 1px solid var(--border);
	}
	.tpl-table tr:last-child td { border-bottom: none; }
	.tpl-table .dim { color: var(--fg-dim); }
	.tpl-table .mono { font-family: var(--font-mono); font-size: 11.5px; }
	.tpl-table .actions { white-space: nowrap; }
	.tpl-table .actions .tb-btn { margin-left: 6px; }

	/* Editor view */
	.editor-grid {
		display: flex;
		flex-direction: column;
		gap: 12px;
	}
	.meta-card {
		display: flex;
		gap: 16px;
		flex-wrap: wrap;
	}
	.meta-card label {
		display: flex;
		flex-direction: column;
		gap: 4px;
		flex: 1;
		min-width: 240px;
	}
	.meta-label {
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.05em;
		text-transform: uppercase;
		color: var(--fg-dim);
	}
	.meta-input {
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		color: var(--fg);
		padding: 8px 12px;
		font-size: 13px;
		font-family: inherit;
		outline: none;
	}
	.meta-input:focus { border-color: var(--accent-cyan); }

	/* Code tabs */
	.tabs-card { padding: 8px; }
	.code-tabs {
		display: inline-flex;
		gap: 2px;
		padding: 2px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: 999px;
		font-family: var(--font-mono);
	}
	.code-tab {
		padding: 6px 14px;
		border-radius: 999px;
		background: transparent;
		border: none;
		color: var(--fg-dim);
		cursor: pointer;
		font-size: 12px;
		font-weight: 500;
		display: inline-flex;
		align-items: center;
		gap: 4px;
	}
	.code-tab:hover { color: var(--fg); }
	.code-tab.active {
		background: var(--surface-hi);
		color: var(--fg);
		box-shadow: inset 0 0 0 1px var(--border-hi);
	}
	.code-tab.filled .dot { color: var(--accent-cyan); font-size: 8px; }

	/* Editor + preview side by side */
	.editor-card {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 12px;
		padding: 12px;
	}
	@media (max-width: 1200px) {
		.editor-card { grid-template-columns: 1fr; }
	}
	.editor-pane,
	.preview-pane {
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-height: 0;
	}
	.pane-label {
		font-family: var(--font-mono);
		font-size: 10.5px;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--fg-dim);
		display: flex;
		gap: 8px;
		align-items: baseline;
	}
	.pane-label .dim { font-size: 11px; }
	.preview-frame {
		width: 100%;
		min-height: 380px;
		background: white;
		border: 1px solid var(--border);
		border-radius: var(--radius);
	}
	.preview-error {
		padding: 16px;
		color: var(--status-down);
		font-size: 13px;
		border: 1px dashed var(--status-down);
		border-radius: var(--radius);
	}

	/* Variables panel */
	.vars-card details > summary {
		cursor: pointer;
		font-family: var(--font-mono);
		font-size: 11.5px;
		letter-spacing: 0.04em;
		text-transform: uppercase;
		color: var(--fg-dim);
		list-style: none;
	}
	.vars-card details > summary::before { content: '▸ '; }
	.vars-card details[open] > summary::before { content: '▾ '; }
	.vars-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
		gap: 6px;
		margin-top: 12px;
	}
	.var-btn {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 2px;
		padding: 8px 10px;
		background: var(--bg);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		cursor: pointer;
		text-align: left;
		color: var(--fg);
		font-family: inherit;
	}
	.var-btn:hover {
		border-color: var(--accent-cyan);
		background: color-mix(in oklch, var(--accent-cyan) 4%, transparent);
	}
	.var-btn code {
		font-family: var(--font-mono);
		font-size: 11.5px;
		color: var(--accent-cyan);
	}
	.var-label {
		font-size: 11px;
		color: var(--fg-dim);
	}
	.vars-help {
		margin-top: 12px;
		color: var(--fg-muted);
		font-size: 12px;
		font-style: italic;
	}

	/* Buttons */
	.tb-btn {
		padding: 5px 12px;
		border-radius: var(--radius);
		background: var(--bg);
		border: 1px solid var(--border);
		color: var(--fg);
		font-family: var(--font-mono);
		font-size: 11px;
		letter-spacing: 0.04em;
		cursor: pointer;
	}
	.tb-btn:hover:not(:disabled) { border-color: var(--border-hi); color: var(--fg); }
	.tb-btn:disabled { opacity: 0.5; cursor: not-allowed; }
	.tb-btn.primary {
		background: var(--accent-cyan);
		border-color: var(--accent-cyan);
		color: var(--bg);
	}
	.tb-btn.primary:hover:not(:disabled) {
		background: color-mix(in oklch, var(--accent-cyan) 88%, white);
	}
	.tb-btn.danger {
		color: var(--status-down);
		border-color: color-mix(in oklch, var(--status-down) 40%, transparent);
	}
	.tb-btn.danger:hover:not(:disabled) {
		background: color-mix(in oklch, var(--status-down) 12%, transparent);
	}
	.tb-btn.sm { padding: 3px 8px; font-size: 10.5px; }

	/* Modal */
	.modal-backdrop {
		position: fixed;
		inset: 0;
		background: rgba(0, 0, 0, 0.5);
		display: flex;
		align-items: center;
		justify-content: center;
		z-index: 1000;
	}
	.modal {
		background: var(--surface);
		border: 1px solid var(--border);
		border-radius: var(--radius);
		padding: 24px;
		max-width: 480px;
		width: 90%;
	}
	.modal h3 {
		font-size: 16px;
		margin: 0 0 12px;
		color: var(--fg);
	}
	.modal p {
		font-size: 13px;
		color: var(--fg-dim);
		margin: 0 0 20px;
	}
	.modal-actions {
		display: flex;
		justify-content: flex-end;
		gap: 8px;
	}
</style>
