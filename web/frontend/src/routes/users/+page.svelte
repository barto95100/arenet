<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Users-page Phase 1 refactor — full rewrite matching the
  operator-supplied mockup at
  docs/mocks/pages/screen/users-page-tarfer.png. Surfaces the
  enriched backend response (email, lastActivityAt,
  activeSessionCount) from commit 1 and adds:
    - 4 KPI cards (Total / Admins / OIDC / Local)
    - Search + role + source filters (frontend-pure)
    - 2-col layout (table left + OIDC summary sidebar right)
    - Online / Actif / Hors-ligne indicator
    - BREAK-GLASS badge on local admins when OIDC is active
    - DELETE action with ConfirmDialog + self-row UX guard

  Out-of-scope (Phase 2-4): "Tester connexion" SSO button,
  invitations card, service accounts, manual email edit.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import { authApi } from '$lib/api/auth';
	import {
		ApiError,
		type AdminUser,
		type UserRole
	} from '$lib/api/types';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import StatCard from '$lib/components/StatCard.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import OIDCConfigSummary from '$lib/components/OIDCConfigSummary.svelte';

	let users = $state<AdminUser[]>([]);
	let loading = $state(true);
	let loadError = $state('');
	let oidcEnabled = $state(false);

	let confirmRoleOpen = $state(false);
	let pendingRole = $state<{ user: AdminUser; nextRole: UserRole } | null>(null);

	let confirmDeleteOpen = $state(false);
	let pendingDelete = $state<AdminUser | null>(null);

	// Search + filter state — pure frontend filtering over the
	// full users[] (admin volumes < 50 — no API surface needed).
	let search = $state('');
	type RoleFilter = 'all' | 'admin' | 'viewer';
	type SourceFilter = 'all' | 'local' | 'oidc';
	let roleFilter = $state<RoleFilter>('all');
	let sourceFilter = $state<SourceFilter>('all');

	onMount(async () => {
		// Belt-and-braces: viewers can type /users directly. The
		// sidebar hides the Administration group for non-admins,
		// the API gate 403s the request, but skipping the doomed
		// fetch reads nicer.
		if (auth.state === 'authenticated' && auth.user?.role !== 'admin') {
			void goto('/dashboard');
			return;
		}
		await load();
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			const [list, oidcStatus] = await Promise.all([
				settingsApi.listAdminUsers(),
				// Anonymous endpoint — break-glass criterion is
				// "OIDC currently active". If OIDC is disabled, no
				// admin is in break-glass mode anymore (no SSO
				// channel to be the alternative to).
				authApi.oidcStatus().catch(() => ({ enabled: false }))
			]);
			users = list;
			oidcEnabled = oidcStatus.enabled ?? false;
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	// --- KPI derivations --------------------------------------

	const counts = $derived.by(() => {
		const total = users.length;
		const admins = users.filter((u) => u.role === 'admin').length;
		const viewers = total - admins;
		const oidc = users.filter((u) => u.authSource === 'oidc').length;
		const local = total - oidc;
		const localAdmins = users.filter(
			(u) => u.authSource === 'local' && u.role === 'admin'
		).length;
		return { total, admins, viewers, oidc, local, localAdmins };
	});

	const subtitle = $derived(
		`${counts.total} compte${counts.total > 1 ? 's' : ''} — ` +
			`${counts.admins} admin${counts.admins > 1 ? 's' : ''}, ` +
			`${counts.viewers} viewer${counts.viewers > 1 ? 's' : ''} · ` +
			`${counts.oidc} OIDC, ${counts.local} local`
	);

	// --- Filtering --------------------------------------------

	const filteredUsers = $derived.by(() => {
		const q = search.trim().toLowerCase();
		return users.filter((u) => {
			if (roleFilter !== 'all' && u.role !== roleFilter) return false;
			if (sourceFilter !== 'all' && u.authSource !== sourceFilter) return false;
			if (q === '') return true;
			return (
				u.username.toLowerCase().includes(q) ||
				u.displayName.toLowerCase().includes(q) ||
				(u.email ?? '').toLowerCase().includes(q) ||
				u.role.includes(q) ||
				u.authSource.includes(q)
			);
		});
	});

	// --- Activity & break-glass derivations -------------------

	type ActivityState = 'online' | 'active' | 'offline';
	function activityFor(u: AdminUser): ActivityState {
		if (u.activeSessionCount > 0 && u.lastActivityAt) {
			const lastMs = new Date(u.lastActivityAt).getTime();
			const ageMs = Date.now() - lastMs;
			if (ageMs <= 5 * 60 * 1000) return 'online';
			if (ageMs <= 60 * 60 * 1000) return 'active';
		}
		return 'offline';
	}

	function activityLabel(state: ActivityState): string {
		switch (state) {
			case 'online':
				return 'En ligne';
			case 'active':
				return 'Actif';
			case 'offline':
				return 'Hors-ligne';
		}
	}

	function activityVariant(
		state: ActivityState
	): 'status-up' | 'status-warn' | 'neutral' {
		switch (state) {
			case 'online':
				return 'status-up';
			case 'active':
				return 'status-warn';
			case 'offline':
				return 'neutral';
		}
	}

	function isBreakGlass(u: AdminUser): boolean {
		// Break-glass criterion (Phase 1 simplification): local
		// admin while OIDC is currently active. If OIDC is
		// disabled, every admin is equivalent — no break-glass
		// distinction needed.
		return u.authSource === 'local' && u.role === 'admin' && oidcEnabled;
	}

	function initials(u: AdminUser): string {
		const source = u.displayName || u.username;
		const parts = source.split(/[\s.\-_]+/).filter(Boolean);
		if (parts.length === 0) return '?';
		if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
		return (parts[0][0] + parts[1][0]).toUpperCase();
	}

	function relativeFromNow(iso: string | undefined): string {
		if (!iso) return '—';
		const ms = Date.now() - new Date(iso).getTime();
		const minutes = Math.floor(ms / 60000);
		if (minutes < 1) return 'à l’instant';
		if (minutes < 60) return `il y a ${minutes} min`;
		const hours = Math.floor(minutes / 60);
		if (hours < 24) return `il y a ${hours} h`;
		const days = Math.floor(hours / 24);
		return `il y a ${days} j`;
	}

	// --- Action handlers --------------------------------------

	function nextRoleFor(u: AdminUser): UserRole {
		return u.role === 'admin' ? 'viewer' : 'admin';
	}

	function onRoleClick(u: AdminUser): void {
		pendingRole = { user: u, nextRole: nextRoleFor(u) };
		confirmRoleOpen = true;
	}

	async function confirmRoleChange(): Promise<void> {
		if (!pendingRole) return;
		const { user, nextRole } = pendingRole;
		try {
			const updated = await settingsApi.updateUserRole(user.id, { role: nextRole });
			users = users.map((u) => (u.id === updated.id ? updated : u));
			pushToast(
				`${user.username} → ${nextRole === 'admin' ? 'admin' : 'viewer'}`,
				'success'
			);
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : 'Failed to change role');
			pushToast(msg, 'danger');
		} finally {
			confirmRoleOpen = false;
			pendingRole = null;
		}
	}

	function onDeleteClick(u: AdminUser): void {
		pendingDelete = u;
		confirmDeleteOpen = true;
	}

	async function confirmDelete(): Promise<void> {
		if (!pendingDelete) return;
		const u = pendingDelete;
		try {
			await settingsApi.deleteAdminUser(u.id);
			users = users.filter((x) => x.id !== u.id);
			pushToast(`${u.username} supprimé`, 'success');
		} catch (err) {
			const msg = err instanceof ApiError ? err.message : (err instanceof Error ? err.message : 'Failed to delete user');
			pushToast(msg, 'danger');
		} finally {
			confirmDeleteOpen = false;
			pendingDelete = null;
		}
	}
</script>

<svelte:head>
	<title>Utilisateurs · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Administration · Utilisateurs"
	title="Utilisateurs"
	subtitle={subtitle}
/>

{#if loading}
	<div class="flex justify-center py-12"><Spinner size="md" /></div>
{:else if loadError}
	<Card padding="p-6">
		<p class="text-sm text-down" role="alert">
			Failed to load users: {loadError}
		</p>
	</Card>
{:else}
	<!-- KPI strip (4-up). All values derive from users[]. -->
	<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6" data-testid="users-kpi-strip">
		<StatCard
			label="Total"
			value={counts.total}
			hint="comptes actifs"
		/>
		<StatCard
			label="Admins"
			value={counts.admins}
			hint={`${counts.localAdmins} local · ${counts.admins - counts.localAdmins} OIDC`}
		/>
		<StatCard
			label="Comptes SSO"
			value={counts.oidc}
			hint="auto-créés via OIDC"
		/>
		<StatCard
			label="Comptes locaux"
			value={counts.local}
			hint={oidcEnabled
				? `${counts.localAdmins} en break-glass`
				: 'gérés manuellement'}
		/>
	</div>

	<div class="grid grid-cols-1 xl:grid-cols-[1.3fr_1fr] gap-4 items-start">
		<!-- LEFT — users table -->
		<div class="rounded-lg border border-border-subtle bg-elevated overflow-hidden">
			<!-- Filter bar -->
			<div class="px-4 py-3 border-b border-border-subtle flex items-center gap-3 flex-wrap">
				<div class="flex-1 min-w-[200px] flex items-center gap-2 px-2 py-1 rounded-md bg-surface border border-border-default">
					<svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true">
						<circle cx="7" cy="7" r="5" />
						<path d="M11 11l3 3" />
					</svg>
					<input
						type="search"
						bind:value={search}
						placeholder="Rechercher (nom, email, rôle, source)…"
						aria-label="Filter users"
						class="flex-1 bg-transparent outline-none text-sm text-primary placeholder-muted"
					/>
				</div>
				<div class="flex items-center gap-1" data-testid="role-filter">
					{#each [['all', 'Tous'], ['admin', 'Admins'], ['viewer', 'Viewers']] as [val, label] (val)}
						<button
							type="button"
							class:active={roleFilter === val}
							class="filter-chip"
							onclick={() => (roleFilter = val as RoleFilter)}
						>
							{label}
						</button>
					{/each}
				</div>
				<div class="flex items-center gap-1" data-testid="source-filter">
					{#each [['all', 'Tous'], ['local', 'Local'], ['oidc', 'OIDC']] as [val, label] (val)}
						<button
							type="button"
							class:active={sourceFilter === val}
							class="filter-chip"
							onclick={() => (sourceFilter = val as SourceFilter)}
						>
							{label}
						</button>
					{/each}
				</div>
			</div>

			{#if filteredUsers.length === 0}
				<div class="p-6 text-sm text-muted">Aucun utilisateur ne correspond aux filtres.</div>
			{:else}
				<table class="w-full">
					<thead>
						<tr class="text-left text-xs uppercase tracking-wider text-muted border-b border-border-subtle">
							<th class="px-4 py-3 font-medium">Utilisateur</th>
							<th class="px-4 py-3 font-medium">Source</th>
							<th class="px-4 py-3 font-medium">Rôle</th>
							<th class="px-4 py-3 font-medium">Dernière activité</th>
							<th class="px-4 py-3 font-medium">État</th>
							<th class="px-4 py-3 font-medium text-right">Actions</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-border-subtle">
						{#each filteredUsers as u (u.id)}
							{@const isSelf = auth.user?.id === u.id}
							{@const breakGlass = isBreakGlass(u)}
							{@const state = activityFor(u)}
							<tr data-testid="user-row-{u.id}">
								<td class="px-4 py-3 text-sm">
									<div class="flex items-center gap-3">
										<div class="avatar" aria-hidden="true">{initials(u)}</div>
										<div>
											<div class="font-medium text-primary flex items-center gap-2">
												<span>{u.displayName || u.username}</span>
												{#if isSelf}
													<span data-testid="self-badge-{u.id}">
														<Badge variant="status-info">VOUS</Badge>
													</span>
												{/if}
											</div>
											<div class="text-xs text-muted">
												{u.email || '—'}
											</div>
										</div>
									</div>
								</td>
								<td class="px-4 py-3 text-sm">
									{#if u.authSource === 'oidc'}
										<Badge variant="status-info">OIDC</Badge>
									{:else}
										<Badge variant="neutral">Local</Badge>
									{/if}
									{#if breakGlass}
										<span class="ml-1" data-testid="break-glass-badge-{u.id}">
											<Badge variant="status-warn">BREAK-GLASS</Badge>
										</span>
									{/if}
								</td>
								<td class="px-4 py-3 text-sm">
									{#if u.role === 'admin'}
										<Badge variant="status-up">Admin</Badge>
									{:else}
										<Badge variant="neutral">Viewer</Badge>
									{/if}
								</td>
								<td class="px-4 py-3 text-sm text-secondary">
									{relativeFromNow(u.lastActivityAt ?? u.lastLoginAt)}
								</td>
								<td class="px-4 py-3 text-sm">
									<Badge variant={activityVariant(state)}>
										{activityLabel(state)}
									</Badge>
								</td>
								<td class="px-4 py-3 text-sm text-right">
									<div class="flex justify-end gap-1">
										<Button
											variant="ghost"
											size="sm"
											onclick={() => onRoleClick(u)}
										>
											{u.role === 'admin' ? 'Rétrograder' : 'Promouvoir'}
										</Button>
										{#if !isSelf}
											<Button
												variant="ghost"
												size="sm"
												onclick={() => onDeleteClick(u)}
												data-testid="delete-btn-{u.id}"
											>
												Supprimer
											</Button>
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}
		</div>

		<!-- RIGHT — sidebar with OIDC read-only summary -->
		<div class="flex flex-col gap-4">
			<OIDCConfigSummary />
		</div>
	</div>
{/if}

<ConfirmDialog
	bind:open={confirmRoleOpen}
	title={pendingRole ? `${pendingRole.nextRole === 'admin' ? 'Promouvoir' : 'Rétrograder'} ${pendingRole.user.username} ?` : ''}
	message={pendingRole
		? pendingRole.nextRole === 'admin'
			? `${pendingRole.user.username} obtiendra l'accès admin complet (CRUD sur routes, settings et utilisateurs).`
			: `${pendingRole.user.username} perdra l'accès en écriture. La rétrogradation du dernier admin local est bloquée (invariant break-glass).`
		: ''}
	confirmLabel={pendingRole?.nextRole === 'admin' ? 'Promouvoir' : 'Rétrograder'}
	confirmVariant={pendingRole?.nextRole === 'admin' ? 'primary' : 'danger'}
	onConfirm={confirmRoleChange}
/>

<ConfirmDialog
	bind:open={confirmDeleteOpen}
	title={pendingDelete ? `Supprimer ${pendingDelete.username} ?` : ''}
	message={pendingDelete
		? `${pendingDelete.username} sera supprimé définitivement et toutes ses sessions invalidées. La suppression du dernier admin local est bloquée (invariant break-glass).`
		: ''}
	confirmLabel="Supprimer"
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>

<style>
	.avatar {
		width: 32px;
		height: 32px;
		border-radius: 50%;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		background: color-mix(in oklch, var(--accent-cyan) 18%, transparent);
		color: var(--accent-cyan);
		font-size: 11px;
		font-weight: 600;
		font-family: var(--font-mono);
		flex: none;
	}
	.filter-chip {
		font-size: 12px;
		padding: 4px 10px;
		border-radius: 6px;
		color: var(--text-secondary);
		background: transparent;
		border: 1px solid transparent;
		cursor: pointer;
		transition: background-color 120ms, color 120ms, border-color 120ms;
	}
	.filter-chip:hover {
		background: var(--bg-elevated);
		color: var(--text-primary);
	}
	.filter-chip.active {
		background: color-mix(in oklch, var(--accent-cyan) 16%, transparent);
		color: var(--accent-cyan);
		border-color: color-mix(in oklch, var(--accent-cyan) 32%, transparent);
	}
</style>
