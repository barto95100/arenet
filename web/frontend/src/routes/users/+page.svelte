<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.4.4.a — /users page (promoted from /admin/users per
  the IA reorg, sidebar group "Administration"). Functional
  content unchanged from the K.2 admin/users page: single-table
  view of all admin users with role + auth source + OIDC linkage,
  plus a confirmation modal for role changes.

  /admin/users keeps responding until R.4.5 adds the redirect to
  /users. Both routes render the same content during the
  transition window so no operator action is required.

  Backend gate: RequireAdminMiddleware on the /admin/users API
  endpoints. The same checks apply to the new /users page; the
  frontend belt-and-braces redirect for non-admin viewers stays.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte';
	import { pushToast } from '$lib/stores/toast';
	import { settingsApi } from '$lib/api/settings';
	import {
		ApiError,
		type AdminUser,
		type UserRole
	} from '$lib/api/types';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Badge from '$lib/components/Badge.svelte';
	import Spinner from '$lib/components/Spinner.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';

	let users = $state<AdminUser[]>([]);
	let loading = $state(true);
	let loadError = $state('');

	let confirmOpen = $state(false);
	let pending = $state<{ user: AdminUser; nextRole: UserRole } | null>(null);

	onMount(() => {
		// Belt-and-braces: a viewer can type /users directly. The
		// sidebar hides Administration for non-admins, the API gate
		// 403s the request, but skipping the doomed fetch reads
		// nicer.
		if (auth.state === 'authenticated' && auth.user?.role !== 'admin') {
			void goto('/dashboard');
			return;
		}
		void load();
	});

	async function load(): Promise<void> {
		loading = true;
		loadError = '';
		try {
			users = await settingsApi.listAdminUsers();
		} catch (err) {
			loadError = err instanceof Error ? err.message : 'Failed to load users';
		} finally {
			loading = false;
		}
	}

	function nextRoleFor(u: AdminUser): UserRole {
		return u.role === 'admin' ? 'viewer' : 'admin';
	}

	function actionLabelFor(u: AdminUser): string {
		return u.role === 'admin' ? 'Demote to viewer' : 'Elevate to admin';
	}

	function onRoleClick(u: AdminUser): void {
		pending = { user: u, nextRole: nextRoleFor(u) };
		confirmOpen = true;
	}

	async function confirmRoleChange(): Promise<void> {
		if (!pending) return;
		const { user, nextRole } = pending;
		try {
			const updated = await settingsApi.updateUserRole(user.id, { role: nextRole });
			users = users.map((u) => (u.id === updated.id ? updated : u));
			pushToast(
				`${user.username} → ${nextRole === 'admin' ? 'admin' : 'viewer'}`,
				'success'
			);
		} catch (err) {
			if (err instanceof ApiError) {
				pushToast(err.message, 'danger');
			} else if (err instanceof Error) {
				pushToast(err.message, 'danger');
			} else {
				pushToast('Failed to change role', 'danger');
			}
		} finally {
			confirmOpen = false;
			pending = null;
		}
	}
</script>

<svelte:head>
	<title>Users · Arenet</title>
</svelte:head>

<PageHeader
	eyebrow="Administration · Utilisateurs"
	title="Users"
	subtitle="Manage admin roles and view OIDC linkage status."
/>

<Card padding="p-6">
	{#if loading}
		<div class="flex justify-center py-8">
			<Spinner size="md" />
		</div>
	{:else if loadError}
		<p class="text-sm text-down" role="alert">
			Failed to load users: {loadError}
		</p>
	{:else if users.length === 0}
		<p class="text-sm text-muted">No users yet.</p>
	{:else}
		<table class="w-full">
			<thead>
				<tr class="text-left text-xs uppercase tracking-wider text-muted border-b border-border-subtle">
					<th class="px-4 py-3 font-medium">User</th>
					<th class="px-4 py-3 font-medium">Source</th>
					<th class="px-4 py-3 font-medium">Role</th>
					<th class="px-4 py-3 font-medium">Last login</th>
					<th class="px-4 py-3 font-medium text-right"></th>
				</tr>
			</thead>
			<tbody class="divide-y divide-border-subtle">
				{#each users as u (u.id)}
					<tr>
						<td class="px-4 py-3 text-sm">
							<div class="font-medium text-primary">{u.username}</div>
							{#if u.displayName && u.displayName !== u.username}
								<div class="text-xs text-muted">{u.displayName}</div>
							{/if}
						</td>
						<td class="px-4 py-3 text-sm">
							{#if u.authSource === 'oidc'}
								<Badge variant="status-up">OIDC</Badge>
							{:else}
								<Badge variant="neutral">Local</Badge>
							{/if}
							{#if u.oidcLinked && u.authSource !== 'oidc'}
								<span class="ml-1 text-xs text-muted">(SSO-linked)</span>
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
							{u.lastLoginAt ?? '—'}
						</td>
						<td class="px-4 py-3 text-sm text-right">
							<Button
								variant="ghost"
								size="sm"
								onclick={() => onRoleClick(u)}
							>
								{actionLabelFor(u)}
							</Button>
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	{/if}
</Card>

<ConfirmDialog
	bind:open={confirmOpen}
	title={pending ? `${pending.nextRole === 'admin' ? 'Elevate' : 'Demote'} ${pending.user.username}?` : ''}
	message={pending
		? pending.nextRole === 'admin'
			? `${pending.user.username} will gain full admin access (CRUD on routes, settings, and users).`
			: `${pending.user.username} will lose write access. Local admin demotions are blocked if this is the last local admin (break-glass invariant).`
		: ''}
	confirmLabel={pending?.nextRole === 'admin' ? 'Elevate' : 'Demote'}
	confirmVariant={pending?.nextRole === 'admin' ? 'primary' : 'danger'}
	onConfirm={confirmRoleChange}
/>
