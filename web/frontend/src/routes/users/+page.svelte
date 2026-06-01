<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.2 stub. Real content lands in R.4 — users + SSO providers
  moved from /admin/users into the top-level /users route per IA
  reorg (Sidebar group "Administration").
-->
<svelte:head>
	<title>Utilisateurs · Arenet</title>
</svelte:head>

<div class="stub">
	<div class="eyebrow">Administration · Utilisateurs</div>
	<h1>Utilisateurs &amp; identités</h1>
	<p class="sub">Page en cours de migration — contenu livré en R.4. La source actuelle reste accessible sur <a href="/admin/users">/admin/users</a>.</p>
</div>

<style>
	.stub { padding: 32px; max-width: 720px; }
	.eyebrow { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
	h1 { color: var(--fg); font-size: 28px; font-weight: 600; margin: 0 0 12px; }
	.sub { color: var(--fg-muted); font-size: 14px; line-height: 1.6; }
	.sub a { color: var(--accent); }
</style>
