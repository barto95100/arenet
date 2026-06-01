<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.2 stub. Real content lands in R.4 — WAF-specific
  configuration (Coraza paranoia + CRS category event counts +
  per-route status). Most widgets shown in the mock are out-of-
  scope feature gaps (see spec §6.1 WAF audit).
-->
<svelte:head>
	<title>WAF · Arenet</title>
</svelte:head>

<div class="stub">
	<div class="eyebrow">Sécurité · Web Application Firewall</div>
	<h1>Règles WAF</h1>
	<p class="sub">Page en cours de migration — contenu livré en R.4. Les événements WAF actuels restent accessibles sur <a href="/security">/security</a>.</p>
</div>

<style>
	.stub { padding: 32px; max-width: 720px; }
	.eyebrow { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
	h1 { color: var(--fg); font-size: 28px; font-weight: 600; margin: 0 0 12px; }
	.sub { color: var(--fg-muted); font-size: 14px; line-height: 1.6; }
	.sub a { color: var(--accent); }
</style>
