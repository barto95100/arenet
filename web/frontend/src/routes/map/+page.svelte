<!--
  Arenet - Homelab-friendly reverse proxy with integrated security
  Copyright (C) 2026  Ludovic Ramos
  Licensed under the GNU AGPL v3 or later. See LICENSE.

  Step R.2 — Map page placeholder. The real feature (geo-IP map
  with MaxMind GeoLite2) is deferred to a later step; see spec
  §6 "Out of scope" + backlog-step-r.md.
-->
<svelte:head>
	<title>Map · Arenet</title>
</svelte:head>

<div class="coming-soon">
	<div class="eyebrow">Aperçu · Carte</div>
	<h1>Vue géographique</h1>
	<p class="sub">Bientôt disponible — la visualisation géographique des sources de trafic et des décisions CrowdSec arrivera dans une étape future. La fonctionnalité nécessite l'intégration d'une base GeoLite2 (MaxMind) et un nouvel ensemble de handlers backend.</p>
</div>

<style>
	.coming-soon { padding: 48px 32px; max-width: 720px; }
	.eyebrow { color: var(--fg-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
	h1 { color: var(--fg); font-size: 28px; font-weight: 600; margin: 0 0 16px; }
	.sub { color: var(--fg-muted); font-size: 14px; line-height: 1.7; }
</style>
