# Arenet Admin UI

SvelteKit frontend for the Arenet admin API.

## Prerequisites

- Node.js ≥ 20
- The Arenet Go binary running on `:8001` (see top-level `make run`)

## Local development

In one terminal, copy the env example and start Vite:

```bash
cd web/frontend
cp .env.example .env       # VITE_API_BASE_URL=http://localhost:8001
npm install
npm run dev
```

In another terminal, start the backend:

```bash
make run                   # builds and runs Arenet with --dev on :8001
```

Open `http://localhost:5173`. Vite serves the UI; API calls go to `:8001`.
CORS is allowed cross-origin because the binary is in `--dev` mode.

Stop Vite with `Ctrl+C`. Stop Arenet with `Ctrl+C` too — the binary handles
SIGINT/SIGTERM with an ordered shutdown (admin server → Caddy → store).

## Production build

```bash
npm run build
```

This emits a static SPA into `web/frontend/build/`. The Go binary embeds
that directory via `//go:embed all:frontend/build` (see `web/embed.go`).
In production mode (no `--dev` flag), the binary serves both the UI and
the API on the same port — typically `:8001` — so `VITE_API_BASE_URL`
should be empty (or omitted) and the client hits same-origin paths.

For a full end-to-end build from the repository root:

```bash
make build                 # runs npm install + npm run build + go build
./bin/arenet               # serves UI + API on :8001
```

## Stack

- SvelteKit 2 / Svelte 5 (runes mode), TypeScript strict
- Tailwind CSS v3 with custom design tokens via CSS variables
- `@sveltejs/adapter-static` with `fallback: '200.html'` (SPA mode)
- Self-hosted Inter + JetBrains Mono fonts under `static/fonts/`
- No automated tests yet — manual visual validation only. Vitest is
  planned for Step E alongside the topology page (D3 + WebSocket).

## Layout

```
src/
├── app.css                       Tailwind + CSS variables + @font-face
├── app.html
├── app.d.ts
├── routes/
│   ├── +layout.svelte            Sidebar shell + ToastContainer + shimmer
│   ├── +layout.ts                prerender=true, ssr=false
│   ├── +page.svelte              / → /routes redirect
│   ├── routes/+page.svelte       Routes management (the main page)
│   ├── topology/+page.svelte     Placeholder (Step E)
│   ├── security/+page.svelte     Placeholder (later step)
│   └── settings/+page.svelte     Placeholder (later step)
└── lib/
    ├── api/                      client.ts, types.ts
    ├── stores/                   toast.ts, loading.ts
    └── components/               Sidebar, Button, Input, Modal, …
```
