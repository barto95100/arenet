// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Vite env augmentation (Step F Chunk 6.3). Declares the project's
// custom VITE_APP_VERSION variable so consumers get type-checking and
// editor autocomplete rather than the fallback `any` that vite's
// built-in ImportMetaEnv exposes for unknown keys.
//
// The value is computed at build/dev startup by vite.config.ts via
// `git describe --tags --always`. Falls back to 'unknown' if git is
// unavailable. See the About section in /settings for the consumer.

/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_APP_VERSION: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}
