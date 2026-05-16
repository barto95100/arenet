// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

import type { Config } from 'tailwindcss';

const config: Config = {
	content: ['./src/**/*.{html,js,ts,svelte}'],
	theme: {
		extend: {
			colors: {
				base: 'var(--bg-base)',
				sidebar: 'var(--bg-sidebar)',
				elevated: 'var(--bg-elevated)',
				surface: 'var(--bg-surface)',
				hover: 'var(--bg-hover)',
				'border-subtle': 'var(--border-subtle)',
				'border-default': 'var(--border-default)',
				'border-strong': 'var(--border-strong)',
				primary: 'var(--text-primary)',
				secondary: 'var(--text-secondary)',
				muted: 'var(--text-muted)',
				inverse: 'var(--text-inverse)',
				cyan: 'var(--accent-cyan)',
				'cyan-dark': 'var(--accent-cyan-d)',
				up: 'var(--status-up)',
				warn: 'var(--status-warn)',
				down: 'var(--status-down)',
				info: 'var(--status-info)'
			},
			fontFamily: {
				sans: ['Inter', 'system-ui', 'sans-serif'],
				mono: ['JetBrains Mono', 'ui-monospace', 'monospace']
			},
			fontSize: {
				xs: '12px',
				sm: '14px',
				base: '16px',
				lg: '20px',
				'2xl': '28px',
				'4xl': '36px'
			},
			boxShadow: {
				'glow-cyan': '0 0 16px rgba(0, 217, 255, 0.4)',
				'glow-green': '0 0 12px rgba(0, 255, 136, 0.4)',
				'glow-red': '0 0 12px rgba(255, 71, 87, 0.4)'
			}
		}
	},
	plugins: []
};

export default config;
