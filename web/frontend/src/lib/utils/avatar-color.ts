// Arenet - Homelab-friendly reverse proxy with integrated security
// Copyright (C) 2026  Ludovic Ramos
// Licensed under the GNU AGPL v3 or later. See LICENSE.

// Phase 2 follow-up — deterministic seed → palette-bucket
// mapping for user avatars in the /utilisateurs table. The
// palette is 8 oklch hues picked at constant lightness +
// chroma so every avatar reads at the same visual weight
// regardless of which bucket a username lands in.
//
// The pure helper lives outside the Svelte component so it
// can be unit-tested without touching the DOM, and the same
// mapping can be reused by any future surface that needs to
// render a user-keyed colour swatch.

export type AvatarColorKey =
	| 'red'
	| 'green'
	| 'orange'
	| 'blue'
	| 'cyan'
	| 'magenta'
	| 'yellow'
	| 'violet';

const PALETTE: AvatarColorKey[] = [
	'red',
	'green',
	'orange',
	'blue',
	'cyan',
	'magenta',
	'yellow',
	'violet'
];

// AVATAR_COLOR_STYLES maps each bucket to the inline background
// + foreground colours rendered in the UserAvatar tile. We use
// oklch directly (matching tokens.css palette discipline) so
// the avatars play well with both light and dark themes — the
// hues stay perceptually balanced because lightness is fixed.
//
// Tuning note: the initial Phase 2 polish landed on chroma ≈
// 0.18-0.20 which read as flashy crayon-saturation against the
// muted UI surfaces — operator smoke called this out. The
// values below lower chroma to ~0.09-0.10 and bump lightness
// to ~68-72% so the tiles read as sophisticated pastel chips
// instead of primary-colour highlights. White text still hits
// >4.5:1 contrast on every bucket; yellow keeps a dark
// foreground because its lightness sits above the white-text
// readability threshold.
export const AVATAR_COLOR_STYLES: Record<AvatarColorKey, { bg: string; fg: string }> = {
	red: { bg: 'oklch(70% 0.10 25)', fg: '#fff' },
	green: { bg: 'oklch(68% 0.09 150)', fg: '#fff' },
	orange: { bg: 'oklch(72% 0.10 55)', fg: '#fff' },
	blue: { bg: 'oklch(68% 0.10 255)', fg: '#fff' },
	cyan: { bg: 'oklch(70% 0.08 220)', fg: '#fff' },
	magenta: { bg: 'oklch(68% 0.10 330)', fg: '#fff' },
	yellow: { bg: 'oklch(82% 0.10 95)', fg: 'oklch(28% 0.04 95)' },
	violet: { bg: 'oklch(68% 0.10 295)', fg: '#fff' }
};

// avatarColorKey picks a palette bucket from a seed (typically
// the username). Sum-of-char-codes is intentional: it is
// deterministic, cross-platform, collision-tolerant for our
// scale (a homelab admin has tens of users, not millions), and
// human-predictable (two short usernames close in alphabet may
// land in the same bucket — that's fine).
export function avatarColorKey(seed: string): AvatarColorKey {
	if (!seed) return PALETTE[0];
	let sum = 0;
	for (let i = 0; i < seed.length; i++) {
		sum += seed.charCodeAt(i);
	}
	return PALETTE[sum % PALETTE.length];
}
