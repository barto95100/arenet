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
export const AVATAR_COLOR_STYLES: Record<AvatarColorKey, { bg: string; fg: string }> = {
	red: { bg: 'oklch(58% 0.20 25)', fg: '#fff' },
	green: { bg: 'oklch(52% 0.16 150)', fg: '#fff' },
	orange: { bg: 'oklch(62% 0.18 50)', fg: '#fff' },
	blue: { bg: 'oklch(54% 0.18 255)', fg: '#fff' },
	cyan: { bg: 'oklch(58% 0.13 220)', fg: '#fff' },
	magenta: { bg: 'oklch(56% 0.20 330)', fg: '#fff' },
	yellow: { bg: 'oklch(72% 0.16 95)', fg: '#000' },
	violet: { bg: 'oklch(52% 0.20 295)', fg: '#fff' }
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
