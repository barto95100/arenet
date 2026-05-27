# SSO provider logos

This directory holds the brand SVG assets rendered on the
`/login` page's "Continuer avec SSO" button (via
`lib/components/SSOProviderLogo.svelte`).

## Files expected

Drop one SVG per provider at the paths below. The frontend
loads them as `<img src="/sso-providers/{kind}.svg" />` where
`kind` is the value persisted on `OIDCConfig.Kind` and exposed
anonymously by `/api/v1/auth/oidc/status`.

| File | Provider | Source |
|------|----------|--------|
| `authentik.svg` | Authentik (goauthentik.io) | https://github.com/goauthentik/authentik — `web/icons/icon.svg` / `icon-left-brand.svg` |
| `keycloak.svg` | Keycloak | https://www.keycloak.org/resources (Press Kit) |
| `authelia.svg` | Authelia | https://github.com/authelia/authelia — `docs/static/images/branding/logo.svg` |

## Licences

Each upstream project distributes its mark under a permissive
licence compatible with Arenet (AGPL-3.0):

- **Authentik** — MIT
- **Keycloak** — Apache 2.0
- **Authelia** — Apache 2.0

Brand asset usage is OK for product integration; the Arenet
binary is not relicensed by carrying these logos as static
files (no derivative work, no modification — they're served
verbatim).

## Visual contract

- Square aspect ratio, transparent background preferred.
- The component renders the SVG inside a 22×22 px box with
  `border-radius: 5px` and a 3 px inner padding (so a square
  logo never touches the edge). A 16×16 or 24×24 viewBox is
  ideal; the component will scale.
- The component falls back to an inline Lucide log-in glyph
  on a neutral orange gradient when:
    - The OIDC `Kind` is empty or unknown.
    - The asset file is missing (the `<img>` will 404 silently
      — the operator sees a blank square next to the label;
      this is benign, the button still works).

## Adding a new provider

1. Add an enum value to `internal/storage/oidc_config.go`
   `OIDCProviderKinds` (last line of the slice).
2. Mirror it in `web/frontend/src/lib/api/types.ts`
   `OIDCProviderKind` and `OIDC_PROVIDER_KINDS`.
3. Add the SVG here at `<newkind>.svg`.
4. Add the kind to the `KNOWN_KINDS` set in
   `SSOProviderLogo.svelte`.

Until these steps are completed, the new provider falls
through to the generic logo (safe default).
