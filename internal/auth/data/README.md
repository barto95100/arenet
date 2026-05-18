# Common passwords (top-10k)

This directory contains the gzipped list of the 10 000 most common
compromised passwords, embedded into the Arenet binary via `//go:embed`
(see `internal/auth/password.go`). Spec §7.4.

## Source

- URL: <https://raw.githubusercontent.com/danielmiessler/SecLists/449409991e08bd5068436d60138ee25cc8f9b316/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt>
- Repository: <https://github.com/danielmiessler/SecLists>
- License: MIT (compatible with this project's AGPL-3.0)
- SecLists commit SHA at download: `449409991e08bd5068436d60138ee25cc8f9b316`
- Download date: 2026-05-18
- Raw file size: 76497 bytes (~76 KB)
- Gzipped file size: 38148 bytes (~37 KB)
- SHA256 of `common-passwords.txt.gz`:
  `836993a8fb0b2fa63cf356861b26e9fbcecb01c77b71036a901e8b83c23d807c`

The file is the xato-net 10-million-passwords top-10k slice, renamed
from `10-million-password-list-top-10000.txt` to
`xato-net-10-million-passwords-10000.txt` upstream by SecLists. Same
underlying data source; only the filename changed.

## Regenerate

To reproduce exactly (same content):

```sh
curl -L -o common-passwords.txt \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/449409991e08bd5068436d60138ee25cc8f9b316/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
gzip -9 common-passwords.txt
mv common-passwords.txt.gz internal/auth/data/
shasum -a 256 internal/auth/data/common-passwords.txt.gz
# Expect: 836993a8fb0b2fa63cf356861b26e9fbcecb01c77b71036a901e8b83c23d807c
```

To refresh to the latest upstream (content may differ; update this
README accordingly before committing):

```sh
curl -L -o common-passwords.txt \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/xato-net-10-million-passwords-10000.txt"
gzip -9 common-passwords.txt
mv common-passwords.txt.gz internal/auth/data/
# Update SecLists commit SHA, download date, sizes and SHA256 above.
```

## Format

- One password per line, UTF-8 encoded, no header.
- Mixed case may appear; `isCommonPassword` does case-insensitive
  lookup (lowercases at load time and at query time).
- 10000 lines exactly.
- Sorted by descending frequency in the underlying xato-net corpus
  (line 1 = most common: `123456`).
