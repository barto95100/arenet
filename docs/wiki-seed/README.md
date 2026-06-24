# Wiki seed

This folder holds the GitHub Wiki pages as draft Markdown files. They're committed in the main repo as a working copy ; the actual rendering lives at https://github.com/barto95100/arenet/wiki

## How to push these to the wiki

The wiki is a **separate git repo** at `git@github.com:barto95100/arenet.wiki.git`. Initialize it via the GitHub UI (any one-page "Create the first page" action) before cloning.

```bash
# 1. Clone the wiki repo somewhere outside this checkout
cd /tmp
git clone git@github.com:barto95100/arenet.wiki.git
cd arenet.wiki

# 2. Copy every .md from docs/wiki-seed/ (except this README)
cp /path/to/arenet/docs/wiki-seed/*.md .
rm README.md  # this file isn't part of the wiki

# 3. Commit + push
git add -A
git commit -m "docs(wiki): seed initial 10 pages + sidebar"
git push origin master
```

The wiki updates immediately. Navigate to https://github.com/barto95100/arenet/wiki to verify.

## Pages

| File | Wiki page name | What |
| ---- | -------------- | ---- |
| `Home.md` | Home | TOC + project overview ; the wiki's landing page |
| `Installation.md` | Installation | Docker + systemd install paths |
| `Routes.md` | Routes | Per-route lifecycle, fields, common patterns |
| `Topology.md` | Topology | Live graph dashboard explainer |
| `WAF.md` | WAF | Coraza + OWASP CRS, FP triage, exclusion patterns |
| `CrowdSec.md` | CrowdSec | Bouncer + agent setup, observability, fail-open behaviour |
| `Country-Block.md` | Country-Block | Per-route GeoIP allow/deny |
| `Rate-Limit.md` | Rate-Limit | Per-route throttling patterns |
| `OIDC-SSO.md` | OIDC-SSO | IdP integration, RBAC, allowlist, break-glass |
| `Backup-Restore.md` | Backup-Restore | Snapshot format, sentinel resolution, disaster recovery |
| `Alerting.md` | Alerting | Step AL : channels + rules + sources + templates |
| `Custom-Error-Pages.md` | Custom-Error-Pages | 3-layer resolution, template editor, Caddy placeholders |
| `Troubleshooting.md` | Troubleshooting | Symptoms + diagnostic recipes |
| `_Sidebar.md` | (sidebar) | GitHub-Wiki-specific : renders as the persistent left sidebar |

## Editing rules

- Keep links to **wiki pages** as bare names without `.md` (GitHub Wiki convention) : `[WAF](WAF)` not `[WAF](WAF.md)`
- Keep links to **main repo files** as full GitHub URLs : `[`docs/...`](https://github.com/barto95100/arenet/blob/main/docs/...)` so the link works from both the wiki AND from this seed folder
- Every page ends with a "See also" section linking related wiki pages + the relevant `internal/` Go source files for operators who want to dig deeper
