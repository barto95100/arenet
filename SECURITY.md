<!-- Arenet — security policy. AGPL-3.0, see LICENSE. -->

# Security policy

Arenet sits in front of other people's services. A flaw here can
expose everything behind it, so reports are welcome and taken
seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security flaw.**

Use GitHub's private vulnerability reporting:

**[Report a vulnerability](https://github.com/barto95100/arenet/security/advisories/new)**

That form is private between you and the maintainer, supports
attachments, and becomes a published advisory with credit to you once a
fix ships — or stays closed and unpublished if the report turns out not
to be a vulnerability.

If the form is unavailable for you, open a public issue saying only
*"I have a security report and cannot use the advisory form"*, with no
technical detail, and a private channel will be arranged.

### What helps

Whatever you have is better than nothing, but a report is quickest to
act on when it says:

- the affected file or endpoint, ideally with a line reference;
- whether it is reachable **unauthenticated** and from which side —
  the admin API (`:8001`, loopback-bound by default on systemd) or the
  proxied data plane (`:80` / `:443`, which faces the internet by
  design);
- the steps to reproduce, and the Arenet version (`arenet --version`,
  or the About card in Settings);
- what an attacker gets out of it.

Proof-of-concept code is welcome and will not be redistributed.

## What to expect

Arenet is a single-maintainer project, so these are honest
expectations rather than a service-level agreement:

| | |
| --- | --- |
| First reply | within 7 days |
| Assessment, with a severity and a plan | within 14 days |
| Fix for something unauthenticated-reachable on the data plane | prioritised over all other work |

You will be told which of those applies, including if the answer is
"this is a real flaw and the fix will take a while" or "this is
working as intended, and here is why".

Please allow 90 days before public disclosure, or less by agreement —
for a flaw that is trivially exploitable and already shipped, faster is
usually better for the people running it.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest `v2.x` release | Yes |
| Anything older | No — upgrade first |

Fixes land in a new patch release on the current line. There are no
backports to earlier minors: the project ships frequently and the
upgrade path is a container tag or a binary swap.

## Scope

**In scope** — anything in this repository: the admin REST API and
WebSocket, the web UI, the Caddy configuration Arenet generates, the
WAF/CrowdSec/rate-limit/country-block integrations, authentication and
sessions (local, OIDC, service accounts, forward-auth), the backup
format and its secret handling, the storage layer and its migrations,
and the packaging (Docker image, systemd unit, install script).

Configuration and documentation count too. A document that tells an
operator a setting is their security boundary when it is not is a real
finding — one such case was fixed in v2.73.

**Out of scope** — flaws in the embedded upstreams themselves, which
have their own disclosure channels: Caddy, Coraza and the OWASP CRS,
CrowdSec and its Caddy bouncer, certmagic. Report those to the project
concerned. If Arenet *configures* one of them insecurely, that is in
scope here.

Also out of scope: an operator deliberately exposing the admin API to
the internet over plain HTTP. It is documented as a footgun, the
default binds loopback, and the hardening checklist covers it.

## Credit

Reporters are credited in the advisory and the release notes unless
they ask not to be.
