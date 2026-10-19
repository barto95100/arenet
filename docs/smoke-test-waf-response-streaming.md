<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
-->

# Smoke test — WAF response-body streaming (v2.77.0, issue #317)

Validates that a route serving a never-ending / chunked response behind
the WAF can stream it to the client instead of being buffered.

## Setup

- A route whose WAF runs the CRS (`wafMode` = detect or block), proxying
  an app that streams a `text/plain` response with no end: Home Assistant
  (`/api/hassio/.../logs/follow`), any SSE endpoint, a long log tail.

## Reproduce the bug (toggle OFF)

1. WAF in **detect** (or block), **Response streaming mode OFF**.
2. Open the streaming view (HA add-on "Logs" tab, or `curl -N` the SSE
   endpoint through Arenet).
3. It **hangs** on "Loading…": the WAF holds the body in its 512 KiB
   buffer and sends nothing until the response ends. Direct to the backend
   (`http://<ip>:<port>`) it works — proving Arenet's WAF is the holder.

## Fix (toggle ON)

1. Edit the route → **WAF** block → **Streaming** → enable **Response body
   (log tails, SSE, downloads)**. Save.
2. Reopen the streaming view: the first chunk arrives in **< 2 s** and it
   keeps scrolling, in **detect AND block** mode.

## What stays protected

- Request URL, headers, and body (unless upload streaming is also on).
- Response **headers** (phase 3).
- Only the response **body** bytes are no longer buffered/scanned, and
  only on this route. No weaker than `WAFMode=off`, far more surgical.

## Non-regression

- A route with the toggle OFF behaves exactly as before (the emitted
  config is byte-identical — `TestBuildConfigJSON_ResponseStreamingOff_ByteIdentical`).
- A CRS request rule (e.g. a SQLi in the query string) still blocks in
  block mode with the toggle ON — only the response body is exempt.

## Notes

- Route-wide, mirroring **Upload streaming mode** (request side). The two
  live together under the WAF block's "Streaming" controls.
- Done in Go (the interceptor), not via SecLang — the SecLang editor's
  `ctl:` policy (decision S1) is untouched.
