<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Design spec. Addresses GitHub issue #317.
-->

# WAF response-body streaming — design

- **Date:** 2026-10-19
- **Target version:** v2.77.0
- **Status:** DRAFT — awaiting operator review
- **Issue:** #317 (Pulpyyyy) — WAF holds streaming responses
- **Related:** `2026-09-22-waf-seclang-editor-design.md` (decision S1), the
  existing `UploadStreamingMode` (request-body counterpart).

## 1. Problem

A route whose WAF runs the CRS includes `@coraza.conf-recommended`, which
sets `SecResponseBodyAccess On` for `text/plain|html|xml` with a 512 KiB
`ProcessPartial` buffer. For a chunked `text/plain` response that never
ends (Home Assistant's `/api/hassio/.../logs/follow`, SSE, long-poll log
tails), Arenet's response interceptor **buffers the body and sends nothing
downstream** until the response ends or 512 KiB is reached — so the client
hangs. This holds **even in detect mode**. Verified against the code:
`internal/waf/interceptor.go:124,155` gates streaming on
`IsResponseBodyAccessible()`; the CRS include is `manager.go:3437`.

## 2. The existing precedent — `UploadStreamingMode`

The symmetric problem on the REQUEST side is already solved, route-wide,
at the Go level:

- `storage.Route.UploadStreamingMode bool` → the WAF module's
  `SkipBodyInspection` (`internal/waf/module.go:120,872`): `processRequest`
  skips feeding the request body to Coraza, paired with Caddy's
  `flush_interval=-1`. Headers / URL / response phases stay live.

This is the model to mirror. It is **not** SecLang and touches **no**
`ctl:` directive, so it sidesteps the S1 question entirely (S1 bans
engine-policy `ctl:` in the free-form SecLang editor; here we never go
through SecLang).

## 3. Decision — a symmetric route-wide toggle, grouped with upload

| # | Decision | Rationale |
|---|----------|-----------|
| R1 | New `storage.Route.ResponseStreamingMode bool`, the exact mirror of `UploadStreamingMode`. Drives a new `SkipResponseBodyInspection` flag on the WAF module. | Symmetry with the request-side feature; migration-free (`omitempty`, default false = today's behaviour). |
| R2 | The response interceptor, when the flag is set, treats the response body as **not accessible** — it never calls `WriteResponseBody`, sets `allowFlushing` from the first write, and streams through. Headers (phase 3) and the request side stay fully inspected. | Done in Go, exactly like `SkipBodyInspection`; no SecLang, no `ctl:`, **S1 untouched**. |
| R3 | Emission pairs it with `flush_interval=-1` (as `UploadStreamingMode` already does), so Caddy flushes each chunk. | Same proven pairing; a buffered reverse_proxy would re-introduce the hold. |
| R4 | **Route-wide**, not per-path. | Matches `UploadStreamingMode` (also route-wide); a streaming route (HA, Jellyfin) is single-purpose, and route-wide request-body skip is already the accepted posture. Per-path response-body scoping is a non-goal (see §5). |
| R5 | **UI: one "Streaming" sub-section** in the WAF block holding BOTH toggles — "Request body (uploads — registries, file servers)" (the existing `uploadStreamingMode`) and "Response body (downloads, log tails, SSE)" (new). | Directly reduces the WAF's visual surface count (the operator's stated concern) by grouping two sibling concepts under one heading instead of scattering them. |
| R6 | We do **not** implement issue #317's per-path generated `ctl:responseBodyAccess=Off` rule, nor open `ctl:` in the SecLang editor. | The Go-level route-wide toggle is simpler, symmetric, groups surfaces, and keeps S1 intact — a strictly better fit than both earlier options. The reporter's analysis is correct; only the delivery differs. |

## 4. What stays inspected

- The **request** side (URL, headers, body unless UploadStreaming is also
  on) — the bulk of CRS value.
- **Response headers** (phase 3).
- Only the **response body** bytes are not buffered/scanned, and only on a
  route the operator explicitly flags.

This is no weaker than the existing `WAFMode=off` / `WAFDisableCRS` the
operator already has, and far more surgical (response body only).

## 5. Non-goals

- **Per-path** response-body exemption. If a route genuinely mixes a
  streaming endpoint with sensitive non-streaming ones, split it or accept
  route-wide. Keeping parity with `UploadStreamingMode` (route-wide) and
  avoiding a new per-path list is the point.
- Touching the SecLang editor or S1. The guided custom-rules editor and
  the SecLang expert editor are unchanged (they are kept — they serve a
  different, non-expert audience; #317 is orthogonal to them).
- The secondary interceptor defect #317 flags (past 512 KiB the body is
  sent but no longer streamed): a separate PR.

## 6. Empirical validation gates

1. **Interceptor streams (the bug):** a test `rwInterceptor` with
   `skipResponseBody=true` fed a chunked `text/plain` writer must flush the
   FIRST chunk downstream before the response ends; with the flag false it
   buffers (today's behaviour). Fails without the fix.
2. **Request side intact:** with `ResponseStreamingMode` on, a CRS request
   rule (e.g. a SQLi in the query) still blocks in block mode — only the
   response body is exempt.
3. **Config validates:** the emitted Caddy JSON (new module field +
   `flush_interval=-1`) passes `caddy.Validate` (`TestBuildConfigJSON_LoadsCleanly*`).
4. **Non-regression:** a route with `ResponseStreamingMode=false` emits
   byte-identical WAF config to today (golden).
5. **Live:** on a real instance, HA's add-on Journal renders in < 2 s and
   keeps scrolling, in detect AND block, with the toggle on.

## 7. Open question for the operator

Route-wide (this spec) vs. a per-path list. Default: route-wide, for
symmetry with uploads and to add zero new per-path surface. Confirm.
