<!--
Arenet - Homelab-friendly reverse proxy with integrated security
Copyright (C) 2026  The Arenet Authors
Implementation plan. Follows the 2026-10-19 WAF response-streaming spec.
-->

# WAF response-body streaming — implementation plan

- **Spec:** [2026-10-19-waf-response-streaming-design.md](../specs/2026-10-19-waf-response-streaming-design.md)
- **Issue:** #317
- **Target:** v2.77.0
- **Branch:** `feature/waf-response-streaming`

Mirror of `UploadStreamingMode` on the response side. Each task compiles,
tests, commits on its own. Fail-first + byte-identity golden on the
untouched path (per the guard skill).

## T1 — storage field

- `storage.Route.ResponseStreamingMode bool` (`json:"response_streaming_mode,omitempty"`),
  mirror of `UploadStreamingMode`: migration-free, default false.
- Backup/restore: confirm the struct round-trips (it's a plain bool, no
  secret) — add to the backup round-trip test if one enumerates fields.
- **Test:** a route JSON with/without the field decodes correctly;
  default false.

## T2 — WAF module + interceptor (the core fix)

- `waf/module.go`: add `SkipResponseBodyInspection bool`
  (`json:"skip_response_body_inspection,omitempty"`), mirror of
  `SkipBodyInspection`.
- `waf/interceptor.go`: the interceptor carries a `skipResponseBody bool`
  (set from the module when it builds the interceptor at :240). When true:
  - `WriteHeader`: set `allowFlushing = true` (stream from the first write);
  - `Write`: bypass the `WriteResponseBody` buffering branch, write straight
    downstream;
  - the finalize path writes nothing buffered.
  Request side and response-header processing are untouched.
- **Test (the bug):** drive `rwInterceptor{skipResponseBody:true}` with a
  chunked writer; assert the first chunk reaches downstream before the
  response is finalized. With `false`, it buffers. Reinjection-verified.

## T3 — emission (manager → module + flush)

- `buildWAFHandler` gains the response-streaming bool; emits
  `skip_response_body_inspection` on the module JSON.
- The reverse_proxy `flush_interval=-1` pairing is applied when
  `ResponseStreamingMode` OR `UploadStreamingMode` is set (today it keys on
  upload only — extend the condition).
- **Tests:** emitted JSON passes `caddy.Validate`
  (`TestBuildConfigJSON_LoadsCleanly*`); **golden byte-identity** for a
  route with the flag OFF (non-regression); a route with it ON carries the
  module field + flush_interval=-1.

## T4 — API wire

- `routeRequest` / response types: `responseStreamingMode` (camelCase),
  mirror of `uploadStreamingMode`; both assembly sites set it; `toResponse`
  maps it.
- **Test:** a literal-JSON wire test (per the "test the wire, not the
  struct" lesson) — POST a route with `"responseStreamingMode":true`, read
  it back, assert the camelCase field round-trips.

## T5 — frontend: grouped "Streaming" section

- A `Streaming` sub-section in the WAF block holding BOTH toggles:
  - existing `uploadStreamingMode` → relabelled "Request body (uploads)";
  - new `responseStreamingMode` → "Response body (downloads, log tails, SSE)".
- `FormData` + hydration (edit) + payload (create/update) for the new field.
- i18n FR + EN for the section heading + both toggles + hints (both
  locales, parity test must pass).
- **Test:** component test — toggling response-streaming ships
  `responseStreamingMode:true`; a route without it ships false/omitted.

## T6 — docs + smoke + notes

- `docs/smoke-test-waf-response-streaming.md`: the HA `/logs/follow` repro.
- Wiki-seed v2.77.0 migration note (EN + FR): a route serving streaming
  responses (log tails, SSE) behind the WAF can enable "Response body
  streaming" so the WAF stops buffering the response; request-side
  inspection unchanged.
- Reply to issue #317 (operator's voice) once merged.

## Validation gates (spec §6)

1. Interceptor streams the first chunk with the flag (fails without).
2. Request-side rule still blocks with the flag on.
3. `caddy.Validate` on the emitted JSON.
4. Byte-identity golden with the flag off (non-regression).
5. Live: HA Journal renders < 2 s, detect + block.

## Open question

Route-wide (this plan) vs per-path — operator confirmed **route-wide**.
