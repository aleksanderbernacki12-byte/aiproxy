# Security remediation, Phase 3C — per-request config snapshot

Date: 2026-09-27
Status: approved (owner delegated Phase 3 decisions, 2026-09-27)

## Purpose

Closes review finding #14 of `docs/reviews/2026-09-12-v0.74.1-system-review.md`.
`ReloadConfig` swaps `Server` fields under `s.mu`, but a request reads them
through ~60 separate getter calls at different moments. A reload landing
mid-request can hand one request two configurations: for example it claims an
idempotency key in the old registry and stores the response in the new one,
or is evaluated by one rules engine and has its response evaluated by another.
The documented promise that in-flight requests keep the old configuration is
not enforced.

## Design

1. **Typed reload input.** `ReloadConfig(cfg RuntimeConfig)` replaces the
   41-parameter signature. `RuntimeConfig` has one field per reloadable
   setting, named like the `Server` field it sets (`Routes` and `ModelRoutes`
   take the exported `Route`/`ModelRoute` types). `internal/cli` and the
   existing test call sites move to it. A zero field means the same as the
   zero argument did before.

2. **One snapshot per request.** `ServeHTTP` calls `s.snapshot()` once: a
   single `s.mu.RLock` section copies every reloadable field (including the
   internal `routes`/`modelRoutes`) into an immutable `*requestConfig`, which
   is stored in the request context. Every request-path read (routing,
   rules, cache, idempotency, coalescing, semantic cache, cost/budget, usage,
   shadow, webhooks fired by the request, upstream transport and timeout,
   breaker, CORS, API keys, IP/geo lists, anomaly, body limits) goes through
   that snapshot, including the `ReverseProxy` callbacks (`Rewrite`,
   `ModifyResponse`, `ErrorHandler`) and the failover transport, which read it
   from the outgoing request's context. `requestConfigFrom(ctx)` falls back to
   a fresh snapshot when none is attached, so internal helpers stay callable
   on their own.

   Exported `Server` fields stay as they are: they remain the construction
   and reload target (tests and the CLI set them directly in 300+ places), and
   are only read by `snapshot()` and by non-request paths. Admin endpoints,
   health checks and other background work read the current configuration via
   the existing locked getters, which is correct for them.

3. **Log file hand-over.** The log file is the only resource `ReloadConfig`
   closes. Today `appendToLogFile` reads `s.LogFile` and then takes
   `logFileMu`, so a reload in between closes the file under the writer.
   Now `appendToLogFile` reads the file inside `logFileMu`, and `ReloadConfig`
   swaps and closes the old file inside `logFileMu` too. Logging always goes
   to the current file (the audit chain stays one continuous sequence), and no
   write hits a closed handle. Nothing else is closed on reload, so no
   in-flight tracking is needed.

Out of scope: closing idle connections of a replaced upstream transport
(today's behavior, bounded by the transport's idle timeout).

## Testing

- Reload mid-upstream-call: the upstream handler blocks; a reload installs a
  Block-all engine and a new idempotency registry; after release the in-flight
  request completes with the old engine's decision and its idempotency entry
  is completed in the old registry, while a new request sees the Block engine.
- Reload in a loop concurrent with proxied requests and admin cache clear,
  under `-race`, with no errors or races.
- Log writes concurrent with reloads: every write lands in exactly one file,
  no write fails on a closed handle.
- Existing reload tests pass on the new signature.
