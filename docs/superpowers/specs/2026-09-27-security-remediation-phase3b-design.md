# Security remediation, Phase 3B — resource limits

Date: 2026-09-27
Status: approved (owner delegated Phase 3 decisions, 2026-09-27)

## Purpose

Closes review finding #12 of `docs/reviews/2026-09-12-v0.74.1-system-review.md`:
nothing bounds response size, stream buffering, idempotency storage, webhook
goroutines, header/idle time on the listeners, or concurrent requests. Each
lets a slow or hostile peer, or plain traffic growth, exhaust memory or
goroutines. Usage is already computed incrementally for streams (Phase 2A).

## Design

Each item below is independent and ships as its own commit.

1. **Listener timeouts.** Both `http.Server`s (proxy and admin) set
   `ReadHeaderTimeout: 10s` and `IdleTimeout: 120s`. No `ReadTimeout` or
   `WriteTimeout`: long request uploads and long streams are legitimate, and
   `upstream_total_timeout` already bounds the upstream side.

2. **Buffered response cap.** `bufferResponse` reads at most
   `max_response_body_bytes` (default 32 MiB, `0` = default) plus one byte. A
   larger body is not forwarded: the client gets `502
   upstream_response_too_large`, the response counts in a new
   `upstream_response_too_large` stat, and nothing is cached or stored.
   Start-time setting (not hot-reloaded), like `listen`.

3. **Stream accumulation.** `streamTee` only accumulates the delivered stream
   (`buf`) when a consumer needs it: the response is cacheable, or an
   idempotency key or coalescing ownership is attached. The accumulation stops
   at `max_response_body_bytes`; a stream that exceeded it is still delivered
   in full but is treated as not complete for cache/idempotency/coalescing (the
   same as a cut-short stream). Compliance raw capture is unchanged (already
   gated on compliance being enabled; bounded by the vault's own limits).

4. **Idempotency bounds.** `idempotency.Registry` gets `MaxEntries` (default
   10 000) and `MaxBytes` (default 64 MiB of stored bodies). `Claim` first
   sweeps expired entries; if still at `MaxEntries`, the oldest *completed*
   entries are evicted. In-flight entries are never evicted; if every entry is
   in flight, `Claim` returns a new `Full` outcome and the proxy answers `503
   idempotency_capacity`. `Store` evicts oldest completed entries until the new
   body fits `MaxBytes`; a single body larger than `MaxBytes` is not stored
   (its key is released so a retry is processed fresh).

5. **Webhook queue.** `postWebhook` enqueues to a bounded queue (256) drained
   by 4 workers started on first use, instead of one goroutine per delivery. A
   full queue drops the delivery, logs `aiproxy: webhook (<label>): queue full,
   dropped` and increments `webhook_dropped`.

6. **Concurrency cap.** `max_concurrent_requests` (default 0 = unlimited, to
   not break existing deployments) caps in-flight proxied requests; above it
   the proxy answers `503 too_many_concurrent_requests` immediately. Admin
   endpoints are not counted. Start-time setting. `aiproxy validate` warns
   when it is unset.

New stats: `upstream_response_too_large`, `webhook_dropped`,
`concurrency_rejected`, `idempotency_full`, each also as a Prometheus counter.

## Testing

Per item: listener fields set (both servers); oversized buffered response →
502 and not cached; stream with no consumer does not grow `buf`; oversized
stream delivered but not cached; idempotency: entry cap evicts oldest completed,
all-in-flight → `Full`/503, body over `MaxBytes` not stored and key released;
webhook: queue of 256 full → drop counted, no goroutine growth; concurrency
cap → 503 while N requests are held open; `validate` warning. `go test -race
./...` green.
