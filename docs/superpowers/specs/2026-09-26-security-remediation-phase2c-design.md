# Security remediation, Phase 2C — idempotency operation identity and uncertain upstream outcomes

Date: 2026-09-26
Status: approved (decisions delegated by the owner on 2026-09-26)

## Purpose

Closes review findings #7 and #8 of
`docs/reviews/2026-09-12-v0.74.1-system-review.md`. Both are about one client
request causing the wrong number of upstream executions: #7 replays an
unrelated operation's response (zero executions of the real one), #8 sends one
operation to two upstreams (two executions). Both reproduce on `main`
(`TestReview_IdempotencyMustRespectOperation`,
`TestReview_FailoverMustNotAssumeTransportErrorMeansUnprocessed`).

Phase 2A is merged; 2B (#4, #5, #11) follows this.

## Scope

In scope:

- The idempotency fingerprint covers the whole operation, and the key
  namespace is the caller's credential identity (#7).
- Waiting `Claim` calls stop when the client disconnects (#7).
- Failover only retries when the request provably never reached the failed
  upstream, or the method is safe (#8).
- A request whose client context is done is never failed over (#8).
- Stats/logging distinguish an uncertain outcome from an ordinary failover
  (#8).
- Follow-up from 2A: `notifyFailoverWebhook` receives masked target URLs.

Out of scope:

- Bounds on idempotency entries and stored bytes (review #12, Phase 3).
- A cross-upstream idempotency protocol. As the review notes, a local key does
  not make two independent upstreams idempotent, so it is not used to justify
  a retry.

## Design

### 1. Idempotency operation identity (#7)

**Namespace.** `Claim/Store/Release` currently use `auth.label`, which is `""`
for every caller when proxy authentication is off. They will use
`partitionIdentity(auth, r)` instead: the Phase 1 hash of the proxy key label
plus the upstream-credential headers. Callers with different credentials can
no longer see each other's records, with or without proxy auth. The value is
kept in `requestContextInfo.idempotencyClient`, which every `Store` call
already reads.

**Fingerprint.** The `bodyHash` passed to `Claim` becomes an operation hash:

```
sha256(method \0 escapedPath \0 rawQuery \0 body)
```

A reused key with a different method, path, query or body yields `Conflict`
(HTTP 409). The route/destination is determined by method, path and body under
the current config, so it needs no separate field. The 409 message changes
from "different body" to "different request". The registry's parameter is
renamed `operationHash`; its logic is unchanged.

**Client disconnect.** `Claim` gains a `ctx context.Context` first parameter.
While waiting on an in-flight owner it also selects on `ctx.Done()` and then
returns a new outcome `Canceled`. ServeHTTP passes `r.Context()` and returns
without writing on `Canceled` (the client is gone).

### 2. Failover on uncertain outcome (#8)

**Decision.** Automatic failover for a method with side effects stops once the
request may have reached the upstream. Only the unambiguous case keeps
failing over: the upstream never received the request headers (connection
refused, DNS failure, TLS handshake failure, dial timeout). That is the case
failover exists for ("target is down"), and it is unaffected. Safe methods
(`GET`, `HEAD`, `OPTIONS`, `TRACE`) keep failing over on any transport error,
because re-executing them has no side effects.

Idempotent-by-RFC methods (`PUT`, `DELETE`) are treated as unsafe: they are
idempotent per resource on *one* server, not across two independent upstreams.

**Detection.** Each attempt runs with an `httptrace.ClientTrace` whose
`WroteHeaders` callback sets a per-attempt flag. After a transport error:

| Condition | Action |
|---|---|
| request context done (client gone, total timeout) | stop, return the error, no failover log |
| headers not written | fail over as today |
| headers written, safe method | fail over as today |
| headers written, unsafe method | stop, return `errUpstreamOutcomeUnknown` |

`errUpstreamOutcomeUnknown` wraps the transport error. The `ErrorHandler` from
2A recognizes it with `errors.Is`, records `Stats.RecordUpstreamOutcomeUnknown`
(new counter, exposed in stats JSON and as
`aiproxy_upstream_outcome_unknown_total`), logs
`aiproxy: upstream: outcome unknown (not retried): <safe error>`, and replies
`502` with the JSON/text error code `upstream_outcome_unknown` via
`writeError`. Other errors keep the plain 502.

The breaker still records the failure for the candidate in every case.

The single-candidate path is unchanged (there is nothing to fail over to).

### 3. Masked failover webhook

`notifyFailoverWebhook(reqCtx.method, reqCtx.url, candidate.String(), next.String(), …)`
passes `logSafeRawURL` of both targets, as `logFailover` already does.

## Testing

- Port both review tests into `reviewfindings_test.go`.
- Idempotency: same key, same body, different path → 409; different method →
  409; different query → 409; identical request → replay (unchanged).
- Idempotency without proxy auth: two callers with different
  `Authorization` headers and the same key and request → each is forwarded
  once, neither gets the other's replay.
- `Claim` with a canceled context while an owner is in flight returns
  `Canceled` promptly (registry unit test).
- Failover: `POST` whose first upstream closes the connection after reading
  the request → exactly one execution, 502 with `upstream_outcome_unknown`,
  counter = 1.
- Failover: `GET` with the same broken first upstream still fails over.
- Failover: `POST` to an unreachable first upstream (connection refused)
  still fails over (existing `TestServer_Failover_*` tests keep passing).
- Failover webhook payload contains no target query value.
- `go test -race ./...`, `go vet ./...`.

## Behavior changes (release notes)

- `Idempotency-Key` records are scoped per caller credential and per
  operation. Reusing a key for a different method, path or query now returns
  409 instead of replaying.
- A `POST`/`PUT`/`PATCH`/`DELETE` whose upstream dropped the connection after
  receiving the request is no longer retried on the next target. The client
  gets `502 upstream_outcome_unknown` and should reconcile or retry with its
  own idempotency. Connection-refused and other pre-send failures still fail
  over.
