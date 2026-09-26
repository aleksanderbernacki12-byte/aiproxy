# Phase 2C: Idempotency Operation Identity and Uncertain Upstream Outcomes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One client request never causes zero (#7) or two (#8) upstream executions of an operation.

**Architecture:** Idempotency keys are namespaced by `partitionIdentity` and fingerprinted by method+path+query+body; `Claim` honors client cancellation. `failoverTransport` traces `WroteHeaders` per attempt and refuses to retry an unsafe method once headers reached the upstream, surfacing `errUpstreamOutcomeUnknown` through the 2A `ErrorHandler`.

**Tech Stack:** Go 1.27 stdlib (`net/http/httptrace`). Spec: `docs/superpowers/specs/2026-09-26-security-remediation-phase2c-design.md`. Branch: `security-phase2c`.

---

## File structure

| File | Change |
|---|---|
| `internal/idempotency/idempotency.go` | `Claim(ctx, …)`, `Canceled` outcome, param rename |
| `internal/idempotency/idempotency_test.go` | update call sites, add cancel test |
| `internal/proxy/proxy.go` | namespace + operation hash, failover trace/decision, ErrorHandler branch, webhook masking |
| `internal/stats/stats.go` | `UpstreamOutcomeUnknown` counter + snapshot field |
| `internal/proxy/reviewfindings_test.go` | port both review tests |
| `internal/proxy/operationsafety_test.go` | new idempotency/failover tests |

---

### Task 1: `Claim` honors context cancellation

- [ ] Write test in `internal/idempotency/idempotency_test.go`: owner claims `(c,k)`; second `Claim(ctx, c, k, sameHash)` with a context canceled after 20ms returns `(nil, Canceled)` within 1s (wait timeout set to 1 minute).
- [ ] Run `go test ./internal/idempotency` → build failure (signature).
- [ ] Implement: add `Canceled` to the `Outcome` consts (doc: "the caller's context ended while waiting on an in-flight owner; the client is gone, so write nothing"). Change signature to `Claim(ctx context.Context, client, key string, operationHash [32]byte)`, rename the field `bodyHash`→`operationHash`, and add `case <-ctx.Done(): return nil, Canceled` to the wait `select`. Update every existing test call to pass `context.Background()`.
- [ ] `go test ./internal/idempotency` passes. Commit `feat(idempotency): stop waiting when the client disconnects`.

### Task 2: Operation fingerprint and credential namespace (#7)

- [ ] Port `TestReview_IdempotencyMustRespectOperation` into `reviewfindings_test.go` (add `idempotency`/`time` imports; inline the `reviewCall` helper body with `httptest.NewRequest`/`ServeHTTP` as done for #9).
- [ ] In `operationsafety_test.go` add: (a) same key+body, `POST /a` then `POST /b` → second is 409 and upstream saw 1 request; (b) `POST /a?x=1` then `POST /a?x=2` → 409; (c) identical request twice → second has `Idempotency-Replayed: true`, upstream saw 1; (d) no proxy auth, same key+request, `Authorization: Bearer alice` then `Bearer bob` → upstream saw 2, neither replayed.
- [ ] Run → (a),(b),(d) and the review test fail.
- [ ] Implement in `ServeHTTP`'s idempotency block:

```go
idempotencyNamespace := partitionIdentity(auth, r)
operationHash := idempotencyOperationHash(r, body)
switch resp, outcome := idem.Claim(r.Context(), idempotencyNamespace, idempotencyKey, operationHash); outcome {
```

add `case idempotency.Canceled: return`, change the conflict message to `"idempotency key already used for a different request"`, change `defer idem.Release(auth.label, …)` and the three cache/coalesce `idem.Store(auth.label, …)` calls to `idempotencyNamespace`, and set `idempotencyClient: idempotencyNamespace` in `reqCtx`. Declare `var idempotencyNamespace string` next to `idempotencyKey` so later code can read it. Add:

```go
// idempotencyOperationHash fingerprints the whole operation, so a reused
// Idempotency-Key for a different method, path or query conflicts instead
// of replaying another operation's response.
func idempotencyOperationHash(r *http.Request, body []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(r.Method))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.EscapedPath()))
	h.Write([]byte{0})
	h.Write([]byte(r.URL.RawQuery))
	h.Write([]byte{0})
	h.Write(body)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}
```

- [ ] `grep -n "auth.label, idempotencyKey" internal/proxy/proxy.go` → no output.
- [ ] Targeted tests pass, then `go test ./internal/proxy`. Update existing idempotency tests only where they asserted the old "different body" message. Commit `fix(proxy): scope idempotency keys to caller and whole operation`.

### Task 3: Stats counter

- [ ] In `internal/stats/stats.go` add `upstreamOutcomeUnknown atomic.Int64`, `RecordUpstreamOutcomeUnknown()`, and `UpstreamOutcomeUnknown int64 \`json:"upstream_outcome_unknown"\`` in `Snapshot`, following the exact pattern of the existing failover counter. Add the Prometheus row `{"aiproxy_upstream_outcome_unknown_total", "Total number of unsafe requests not retried because the upstream may have received them.", func(s stats.Snapshot) int64 { return s.UpstreamOutcomeUnknown }}` next to the failover metric in `proxy.go`.
- [ ] `go test ./internal/stats ./internal/proxy` passes (a metrics-listing test may need the new name). Commit with Task 4.

### Task 4: Failover only when the outcome is certain (#8)

- [ ] Port `TestReview_FailoverMustNotAssumeTransportErrorMeansUnprocessed`.
- [ ] In `operationsafety_test.go`: (a) `POST` with a first upstream that reads the body then hijack-closes, second OK → executions == 1, status 502, body contains `upstream_outcome_unknown` when `Accept: application/json`, `Stats.Snapshot().UpstreamOutcomeUnknown == 1`; (b) same with `GET` → second upstream serves 200; (c) `POST` with first upstream a closed port (`freeLoopbackAddr`) → second serves 200; (d) failover webhook payload for a target URL with `?key=FAKE_PRIVATE_VALUE` has no `FAKE_PRIVATE_VALUE`.
- [ ] Run → (a) and the review test fail; (d) fails.
- [ ] Implement in `proxy.go`:

```go
// errUpstreamOutcomeUnknown marks a transport failure after the request
// headers reached the upstream, for a method with side effects: the
// upstream may have executed it, so it is not retried elsewhere.
var errUpstreamOutcomeUnknown = errors.New("upstream outcome unknown")

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return false
}
```

In the multi-candidate loop, before `base.RoundTrip(attempt)`:

```go
		var wroteHeaders atomic.Bool
		attempt = attempt.WithContext(httptrace.WithClientTrace(attempt.Context(), &httptrace.ClientTrace{
			WroteHeaders: func() { wroteHeaders.Store(true) },
		}))
```

After recording the breaker failure and `lastErr = err`:

```go
		if req.Context().Err() != nil {
			break
		}
		if wroteHeaders.Load() && !safeMethod(req.Method) {
			lastErr = fmt.Errorf("%w: %w", errUpstreamOutcomeUnknown, err)
			break
		}
```

(`break` falls through to the existing `cancel()` + `return nil, lastErr`.) Change the webhook call to `t.server.notifyFailoverWebhook(reqCtx.method, reqCtx.url, t.server.logSafeRawURL(candidate.String()), t.server.logSafeRawURL(next.String()), reqCtx.requestID)`.

In the 2A `ErrorHandler`:

```go
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, errUpstreamOutcomeUnknown) {
				s.Stats.RecordUpstreamOutcomeUnknown()
				s.logError("aiproxy: upstream: outcome unknown (not retried): %s", s.logSafeError(err))
				writeError(w, r, http.StatusBadGateway, "upstream_outcome_unknown", "the upstream may have received this request before the connection failed; it was not retried", "")
				return
			}
			s.logError("aiproxy: upstream: %s", s.logSafeError(err))
			w.WriteHeader(http.StatusBadGateway)
		},
```

Check that `logSafeError` still finds the `*url.Error` through the `%w` wrap (it uses `errors.As`).

- [ ] Targeted tests pass; `go test -race ./internal/proxy`. Existing hijack-based failover/breaker tests that use `POST` now legitimately stop failing over: switch their request to `GET` if the test is about breaker/failover mechanics (not about method semantics), and say so in the commit. Commit `fix(proxy): never fail over an unsafe request the upstream may have received`.

### Task 5: Docs and verification

- [ ] README: in the failover section (`grep -n -i "failover" README.md | head`) add the rule table in plain words and the `upstream_outcome_unknown` error; in the idempotency section note per-caller, per-operation scoping and 409 on reuse.
- [ ] `gofmt -l internal && go vet ./... && go test -race ./...` clean; all `TestReview_*` pass.
- [ ] Commit `docs: describe failover safety and idempotency scoping`.
