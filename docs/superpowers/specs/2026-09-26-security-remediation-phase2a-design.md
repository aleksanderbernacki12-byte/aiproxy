# Security remediation, Phase 2A — log-safe URLs and usage accounting on blocked responses

Date: 2026-09-26
Status: draft, pending review

## Purpose

Phase 2 of the remediation of `docs/reviews/2026-09-12-v0.74.1-system-review.md`
covers findings #4, #5, #7, #8, #9 and #10. All six were re-verified to still
fail on `main` (01bfe7c) with the review's own `TestReview_*` reproduction
tests on 2026-09-26. Phase 2 is split into three sub-projects, each with its
own spec → plan → implementation cycle:

| Sub-project | Findings | Order |
|---|---|---|
| **2A — this spec** | #9 URL masking in logs/webhooks, #10 usage on blocked responses | 1st |
| 2C | #7 idempotency operation identity, #8 uncertain outcome on transport error | 2nd |
| 2B | #4 full rule evaluation, #5 decoded JSON + reassembled SSE text, #11 SSE parser | 3rd |

2A goes first because it is small, changes no policy semantics, and removes
credential leakage into logs that cannot be recalled once written (including
the WORM Secure Vault).

## Scope

In scope:

- One shared function that turns a request URL into a log-safe string, used
  for every terminal/file/JSON log line, audit-log entry, dashboard event,
  webhook payload, and Secure Vault evidence record (#9).
- Webhook delivery errors never print the webhook URL (#9).
- Upstream token usage is accounted for (token limiter, stats, cost budgets)
  whether or not the response is delivered, blocked or redacted (#10).

Out of scope:

- Rule matching keeps the raw URL. Masking applies only to what is *recorded*,
  never to what the rules engine or routing sees.
- Separate delivered-vs-blocked token statistics and an explicit
  "usage unknown" counter for cut-short streams (the review mentions both as
  follow-ups; neither is needed to close #10).
- Budget reservation for in-flight requests and budget persistence across
  restarts (review #10 "på sikt").

## Design

### 1. Log-safe URL (finding #9)

New file `internal/proxy/logurl.go`:

```go
// logSafeURL returns u in a form that is safe to write to any log, webhook
// payload or evidence record.
func (s *Server) logSafeURL(u *url.URL) string
```

Behavior, applied to a copy of `u`:

1. **Userinfo** is removed (`https://user:pass@host/…` → `https://host/…`).
2. **Every query value** is replaced with `REDACTED`; keys and their order are
   kept (`?api_key=x&model=gpt` → `?api_key=REDACTED&model=REDACTED`). Values
   are masked regardless of parameter name, because a denylist of names
   misses credentials in parameters with unexpected names. A key with an
   empty value stays empty.
3. **Fragment** is removed.
4. **Path** is passed through `rules.Engine.MaskSecrets` (below), so a
   credential embedded in a path segment is masked by the same patterns
   (built-in and custom) the operator already configured.

`nil` returns `""`.

New method in `internal/rules/rules.go`:

```go
// MaskSecrets replaces every match of every body regex rule in s with
// "[REDACTED:<rule name>]", regardless of the rule's action, dry-run flag,
// or target/client scoping. It is for log output only and never affects
// policy decisions.
func (e *Engine) MaskSecrets(s string) string
```

Scoping and action are deliberately ignored: a log line must not contain a
secret even if the rule that recognizes it is scoped elsewhere or is only in
dry-run.

**Call sites.** `ServeHTTP` computes `logURL := s.logSafeURL(r.URL)` once and
passes it to every `log*` and `notify*` call that currently receives
`r.URL.String()`. `requestContextInfo.url` is set to `logURL`: every reader of
that field is a log, webhook, dry-run report or compliance event (verified;
response-side rule evaluation takes body/target/client, and
`checkReplayPolicy` reads `r.URL` directly). The rules engine calls that take
`r.URL.String()` are unchanged. The shadow-traffic error log
(`logShadowError`) and the circuit-breaker log lines that print a configured
target URL (`recordBreakerFailure`/`recordBreakerSuccess`) use `logSafeURL` on
those URLs too, since a target URL from config can carry a key in its query.

**Secure Vault / compliance evidence.** `ComplianceEvent.RequestURL` is set
from `logSafeURL` too. Vault objects are WORM and cannot be deleted, so a
credential written there is permanent. This mirrors the existing
`sanitizeEvidenceHeaders` treatment of headers.

**Errors that embed URLs.** Go's `*url.Error` (returned by every
`http.Client`/`RoundTrip` failure) prints the full request URL, including the
client's query string. A helper `logSafeError(err) string` renders a
`*url.Error` as `Op + " " + logSafeRawURL(URL) + ": " + Err` and any other
error unchanged. It is used for:

- `postWebhook`: logs only `Op` and the inner `Err`, never even a masked URL,
  because a webhook URL (Slack especially) carries its credential in the path.
- `logShadowError`: the mirror request's URL includes the client's query.
- Upstream proxy errors: `httputil.ReverseProxy` has no `ErrorHandler`, so
  Go's default handler writes `http: proxy error: Get "<full upstream URL>"`
  to the process-wide standard logger. A new `ErrorHandler` logs
  `aiproxy: upstream: <logSafeError(err)>` through `s.logError` and replies
  `502 Bad Gateway`, the same status the default handler uses.

`logFailover`'s failed/next target URLs are passed through `logSafeRawURL`
as well.

### 2. Usage on blocked responses (finding #10)

**Buffered responses (`bufferResponse`).** Usage is extracted from
`rawResponseBody` and accounted via `logUsageFromBody` *before* the block
branch returns, and from `rawResponseBody` (not the possibly redacted `body`)
in the redact/allow path. It runs exactly once per response. A redaction rule
that happens to match inside the `usage` object can therefore no longer hide
consumption either.

**Streams (`streamTee.onComplete`).** `logUsageFromBody` receives `rawData`
(everything read from upstream) instead of `data` (what was delivered). A
stream cut short by a Block rule is accounted for with whatever usage the
upstream had sent before the cut. If none had arrived, nothing is recorded,
which is the current behavior and is documented as a known limitation.

Stats counters are unchanged: tokens the upstream consumed count toward the
same `tokens_used` totals, limiters and budgets whether delivered or not.

## Testing

- Port `TestReview_QueryCredentialsMustNotEnterLogs` and
  `TestReview_BlockedResponseMustStillAccountForUsage` from
  `docs/reviews/2026-09-12-v0.74.1-repro/` into
  `internal/proxy/reviewfindings_test.go` as permanent regressions (as in
  Phase 1).
- Unit tests for `logSafeURL`: userinfo, masked query values with keys kept,
  empty value, fragment dropped, path secret masked by a built-in pattern,
  nil URL.
- Unit tests for `MaskSecrets`: block-, redact- and dry-run rules all mask;
  a rule scoped to another target still masks; no rules → unchanged.
- JSON log format and file log contain no query value.
- A webhook pointed at an unreachable URL with a query secret produces an
  error log line without the URL.
- An unreachable upstream produces a 502 and a log line without the client's
  query value.
- A failing shadow mirror logs no query value.
- A compliance event for `/chat?api_key=secret` carries the masked URL.
- Redact rule matching inside the `usage` object still yields correct token
  accounting.
- Streaming: a stream blocked after its usage event is accounted for.
- `go test ./... -race` and `go vet ./...` pass.

## Behavior changes (for release notes)

- Logs, webhooks and Secure Vault evidence no longer contain query values,
  URL userinfo or fragments; secrets in paths are masked with the configured
  rule patterns.
- Blocked and redacted responses now count toward token rate limits and cost
  budgets. Operators may see budgets reached earlier than before, which
  reflects actual upstream spend.
