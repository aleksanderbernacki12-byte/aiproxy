# Security remediation, Phase 1 — client/admin isolation, cache identity, policy-before-replay

Date: 2026-09-12
Status: approved, pending implementation plan

## Purpose

An independent security review (`docs/reviews/2026-09-12-v0.74.1-system-review.md`,
12 findings, all independently re-verified against current `main` via its own
reproduction tests before this work began — see that file's own "Verifiering"
section and the 12 `TestReview_*` cases it ships) found that aiproxy's cache,
coalescing, semantic cache, idempotency, and admin-auth mechanisms all share
one root problem: none of them are aware of *which client* is asking, and none
of them re-validate a previously-produced response against the rules that
apply *right now*. This phase closes the four highest-severity findings from
that review (its own numbering: #1, #2, #3, #6), which the review's own
"Föreslagen arbetsordning" groups together as the first phase, since a
coherent fix needs all four designed with the same notion of "client identity"
and "current policy" in mind.

## Scope for Phase 1

In scope (review finding numbers in parens):

- Cache and request-coalescing partition by client identity and upstream
  credential, not just method+URL+body (#1).
- Every replay path (exact-match cache, coalescing, semantic cache,
  idempotency) re-validates against the *current* rules engine before
  releasing a stored response to the client (#2).
- Semantic cache requires exact agreement on everything except the
  approximately-matched prompt text — model, streaming, roles, tools,
  response format, generation parameters (#3).
- A distinct admin-key concept, separate from proxy client keys, gates the
  five admin paths (`stats`, `metrics`, `dashboard`, `cacheClear`, `drain`)
  (#6).

Explicitly out of scope for this phase (later phases per the review's own
proposed order):

- Full multi-rule evaluation (redact-then-block) and decoded-JSON/SSE content
  scanning — finding #4, #5, #11 (Phase 2).
- Idempotency's operation fingerprint (method+path, not just body),
  failover's transport-error-may-have-executed problem, and usage accounting
  for blocked responses — findings #7, #8, #10 (Phase 3).
- Resource limits, disk cache permissions/atomicity, per-request config
  snapshotting — findings #12, #13, #14 (Phase 4).
- Release pipeline / installer / Homebrew hardening (Phase 5).

## Design

### 1. Cache/coalescing partition identity (finding #1)

`cache.Key` gains a fourth parameter:

```go
func Key(method, targetURL string, body []byte, partitionID string) string
```

`partitionID` is computed once per request in `ServeHTTP`, right where
`auth` (the result of `checkProxyAuth`) is already available:

```go
func partitionIdentity(auth clientAuth, r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(auth.label))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("Authorization")))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("X-Api-Key")))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("Proxy-Authorization")))
	return hex.EncodeToString(h.Sum(nil))
}
```

Both real-world identity dimensions are covered: aiproxy's own proxy-key
identity (`auth.label`, already resolved by `checkProxyAuth`) and the actual
credential the caller supplies to authenticate to the *upstream* API — since
`Rewrite` never touches headers (aiproxy is a bring-your-own-key passthrough),
two callers can share one proxy key configuration yet carry two different
personal upstream credentials, and both must land in different partitions.
Hashed with SHA256, exactly like `idempotency`'s existing `bodyHash` — the raw
credential values are never stored on disk, in a cache filename, or in any
log line.

`coalesce.Group` needs no code change: `ServeHTTP` already passes it the same
`cacheKey` the real cache computes (see `coalesce`'s own package doc:
"a coalescing key is the same content-derived cache key the real cache itself
already computes") — fixing `cache.Key`'s inputs fixes coalescing identically,
for free.

No new config knob for "share this cache across clients anyway" — YAGNI. If a
real use case for intentionally shared caching of public, credential-
independent content shows up later, it can be added as an explicit opt-in
then; today, every cached response is potentially credential- or
client-specific, so partitioning is the only safe default.

This is a one-way, strictly-stricter behavior change. It has no migration to
write: post-upgrade, every pre-existing on-disk cache entry has a body hash
computed against the old key shape, so it simply never matches the new key
shape again and ages out under existing TTL/size eviction like any other
stale entry — no explicit cache-wipe step is needed on upgrade.

### 2. Policy-before-replay (finding #2)

Before **any** of the four replay paths hands a previously-produced response
to the client — exact-match cache hit, coalesced-request replay, semantic
cache hit, or idempotency replay — it is re-evaluated against the *live*
`Engine` exactly as if it had just arrived from upstream this moment:

```go
action, _, filteredBody, matchedRule, _, err := s.Engine.EvaluateResponse(rules.Request{
	Method:  r.Method,
	URL:     forwardPath,
	Headers: filterHeadersForScanning(storedHeader),
	Body:    storedBody,
}, auth.label)
```

- `Block` → the client receives the standard block response (same status
  code, body, and logging/webhook/stats path a live block produces today),
  and the replay is recorded as blocked, not served. Crucially, for
  idempotency this means the operation is **not** re-forwarded upstream —
  a policy rejection on replay must never fall through to executing the
  request again, since idempotency's whole purpose is guaranteeing an
  operation with side effects runs at most once (this is also why finding
  #8, in Phase 3, matters: automatic retry-on-transport-error already risks
  this same double-execution from a different angle).
- `Redact` → the redacted body is served, exactly like a live redact would
  produce, with the same rule-name/log/webhook trail a fresh redaction gets.
- `Allow` → served unchanged, as today.

This is deliberately simpler than the review's own suggested alternative
(tagging each stored entry with a policy version and invalidating or
re-checking only on version mismatch): it needs no versioning scheme, no
invalidation bookkeeping, and is *always* current rather than current-as-of-
last-invalidation. The cost — running `Evaluate`/`EvaluateResponse` again on
every replay — is negligible: it's in-process regex matching against
already-buffered bytes, not an upstream call, and every replay path already
holds the full response body in memory to serve it.

One shared helper (`s.reevaluateStoredResponse(auth, r, forwardPath, header,
body) (allowed bool, ...)`) is called from all four replay sites instead of
four bespoke checks, so the four mechanisms can never drift out of sync on
this behavior in the future.

### 3. Semantic cache exact-match fields (finding #3)

`extractPromptText` is extended to also return a **structural remainder**:
the request body with only the free-text values it already extracts (message
`content` strings/text-blocks, `prompt`, `input`) blanked out in place,
leaving everything else — `model`, `stream`, message `role`s, `tools`,
`response_format`, `temperature`/`top_p`/other generation parameters, and any
future provider-specific field — untouched:

```go
func extractPromptText(body []byte) (text string, remainder []byte, ok bool)
```

`remainder`'s SHA256 becomes a new, mandatory **exact**-match component:
`semcache.Index.FindBest` only considers a candidate at all when its stored
remainder hash equals the incoming request's remainder hash; approximate
similarity (`semcache.Similarity`) is only computed among candidates that
already passed that equality check. `Index.Add`/`FindBest` gain a
`remainderHash string` parameter alongside their existing `target`/`fp`/
`cacheKey` ones.

This is deliberately not an enumerated field list (`model`, `stream`,
`system`, ...) the way the review itself suggests, because an enumerated list
needs updating every time a provider adds a new relevant request parameter
aiproxy doesn't yet know to check — a silent, easy-to-miss maintenance
burden. Hashing "everything that isn't extracted free text" is exact by
construction and never goes stale. It also incidentally fixes the review's
secondary observation that message **roles** are lost today: a role stays
part of the remainder (only a message's `content` value is blanked, not the
`role` key next to it), so a system-authored and a user-authored copy of the
same sentence are no longer treated as interchangeable.

The semantic cache also benefits from Section 1's fix, with no `semcache`
API change needed for it: `Index.Add`/`FindBest` already partition
exclusively by their `target string` argument, so `proxy.go`'s one call site
passes `targetLabel + "\x00" + partitionIdentity(auth, r)` as `target`
instead of `targetLabel` alone — the `semcache` package stays unaware that
its opaque partition label is now composite, and a semantic cache hit
becomes exactly as client-partitioned as an exact-match one.

### 4. Admin/client key separation (finding #6)

Two new `Server` fields, structurally identical to the existing proxy-key
ones:

```go
AdminAPIKey  string
AdminAPIKeys []ProxyKey
```

(`ProxyKey`'s existing shape — `Name`, `Key`, plus its rate-limit/cost-budget
fields — is reused as-is for admin keys too, even though an admin key has no
practical use for a per-key rate limit or cost budget; introducing a
separate, narrower type for admin keys purely to omit fields that are simply
never set on them would be more code for no behavioral difference.)

A new `checkAdminAuth(r *http.Request) bool` mirrors `checkProxyAuth`'s
constant-time comparison logic, checked in place of `checkProxyAuth` — not in
addition to it — for exactly the five admin paths (`statsPath`, `metricsPath`,
`dashboardPath`, `cacheClearPath`, `drainPath`).

Concretely, `checkNetworkAndAuthAccess` (today: CORS, then IP allow/deny, then
country allow/deny, then per-IP rate limit, then `checkProxyAuth`, as one
block) is split so the first four network-level gates become their own
private helper, `checkNetworkAccess(w, r, requestID) bool`, with no auth
opinion of its own. `checkNetworkAndAuthAccess` becomes a thin wrapper: call
`checkNetworkAccess`, then `checkProxyAuth` — used exactly where it is used
today, for ordinary proxied traffic. A new sibling,
`checkNetworkAndAdminAuthAccess(w, r, requestID) (clientAuth, bool)`, calls
the same `checkNetworkAccess` then `checkAdminAuth` instead — used for the
five admin paths in both `ServeHTTP` and `adminMux.ServeHTTP`, so the two
dispatch paths keep sharing identical network-level gating while diverging
only on which credential they require, and neither call site needs an
`isAdminPath bool` flag threaded through shared logic.

Per the explicit decision already made this session: **once `AdminAPIKey`/
`AdminAPIKeys` exists as a feature, admin paths always require an explicit
admin key** — a proxy client key that used to authenticate against
`/_aiproxy/drain` no longer does, regardless of whether `AdminAddr` is
configured. There is no fallback-to-proxy-keys compatibility path. This is a
deliberate breaking change to close finding #6 in every deployment shape,
including the common single-listener one where `AdminAddr` was never set.

`aiproxy validate` gains a new warning (not a hard error — an operator may
have a legitimate reason to run without any admin key at all, e.g. a
single-user local setup): if `admin_api_key`/`admin_api_keys` are both unset
in the config file, print a clear warning naming the exposed capability
(drain, cache-clear, stats) so an upgrading operator sees an actionable
message instead of silently discovering a 401 on their next `drain` call.

**Correction found during plan-writing:** the design originally described this
warning as conditional on whether `-admin-addr` is set and, if so, whether
it's bound to loopback. `AdminAddr` turns out to be a `start`-time-only CLI
flag (`-admin-addr`) with no config-file equivalent at all — `runValidate`
parses only `-config` and has no way to know what `-admin-addr` value (if
any) a later `aiproxy start` invocation will use. The warning is therefore
unconditional on admin-key absence alone, regardless of `AdminAddr`: even a
deployment that will bind the admin surface to loopback still benefits from
being told its admin paths accept any configured proxy key today, since IP
binding and key-based authorization are additive protections, not
substitutes for each other. Introducing a config-file-visible admin bind
address purely to make this warning AdminAddr-aware would be unrelated scope
creep for this phase.

## Config surface

New top-level fields, `admin_api_key` (string) and `admin_api_keys` (array,
same shape as `proxy_api_keys`):

```jsonc
{
  "admin_api_key": "...",
  "admin_api_keys": [
    { "name": "ops-oncall", "key": "..." }
  ]
}
```

No change to `proxy_api_key`/`proxy_api_keys`' own schema. No new schema for
Sections 1–3 — the partition identity, policy-before-replay re-check, and
semantic cache remainder hash are all internal mechanisms with no config
surface of their own, matching how the existing cache/coalescing/semantic
cache features already have no per-request-shape configuration.

## Code organization

- `internal/cache/cache.go`: `Key` signature grows a `partitionID string`
  parameter (Section 1).
- `internal/semcache/semcache.go`: `Index.Add`/`FindBest` grow a
  `remainderHash string` parameter, checked for exact equality before
  `Similarity` is consulted (Section 3). No change needed for partitioning —
  see Section 3's note on composing `partitionIdentity` into the existing
  `target` argument instead.
- `internal/proxy/proxy.go`:
  - `partitionIdentity(auth clientAuth, r *http.Request) string` (new,
    Section 1), called once in `ServeHTTP` alongside where `auth` is
    resolved, threaded into every `cache.Key`/coalescer/semantic-cache
    call site that currently omits it.
  - `extractPromptText`'s signature changes to also return the structural
    remainder (Section 3); its one call site updates to pass the new
    `remainderHash` through to `SemanticIndex.Add`/`FindBest`.
  - `s.reevaluateStoredResponse(...)` (new, Section 2), called from all four
    replay sites: the exact-match cache-hit branch, the coalescer's `Replay`
    branch, the semantic-cache-hit branch, and the idempotency `Replay`
    branch.
  - `AdminAPIKey`/`AdminAPIKeys` fields (Section 4), `checkAdminAuth`,
    `ReloadConfig`'s parameter list grows both new fields (matching how every
    other reloadable field already appears there).
  - `checkNetworkAndAuthAccess` splits into a shared `checkNetworkAccess`
    (CORS/IP/country/IP-rate-limit, no auth opinion) plus two thin callers:
    the existing `checkNetworkAndAuthAccess` (proxy auth, unchanged call
    sites) and a new `checkNetworkAndAdminAuthAccess` (admin auth). `
    ServeHTTP`/`adminMux.ServeHTTP` call the admin variant specifically for
    the five admin paths, the proxy variant for everything else (Section 4).
- `internal/cli/cli.go`: config parsing for `admin_api_key`/`admin_api_keys`
  (mirroring `proxy_api_key`/`proxy_api_keys`'s existing parsing exactly),
  `buildLiveConfig`/`runValidate` wiring, and the new validate-time warning
  when admin paths are reachable with no admin key configured.
- `internal/config/config.go`: `AdminAPIKey string` / `AdminAPIKeys
  []ProxyKeyConfig` fields on the config struct (mirroring the existing
  `ProxyAPIKey`/`ProxyAPIKeys` fields exactly).
- `README.md`: document `admin_api_key`/`admin_api_keys`, the fail-closed
  behavior and the new validate warning; extend the existing cache/coalescing/
  semantic-cache sections with one sentence each noting client-partitioning
  and current-policy re-validation on replay.

## Testing plan

Each of the four review reproduction tests (already committed at
`docs/reviews/2026-09-12-v0.74.1-repro/`) becomes this phase's own real,
permanent regression test once copied into its proper package and adapted to
the new function signatures:

- `TestReview_CacheMustIsolateCredentials` → `internal/proxy`: two different
  upstream `Authorization` values behind the same route, same body, must
  never receive each other's cached response.
- `TestReview_CacheMustEnforceClientRules` → `internal/proxy`: a per-key
  block rule (`Keys: []string{"bob"}`) must still fire for bob even when
  alice's identical, unblocked request already populated the cache.
- `TestReview_SemanticCacheMustRespectModelAndStream` → `internal/proxy`: an
  identical prompt sent to `model-a`/non-streaming then `model-b`/streaming
  must never produce a semantic-cache hit.
- `TestReview_ClientKeyMustNotControlDrain` → `internal/proxy`: an ordinary
  configured proxy key must receive 401/403 (not 200) against `/_aiproxy/
  drain`, `/_aiproxy/stats`, `/_aiproxy/cache/clear`; a configured admin key
  must succeed.

Additional cases beyond the four inherited ones:

- Coalescing: two concurrent identical requests from two different upstream
  credentials must each be forwarded independently (no coalescing across
  partitions), while two concurrent identical requests from the *same*
  partition still coalesce as today.
- Policy-before-replay: a cache entry populated before a block rule existed
  (or before it matched) must be blocked, not served, once the rule is added
  and a second identical request arrives — for all four replay mechanisms
  (cache, coalescing, semantic cache, idempotency), not just the exact-match
  cache case inherited above. The idempotency variant specifically asserts
  the request is **not** re-forwarded upstream when the stored response is
  now blocked (a second upstream call would itself be a new, separate bug).
- Semantic cache: identical prompt text with every other field held constant
  except one (`model`, `stream`, a tool definition, `response_format`,
  `temperature`) must fail to match, one negative test per field, so a
  future regression narrowing the remainder hash's coverage is caught
  per-field rather than only in aggregate.
- Admin keys: `aiproxy validate` emits the new warning whenever
  `admin_api_key`/`admin_api_keys` are both unset in the config file (see
  the Section 4 correction above — this is unconditional on `AdminAddr`,
  which validate cannot see); no warning when either is configured.
- `ReloadConfig` correctly swaps live `AdminAPIKey`/`AdminAPIKeys` without a
  restart, matching every other reloadable field's existing test coverage
  pattern.

## Rejected alternatives

- **Policy-version tagging instead of always-re-evaluate** (Section 2): the
  review's own suggested approach. Rejected because it requires designing and
  maintaining a version/generation concept for the rules engine, an
  invalidation-or-recheck decision per version bump, and is only ever as
  fresh as the last invalidation — versus always-re-evaluate, which needs no
  version concept at all and is unconditionally correct by construction. The
  performance cost of re-running regex matching against already-buffered
  bytes on a replay is negligible next to that simplicity win.
- **Scopes/roles matrix (`proxy:use`, `stats:read`, `cache:clear`,
  `drain:write`) instead of a binary admin key** (Section 4): the review
  raises this as one option among others. Rejected for v1 as over-engineering
  relative to the actual requirement ("a client must never administer the
  instance") — a binary distinction closes the finding completely; a
  granular scope matrix adds config surface and code paths with no present
  use case, and can be layered on top of the `AdminAPIKey`/`AdminAPIKeys`
  fields later without breaking them if a real need for finer-grained roles
  ever appears.
- **Enumerated exact-match field list for semantic cache** (Section 3):
  rejected in favor of structural-remainder hashing — see Section 3's own
  reasoning above.
- **Opt-in "shared cache across clients" config knob** (Section 1): rejected
  as YAGNI — no current use case, and it would need its own careful design
  (which endpoints are safe to share, how a client opts in) that is better
  deferred until someone actually needs it.
