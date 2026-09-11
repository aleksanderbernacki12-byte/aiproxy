# Semantic cache — design spec

Date: 2026-09-12
Status: approved, pending implementation plan

## Purpose

aiproxy's existing on-disk cache (`internal/cache`) only serves a hit for a
byte-for-byte identical request (same method, target URL, and body — see
`cache.Key`). Two functionally identical LLM calls that differ by even a
single character — a rephrased prompt, reordered whitespace, a client that
appends a timestamp to its system message — are two independent cache
misses, two independent upstream calls, two independent bills.

Semantic cache adds a second, approximate lookup layer: when the exact
cache misses, aiproxy checks whether a *recent, sufficiently similar*
request already has a cached answer for this target, and serves that
instead of forwarding upstream. This is the first aiproxy feature that
reasons about LLM request *content* rather than treating the body as an
opaque blob — the "AI-aware intelligence" direction chosen over generic
reverse-proxy features.

This is explicitly an approximate, best-effort feature. It trades a small
risk of serving a slightly-mismatched answer for a real reduction in
upstream calls/cost on repetitive or near-duplicate traffic (the exact
pattern aiproxy already targets: runaway/repetitive agent loops). Clients
are always told when this trade was made (see Transparency below) so they
can decide whether it's acceptable for that call.

## Scope for v1

- **Global-only configuration** — no per-target override, mirroring
  `cache_request_coalescing` (the most recent and most architecturally
  similar feature) rather than the older per-target `cache_enabled`/
  `cache_ttl_seconds` pattern. Per-target tuning can be added later if a
  real need shows up; nothing here forecloses it.
- **Requires `cache_enabled: true`** — same reasoning as
  `cache_request_coalescing` and `cache_ttl_seconds`: this feature only
  makes sense layered on top of the real cache, which is what actually
  stores and serves the response bytes.
- **Local-only similarity computation.** No external embeddings API, no
  new secret to manage, no added latency or cost on a cache miss. This
  was a deliberate, explicit trade against true semantic (meaning-based)
  matching — see "Rejected: external embeddings" below.
- Best-effort text extraction from common LLM request body shapes only
  (see below). A request whose body doesn't match any recognized shape
  simply never participates in semantic caching — exact-match caching is
  completely unaffected either way.

## Text extraction

New shallow, best-effort struct in `internal/proxy` (same style and
precedent as the existing `modelField` used by `resolveModelRoute`):

```go
type promptFields struct {
    Prompt   string `json:"prompt"`
    Input    string `json:"input"`
    Messages []struct {
        Content json.RawMessage `json:"content"`
    } `json:"messages"`
}
```

`Content` is decoded permissively: a plain JSON string is used directly;
a JSON array (OpenAI/Anthropic "content blocks" shape,
`[{"type":"text","text":"..."}]`) has every block's `text` field
concatenated, in order. Extraction concatenates, in order: every
`messages[].content` text, then `Prompt`, then `Input`. If none of these
fields decode to any non-empty text, the request is not a candidate for
semantic caching (falls through to existing exact-cache-miss behavior,
unchanged).

This is intentionally not an exhaustive or provider-specific parser — it
covers the two dominant chat-message conventions (OpenAI- and
Anthropic-shaped `messages[].content`) plus the legacy single-string
`prompt`/`input` fields, the same "recognize the common shape, don't
guess at the rest" discipline already used for `model`-based routing.

## Fingerprinting & similarity

New package `internal/semcache`, deliberately independent of
`internal/proxy`, `internal/cache`, `internal/coalesce`, and
`internal/idempotency` — it knows nothing about HTTP, JSON, or caching
semantics; it operates purely on text and integer fingerprints, which
keeps it trivially unit-testable without any HTTP/JSON scaffolding.

```go
// Fingerprint returns text's shingle fingerprint: lowercase, collapse
// whitespace, split into words, hash every overlapping 3-word shingle
// (FNV-1a, 64-bit), and return the deduplicated, sorted set of hashes.
func Fingerprint(text string) []uint64

// Similarity returns the Jaccard similarity of two fingerprints —
// |intersection| / |union| — computed exactly via a merge over the two
// sorted slices, in [0, 1]. Two empty fingerprints are defined as 0
// (never a match), not 1, so an empty/unextractable prompt can never
// spuriously "match" another one.
func Similarity(a, b []uint64) float64
```

Exact Jaccard over shingle sets, **not** an approximate sketch (MinHash/
SimHash). At aiproxy's actual operating scale — a local proxy's semantic
index, capped at a few thousand entries per target (see Index below) —
an exact merge-based comparison costs microseconds; there is no
scale problem to approximate away, and skipping the approximation buys
fully deterministic, seed-free unit tests (a real correctness property,
not just convenience: MinHash's whole value proposition is trading exact
correctness for a compact sketch at scales this feature doesn't
encounter). 3-word shingles were chosen (over word-level unigrams, which
match on individual word overlap regardless of order, or character
n-grams, which are more robust to typos but far more expensive at these
text lengths) as the standard middle ground for near-duplicate detection
— it tolerates minor rewording/reordering better than a hash of the
whole normalized string while still requiring genuine multi-word overlap
to register any similarity at all.

**What this does and doesn't catch.** Shingle-based Jaccard finds
near-duplicate *phrasings* — the same request restated with minor edits,
whitespace/punctuation differences, or small additions. It does **not**
find true paraphrases with substantially different wording but the same
meaning ("what's the capital of Sweden" vs. "name Sweden's seat of
government") — that would require real embeddings. This limitation is
the direct, accepted consequence of the "local-only, no external calls"
scope decision above, and must be stated plainly in the README so users
don't over-expect it.

## Index

```go
type Index struct {
    mu      sync.Mutex
    maxSize int
    entries map[string][]entry // target -> insertion order, oldest first
}

type entry struct {
    fingerprint []uint64
    cacheKey    string
}

func NewIndex(maxSize int) *Index

// Add appends fp/cacheKey for target, evicting the oldest entry for that
// target first if it's already at maxSize (FIFO, not LRU — see below).
func (ix *Index) Add(target string, fp []uint64, cacheKey string)

// FindBest returns the highest-similarity entry for target that is at
// or above threshold, or ok=false if none qualifies.
func (ix *Index) FindBest(target string, fp []uint64, threshold float64) (cacheKey string, similarity float64, ok bool)

func (ix *Index) Len(target string) int
```

FIFO eviction (not LRU, not TTL-based) was chosen deliberately: unlike
`idempotency.Registry`, which needs a TTL because a client might
legitimately retry the same idempotency key hours later, a semantic
index entry's only job is to catch traffic that's *clustered in time*
(the repetitive-agent-loop case this whole feature targets) — a fixed
capacity cap is simpler than a timer-driven sweep goroutine and needs no
background goroutine at all, while still bounding memory unconditionally
regardless of how `cache_ttl_seconds` is configured (including
`cache_ttl_seconds: 0`, "never expire").

`maxSize` is an internal constant, `DefaultIndexSize = 2000` entries per
target, not user-configurable for v1 — a config knob here would require
the user to reason about memory-vs-recall trade-offs with no real-world
data yet to size it against. 2000 fingerprints per target is a small,
fixed memory cost (each fingerprint is at most a few hundred `uint64`s)
against realistic per-target request volumes for a local proxy; revisit
if real usage shows it needs to be exposed as config.

## Request flow integration

Hooks into `internal/proxy/proxy.go`'s existing cache block, right after
today's exact-key `cch.Get` miss and before the coalescing `Claim` call
that already lives in that same `if cch != nil && cacheEnabledForTarget`
block:

1. Exact cache lookup (unchanged). Hit → served as today, semantic layer
   never runs.
2. On exact miss, if `semantic_cache_enabled`: extract prompt text
   (above); if extraction succeeds, compute its fingerprint and call
   `Index.FindBest(target, fp, threshold)`.
3. If a candidate is found, **re-verify freshness** by calling the real
   `cch.Get(candidateCacheKey, ttl)` — the index only stores fingerprints
   and keys, never response bytes, so a candidate whose underlying entry
   has since expired (TTL) or been evicted (`MaxSizeBytes` LRU) must be
   caught here. If that lookup misses, the semantic candidate is treated
   as a full miss for this request — **no second-best fallback** attempt,
   matching the project's established "collapse to one check, don't chase
   edge cases with more branches" discipline (e.g. idempotency's single
   Claim attempt, coalescing's single Claim attempt). Falls through to
   the existing coalescing → upstream-forward path exactly as if no
   semantic match had been searched for.
4. If the re-verified fetch hits, serve that cached response with the
   transparency headers below, and skip coalescing/upstream entirely for
   this request.
5. Indexing for *future* lookups happens at every point a response is
   currently written to the real cache (the existing `cch.Set` call
   sites in `bufferResponse` and `streamResponse`) — immediately after a
   successful `Set`, also extract+fingerprint that request's prompt text
   and `Index.Add` it. A request that was itself served from the
   semantic cache is not re-indexed (it produced no new upstream
   response bytes to index against).

## Transparency & observability

- Response headers on a semantic-cache hit only:
  `X-Semantic-Cache-Hit: true` and `X-Semantic-Cache-Similarity: 0.93`
  (formatted to 2 decimal places) — mirrors the reasoning already
  established for `Idempotency-Replayed: true`: the client opted into
  (or at least was told about, via config/docs) an approximate-match
  feature and deserves to know when a specific response used it, since
  it's the one case where aiproxy knowingly serves an answer to a
  *different* request than the one the client actually sent.
- New per-target stats counter `SemanticCacheHits`, mirroring
  `CacheHits`/`CoalescedRequests` exactly (same `counters` struct, same
  `Record*`/snapshot/reset shape).
- New Prometheus metric `aiproxy_semantic_cache_hits_total`, labeled by
  target, alongside the existing `aiproxy_cache_hits_total`.
- New log line on hit, `[SEMANTIC CACHE HIT]`, following the existing
  colored-log-line convention (reusing the cache hit's color).

## Config surface

```jsonc
{
  "cache_enabled": true,
  "semantic_cache_enabled": true,
  "semantic_cache_threshold": 0.9
}
```

- `Config.SemanticCacheEnabled bool` (`semantic_cache_enabled`) —
  global only, default `false`.
- `Config.SemanticCacheThreshold float64` (`semantic_cache_threshold`) —
  **required** when `semantic_cache_enabled` is `true` (validated in
  `runValidate` and `buildLiveConfig`, same asymmetry already accepted
  for `cost_budget`/`cost_per_1k_tokens`), must be in `(0, 1]`. Required
  rather than defaulted — mirroring `idempotency_ttl_seconds`'s "TTL
  required when idempotency is enabled" precedent — because there is no
  universally-safe default threshold the way "never expire" is a safe
  default TTL: too low risks serving wrong answers, too high makes the
  feature a no-op, and the right value is inherently workload-specific.
- Validation errors: `semantic_cache_enabled requires cache_enabled`,
  `semantic_cache_threshold requires semantic_cache_enabled`,
  `semantic_cache_threshold must be greater than 0 and at most 1`.
- Startup notice line and `runValidate` summary line, matching every
  prior feature's pattern (e.g. `cache request coalescing:`).

## Rejected alternatives (recorded for future reference)

- **External embeddings API for true semantic matching** — rejected for
  v1 per the direct clarifying-question answer: adds latency and cost to
  every cache miss (defeating some of the cost-saving purpose), adds a
  new secret to manage, and breaks the project's maintained
  zero-external-dependency stance. Could be revisited later as an
  opt-in upgrade layered *behind* this same `Index`/`FindBest` interface
  (a different `Fingerprint` implementation), without disturbing this
  design.
- **MinHash/SimHash approximate sketches** — rejected because the
  project's actual scale doesn't need the space savings, and exact
  Jaccard is simpler to implement, explain, and test deterministically.
- **Per-target threshold override** — deferred, not rejected outright;
  no per-target need has been identified yet, and global-only exactly
  mirrors the newest comparable feature (`cache_request_coalescing`).
- **Invisible semantic hits (no marker header)** — rejected per the
  direct clarifying-question answer: unlike coalescing (which serves the
  literal same response the client would have gotten anyway, just from
  another concurrent copy of the same request), a semantic hit can serve
  an answer to a *materially different* request, which the client should
  be able to detect.

## Testing plan

- **`internal/semcache` unit tests** (no HTTP/JSON involved, fully
  deterministic, no network): `Fingerprint` normalization (case,
  whitespace, shingling boundaries), `Similarity` on known set pairs
  (identical, disjoint, partial overlap, both-empty), `Index.Add` FIFO
  eviction at capacity, `Index.FindBest` threshold boundary behavior
  (exactly-at-threshold counts as a match), multi-target isolation (an
  entry added under one target is never returned for another).
- **`internal/proxy` integration tests**, real HTTP requests against a
  real local upstream test server (no mocking, per established project
  practice): a rephrased-but-similar prompt served from a prior
  response's cache entry with the marker headers present and correct
  similarity value; a genuinely different-topic prompt never matching
  (independent real upstream hit); the re-verify-freshness path (index
  entry present but underlying cache entry already TTL-expired) falling
  through to a real fresh upstream forward, not an error; threshold
  boundary enforced with real bodies just above/below the configured
  cutoff; stats/Prometheus/log line assertions; `ReloadConfig` hot-swap
  of `semantic_cache_enabled`/`semantic_cache_threshold` taking effect
  without a restart.
- **`internal/cli` validation tests**: every new validation error message
  above, plus a valid config accepted.
