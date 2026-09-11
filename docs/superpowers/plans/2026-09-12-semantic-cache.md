# Semantic Cache Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an approximate second cache layer (`semantic_cache_enabled` / `semantic_cache_threshold`) that serves a request from a recent, sufficiently similar prior request's cached answer when the exact-match cache misses — using only local, deterministic text-similarity (no external embeddings API).

**Architecture:** A new, dependency-free `internal/semcache` package computes a word-shingle fingerprint for extracted prompt text and holds a per-target, FIFO-capped index of `{fingerprint, cache key}` pairs; `internal/proxy` extracts prompt text from recognized LLM body shapes, checks the index right after an exact-cache miss (re-verifying any candidate against the real on-disk cache before serving it), and indexes every newly-cached response for future lookups. Global-only config, gated behind `cache_enabled`, mirroring `cache_request_coalescing`.

**Tech Stack:** Go standard library only (`hash/fnv`, `sort`, `sync`, `encoding/json`) — no new external dependencies.

**Spec:** `docs/superpowers/specs/2026-09-12-semantic-cache-design.md`

---

### Task 1: `internal/semcache` package

**Files:**
- Create: `internal/semcache/semcache.go`
- Create: `internal/semcache/semcache_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/semcache/semcache_test.go
package semcache_test

import (
	"testing"

	"aiproxy/internal/semcache"
)

func TestFingerprint_NormalizesCaseAndWhitespace(t *testing.T) {
	a := semcache.Fingerprint("Hello   World Today")
	b := semcache.Fingerprint("hello world today")
	if semcache.Similarity(a, b) != 1 {
		t.Fatalf("expected identical fingerprints after normalization, got similarity %v", semcache.Similarity(a, b))
	}
}

func TestFingerprint_ShortTextHasEmptyFingerprint(t *testing.T) {
	fp := semcache.Fingerprint("hi there")
	if len(fp) != 0 {
		t.Fatalf("expected empty fingerprint for text shorter than one shingle, got %d hashes", len(fp))
	}
}

func TestFingerprint_UnrelatedTextsHaveNoOverlap(t *testing.T) {
	a := semcache.Fingerprint("what is the capital of Sweden")
	b := semcache.Fingerprint("explain how photosynthesis works in plants")
	if sim := semcache.Similarity(a, b); sim != 0 {
		t.Fatalf("expected 0 similarity for unrelated text, got %v", sim)
	}
}

func TestSimilarity_IdenticalFingerprintsIsOne(t *testing.T) {
	fp := semcache.Fingerprint("the quick brown fox jumps over the lazy dog")
	if sim := semcache.Similarity(fp, fp); sim != 1 {
		t.Fatalf("expected similarity 1 for identical fingerprints, got %v", sim)
	}
}

func TestSimilarity_PartialOverlapComputesExactJaccard(t *testing.T) {
	a := []uint64{1, 2, 3, 4}
	b := []uint64{3, 4, 5, 6}
	// intersection={3,4} (2), union={1,2,3,4,5,6} (6) -> 2/6
	want := float64(2) / float64(6)
	if sim := semcache.Similarity(a, b); sim != want {
		t.Fatalf("similarity = %v, want %v", sim, want)
	}
}

func TestSimilarity_BothEmptyIsZeroNotOne(t *testing.T) {
	if sim := semcache.Similarity(nil, nil); sim != 0 {
		t.Fatalf("expected 0 for two empty fingerprints, got %v", sim)
	}
}

func TestSimilarity_OneEmptyIsZero(t *testing.T) {
	nonEmpty := []uint64{1, 2, 3}
	if sim := semcache.Similarity(nil, nonEmpty); sim != 0 {
		t.Fatalf("expected 0 when one fingerprint is empty, got %v", sim)
	}
}

func TestIndex_AddAndFindBest_ExactMatch(t *testing.T) {
	ix := semcache.NewIndex(10)
	fp := semcache.Fingerprint("what is the capital of Sweden")
	ix.Add("targetA", fp, "cachekey-1")

	key, sim, ok := ix.FindBest("targetA", fp, 0.5)
	if !ok {
		t.Fatal("expected a match")
	}
	if key != "cachekey-1" {
		t.Fatalf("cacheKey = %q, want %q", key, "cachekey-1")
	}
	if sim != 1 {
		t.Fatalf("similarity = %v, want 1", sim)
	}
}

func TestIndex_FindBest_BelowThresholdNotFound(t *testing.T) {
	ix := semcache.NewIndex(10)
	ix.Add("targetA", semcache.Fingerprint("what is the capital of Sweden"), "cachekey-1")

	_, _, ok := ix.FindBest("targetA", semcache.Fingerprint("explain how photosynthesis works in plants"), 0.5)
	if ok {
		t.Fatal("expected no match for unrelated text")
	}
}

func TestIndex_FindBest_AtExactlyThresholdCountsAsMatch(t *testing.T) {
	ix := semcache.NewIndex(10)
	a := []uint64{1, 2, 3, 4}
	b := []uint64{3, 4, 5, 6} // similarity exactly 2/6
	ix.Add("targetA", a, "cachekey-1")

	threshold := float64(2) / float64(6)
	_, sim, ok := ix.FindBest("targetA", b, threshold)
	if !ok {
		t.Fatalf("expected a match when similarity (%v) exactly equals threshold", sim)
	}
}

func TestIndex_FindBest_ReturnsHighestSimilarityAmongMultiple(t *testing.T) {
	ix := semcache.NewIndex(10)
	query := []uint64{1, 2, 3, 4, 5}
	ix.Add("targetA", []uint64{1, 2, 3}, "low-overlap")   // 3/5 = 0.6
	ix.Add("targetA", []uint64{1, 2, 3, 4, 5}, "exact")   // 5/5 = 1.0
	ix.Add("targetA", []uint64{1, 2, 3, 4}, "mid-overlap") // 4/5 = 0.8

	key, sim, ok := ix.FindBest("targetA", query, 0.5)
	if !ok || key != "exact" {
		t.Fatalf("FindBest = (%q, %v, %v), want (\"exact\", 1, true)", key, sim, ok)
	}
}

func TestIndex_Add_EvictsOldestWhenAtCapacity(t *testing.T) {
	ix := semcache.NewIndex(2)
	first := semcache.Fingerprint("what is the capital of Sweden")
	ix.Add("targetA", first, "cachekey-1")
	ix.Add("targetA", semcache.Fingerprint("explain how photosynthesis works"), "cachekey-2")
	ix.Add("targetA", semcache.Fingerprint("describe the water cycle in nature"), "cachekey-3")

	if n := ix.Len("targetA"); n != 2 {
		t.Fatalf("Len = %d, want 2 (capacity 2, oldest evicted)", n)
	}
	if _, _, ok := ix.FindBest("targetA", first, 0.99); ok {
		t.Fatal("expected the oldest entry to have been evicted, but it was still found")
	}
}

func TestIndex_MultiTargetIsolation(t *testing.T) {
	ix := semcache.NewIndex(10)
	fp := semcache.Fingerprint("what is the capital of Sweden")
	ix.Add("targetA", fp, "cachekey-1")

	if _, _, ok := ix.FindBest("targetB", fp, 0.5); ok {
		t.Fatal("expected an entry added under targetA to never match a lookup under targetB")
	}
}

func TestIndex_Len(t *testing.T) {
	ix := semcache.NewIndex(10)
	if n := ix.Len("targetA"); n != 0 {
		t.Fatalf("Len on empty index = %d, want 0", n)
	}
	ix.Add("targetA", semcache.Fingerprint("some text here today"), "cachekey-1")
	if n := ix.Len("targetA"); n != 1 {
		t.Fatalf("Len after one Add = %d, want 1", n)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/semcache/... -v`
Expected: FAIL — `package aiproxy/internal/semcache is not in std` / `no such file or directory` (the package doesn't exist yet).

- [ ] **Step 3: Write the implementation**

```go
// internal/semcache/semcache.go

// Package semcache implements aiproxy's local, approximate semantic
// cache index: a text fingerprint plus a Jaccard-similarity index used
// to find a recent, sufficiently similar prior request's cached answer
// for one that doesn't match anything in the exact-match cache. It
// knows nothing about HTTP, JSON, or aiproxy's cache/coalesce/
// idempotency packages — only text and integer fingerprints — the same
// isolation every other internal package here holds to.
package semcache

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"
)

// DefaultIndexSize is the default per-target capacity of an Index — see
// NewIndex.
const DefaultIndexSize = 2000

// shingleSize is the number of consecutive words hashed together into
// one shingle. 3 is the standard middle ground for near-duplicate
// detection: word-level unigrams (shingleSize 1) would match on
// individual word overlap regardless of order, while character n-grams
// are far more expensive at these text lengths for little extra benefit
// here.
const shingleSize = 3

// Fingerprint returns text's shingle fingerprint: lowercase, collapse
// whitespace, split into words, hash every overlapping shingleSize-word
// shingle (FNV-1a, 64-bit), and return the deduplicated, sorted set of
// hashes. Two calls with equivalent text (same words, any whitespace)
// always return identical fingerprints — Similarity relies on this to
// compare fingerprints by a simple merge, with no normalization step of
// its own. Text with fewer than shingleSize words produces an empty
// fingerprint (zero shingles exist) — Similarity treats two empty
// fingerprints as never matching, so a trivially short prompt simply
// never participates in semantic matching, in either direction.
func Fingerprint(text string) []uint64 {
	words := strings.Fields(strings.ToLower(text))
	seen := make(map[uint64]struct{})
	for i := 0; i+shingleSize <= len(words); i++ {
		h := fnv.New64a()
		for j := i; j < i+shingleSize; j++ {
			h.Write([]byte(words[j]))
			h.Write([]byte{0})
		}
		seen[h.Sum64()] = struct{}{}
	}
	hashes := make([]uint64, 0, len(seen))
	for h := range seen {
		hashes = append(hashes, h)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	return hashes
}

// Similarity returns the Jaccard similarity of two fingerprints —
// |intersection| / |union| — computed exactly via a merge over the two
// sorted slices, in [0, 1]. Two empty fingerprints are defined as 0, not
// 1 (which the standard Jaccard definition over two empty sets would
// otherwise give): an empty or unextractable prompt must never
// spuriously "match" another one.
func Similarity(a, b []uint64) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var i, j, intersection int
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			intersection++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	union := len(a) + len(b) - intersection
	return float64(intersection) / float64(union)
}

// entry is one recorded fingerprint/cache-key pair inside an Index.
type entry struct {
	fingerprint []uint64
	cacheKey    string
}

// Index holds, per target, the most recent fingerprints of requests
// that produced a real cached response, used to find a similar-enough
// prior request for one that doesn't match the exact-match cache.
//
// Capped at maxSize entries per target, evicted oldest-first (FIFO, not
// LRU or TTL-based): unlike idempotency.Registry, an entry here only
// needs to catch traffic clustered in time — the repetitive-agent-loop
// case this whole feature targets — so a fixed capacity is simpler than
// a timer-driven sweep and bounds memory unconditionally, regardless of
// how the real cache's own TTL is configured (including "never
// expire"). An Index never stores response bytes itself, only
// fingerprints and the real cache's own key — the caller must always
// re-verify a candidate against the real cache before serving it, since
// the underlying entry may have since expired or been evicted there.
type Index struct {
	mu      sync.Mutex
	maxSize int
	entries map[string][]entry
}

// NewIndex creates an Index capping each target's own entries at
// maxSize.
func NewIndex(maxSize int) *Index {
	return &Index{maxSize: maxSize, entries: make(map[string][]entry)}
}

// Add records fp/cacheKey under target, evicting that target's oldest
// entry first if it's already at maxSize.
func (ix *Index) Add(target string, fp []uint64, cacheKey string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	list := ix.entries[target]
	if len(list) >= ix.maxSize {
		list = list[1:]
	}
	ix.entries[target] = append(list, entry{fingerprint: fp, cacheKey: cacheKey})
}

// FindBest returns the highest-similarity entry recorded under target
// that's at or above threshold, or ok=false if none qualifies (either
// because target has no entries, or none reach threshold).
func (ix *Index) FindBest(target string, fp []uint64, threshold float64) (cacheKey string, similarity float64, ok bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var best float64
	var bestKey string
	found := false
	for _, e := range ix.entries[target] {
		sim := Similarity(fp, e.fingerprint)
		if sim >= threshold && (!found || sim > best) {
			best = sim
			bestKey = e.cacheKey
			found = true
		}
	}
	return bestKey, best, found
}

// Len reports how many entries are currently recorded under target —
// used by tests to assert eviction behavior.
func (ix *Index) Len(target string) int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.entries[target])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/semcache/... -v -race`
Expected: PASS (all 13 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/semcache/semcache.go internal/semcache/semcache_test.go
git commit -m "$(cat <<'EOF'
Add internal/semcache package for approximate prompt-similarity caching

Local, dependency-free shingle-based Jaccard similarity and a
FIFO-capped per-target index, built independently of cache/coalesce/
idempotency per the design spec.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Config fields

**Files:**
- Modify: `internal/config/config.go:626` (right after `CacheRequestCoalescing`)

- [ ] **Step 1: Add the two new fields**

Find this in `internal/config/config.go` (the `CacheRequestCoalescing` field and its doc comment, ending at line 626):

```go
	CacheRequestCoalescing bool `json:"cache_request_coalescing,omitempty"`
```

Replace with:

```go
	CacheRequestCoalescing bool `json:"cache_request_coalescing,omitempty"`

	// SemanticCacheEnabled turns on an approximate second cache layer:
	// when the exact-match cache misses, aiproxy checks whether a
	// recent, sufficiently similar request (see SemanticCacheThreshold)
	// already produced a cached answer for this target, using only a
	// local text-similarity comparison — no external embeddings API, no
	// added latency or cost on a miss. Global only, no per-target
	// override, mirroring CacheRequestCoalescing rather than the older
	// per-target CacheEnabled/CacheTTLSeconds pattern. A hit here is
	// marked with an X-Semantic-Cache-Hit response header, unlike
	// CacheRequestCoalescing's deliberately invisible replay: unlike
	// coalescing, which serves the literal answer the client would have
	// gotten anyway, a semantic hit can serve the answer to a materially
	// different request, which the client should be able to detect. Only
	// meaningful alongside CacheEnabled, same reasoning as
	// CacheRequestCoalescing: there's no cache key for a semantic match
	// to point at otherwise. false (the default) means this second
	// lookup layer never runs at all, unchanged from before this field
	// existed.
	SemanticCacheEnabled bool `json:"semantic_cache_enabled,omitempty"`

	// SemanticCacheThreshold is the minimum Jaccard similarity (0
	// exclusive, 1 inclusive) two requests' extracted prompt text must
	// reach for the more recent one to be served the older one's cached
	// answer — see the semcache package. Required whenever
	// SemanticCacheEnabled is true: unlike CacheTTLSeconds' "zero means
	// never expire" default, there is no universally safe default
	// threshold (too low risks serving a mismatched answer, too high
	// makes the feature a no-op, and the right value is inherently
	// workload-specific), the same reasoning IdempotencyTTLSeconds
	// already requires an explicit value for — including that same
	// field's asymmetry: a threshold set without SemanticCacheEnabled is
	// not itself flagged as an error, only the reverse.
	SemanticCacheThreshold float64 `json:"semantic_cache_threshold,omitempty"`
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./...`
Expected: success, no output.

- [ ] **Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "$(cat <<'EOF'
Add semantic_cache_enabled/semantic_cache_threshold config fields

Config-only groundwork for the semantic cache feature; not yet wired
into anything.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Server plumbing — fields, accessors, `ReloadConfig` growth

This task adds the `Server`-level storage for the semantic index/threshold and grows `ReloadConfig`'s signature to carry them through a config reload, mirroring exactly how `Coalescer`/`Idempotency` were added in earlier releases. It's purely mechanical and additive — no behavior changes yet, so the entire existing test suite must still pass unchanged afterwards.

**Files:**
- Modify: `internal/proxy/proxy.go` (imports, `Server` struct, accessors, `ReloadConfig` signature and body, `requestContextInfo` struct)
- Modify (via script): `internal/proxy/proxy_test.go`, `internal/proxy/idempotency_test.go`, `internal/proxy/coalesce_test.go`, `internal/cli/cli.go` (every `ReloadConfig` call site)

- [ ] **Step 1: Add the import**

In `internal/proxy/proxy.go`, find:

```go
	"aiproxy/internal/rules"
	"aiproxy/internal/stats"
)
```

Replace with:

```go
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
	"aiproxy/internal/stats"
)
```

- [ ] **Step 2: Add the `Server` struct fields**

Find:

```go
	Coalescer *coalesce.Group

	// CacheTTL is the server-wide default TTL passed to Cache.Get/
```

Replace with:

```go
	Coalescer *coalesce.Group

	// SemanticIndex, if non-nil, is checked right after an exact-match
	// cache lookup misses: it finds the most recent, sufficiently
	// similar (see SemanticCacheThreshold) prior request's own cache key
	// for this target, using only a local text-similarity comparison —
	// see the semcache package's own doc comment. A hit here is marked
	// with an X-Semantic-Cache-Hit response header, unlike Coalescer's
	// deliberately invisible replay: unlike coalescing, which serves the
	// literal answer the client would have gotten anyway, a semantic hit
	// can serve the answer to a materially different request. nil (the
	// default, whenever semantic_cache_enabled isn't configured)
	// disables this second lookup layer entirely. Only meaningful
	// alongside Cache being non-nil.
	SemanticIndex *semcache.Index

	// SemanticCacheThreshold is the minimum Jaccard similarity (see
	// semcache.Similarity) two requests' extracted prompt text must
	// reach for SemanticIndex to treat them as a match. Only meaningful
	// alongside SemanticIndex being non-nil.
	SemanticCacheThreshold float64

	// CacheTTL is the server-wide default TTL passed to Cache.Get/
```

- [ ] **Step 3: Add the accessors**

Find:

```go
func (s *Server) getCoalescer() *coalesce.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Coalescer
}
```

Replace with:

```go
func (s *Server) getCoalescer() *coalesce.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Coalescer
}

func (s *Server) getSemanticIndex() *semcache.Index {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SemanticIndex
}

func (s *Server) getSemanticCacheThreshold() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.SemanticCacheThreshold
}
```

- [ ] **Step 4: Add the `requestContextInfo` field**

Find:

```go
	// coalesceOwned is true when this request won ownership of
	// cacheKey's own coalescing claim (see Server.Coalescer) — meaning
	// bufferResponse/streamResponse must call Coalescer.Store once the
	// real response is known, waking any concurrent identical request
	// that's waiting on it. false whenever coalescing isn't configured,
	// this request's own content wasn't a cache miss in the first
	// place, or it gave up waiting for another owner instead (Bypass) —
	// in every one of those cases there is no claim this request holds
	// to complete.
	coalesceOwned bool
```

Replace with:

```go
	// coalesceOwned is true when this request won ownership of
	// cacheKey's own coalescing claim (see Server.Coalescer) — meaning
	// bufferResponse/streamResponse must call Coalescer.Store once the
	// real response is known, waking any concurrent identical request
	// that's waiting on it. false whenever coalescing isn't configured,
	// this request's own content wasn't a cache miss in the first
	// place, or it gave up waiting for another owner instead (Bypass) —
	// in every one of those cases there is no claim this request holds
	// to complete.
	coalesceOwned bool

	// semanticFingerprint is this request's own extracted-prompt
	// fingerprint (see semcache.Fingerprint), computed once in ServeHTTP
	// alongside cacheKey — nil whenever semantic caching is disabled or
	// no recognizable prompt text could be extracted from the body.
	// Carried through to bufferResponse/streamResponse so they can index
	// it (Server.SemanticIndex.Add) once this request's own real
	// response is known, the same way cacheKey lets them write the
	// on-disk cache entry.
	semanticFingerprint []uint64
```

- [ ] **Step 5: Run the mechanical `ReloadConfig` signature-growth script**

This appends two parameters (`semanticIndex *semcache.Index, semanticCacheThreshold float64`) to `ReloadConfig`'s signature, assigns them to the two new `Server` fields, and appends `, nil, 0` to every one of the 19 existing call sites (all of them currently end their argument list right after the `coalescer` argument) so the whole repo keeps compiling. `internal/cli/cli.go`'s call site is deliberately given `nil, 0` here too — it's switched to the real `lc.semanticIndex, lc.semanticCacheThreshold` values in Task 8, once those `liveConfig` fields exist.

Run this from the repo root:

```bash
python3 <<'EOF'
def insert_before_close(text, open_idx, insertion):
    depth = 0
    i = open_idx
    while i < len(text):
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return text[:i] + insertion + text[i:]
        i += 1
    raise ValueError("no matching close paren found")

# 1. Patch the ReloadConfig signature + field assignments in proxy.go
path = "internal/proxy/proxy.go"
with open(path) as f:
    text = f.read()

sig_marker = "func (s *Server) ReloadConfig("
sig_idx = text.index(sig_marker)
open_idx = sig_idx + len(sig_marker) - 1
text = insert_before_close(text, open_idx, ", semanticIndex *semcache.Index, semanticCacheThreshold float64")

old_assign = "\ts.Idempotency = idempotencyRegistry\n\ts.Coalescer = coalescer\n"
new_assign = old_assign + "\ts.SemanticIndex = semanticIndex\n\ts.SemanticCacheThreshold = semanticCacheThreshold\n"
count = text.count(old_assign)
if count != 1:
    raise ValueError(f"expected exactly one match for field-assignment block, found {count}")
text = text.replace(old_assign, new_assign, 1)

with open(path, "w") as f:
    f.write(text)

# 2. Patch every ReloadConfig call site
import re
call_sites = [
    "internal/proxy/proxy_test.go",
    "internal/proxy/idempotency_test.go",
    "internal/proxy/coalesce_test.go",
    "internal/cli/cli.go",
]
for p in call_sites:
    with open(p) as f:
        text = f.read()
    marker = ".ReloadConfig("
    positions = [m.start() for m in re.finditer(re.escape(marker), text)]
    print(p, "call sites:", len(positions))
    for pos in reversed(positions):
        open_idx = pos + len(marker) - 1
        text = insert_before_close(text, open_idx, ", nil, 0")
    with open(p, "w") as f:
        f.write(text)

print("done")
EOF
```

Expected output:
```
internal/proxy/proxy_test.go call sites: 16
internal/proxy/idempotency_test.go call sites: 1
internal/proxy/coalesce_test.go call sites: 1
internal/cli/cli.go call sites: 1
done
```

- [ ] **Step 6: Format and verify the whole repo still builds and passes**

```bash
gofmt -w internal/proxy/proxy.go internal/proxy/proxy_test.go internal/proxy/idempotency_test.go internal/proxy/coalesce_test.go internal/cli/cli.go
go build ./...
gofmt -l .
go vet ./...
go test ./... -race
```

Expected: `go build`, `gofmt -l .` (no output), `go vet`, and `go test` all succeed — every existing test still passes unchanged, since this task is purely additive.

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/proxy_test.go internal/proxy/idempotency_test.go internal/proxy/coalesce_test.go internal/cli/cli.go
git commit -m "$(cat <<'EOF'
Wire semantic cache fields through Server and ReloadConfig

Mechanical plumbing only (Server.SemanticIndex/SemanticCacheThreshold,
their accessors, and the ReloadConfig signature growth this requires)
— no behavior change yet.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Prompt-text extraction

**Files:**
- Modify: `internal/proxy/proxy.go` (add `promptFields`, `contentBlock`, `extractPromptText` near `modelField`/`resolveModelRoute`)
- Create: `internal/proxy/semanticcache_internal_test.go` (white-box, `package proxy`, mirroring the `drainmode_test.go`/`shadowtraffic_test.go` precedent for testing unexported helpers directly)

- [ ] **Step 1: Write the failing tests**

```go
// internal/proxy/semanticcache_internal_test.go
package proxy

import "testing"

func TestExtractPromptText_PlainStringContent(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world"}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_ContentBlocksArray(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"text","text":"world"}]}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_MultipleMessagesConcatenated(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hello world"}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "be terse hello world" {
		t.Fatalf("text = %q, want %q", text, "be terse hello world")
	}
}

func TestExtractPromptText_TopLevelPromptField(t *testing.T) {
	body := []byte(`{"prompt":"legacy completion prompt"}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "legacy completion prompt" {
		t.Fatalf("text = %q, want %q", text, "legacy completion prompt")
	}
}

func TestExtractPromptText_TopLevelInputField(t *testing.T) {
	body := []byte(`{"input":"some input text"}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "some input text" {
		t.Fatalf("text = %q, want %q", text, "some input text")
	}
}

func TestExtractPromptText_UnrecognizedShapeReturnsFalse(t *testing.T) {
	body := []byte(`{"foo":"bar"}`)
	if _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false for a body with no recognized prompt field")
	}
}

func TestExtractPromptText_InvalidJSONReturnsFalse(t *testing.T) {
	if _, ok := extractPromptText([]byte("not json")); ok {
		t.Fatal("expected ok=false for invalid JSON")
	}
}

func TestExtractPromptText_EmptyContentReturnsFalse(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":""}]}`)
	if _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false when every recognized field is empty")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/... -run TestExtractPromptText -v`
Expected: FAIL — `undefined: extractPromptText`.

- [ ] **Step 3: Write the implementation**

In `internal/proxy/proxy.go`, find the `modelField` type (used by `resolveModelRoute`):

```go
type modelField struct {
	Model string `json:"model"`
}
```

Add the new types and function immediately after it:

```go
type modelField struct {
	Model string `json:"model"`
}

// promptFields is a shallow, best-effort decode of the request body
// looking for text meaningful to semantic caching — the same
// "recognize the common shape, don't guess at the rest" discipline
// modelField already uses for the "model" field. Covers the two
// dominant chat-message conventions (OpenAI/Anthropic-shaped
// messages[].content) plus the legacy single-string prompt/input
// fields. A body that matches none of these simply never participates
// in semantic caching — the existing exact-match cache is unaffected
// either way.
type promptFields struct {
	Prompt   string `json:"prompt"`
	Input    string `json:"input"`
	Messages []struct {
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
}

// contentBlock is one entry of a "content blocks" array, e.g.
// [{"type":"text","text":"..."}] — the shape both OpenAI and Anthropic
// use for multi-part (text + image, etc.) message content.
type contentBlock struct {
	Text string `json:"text"`
}

// extractPromptText returns the concatenated text aiproxy recognizes in
// body for semantic caching, and whether any was found at all.
// messages[].content is decoded permissively: a plain JSON string is
// used directly, a JSON array of content blocks has every block's text
// field concatenated in order. Extraction concatenates, in order: every
// message's content, then Prompt, then Input.
func extractPromptText(body []byte) (string, bool) {
	var pf promptFields
	if err := json.Unmarshal(body, &pf); err != nil {
		return "", false
	}

	var b strings.Builder
	for _, m := range pf.Messages {
		if len(m.Content) == 0 {
			continue
		}
		var asString string
		if err := json.Unmarshal(m.Content, &asString); err == nil {
			b.WriteString(asString)
			b.WriteByte(' ')
			continue
		}
		var blocks []contentBlock
		if err := json.Unmarshal(m.Content, &blocks); err == nil {
			for _, blk := range blocks {
				b.WriteString(blk.Text)
				b.WriteByte(' ')
			}
		}
	}
	b.WriteString(pf.Prompt)
	b.WriteByte(' ')
	b.WriteString(pf.Input)

	text := strings.TrimSpace(b.String())
	if text == "" {
		return "", false
	}
	return text, true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/... -run TestExtractPromptText -v`
Expected: PASS (all 8 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/semanticcache_internal_test.go
git commit -m "$(cat <<'EOF'
Add best-effort prompt-text extraction for semantic caching

Recognizes OpenAI/Anthropic-shaped messages[].content (string or
content-block array) plus legacy top-level prompt/input fields; not yet
called from anywhere.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Stats counter and Prometheus metric

**Files:**
- Modify: `internal/stats/stats.go`
- Modify: `internal/proxy/proxy.go:4778` (the `promCounters` table)

- [ ] **Step 1: Add the counter field**

Find:

```go
	cacheHits         atomic.Int64
	coalescedRequests atomic.Int64
	staleCacheHits    atomic.Int64
```

Replace with:

```go
	cacheHits         atomic.Int64
	coalescedRequests atomic.Int64
	semanticCacheHits atomic.Int64
	staleCacheHits    atomic.Int64
```

- [ ] **Step 2: Add it to the snapshot mapping**

Find:

```go
		CacheHits:         c.cacheHits.Load(),
		CoalescedRequests: c.coalescedRequests.Load(),
		StaleCacheHits:    c.staleCacheHits.Load(),
```

Replace with:

```go
		CacheHits:         c.cacheHits.Load(),
		CoalescedRequests: c.coalescedRequests.Load(),
		SemanticCacheHits: c.semanticCacheHits.Load(),
		StaleCacheHits:    c.staleCacheHits.Load(),
```

- [ ] **Step 3: Add the `Record` method**

Find:

```go
func (s *Stats) RecordCoalescedRequest(target string) {
	s.overall.coalescedRequests.Add(1)
	s.counterFor(target).coalescedRequests.Add(1)
}
```

Replace with:

```go
func (s *Stats) RecordCoalescedRequest(target string) {
	s.overall.coalescedRequests.Add(1)
	s.counterFor(target).coalescedRequests.Add(1)
}

// RecordSemanticCacheHit records one request served by an approximate
// match against a recent, sufficiently similar prior request's own
// cached answer — see the semcache package and Server.SemanticIndex.
// Attributed to target the same way RecordCacheHit is. Distinct from
// CacheHits: a cache hit's response belongs to this exact request's own
// prior occurrence; a semantic cache hit's response belongs to a
// different (if similar) request.
func (s *Stats) RecordSemanticCacheHit(target string) {
	s.overall.semanticCacheHits.Add(1)
	s.counterFor(target).semanticCacheHits.Add(1)
}
```

- [ ] **Step 4: Add the `Snapshot` field**

Find:

```go
	// CoalescedRequests counts requests served by waiting for and
	// replaying a concurrent, still-in-flight identical request's own
	// response — see Stats.RecordCoalescedRequest and the coalesce
	// package. Distinct from CacheHits: a cache hit is served from a
	// completed, previously-cached response; a coalesced request is
	// served from another request that was, at the time this one
	// arrived, still in progress. Always 0 when cache_request_coalescing
	// isn't configured.
	CoalescedRequests int64 `json:"coalesced_requests"`
```

Replace with:

```go
	// CoalescedRequests counts requests served by waiting for and
	// replaying a concurrent, still-in-flight identical request's own
	// response — see Stats.RecordCoalescedRequest and the coalesce
	// package. Distinct from CacheHits: a cache hit is served from a
	// completed, previously-cached response; a coalesced request is
	// served from another request that was, at the time this one
	// arrived, still in progress. Always 0 when cache_request_coalescing
	// isn't configured.
	CoalescedRequests int64 `json:"coalesced_requests"`

	// SemanticCacheHits counts requests served by an approximate match
	// against a recent, sufficiently similar prior request's own cached
	// answer — see Stats.RecordSemanticCacheHit and the semcache
	// package. Distinct from CacheHits: the served response belongs to
	// a different (if similar) request, not this exact one's own prior
	// occurrence. Always 0 when semantic_cache_enabled isn't configured.
	SemanticCacheHits int64 `json:"semantic_cache_hits"`
```

- [ ] **Step 5: Add the text-summary lines**

Find:

```go
	// Same reasoning again: 0 for every run that never configured
	// cache_request_coalescing, or that did but no two identical
	// requests ever actually overlapped in flight.
	if s.CoalescedRequests > 0 {
		out += fmt.Sprintf("\nCoalesced requests:   %d", s.CoalescedRequests)
	}
```

Replace with:

```go
	// Same reasoning again: 0 for every run that never configured
	// cache_request_coalescing, or that did but no two identical
	// requests ever actually overlapped in flight.
	if s.CoalescedRequests > 0 {
		out += fmt.Sprintf("\nCoalesced requests:   %d", s.CoalescedRequests)
	}
	// Same reasoning again: 0 for every run that never configured
	// semantic_cache_enabled, or that did but no request ever came in
	// similar enough to an earlier one to cross semantic_cache_threshold.
	if s.SemanticCacheHits > 0 {
		out += fmt.Sprintf("\nSemantic cache hits:  %d", s.SemanticCacheHits)
	}
```

Find:

```go
		if t.CoalescedRequests > 0 {
			fmt.Fprintf(&b, " coalesced=%d", t.CoalescedRequests)
		}
```

Replace with:

```go
		if t.CoalescedRequests > 0 {
			fmt.Fprintf(&b, " coalesced=%d", t.CoalescedRequests)
		}
		if t.SemanticCacheHits > 0 {
			fmt.Fprintf(&b, " semantic-cache-hits=%d", t.SemanticCacheHits)
		}
```

- [ ] **Step 6: Add the Prometheus metric**

In `internal/proxy/proxy.go`, find:

```go
	{"aiproxy_coalesced_requests_total", "Total number of requests served by waiting for and replaying a concurrent, still-in-flight identical request's own response.", func(s stats.Snapshot) int64 { return s.CoalescedRequests }},
```

Replace with:

```go
	{"aiproxy_coalesced_requests_total", "Total number of requests served by waiting for and replaying a concurrent, still-in-flight identical request's own response.", func(s stats.Snapshot) int64 { return s.CoalescedRequests }},
	{"aiproxy_semantic_cache_hits_total", "Total number of requests served by an approximate match against a recent, sufficiently similar prior request's own cached answer.", func(s stats.Snapshot) int64 { return s.SemanticCacheHits }},
```

- [ ] **Step 7: Verify it compiles**

Run: `go build ./... && gofmt -l . && go vet ./...`
Expected: success, no `gofmt` output.

- [ ] **Step 8: Commit**

```bash
git add internal/stats/stats.go internal/proxy/proxy.go
git commit -m "$(cat <<'EOF'
Add SemanticCacheHits stats counter and Prometheus metric

Mirrors CoalescedRequests exactly (per-target counter, top-level and
per-target snapshot fields, text summary lines, Prometheus series); not
yet recorded from anywhere.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Logging

**Files:**
- Modify: `internal/proxy/proxy.go` (`logEvent` struct, new `logSemanticCacheHit`)

- [ ] **Step 1: Add the `logEvent` field**

Find:

```go
	// AgeSeconds and Stale are only set on a cache_hit event: how many
	// seconds old the served entry was (see cache.Cache.Get), and
	// whether that age had already crossed cache.Cache.IsStale's warning
	// threshold — never a reason to treat the hit as a miss, purely
	// informational, the same "still genuinely served" semantics
	// IsStale's own doc comment describes. AgeSeconds is a pointer, not
	// a plain int, for the same reason DurationMS is: an entry served
	// the instant after being cached has a real, meaningful age of
	// exactly 0, not the same thing as the field being absent.
	AgeSeconds *int `json:"age_seconds,omitempty"`
	Stale      bool `json:"stale,omitempty"`
```

Replace with:

```go
	// AgeSeconds and Stale are only set on a cache_hit event: how many
	// seconds old the served entry was (see cache.Cache.Get), and
	// whether that age had already crossed cache.Cache.IsStale's warning
	// threshold — never a reason to treat the hit as a miss, purely
	// informational, the same "still genuinely served" semantics
	// IsStale's own doc comment describes. AgeSeconds is a pointer, not
	// a plain int, for the same reason DurationMS is: an entry served
	// the instant after being cached has a real, meaningful age of
	// exactly 0, not the same thing as the field being absent.
	AgeSeconds *int `json:"age_seconds,omitempty"`
	Stale      bool `json:"stale,omitempty"`

	// Similarity is only set on a semantic_cache_hit event: the Jaccard
	// similarity (see semcache.Similarity) between this request's own
	// extracted prompt text and the matched prior request's — always
	// greater than 0 in practice, since it can only be set once it
	// crossed semantic_cache_threshold, so a plain float64 with
	// omitempty is safe here (unlike AgeSeconds/DurationMS, which can
	// legitimately be a real, meaningful zero).
	Similarity float64 `json:"similarity,omitempty"`
```

- [ ] **Step 2: Add `logSemanticCacheHit`**

Find:

```go
func (s *Server) logCoalescedRequest(method, reqURL, requestID string) {
	ev := s.recordLogEvent(logEvent{Level: "coalesced", Method: method, URL: reqURL, RequestID: requestID})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[COALESCED] %s %s - served from a concurrent in-flight request%s", ansiPurple, method, reqURL, ansiReset)
}
```

Replace with:

```go
func (s *Server) logCoalescedRequest(method, reqURL, requestID string) {
	ev := s.recordLogEvent(logEvent{Level: "coalesced", Method: method, URL: reqURL, RequestID: requestID})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[COALESCED] %s %s - served from a concurrent in-flight request%s", ansiPurple, method, reqURL, ansiReset)
}

// logSemanticCacheHit logs a request served by an approximate match
// against a recent, sufficiently similar prior request — see
// semcache.Index.FindBest and Server.SemanticCacheThreshold. Distinct
// from logCacheHit: the served response belongs to a different (if
// similar) request, so there's no meaningful "this request's own age"
// to report the way a genuine cache hit has.
func (s *Server) logSemanticCacheHit(method, reqURL, requestID string, similarity float64) {
	ev := s.recordLogEvent(logEvent{Level: "semantic_cache_hit", Method: method, URL: reqURL, RequestID: requestID, Similarity: similarity})
	if s.LogFormat == LogFormatJSON {
		s.logEventJSON(ev)
		return
	}
	s.logf("%s[SEMANTIC CACHE HIT] %s %s - similarity %.2f%s", ansiPurple, method, reqURL, similarity, ansiReset)
}
```

- [ ] **Step 3: Verify it compiles**

Run: `go build ./... && gofmt -l . && go vet ./...`
Expected: success, no `gofmt` output.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/proxy.go
git commit -m "$(cat <<'EOF'
Add semantic_cache_hit log event

Mirrors logCoalescedRequest's structure; not yet called from anywhere.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Request-flow integration

This is the task that makes the feature actually work end-to-end: the `ServeHTTP` lookup (serving a semantic match) and the two indexing call sites (recording a fingerprint once a real response is cached). These two halves are inseparable to test — the lookup has nothing to find without the indexing half also existing — so they're implemented and tested together.

**Files:**
- Modify: `internal/proxy/proxy.go` (`ServeHTTP`'s cache block, `reqCtx` construction, `bufferResponse`, `streamResponse`, `writeStreamToCache`)
- Create: `internal/proxy/semanticcache_test.go` (black-box, `package proxy_test`, mirroring `coalesce_test.go`)

- [ ] **Step 1: Write the failing integration tests**

```go
// internal/proxy/semanticcache_test.go
package proxy_test

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
)

func newSemanticCacheTestServer(t *testing.T, upstream *httptest.Server, threshold float64) (*proxy.Server, *httptest.Server) {
	t.Helper()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c
	srv.SemanticIndex = semcache.NewIndex(semcache.DefaultIndexSize)
	srv.SemanticCacheThreshold = threshold
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	t.Cleanup(frontend.Close)
	t.Cleanup(upstream.Close)
	return srv, frontend
}

func countingUpstream(hits *atomic.Int32, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(body))
	}))
}

func TestServer_SemanticCache_RephrasedPromptServedFromSimilarEntry(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "Stockholm is the capital of Sweden.")
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	first, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	firstBody, _ := io.ReadAll(first.Body)
	first.Body.Close()

	second, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	secondBody, _ := io.ReadAll(second.Body)
	second.Body.Close()

	if hits.Load() != 1 {
		t.Fatalf("upstream hits = %d, want 1 (second request should have been served from the semantic match)", hits.Load())
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("bodies differ: %q vs %q", firstBody, secondBody)
	}
	if got := second.Header.Get("X-Semantic-Cache-Hit"); got != "true" {
		t.Fatalf("X-Semantic-Cache-Hit = %q, want \"true\"", got)
	}
	if got := second.Header.Get("X-Semantic-Cache-Similarity"); got == "" {
		t.Fatal("expected X-Semantic-Cache-Similarity to be set")
	}
	if got := first.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("first (genuine miss) response should not carry X-Semantic-Cache-Hit, got %q", got)
	}
}

func TestServer_SemanticCache_DifferentTopicNeverMatches(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"Explain how photosynthesis works in plants"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (unrelated prompts must never coalesce)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header, got %q", got)
	}
}

func TestServer_SemanticCache_ThresholdTooHighRejectsNearMiss(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	// threshold 0.99 is high enough that even a close rewording won't
	// reach it, given real word-level shingle overlap.
	_, frontend := newSemanticCacheTestServer(t, upstream, 0.99)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (threshold 0.99 should reject this near-miss)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header, got %q", got)
	}
}

func TestServer_SemanticCache_StaleIndexEntryFallsThroughToFreshForward(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	srv, frontend := newSemanticCacheTestServer(t, upstream, 0.5)
	srv.CacheTTL = 50 * time.Millisecond

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	time.Sleep(150 * time.Millisecond) // let the real cache entry's TTL expire

	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (a stale index entry must fall through to a fresh forward, not error)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header for a stale candidate, got %q", got)
	}
}

func TestServer_SemanticCache_DisabledBehavesAsBeforeRegression(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c // SemanticIndex left nil: semantic caching disabled
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()
	defer upstream.Close()

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	resp, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits = %d, want 2 (semantic caching disabled, both requests must forward independently)", hits.Load())
	}
	if got := resp.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit header when disabled, got %q", got)
	}
}

func TestServer_SemanticCache_StatsAndLog(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	srv, frontend := newSemanticCacheTestServer(t, upstream, 0.5)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))

	if n := srv.Stats.Snapshot().SemanticCacheHits; n != 1 {
		t.Fatalf("stats SemanticCacheHits = %d, want 1", n)
	}
}

func TestServer_SemanticCache_ReloadConfigHotSwapsThresholdAndEnablement(t *testing.T) {
	t.Chdir(t.TempDir())
	var hits atomic.Int32
	upstream := countingUpstream(&hits, "a real answer")
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	srv := proxy.New("unused", targetURL, rules.NewEngine(rules.Allow))
	srv.Cache = c // starts with semantic caching disabled
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()
	defer upstream.Close()

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	beforeReload, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits before reload = %d, want 2 (disabled)", hits.Load())
	}
	if got := beforeReload.Header.Get("X-Semantic-Cache-Hit"); got != "" {
		t.Fatalf("expected no semantic cache hit before reload, got %q", got)
	}

	idx := semcache.NewIndex(semcache.DefaultIndexSize)
	srv.ReloadConfig(srv.Engine, nil, c, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil, false, nil, nil, idx, 0.5)

	http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"What is the capital of Sweden?"}]}`))
	afterReload, err := http.Post(frontend.URL+"/chat", "application/json", strings.NewReader(`{"messages":[{"role":"user","content":"what's the capital of sweden"}]}`))
	if err != nil {
		t.Fatalf("fourth request: %v", err)
	}
	if hits.Load() != 3 {
		t.Fatalf("upstream hits after reload = %d, want 3 (only the third request should be a genuine miss; the fourth should be a semantic hit)", hits.Load())
	}
	if got := afterReload.Header.Get("X-Semantic-Cache-Hit"); got != "true" {
		t.Fatalf("expected a semantic cache hit after reload enabled it, got header %q", got)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/... -run TestServer_SemanticCache -v`
Expected: FAIL — every test times out waiting for a hit count that never drops (no lookup/indexing exists yet, so every request is an independent forward and e.g. `TestServer_SemanticCache_RephrasedPromptServedFromSimilarEntry` sees `hits.Load() == 2`, not 1).

- [ ] **Step 3: Implement the `ServeHTTP` lookup block**

Find (the `var cacheKey string` / `var coalesceOwnedForReqCtx bool` declarations right before the cache block):

```go
	var cacheKey string
	var coalesceOwnedForReqCtx bool
	if cch := s.getCache(); cch != nil && s.cacheEnabledForTarget(targetLabel) {
```

Replace with:

```go
	var cacheKey string
	var coalesceOwnedForReqCtx bool
	var semanticFingerprintForReqCtx []uint64
	if cch := s.getCache(); cch != nil && s.cacheEnabledForTarget(targetLabel) {
```

Find the end of the exact-cache-hit block and the start of the coalescing comment:

```go
			s.logCacheHit(r.Method, r.URL.String(), requestID, age, stale)
			return
		}

		// A genuine cache miss: if request coalescing is on, see
```

Replace with:

```go
			s.logCacheHit(r.Method, r.URL.String(), requestID, age, stale)
			return
		}

		// A genuine exact-cache miss: if a prompt can be extracted from
		// the body, compute its fingerprint once — used both to search
		// for an existing similar answer right below and, regardless of
		// whether one is found, to index this request's own eventual
		// response for future lookups (see the Index.Add call sites in
		// bufferResponse/streamResponse). See Server.SemanticIndex's own
		// doc comment for why this is a second, approximate layer
		// checked only after the exact-match cache already missed.
		if threshold := s.getSemanticCacheThreshold(); threshold > 0 {
			if text, extracted := extractPromptText(body); extracted {
				semanticFingerprintForReqCtx = semcache.Fingerprint(text)
				if idx := s.getSemanticIndex(); idx != nil {
					if candidateKey, similarity, found := idx.FindBest(targetLabel, semanticFingerprintForReqCtx, threshold); found {
						if cached, hit, _, err := cch.Get(candidateKey, ttl); err == nil && hit {
							defer cached.Body.Close()
							copyHeader(w.Header(), cached.Header)
							w.Header().Set("X-Semantic-Cache-Hit", "true")
							w.Header().Set("X-Semantic-Cache-Similarity", strconv.FormatFloat(similarity, 'f', 2, 64))
							w.WriteHeader(cached.StatusCode)
							// Same reasoning as the exact-cache-hit branch
							// above: a semantic hit never reaches
							// bufferResponse/streamResponse either, so an
							// owned idempotency claim must be completed
							// right here.
							if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
								cachedBody, readErr := io.ReadAll(cached.Body)
								w.Write(cachedBody)
								if readErr == nil {
									idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: cached.StatusCode, Header: cached.Header.Clone(), Body: cachedBody})
								}
							} else {
								io.Copy(w, cached.Body)
							}
							s.Stats.RecordSemanticCacheHit(targetLabel)
							s.logSemanticCacheHit(r.Method, r.URL.String(), requestID, similarity)
							return
						}
					}
				}
			}
		}

		// A genuine cache miss: if request coalescing is on, see
```

- [ ] **Step 4: Carry the fingerprint through `reqCtx`**

Find:

```go
		idempotencyClient: auth.label,
		idempotencyKey:    idempotencyKey,
		coalesceOwned:     coalesceOwnedForReqCtx,
```

Replace with:

```go
		idempotencyClient:   auth.label,
		idempotencyKey:      idempotencyKey,
		coalesceOwned:       coalesceOwnedForReqCtx,
		semanticFingerprint: semanticFingerprintForReqCtx,
```

- [ ] **Step 5: Index on `bufferResponse`'s cache write**

Find:

```go
	if cch := s.getCache(); cch != nil && resp.StatusCode == http.StatusOK && reqCtx.cacheKey != "" {
		// httputil.DumpResponse drains and then restores resp.Body itself,
		// so the client still receives the body intact afterwards. This
		// runs before the usage log line so a durable cache write is
		// never left pending behind an already-visible log line.
		if err := cch.Set(reqCtx.cacheKey, resp); err != nil {
			s.logError("aiproxy: cache: failed to store response: %v", err)
		}
	}
```

Replace with:

```go
	if cch := s.getCache(); cch != nil && resp.StatusCode == http.StatusOK && reqCtx.cacheKey != "" {
		// httputil.DumpResponse drains and then restores resp.Body itself,
		// so the client still receives the body intact afterwards. This
		// runs before the usage log line so a durable cache write is
		// never left pending behind an already-visible log line.
		if err := cch.Set(reqCtx.cacheKey, resp); err != nil {
			s.logError("aiproxy: cache: failed to store response: %v", err)
		} else if idx := s.getSemanticIndex(); idx != nil && reqCtx.semanticFingerprint != nil {
			idx.Add(reqCtx.targetLabel, reqCtx.semanticFingerprint, reqCtx.cacheKey)
		}
	}
```

- [ ] **Step 6: Index on `streamResponse`'s cache write**

`writeStreamToCache` currently swallows its own error, so `streamResponse` has no way to know whether the write actually succeeded. Give it a return value first.

Find:

```go
// writeStreamToCache stores a completed stream's accumulated bytes under
// key in cch. A stream that was cut short (client disconnect, upstream
// error) must never reach here: a future "hit" would silently replay a
// truncated response as if it were complete.
func (s *Server) writeStreamToCache(cch *cache.Cache, key string, statusCode int, header http.Header, data []byte) {
	cached := &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
	if err := cch.Set(key, cached); err != nil {
		s.logError("aiproxy: cache: failed to store response: %v", err)
	}
}
```

Replace with:

```go
// writeStreamToCache stores a completed stream's accumulated bytes under
// key in cch, reporting whether the write succeeded. A stream that was
// cut short (client disconnect, upstream error) must never reach here:
// a future "hit" would silently replay a truncated response as if it
// were complete.
func (s *Server) writeStreamToCache(cch *cache.Cache, key string, statusCode int, header http.Header, data []byte) bool {
	cached := &http.Response{
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
	if err := cch.Set(key, cached); err != nil {
		s.logError("aiproxy: cache: failed to store response: %v", err)
		return false
	}
	return true
}
```

Now find its one call site:

```go
		if cch := s.getCache(); cleanEOF && cch != nil && statusCode == http.StatusOK && reqCtx.cacheKey != "" {
			s.writeStreamToCache(cch, reqCtx.cacheKey, statusCode, header, data)
		}
```

Replace with:

```go
		if cch := s.getCache(); cleanEOF && cch != nil && statusCode == http.StatusOK && reqCtx.cacheKey != "" {
			if s.writeStreamToCache(cch, reqCtx.cacheKey, statusCode, header, data) {
				if idx := s.getSemanticIndex(); idx != nil && reqCtx.semanticFingerprint != nil {
					idx.Add(reqCtx.targetLabel, reqCtx.semanticFingerprint, reqCtx.cacheKey)
				}
			}
		}
```

- [ ] **Step 7: Run tests to verify they pass**

```bash
gofmt -w internal/proxy/proxy.go
go test ./internal/proxy/... -run TestServer_SemanticCache -v -race
```

Expected: PASS (all 7 tests).

- [ ] **Step 8: Run the full existing test suite for regressions**

```bash
go build ./...
gofmt -l .
go vet ./...
go test ./... -race
```

Expected: everything passes — in particular every pre-existing cache/coalesce/idempotency test, since this task's new code paths are all gated behind `getSemanticCacheThreshold() > 0` / a non-nil `SemanticIndex`, both of which stay zero-value/nil in every test that doesn't explicitly set them.

- [ ] **Step 9: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/semanticcache_test.go
git commit -m "$(cat <<'EOF'
Wire semantic cache lookup and indexing into the request flow

Checked right after an exact-match cache miss, re-verified against the
real cache before serving, and indexed on every real cache write —
internal/proxy.Server.SemanticIndex/SemanticCacheThreshold are now
fully functional when set directly (CLI wiring follows in a later
commit).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: CLI wiring

**Files:**
- Modify: `internal/cli/cli.go` (`liveConfig` struct, `buildLiveConfig`, `runValidate`, startup notice, the `ReloadConfig` call site)
- Modify: `internal/cli/cli_test.go`

- [ ] **Step 1: Write the failing validation tests**

Add these tests to `internal/cli/cli_test.go` (package `cli_test`, appended near the existing `TestExecute_Validate_CacheRequestCoalescingWithoutCacheEnabled_ReportsProblem` / `TestExecute_Validate_ValidConfig_WithCacheRequestCoalescing_ReturnsZero` tests, whose exact pattern — `os.WriteFile` a config into `t.TempDir()`, then `cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)` — these five mirror directly):

```go
func TestExecute_Validate_SemanticCacheEnabledWithoutCacheEnabled_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"semantic_cache_enabled": true, "semantic_cache_threshold": 0.9}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "semantic_cache_enabled requires cache_enabled") {
		t.Errorf("stderr missing the requires-cache_enabled problem: %q", stderr.String())
	}
}

func TestExecute_Validate_SemanticCacheEnabledWithoutThreshold_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "semantic_cache_enabled": true}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "semantic_cache_enabled requires semantic_cache_threshold") {
		t.Errorf("stderr missing the requires-threshold problem: %q", stderr.String())
	}
}

func TestExecute_Validate_SemanticCacheThresholdNegative_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "semantic_cache_enabled": true, "semantic_cache_threshold": -0.1}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "must not be negative") {
		t.Errorf("stderr missing the negative-threshold problem: %q", stderr.String())
	}
}

func TestExecute_Validate_SemanticCacheThresholdAboveOne_ReportsProblem(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "semantic_cache_enabled": true, "semantic_cache_threshold": 1.5}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "must not be greater than 1") {
		t.Errorf("stderr missing the out-of-range problem: %q", stderr.String())
	}
}

func TestExecute_Validate_ValidConfig_WithSemanticCache_ReturnsZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "aiproxy.json")
	raw := `{"cache_enabled": true, "semantic_cache_enabled": true, "semantic_cache_threshold": 0.9}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := cli.Execute([]string{"validate", "-config", path}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "semantic cache enabled:  true") {
		t.Fatalf("stdout missing semantic cache enabled summary line: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "semantic cache threshold: 0.9") {
		t.Fatalf("stdout missing semantic cache threshold summary line: %q", stdout.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli/... -run TestExecute_Validate_SemanticCache -v`
Expected: FAIL — none of the four bad configs are rejected yet (exit code 0 instead of 1), and the valid-config test fails on the missing summary lines, since no validation or summary output exists yet.

- [ ] **Step 3: Add the `liveConfig` fields**

Find:

```go
	idempotency        *idempotency.Registry
	coalescer          *coalesce.Group
```

Replace with:

```go
	idempotency            *idempotency.Registry
	coalescer              *coalesce.Group
	semanticIndex          *semcache.Index
	semanticCacheThreshold float64
```

- [ ] **Step 4: Add the import**

Find:

```go
	"aiproxy/internal/rules"
)
```

Replace with:

```go
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
)
```

- [ ] **Step 5: Add construction + validation in `buildLiveConfig`**

Find:

```go
	if cfg.CacheEnabled {
		c, err := cache.New()
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: %w", err))
		} else {
			c.MaxSizeBytes = cfg.CacheMaxSizeBytes
			lc.cache = c
			lc.cacheTTL = time.Duration(cfg.CacheTTLSeconds) * time.Second
			if cfg.CacheRequestCoalescing {
				lc.coalescer = coalesce.NewGroup(coalesce.DefaultWaitTimeout)
			}
		}
	}
	if cfg.CacheRequestCoalescing && !cfg.CacheEnabled {
		errs = append(errs, fmt.Errorf("cache_request_coalescing requires cache_enabled to be set (there's no cache key for it to coalesce requests by otherwise)"))
	}
```

Replace with:

```go
	if cfg.CacheEnabled {
		c, err := cache.New()
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: %w", err))
		} else {
			c.MaxSizeBytes = cfg.CacheMaxSizeBytes
			lc.cache = c
			lc.cacheTTL = time.Duration(cfg.CacheTTLSeconds) * time.Second
			if cfg.CacheRequestCoalescing {
				lc.coalescer = coalesce.NewGroup(coalesce.DefaultWaitTimeout)
			}
			if cfg.SemanticCacheEnabled && cfg.SemanticCacheThreshold > 0 {
				lc.semanticIndex = semcache.NewIndex(semcache.DefaultIndexSize)
				lc.semanticCacheThreshold = cfg.SemanticCacheThreshold
			}
		}
	}
	if cfg.CacheRequestCoalescing && !cfg.CacheEnabled {
		errs = append(errs, fmt.Errorf("cache_request_coalescing requires cache_enabled to be set (there's no cache key for it to coalesce requests by otherwise)"))
	}
	if cfg.SemanticCacheEnabled && !cfg.CacheEnabled {
		errs = append(errs, fmt.Errorf("semantic_cache_enabled requires cache_enabled to be set (there's no cache key for a semantic match to point at otherwise)"))
	}
	if cfg.SemanticCacheEnabled && cfg.SemanticCacheThreshold <= 0 {
		errs = append(errs, fmt.Errorf("semantic_cache_enabled requires semantic_cache_threshold to be set (there is no safe default similarity threshold)"))
	}
```

- [ ] **Step 6: Wire the two fields into the `Server`**

Find:

```go
	server.Idempotency = lc.idempotency
	server.Coalescer = lc.coalescer
```

Replace with:

```go
	server.Idempotency = lc.idempotency
	server.Coalescer = lc.coalescer
	server.SemanticIndex = lc.semanticIndex
	server.SemanticCacheThreshold = lc.semanticCacheThreshold
```

- [ ] **Step 7: Swap the `ReloadConfig` call site's placeholder values**

Find (the trailing arguments Task 3's script appended):

```go
	server.ReloadConfig(lc.engine, lc.limiter, lc.cache, lc.cost, lc.costBudget, lc.maxBodyBytes, lc.webhookURL, lc.webhooks, lc.proxyAPIKey, lc.proxyAPIKeys, lc.logFile, routes, modelRoutes, lc.ipAllowList, lc.ipDenyList, lc.tokenLimiter, lc.geoIPTable, lc.countryAllowList, lc.countryDenyList, lc.anomalyDetector, lc.anomalyDryRun, lc.upstreamTransport, lc.upstreamTotalTimeout, lc.targetBreaker, lc.cors, lc.healthCheckInterval, lc.healthCheckPath, lc.targetCostRates, lc.ipLimiter, lc.cacheTTL, lc.targetCacheTTL, lc.targetCacheEnabled, lc.targetShadowURL, lc.targetShadowSampleRate, lc.costBudgetHardStop, lc.idempotency, lc.coalescer, nil, 0)
```

Replace with:

```go
	server.ReloadConfig(lc.engine, lc.limiter, lc.cache, lc.cost, lc.costBudget, lc.maxBodyBytes, lc.webhookURL, lc.webhooks, lc.proxyAPIKey, lc.proxyAPIKeys, lc.logFile, routes, modelRoutes, lc.ipAllowList, lc.ipDenyList, lc.tokenLimiter, lc.geoIPTable, lc.countryAllowList, lc.countryDenyList, lc.anomalyDetector, lc.anomalyDryRun, lc.upstreamTransport, lc.upstreamTotalTimeout, lc.targetBreaker, lc.cors, lc.healthCheckInterval, lc.healthCheckPath, lc.targetCostRates, lc.ipLimiter, lc.cacheTTL, lc.targetCacheTTL, lc.targetCacheEnabled, lc.targetShadowURL, lc.targetShadowSampleRate, lc.costBudgetHardStop, lc.idempotency, lc.coalescer, lc.semanticIndex, lc.semanticCacheThreshold)
```

(If the exact trailing `, nil, 0)` text doesn't match verbatim due to line wrapping, run `grep -n "server.ReloadConfig(lc.engine" internal/cli/cli.go` to find the real line and edit its final two arguments from `nil, 0` to `lc.semanticIndex, lc.semanticCacheThreshold` directly.)

- [ ] **Step 8: Add `runValidate`'s inline validation checks**

Find:

```go
	if cfg.CacheRequestCoalescing && !cfg.CacheEnabled {
		problems = append(problems, "cache_request_coalescing requires cache_enabled to be set (there's no cache key for it to coalesce requests by otherwise)")
	}
```

Replace with:

```go
	if cfg.CacheRequestCoalescing && !cfg.CacheEnabled {
		problems = append(problems, "cache_request_coalescing requires cache_enabled to be set (there's no cache key for it to coalesce requests by otherwise)")
	}
	if cfg.SemanticCacheThreshold < 0 {
		problems = append(problems, fmt.Sprintf("semantic_cache_threshold: %g must not be negative", cfg.SemanticCacheThreshold))
	}
	if cfg.SemanticCacheThreshold > 1 {
		problems = append(problems, fmt.Sprintf("semantic_cache_threshold: %g must not be greater than 1", cfg.SemanticCacheThreshold))
	}
	if cfg.SemanticCacheEnabled && cfg.SemanticCacheThreshold <= 0 {
		problems = append(problems, "semantic_cache_enabled requires semantic_cache_threshold to be set (there is no safe default similarity threshold)")
	}
	if cfg.SemanticCacheEnabled && !cfg.CacheEnabled {
		problems = append(problems, "semantic_cache_enabled requires cache_enabled to be set (there's no cache key for a semantic match to point at otherwise)")
	}
```

- [ ] **Step 9: Add the `runValidate` summary line**

Find:

```go
	fmt.Fprintf(stdout, "  cache request coalescing: %v\n", cfg.CacheRequestCoalescing)
```

Replace with:

```go
	fmt.Fprintf(stdout, "  cache request coalescing: %v\n", cfg.CacheRequestCoalescing)
	fmt.Fprintf(stdout, "  semantic cache enabled:  %v\n", cfg.SemanticCacheEnabled)
	fmt.Fprintf(stdout, "  semantic cache threshold: %g\n", cfg.SemanticCacheThreshold)
```

- [ ] **Step 10: Add the startup notice**

Find:

```go
			if cfg.CacheRequestCoalescing {
				fmt.Fprintln(stdout, "response cache: request coalescing enabled (concurrent identical misses share one upstream call)")
			}
		}
```

Replace with:

```go
			if cfg.CacheRequestCoalescing {
				fmt.Fprintln(stdout, "response cache: request coalescing enabled (concurrent identical misses share one upstream call)")
			}
			if cfg.SemanticCacheEnabled {
				fmt.Fprintf(stdout, "response cache: semantic matching enabled (threshold %g)\n", cfg.SemanticCacheThreshold)
			}
		}
```

- [ ] **Step 11: Run tests to verify they pass**

```bash
gofmt -w internal/cli/cli.go
go test ./internal/cli/... -run TestExecute_Validate_SemanticCache -v
```

Expected: PASS (all 5 tests).

- [ ] **Step 12: Run the full test suite**

```bash
go build ./...
gofmt -l .
go vet ./...
go test ./... -race
```

Expected: everything passes.

- [ ] **Step 13: Commit**

```bash
git add internal/cli/cli.go internal/cli/cli_test.go
git commit -m "$(cat <<'EOF'
Wire semantic_cache_enabled/semantic_cache_threshold through the CLI

Validation (requires cache_enabled, requires an explicit threshold in
(0,1]), construction, startup notice, and aiproxy validate's summary
line — mirrors cache_request_coalescing's own wiring.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: README documentation

**Files:**
- Modify: `README.md` (insert a new `### Semantic cache` section)

- [ ] **Step 1: Insert the new section**

Find:

```
Each coalesced request is logged
(`[COALESCED]`, purple; `"coalesced"` under `--log-format json`) and
counted in `stats.coalesced_requests` and the Prometheus
`aiproxy_coalesced_requests_total` counter, broken down per target like
`cache_hits` — distinct from a cache hit itself, which is served from a
*completed*, previously cached response rather than one still in
progress.

### Idempotency-Key deduplication
```

Replace with:

```
Each coalesced request is logged
(`[COALESCED]`, purple; `"coalesced"` under `--log-format json`) and
counted in `stats.coalesced_requests` and the Prometheus
`aiproxy_coalesced_requests_total` counter, broken down per target like
`cache_hits` — distinct from a cache hit itself, which is served from a
*completed*, previously cached response rather than one still in
progress.

### Semantic cache

The exact-match cache above only serves a hit for a byte-for-byte
identical request. `semantic_cache_enabled` adds a second, approximate
lookup layer on top of it: when the exact cache misses, aiproxy checks
whether a recent, sufficiently similar request already has a cached
answer for this target — a rephrased prompt, reordered whitespace, a
client that appends a timestamp to its system message — and serves that
instead of forwarding upstream:

```json
{
  "cache_enabled": true,
  "semantic_cache_enabled": true,
  "semantic_cache_threshold": 0.9
}
```

Only meaningful alongside `cache_enabled`, same reasoning as
`cache_request_coalescing`; `aiproxy validate` rejects
`semantic_cache_enabled` set without it, or without an explicit
`semantic_cache_threshold` — there is no universally safe default
similarity threshold the way "never expire" is a safe default TTL, so
one must always be set (in `(0, 1]`) when this is turned on.

Similarity is computed entirely locally: aiproxy extracts the prompt
text it recognizes from the request body (the `content` of each entry
in a `messages` array — OpenAI/Anthropic style, plain string or a
content-block array — plus the legacy top-level `prompt`/`input`
fields), splits it into overlapping 3-word shingles, and compares two
requests' shingle sets by exact Jaccard similarity (no external
embeddings API, no added latency or cost on a miss). This catches
near-duplicate *phrasings* — the same request restated with minor edits
or additions — but not a true paraphrase with substantially different
wording, which would require real, meaning-based embeddings; a request
whose body doesn't match any recognized shape simply never participates
in semantic caching, with no effect on the exact-match cache. Unlike a
coalesced request, a semantic cache hit is always marked with
`X-Semantic-Cache-Hit: true` and `X-Semantic-Cache-Similarity: 0.93`
response headers: it can serve the answer to a *materially different*
request than the one the client actually sent, and the client should be
able to detect that. Each semantic cache hit is logged (`[SEMANTIC
CACHE HIT]`, purple; `"semantic_cache_hit"` under `--log-format json`)
and counted in `stats.semantic_cache_hits` and the Prometheus
`aiproxy_semantic_cache_hits_total` counter, broken down per target like
`cache_hits`.

### Idempotency-Key deduplication
```

- [ ] **Step 2: Verify the README still renders sensibly**

Run: `grep -n "^### " README.md` and confirm `### Semantic cache` now appears between `### Request coalescing` and `### Idempotency-Key deduplication`.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
Document semantic cache in README

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Final verification

**Files:** none (verification only)

- [ ] **Step 1: Full clean build and test pass**

```bash
go build ./...
gofmt -l .
go vet ./...
go test ./... -race
```

Expected: `go build` succeeds, `gofmt -l .` prints nothing, `go vet` succeeds, and every test in every package passes, including `-race` across `internal/semcache`, `internal/proxy` (all pre-existing suites plus the two new semantic-cache test files), `internal/cli`, and `internal/stats`.

- [ ] **Step 2: Run the semantic-cache tests specifically, repeated, to rule out flakiness**

```bash
for i in 1 2 3 4 5; do go test ./internal/proxy/... -run TestServer_SemanticCache -race -count=1 || break; done
```

Expected: PASS all 5 iterations — the feature has no timing-sensitive logic except the deliberately-real `time.Sleep` in `TestServer_SemanticCache_StaleIndexEntryFallsThroughToFreshForward`, which sleeps 3x the configured TTL and should never flake.

- [ ] **Step 3: Confirm no stray files**

```bash
git status
```

Expected: working tree clean (everything from Tasks 1–9 already committed).

This plan's scope ends here — release (version bump, tag, GitHub release, GHCR image, Homebrew/Scoop/deb/rpm publishing, and E2E verification against the real published artifacts) follows the project's established separate release process once this plan's implementation is reviewed and approved, not as part of this plan.
