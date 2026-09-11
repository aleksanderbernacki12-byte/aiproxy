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

// entry is one recorded fingerprint/cache-key pair inside a ring.
type entry struct {
	fingerprint []uint64
	cacheKey    string
}

// ring is a fixed-capacity FIFO buffer of entries for one target. buf is
// pre-allocated at its final length (cap(buf) never changes), so
// add's overwrite-in-place is genuinely O(1) — unlike slicing off the
// head of a growing []entry, which shrinks capacity in lockstep with
// length and forces append to reallocate and copy the whole backing
// array on nearly every call once the buffer is full.
type ring struct {
	buf   []entry
	head  int // index of the oldest entry currently stored
	count int // number of valid entries in buf (<= len(buf))
}

func newRing(size int) *ring {
	return &ring{buf: make([]entry, size)}
}

// add writes e into the next free slot, or — once the ring is full —
// overwrites the oldest entry and advances head to the new oldest one.
func (r *ring) add(e entry) {
	idx := (r.head + r.count) % len(r.buf)
	r.buf[idx] = e
	if r.count < len(r.buf) {
		r.count++
	} else {
		r.head = (r.head + 1) % len(r.buf)
	}
}

// forEach visits every valid entry, oldest first.
func (r *ring) forEach(fn func(entry)) {
	for i := 0; i < r.count; i++ {
		fn(r.buf[(r.head+i)%len(r.buf)])
	}
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
	rings   map[string]*ring
}

// NewIndex creates an Index capping each target's own entries at
// maxSize. A non-positive maxSize is clamped to 1 rather than left to
// panic on the first Add (make([]entry, n) with n <= 0 is either a
// no-op or invalid) — Add is on the hot request path (Task 7), so this
// constructor must never be a landmine.
func NewIndex(maxSize int) *Index {
	if maxSize <= 0 {
		maxSize = 1
	}
	return &Index{maxSize: maxSize, rings: make(map[string]*ring)}
}

// Add records fp/cacheKey under target, evicting that target's oldest
// entry first if it's already at maxSize.
func (ix *Index) Add(target string, fp []uint64, cacheKey string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, ok := ix.rings[target]
	if !ok {
		r = newRing(ix.maxSize)
		ix.rings[target] = r
	}
	r.add(entry{fingerprint: fp, cacheKey: cacheKey})
}

// FindBest returns the highest-similarity entry recorded under target
// that's at or above threshold, or ok=false if none qualifies (either
// because target has no entries, or none reach threshold).
func (ix *Index) FindBest(target string, fp []uint64, threshold float64) (cacheKey string, similarity float64, ok bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, exists := ix.rings[target]
	if !exists {
		return "", 0, false
	}
	var best float64
	var bestKey string
	found := false
	r.forEach(func(e entry) {
		sim := Similarity(fp, e.fingerprint)
		if sim >= threshold && (!found || sim > best) {
			best = sim
			bestKey = e.cacheKey
			found = true
		}
	})
	return bestKey, best, found
}

// Len reports how many entries are currently recorded under target —
// used by tests to assert eviction behavior.
func (ix *Index) Len(target string) int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if r, ok := ix.rings[target]; ok {
		return r.count
	}
	return 0
}
