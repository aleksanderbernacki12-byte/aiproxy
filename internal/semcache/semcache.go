// Package semcache implements aiproxy's local, approximate semantic
// cache index: a text fingerprint plus a Jaccard-similarity index used
// to find a recent, sufficiently similar prior request's cached answer
// for one that doesn't match anything in the exact-match cache. It
// knows nothing about HTTP, JSON, or aiproxy's cache/coalesce/
// idempotency packages — only text and integer fingerprints — the same
// isolation every other internal package here holds to.
package semcache

import (
	"container/list"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
)

// DefaultIndexSize is the default per-target capacity of an Index — see
// NewIndex.
const DefaultIndexSize = 2000

// DefaultMaxTargets is the default cap on the total number of distinct
// targets an Index tracks at once — see NewIndex and Index's own doc
// comment for why this exists at all. The arithmetic: each target's
// ring pre-allocates DefaultIndexSize entries up front (see newRing),
// and an empty entry costs 56 bytes on a 64-bit platform — a []uint64
// slice header (24 bytes: data pointer + len + cap, 8 bytes each) plus
// two string headers (16 bytes each: data pointer + len) for
// remainderHash and cacheKey, i.e. 24 + 16 + 16 = 56. One fully
// pre-allocated ring therefore costs DefaultIndexSize * 56 = 2000 * 56
// = 112,000 bytes (~109KiB) even before a single Add fills it in. At
// DefaultMaxTargets = 2000, the worst case — every tracked target's
// ring fully allocated — is 2000 * 112,000 = 224,000,000 bytes
// (~214MiB): a fixed, sane ceiling for a proxy process, not the
// hundreds of megabytes an unbounded map of client-controlled target
// strings (see Index's own doc comment) could otherwise reach.
//
// Sizing this isn't just about memory: a target is (targetLabel,
// caller-credential identity, resolved destination), so the number of
// LEGITIMATE targets a deployment actually needs is roughly (distinct
// routes) * (distinct caller credentials) * (distinct destinations per
// route — e.g. Azure OpenAI deployments) — all admin/tenant-controlled,
// not attacker-controlled. Set too low relative to that product, every
// new legitimate partition evicts another still-warm one: not a crash
// or leak, just a silent semantic-cache hit-rate regression, visible
// only as an unexplained drop in per-target semantic-cache-hit stats.
// 2000 gives real headroom over the roughly-1000-target figure a
// fairly large multi-tenant deployment (dozens of keys times tens of
// destinations) would already reach, while still bounding worst-case
// memory to a fixed, known ceiling instead of leaving it unbounded.
const DefaultMaxTargets = 2000

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
	h := fnv.New64a()
	for i := 0; i+shingleSize <= len(words); i++ {
		h.Reset()
		for j := i; j < i+shingleSize; j++ {
			h.Write([]byte(words[j]))
			h.Write([]byte{0})
		}
		seen[h.Sum64()] = struct{}{}
	}
	hashes := make([]uint64, 0, len(seen))
	for hash := range seen {
		hashes = append(hashes, hash)
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

// entry is one recorded fingerprint/remainderHash/cache-key triple
// inside a ring.
type entry struct {
	fingerprint   []uint64
	remainderHash string
	cacheKey      string
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
// fingerprints, remainderHash, and the real cache's own key — the
// caller must always re-verify a candidate against the real cache
// before serving it, since the underlying entry may have since expired
// or been evicted there.
//
// The map holding those per-target rings — ix.rings — is ALSO capped,
// at maxTargets, with LRU eviction of whichever target was least
// recently Add'ed or FindBest'ed (see touch). This is a separate axis
// from the per-target FIFO above, guarding against a different threat:
// target is not a small, admin-controlled, effectively fixed set of
// route labels — it can be composed from client-controlled, unbounded-
// cardinality content (see proxy.semanticPartitionTarget, which folds
// in resolvedDestination — the caller's own resolved request URL,
// including path and query string). A single authenticated client can
// therefore vary its own request's path suffix or query string across
// requests and, without this cap, grow ix.rings by one freshly
// allocated ring per distinct value it sends, without limit, until the
// process OOMs — capping only entries-per-target does nothing to stop
// this, since the attack is in how MANY targets exist, not how many
// entries live under any single one of them.
type Index struct {
	mu         sync.Mutex
	maxSize    int
	maxTargets int
	rings      map[string]*ring

	order    *list.List               // front = least recently used target, back = most recently used
	elements map[string]*list.Element // target -> its node in order
}

// NewIndex creates an Index capping each target's own entries at
// maxSize, and the total number of distinct targets tracked at once at
// maxTargets (see Index's own doc comment for why the latter exists).
// A non-positive maxSize, or a non-positive maxTargets, is clamped to 1
// rather than left to panic on the first Add (make([]entry, n) with n
// <= 0 is either a no-op or invalid) or to silently disable the total-
// target cap entirely — Add and FindBest are both on the hot request
// path (Task 7), so this constructor must never be a landmine.
func NewIndex(maxSize, maxTargets int) *Index {
	if maxSize <= 0 {
		maxSize = 1
	}
	if maxTargets <= 0 {
		maxTargets = 1
	}
	return &Index{
		maxSize:    maxSize,
		maxTargets: maxTargets,
		rings:      make(map[string]*ring),
		order:      list.New(),
		elements:   make(map[string]*list.Element),
	}
}

// touch marks target most-recently-used, creating a new ring for it if
// this is the first time it's been seen, and returns that ring
// (existing or newly created). Mirrors cache.Cache's own touch, which
// is likewise called on both a read (Get hit) and a write (Set) — see
// Add and FindBest below, which call this on every write and every
// read (of a target that already exists) respectively, so a target
// being merely read from protects it from eviction exactly as much as
// one being written to.
//
// If creating a new ring pushes the number of distinct targets over
// maxTargets, the single least-recently-used OTHER target is evicted:
// its ring, list element, and map entry are all removed together, so
// nothing keeps it reachable for garbage collection. The target this
// call just touched is always the most-recently-used immediately
// afterward (pushed to the back of order), so eviction — which only
// ever removes from the front — can never remove it; with maxTargets
// clamped to at least 1, a brand-new target added via Add or FindBest
// always survives its own call, exactly like cache.Cache's
// evictUntilUnderBudget always leaving behind the entry Set just wrote.
//
// Must be called with ix.mu already held.
func (ix *Index) touch(target string) *ring {
	if el, ok := ix.elements[target]; ok {
		ix.order.MoveToBack(el)
		return ix.rings[target]
	}
	// Defensive: rings and elements are only ever mutated together by
	// this method, so ok is always expected false here (the ix.elements
	// check above already ruled out target being tracked) — kept as a
	// guard against a future edit desyncing the two maps, not because
	// it's expected to ever trigger today.
	r, ok := ix.rings[target]
	if !ok {
		r = newRing(ix.maxSize)
		ix.rings[target] = r
	}
	el := ix.order.PushBack(target)
	ix.elements[target] = el
	for len(ix.rings) > ix.maxTargets {
		front := ix.order.Front()
		evictTarget := front.Value.(string)
		ix.order.Remove(front)
		delete(ix.elements, evictTarget)
		delete(ix.rings, evictTarget)
	}
	return r
}

// Add records fp/remainderHash/cacheKey under target, evicting that
// target's oldest entry first if it's already at maxSize. remainderHash
// is an exact-match requirement FindBest checks before it ever
// considers fingerprint similarity — see FindBest's own doc comment.
// remainderHash must be a hash of the structural remainder (see
// proxy.extractPromptText), never the raw remainder bytes themselves —
// Add has no way to enforce this, so getting it wrong here would mean
// raw request content ends up held in memory in this index. Marks
// target most-recently-used (see touch), creating it if it doesn't
// already exist and evicting the least-recently-used other target if
// that creation pushes the index over maxTargets.
func (ix *Index) Add(target string, fp []uint64, remainderHash, cacheKey string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r := ix.touch(target)
	r.add(entry{fingerprint: fp, remainderHash: remainderHash, cacheKey: cacheKey})
}

// FindBest returns the highest-similarity entry recorded under target
// that has an EXACTLY matching remainderHash and is at or above
// threshold, or ok=false if none qualifies (target has no entries, none
// share remainderHash, or none reach threshold among those that do).
// remainderHash is checked first, before Similarity is even computed —
// see docs/reviews/2026-09-12-v0.74.1-system-review.md finding #3: two
// requests with similar prompt text but a different model, streaming
// mode, tool set, or generation parameters must never be treated as
// interchangeable just because their extracted text happens to match.
// If target already has a ring, this call marks it most-recently-used
// (see touch) — protecting it from the total-target eviction — whether
// or not a qualifying match is ultimately found; a target with no ring
// at all is left untouched rather than created here, since a pure read
// creating an empty ring would itself be a way to inflate the total
// target count without ever calling Add.
func (ix *Index) FindBest(target string, fp []uint64, remainderHash string, threshold float64) (cacheKey string, similarity float64, ok bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, exists := ix.rings[target]
	if !exists {
		return "", 0, false
	}
	ix.touch(target)
	var best float64
	var bestKey string
	found := false
	r.forEach(func(e entry) {
		if e.remainderHash != remainderHash {
			return
		}
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

// TargetCount reports how many distinct targets are currently tracked
// — used by tests to assert the maxTargets cap is enforced.
func (ix *Index) TargetCount() int {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return len(ix.rings)
}
