package semcache_test

import (
	"fmt"
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
	ix.Add("targetA", []uint64{1, 2, 3}, "low-overlap")    // 3/5 = 0.6
	ix.Add("targetA", []uint64{1, 2, 3, 4, 5}, "exact")    // 5/5 = 1.0
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

// TestIndex_Add_RingBufferWrapsAcrossMultipleCycles adds more than twice
// the capacity worth of entries (so the underlying ring buffer's head
// wraps past index 0 more than once) and checks, via the public API
// only, that the oldest entries are evicted in strict FIFO order and
// exactly the newest maxSize entries survive.
func TestIndex_Add_RingBufferWrapsAcrossMultipleCycles(t *testing.T) {
	ix := semcache.NewIndex(3)
	texts := []string{
		"alpha bravo charlie delta",
		"echo foxtrot golf hotel",
		"india juliet kilo lima",
		"mike november oscar papa",
		"quebec romeo sierra tango",
		"uniform victor whiskey xray",
		"yankee zulu alpha bravo",
	}
	for i, text := range texts {
		ix.Add("targetA", semcache.Fingerprint(text), fmt.Sprintf("k%d", i+1))
	}

	if n := ix.Len("targetA"); n != 3 {
		t.Fatalf("Len = %d, want 3 after adding past capacity across multiple wraps", n)
	}

	// The oldest four (k1-k4) must have been evicted.
	for i := 1; i <= 4; i++ {
		fp := semcache.Fingerprint(texts[i-1])
		if _, sim, ok := ix.FindBest("targetA", fp, 0.99); ok {
			t.Fatalf("expected k%d to have been evicted, but it matched with similarity %v", i, sim)
		}
	}

	// The newest three (k5-k7) must still be present.
	for i := 5; i <= 7; i++ {
		fp := semcache.Fingerprint(texts[i-1])
		key, sim, ok := ix.FindBest("targetA", fp, 0.99)
		if !ok || key != fmt.Sprintf("k%d", i) {
			t.Fatalf("expected k%d still present with similarity ~1, got key=%q sim=%v ok=%v", i, key, sim, ok)
		}
	}
}

// TestNewIndex_NonPositiveMaxSizeClampsToOne confirms NewIndex's
// documented guard: a non-positive maxSize no longer panics on the
// first Add and instead behaves as a cap of 1.
func TestNewIndex_NonPositiveMaxSizeClampsToOne(t *testing.T) {
	for _, maxSize := range []int{0, -1, -100} {
		ix := semcache.NewIndex(maxSize)
		ix.Add("targetA", semcache.Fingerprint("some example text here"), "k1")
		if n := ix.Len("targetA"); n != 1 {
			t.Fatalf("NewIndex(%d): Len after first Add = %d, want 1", maxSize, n)
		}

		ix.Add("targetA", semcache.Fingerprint("another unrelated text now"), "k2")
		if n := ix.Len("targetA"); n != 1 {
			t.Fatalf("NewIndex(%d): Len after second Add = %d, want 1 (cap clamped to 1)", maxSize, n)
		}
		if _, _, ok := ix.FindBest("targetA", semcache.Fingerprint("some example text here"), 0.99); ok {
			t.Fatalf("NewIndex(%d): expected first entry to be evicted once at capacity 1", maxSize)
		}
	}
}
