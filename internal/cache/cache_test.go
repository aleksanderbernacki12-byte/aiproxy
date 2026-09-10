package cache_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aiproxy/internal/cache"
)

func newTestCache(t *testing.T) *cache.Cache {
	t.Helper()
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	return c
}

func testResponse(body string) *http.Response {
	rec := httptest.NewRecorder()
	rec.WriteHeader(http.StatusOK)
	rec.Body.WriteString(body)
	return rec.Result()
}

func TestCache_SetAndGet_RoundTrips(t *testing.T) {
	c := newTestCache(t)

	if err := c.Set("key1", testResponse("hello")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	resp, hit, err := c.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatal("hit = false, want true after Set")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

func TestCache_Get_MissWhenKeyAbsent(t *testing.T) {
	c := newTestCache(t)

	_, hit, err := c.Get("never-set")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hit {
		t.Fatal("hit = true, want false for a key that was never Set")
	}
}

func TestCache_TTL_ZeroMeansNoExpiry(t *testing.T) {
	c := newTestCache(t)
	// c.TTL left at its zero value.

	if err := c.Set("key1", testResponse("hello")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	_, hit, err := c.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatal("hit = false, want true — TTL=0 must mean entries never expire")
	}
}

func TestCache_TTL_ExpiresOldEntry(t *testing.T) {
	c := newTestCache(t)
	c.TTL = 20 * time.Millisecond

	if err := c.Set("key1", testResponse("hello")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	_, hit, err := c.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if hit {
		t.Fatal("hit = true, want false — entry is older than TTL")
	}
}

func TestCache_TTL_ExpiredEntryIsRemovedFromDisk(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	c.TTL = 20 * time.Millisecond

	if err := c.Set("key1", testResponse("hello")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if _, hit, err := c.Get("key1"); err != nil || hit {
		t.Fatalf("Get: hit=%v err=%v, want a miss", hit, err)
	}

	entryPath := filepath.Join(dir, cache.DirName, "key1.bin")
	if _, err := os.Stat(entryPath); !os.IsNotExist(err) {
		t.Fatalf("expired entry file still exists on disk (stat err: %v), want it removed by Get", err)
	}
}

func TestCache_Set_ResetsAgeForTTL(t *testing.T) {
	c := newTestCache(t)
	c.TTL = 80 * time.Millisecond

	if err := c.Set("key1", testResponse("v1")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	// Re-Set before the original TTL would have expired — this should
	// reset the entry's age, not just extend on top of the old one.
	if err := c.Set("key1", testResponse("v2")); err != nil {
		t.Fatalf("Set (again): %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	// 100ms since the first Set (which would have expired an 80ms TTL by
	// now), but only 50ms since the second — must still be a hit.

	_, hit, err := c.Get("key1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !hit {
		t.Fatal("hit = false, want true — re-Set must reset the entry's age")
	}
}

func TestCache_Clear_RemovesAllEntries(t *testing.T) {
	c := newTestCache(t)

	if err := c.Set("key1", testResponse("a")); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	if err := c.Set("key2", testResponse("b")); err != nil {
		t.Fatalf("Set key2: %v", err)
	}

	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	for _, key := range []string{"key1", "key2"} {
		if _, hit, err := c.Get(key); err != nil || hit {
			t.Errorf("Get(%q) after Clear: hit=%v err=%v, want a miss", key, hit, err)
		}
	}
}

// entryFileSize returns the on-disk size, in bytes, of the file backing
// key relative to the current working directory — used to compute a
// MaxSizeBytes budget in exact multiples of a real dumped entry's size,
// rather than guessing at httputil.DumpResponse's header overhead.
func entryFileSize(t *testing.T, key string) int64 {
	t.Helper()
	info, err := os.Stat(filepath.Join(cache.DirName, key+".bin"))
	if err != nil {
		t.Fatalf("stat %s: %v", key, err)
	}
	return info.Size()
}

func TestCache_MaxSizeBytes_ZeroMeansUnbounded(t *testing.T) {
	c := newTestCache(t)
	// c.MaxSizeBytes left at its zero value.

	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("key%d", i)
		if err := c.Set(key, testResponse(strings.Repeat("x", 1000))); err != nil {
			t.Fatalf("Set(%s): %v", key, err)
		}
	}

	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("key%d", i)
		if _, hit, err := c.Get(key); err != nil || !hit {
			t.Errorf("Get(%s): hit=%v err=%v, want a hit — MaxSizeBytes=0 must never evict anything", key, hit, err)
		}
	}
}

// TestCache_MaxSizeBytes_EvictsOldestFirstOnceOverBudget proves the
// core eviction contract: once the tracked total would exceed
// MaxSizeBytes, the least-recently-used entry (here, simply the oldest,
// since none has been Get since being Set) is removed — from both the
// index (a subsequent Get misses) and disk.
func TestCache_MaxSizeBytes_EvictsOldestFirstOnceOverBudget(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	body := strings.Repeat("x", 100)
	if err := c.Set("key1", testResponse(body)); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	entrySize := entryFileSize(t, "key1")
	c.MaxSizeBytes = entrySize*2 + entrySize/2 // room for 2 entries, not 3

	if err := c.Set("key2", testResponse(body)); err != nil {
		t.Fatalf("Set key2: %v", err)
	}
	if err := c.Set("key3", testResponse(body)); err != nil {
		t.Fatalf("Set key3: %v", err)
	}

	if _, hit, err := c.Get("key1"); err != nil || hit {
		t.Errorf("Get(key1): hit=%v err=%v, want a miss — it should have been evicted as least-recently-used", hit, err)
	}
	if _, hit, err := c.Get("key3"); err != nil || !hit {
		t.Errorf("Get(key3): hit=%v err=%v, want a hit — the most recently written entry must survive", hit, err)
	}

	if _, err := os.Stat(filepath.Join(dir, cache.DirName, "key1.bin")); !os.IsNotExist(err) {
		t.Fatalf("evicted entry's file still exists on disk (stat err: %v), want it removed", err)
	}
}

// TestCache_MaxSizeBytes_GetProtectsEntryFromEviction proves eviction is
// genuinely LRU (least-recently-*used*), not just oldest-written: an old
// entry that's been Get since — marking it most-recently-used — survives
// in favor of evicting a newer entry that was never read again.
func TestCache_MaxSizeBytes_GetProtectsEntryFromEviction(t *testing.T) {
	c := newTestCache(t)

	body := strings.Repeat("x", 100)
	if err := c.Set("key1", testResponse(body)); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	entrySize := entryFileSize(t, "key1")
	c.MaxSizeBytes = entrySize*2 + entrySize/2 // room for 2 entries, not 3

	if err := c.Set("key2", testResponse(body)); err != nil {
		t.Fatalf("Set key2: %v", err)
	}
	// Touch key1 — it's now more recently used than key2, even though
	// key2 was written later.
	if _, hit, err := c.Get("key1"); err != nil || !hit {
		t.Fatalf("Get key1 (priming): hit=%v err=%v, want a hit", hit, err)
	}

	if err := c.Set("key3", testResponse(body)); err != nil {
		t.Fatalf("Set key3: %v", err)
	}

	if _, hit, err := c.Get("key2"); err != nil || hit {
		t.Errorf("Get(key2): hit=%v err=%v, want a miss — key2 was the least recently used, not key1", hit, err)
	}
	if _, hit, err := c.Get("key1"); err != nil || !hit {
		t.Errorf("Get(key1): hit=%v err=%v, want a hit — it was touched more recently than key2", hit, err)
	}
}

// TestCache_MaxSizeBytes_SingleOversizedEntrySurvives proves a single
// entry larger than MaxSizeBytes on its own is never deleted right
// after being written — there's nothing else left to evict it in favor
// of, and Set must never fail or silently drop the response it was just
// asked to cache purely because of the size policy.
func TestCache_MaxSizeBytes_SingleOversizedEntrySurvives(t *testing.T) {
	c := newTestCache(t)
	c.MaxSizeBytes = 10 // far smaller than the entry below

	if err := c.Set("key1", testResponse(strings.Repeat("x", 1000))); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, hit, err := c.Get("key1"); err != nil || !hit {
		t.Errorf("Get(key1): hit=%v err=%v, want a hit — a single oversized entry must still be served", hit, err)
	}
}

// TestCache_MaxSizeBytes_ClearResetsAccounting proves Clear discards the
// in-memory LRU index along with the on-disk entries — otherwise a
// stale totalSize would make later Sets evict incorrectly (or refuse to
// evict at all) against entries that no longer exist.
func TestCache_MaxSizeBytes_ClearResetsAccounting(t *testing.T) {
	c := newTestCache(t)

	body := strings.Repeat("x", 100)
	if err := c.Set("key1", testResponse(body)); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	entrySize := entryFileSize(t, "key1")
	c.MaxSizeBytes = entrySize*2 + entrySize/2 // room for 2 entries, not 3

	if err := c.Set("key2", testResponse(body)); err != nil {
		t.Fatalf("Set key2: %v", err)
	}
	if err := c.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}

	// Post-Clear, the budget should behave as if the cache were brand
	// new: two more entries fit without either evicting the other.
	if err := c.Set("key3", testResponse(body)); err != nil {
		t.Fatalf("Set key3: %v", err)
	}
	if err := c.Set("key4", testResponse(body)); err != nil {
		t.Fatalf("Set key4: %v", err)
	}
	if _, hit, err := c.Get("key3"); err != nil || !hit {
		t.Errorf("Get(key3): hit=%v err=%v, want a hit", hit, err)
	}
	if _, hit, err := c.Get("key4"); err != nil || !hit {
		t.Errorf("Get(key4): hit=%v err=%v, want a hit", hit, err)
	}
}

// TestCache_MaxSizeBytes_LoadsExistingEntriesOnNew proves a fresh Cache
// (a new process against an existing cache directory) correctly
// accounts for entries it never itself Set — eviction must still trip
// against a cache that was already large before this process started,
// not just against what's been written since.
func TestCache_MaxSizeBytes_LoadsExistingEntriesOnNew(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	c1, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New (1st process): %v", err)
	}
	body := strings.Repeat("x", 100)
	if err := c1.Set("key1", testResponse(body)); err != nil {
		t.Fatalf("Set key1: %v", err)
	}
	time.Sleep(10 * time.Millisecond) // ensure a distinct, later mtime for key2
	if err := c1.Set("key2", testResponse(body)); err != nil {
		t.Fatalf("Set key2: %v", err)
	}

	// Simulate a restart: a brand new Cache value over the same
	// on-disk directory, with no in-process history of key1/key2 at all.
	c2, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New (2nd process): %v", err)
	}
	c2.MaxSizeBytes = 150 // room for only one ~100-byte entry

	if err := c2.Set("key3", testResponse(body)); err != nil {
		t.Fatalf("Set key3: %v", err)
	}

	if _, hit, err := c2.Get("key1"); err != nil || hit {
		t.Errorf("Get(key1): hit=%v err=%v, want a miss — the oldest pre-existing entry should have been evicted", hit, err)
	}
	if _, hit, err := c2.Get("key3"); err != nil || !hit {
		t.Errorf("Get(key3): hit=%v err=%v, want a hit", hit, err)
	}
}

func TestCache_Clear_OnMissingDirectoryIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	c, err := cache.New()
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	// Remove the directory New() just created, simulating a cache that
	// was never actually written to (or was cleared already).
	if err := os.RemoveAll(filepath.Join(dir, cache.DirName)); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	if err := c.Clear(); err != nil {
		t.Fatalf("Clear on a missing directory = %v, want nil (already-empty is not an error)", err)
	}
}
