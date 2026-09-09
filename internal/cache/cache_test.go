package cache_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
