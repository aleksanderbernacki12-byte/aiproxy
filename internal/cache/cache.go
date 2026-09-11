// Package cache implements aiproxy's local, on-disk response cache. Each
// cached upstream response is stored as a raw HTTP/1.1 dump on disk,
// keyed by the SHA256 hash of the request that produced it, using only
// the standard library.
package cache

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DirName is the cache subdirectory created inside the working directory.
const DirName = ".aiproxy_cache"

// Cache stores and retrieves cached HTTP responses on disk under dir.
type Cache struct {
	dir string

	// TTL, if greater than zero, expires an entry this long after it was
	// last written (Set) — Get treats an older entry as a plain cache
	// miss and removes it. Zero (the default) means entries never expire
	// on their own, the same behavior as before this field existed.
	// Exported so the cli package can set it directly after New,
	// mirroring how proxy.Server's own tunables work.
	TTL time.Duration

	// MaxSizeBytes, if greater than zero, caps the total size of every
	// entry on disk under dir combined — once a Set would push the
	// total over this limit, the least-recently-used entries are
	// evicted, oldest-used first, until there's room again. "Used" here
	// means an in-memory recency index (order/elements below), updated
	// on every Get hit and Set — not filesystem access time, which Go's
	// standard library has no portable, syscall-free way to read, and
	// which many filesystems don't even update by default. Kept
	// entirely separate from TTL: a cache hit never touches an entry's
	// on-disk mtime, so TTL's own "expires N seconds after it was
	// written" semantics are unaffected by how often (or rarely) an
	// entry is read. Zero (the default) means the cache is never
	// size-capped, unbounded, the same behavior as before this field
	// existed.
	MaxSizeBytes int64

	mu        sync.Mutex
	order     *list.List               // front = least recently used, back = most recently used
	elements  map[string]*list.Element // key -> its node in order
	totalSize int64
}

// lruEntry is one node's payload in Cache.order.
type lruEntry struct {
	key  string
	size int64
}

// New creates a Cache rooted at DirName in the current working directory,
// creating the directory first if it does not already exist. Any entries
// already on disk (from a previous run) are loaded into the in-memory
// LRU index, oldest-written first, so MaxSizeBytes accounting is correct
// from the very first Set even against a cache directory that already
// existed before this process started.
func New() (*Cache, error) {
	if err := os.MkdirAll(DirName, 0o755); err != nil {
		return nil, err
	}
	c := &Cache{
		dir:      DirName,
		order:    list.New(),
		elements: make(map[string]*list.Element),
	}
	if err := c.loadExisting(); err != nil {
		return nil, err
	}
	return c, nil
}

// loadExisting populates order/elements/totalSize from whatever is
// already on disk under c.dir, ordered oldest-mtime-first — a
// reasonable initial recency guess for entries this process has never
// itself Get/Set yet. An entry this process can't stat (a permissions
// problem, or it vanishing mid-scan) is skipped rather than failing
// startup entirely — best-effort accounting, same discipline as Get's
// own best-effort os.Remove on an expired entry.
func (c *Cache) loadExisting() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	type onDiskEntry struct {
		key     string
		size    int64
		modTime time.Time
	}
	files := make([]onDiskEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, onDiskEntry{
			key:     strings.TrimSuffix(e.Name(), ".bin"),
			size:    info.Size(),
			modTime: info.ModTime(),
		})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })

	for _, f := range files {
		el := c.order.PushBack(&lruEntry{key: f.key, size: f.size})
		c.elements[f.key] = el
		c.totalSize += f.size
	}
	return nil
}

// Key computes the cache key for a request: the hex-encoded SHA256 hash
// of the HTTP method, the fully-resolved target URL, and the entire
// request body. NUL bytes separate the fields so that, for example,
// method "GETX" + url "Y" cannot collide with method "GET" + url "XY".
func Key(method, targetURL string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(targetURL))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (c *Cache) path(key string) string {
	return filepath.Join(c.dir, key+".bin")
}

// Get returns the cached response for key, if present and not expired,
// along with its age — how long ago it was written (Set), regardless of
// whether TTL is even configured — so a caller can report exactly how
// fresh a cache hit actually is (see IsStale). The second return value
// reports whether a live cache entry existed; a false with a nil error
// means a plain cache miss — including an entry that existed but was
// older than TTL, which Get also removes from disk on its way out, the
// same as if it had never been cached at all (age is always zero
// alongside a miss). A real hit marks key most-recently-used in the LRU
// index, protecting it from the next Set's size-based eviction.
func (c *Cache) Get(key string) (*http.Response, bool, time.Duration, error) {
	path := c.path(key)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, 0, nil
		}
		return nil, false, 0, err
	}
	age := time.Since(info.ModTime())
	if c.TTL > 0 && age > c.TTL {
		os.Remove(path) // best-effort: a failed cleanup just leaves a stale, inert file behind
		c.forget(key)
		return nil, false, 0, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, 0, nil
		}
		return nil, false, 0, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, false, 0, err
	}

	c.touch(key, int64(len(data)))
	return resp, true, age, nil
}

// staleThresholdRatio is the fraction of TTL past which IsStale flags a
// cache hit as getting old — purely informational: an entry is only
// ever actually evicted once it's fully past TTL (see Get above), not
// at this earlier point. Not exposed as config — one universally
// reasonable default rather than a knob every deployment needs to tune,
// the same reasoning behind the anomaly package's own unexported
// minRequestsFloor/emaAlpha constants.
const staleThresholdRatio = 0.8

// IsStale reports whether age — a cache hit's own age, as returned by
// Get — has crossed staleThresholdRatio of c.TTL, a signal that this
// entry will need refreshing soon. Always false when TTL itself is
// unset (c.TTL <= 0): there is no "getting old relative to TTL" without
// a TTL to be relative to, the same as an entry that never expires on
// its own having nothing to warn about.
func (c *Cache) IsStale(age time.Duration) bool {
	if c.TTL <= 0 {
		return false
	}
	return age >= time.Duration(float64(c.TTL)*staleThresholdRatio)
}

// Set dumps resp, including its body, and stores it under key. A
// re-Set of an existing key resets its age for TTL purposes, same as
// writing a brand new entry — the file's mtime is what Get's TTL check
// reads, and a plain overwrite naturally updates it. key is always
// marked most-recently-used afterward; if MaxSizeBytes is set, entries
// are then evicted oldest-used-first until the tracked total is back at
// or under budget.
func (c *Cache) Set(key string, resp *http.Response) error {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.path(key), dump, 0o644); err != nil {
		return err
	}
	c.touch(key, int64(len(dump)))
	if c.MaxSizeBytes > 0 {
		c.evictUntilUnderBudget()
	}
	return nil
}

// touch marks key most-recently-used, inserting it into the LRU index
// if this is the first time it's been seen (a Set, or a Get for an
// entry loadExisting skipped or that predates this process), and keeps
// totalSize in sync with size either way.
func (c *Cache) touch(key string, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.elements[key]; ok {
		c.order.MoveToBack(el)
		entry := el.Value.(*lruEntry)
		c.totalSize += size - entry.size
		entry.size = size
		return
	}
	el := c.order.PushBack(&lruEntry{key: key, size: size})
	c.elements[key] = el
	c.totalSize += size
}

// forget removes key from the LRU index, if tracked at all — used when
// an entry is deleted from disk outside of eviction (Get's own TTL
// expiry).
func (c *Cache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forgetLocked(key)
}

func (c *Cache) forgetLocked(key string) {
	el, ok := c.elements[key]
	if !ok {
		return
	}
	c.order.Remove(el)
	delete(c.elements, key)
	c.totalSize -= el.Value.(*lruEntry).size
}

// evictUntilUnderBudget removes the least-recently-used entries — the
// front of order — until the tracked total size is at or under
// MaxSizeBytes, or only one entry (the one Set just wrote, always the
// most-recently-used) is left. A single entry larger than MaxSizeBytes
// on its own is therefore never deleted immediately after being
// written — there's nothing left to evict it in favor of, and a size
// policy should never make Set itself fail or silently drop the very
// response it was just asked to cache.
func (c *Cache) evictUntilUnderBudget() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.totalSize > c.MaxSizeBytes && c.order.Len() > 1 {
		front := c.order.Front()
		entry := front.Value.(*lruEntry)
		os.Remove(c.path(entry.key)) // best-effort: a failed removal just leaves a stale file the index no longer tracks
		c.order.Remove(front)
		delete(c.elements, entry.key)
		c.totalSize -= entry.size
	}
}

// Clear deletes every cached entry, without removing the cache
// directory itself — a manual invalidation, for a running proxy that
// needs to stop serving stale responses right now instead of waiting
// out TTL (or, with no TTL configured at all, the only way to ever
// evict anything). A cache directory that doesn't exist yet is treated
// as already empty, not an error. The in-memory LRU index is reset
// alongside the on-disk entries, so size accounting stays correct.
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(c.dir, e.Name())); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	c.mu.Lock()
	c.order.Init()
	c.elements = make(map[string]*list.Element)
	c.totalSize = 0
	c.mu.Unlock()
	return nil
}
