// Package cache implements aiproxy's local, on-disk response cache. Each
// cached upstream response is stored as a raw HTTP/1.1 dump on disk,
// keyed by the SHA256 hash of the request that produced it, using only
// the standard library.
package cache

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
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
}

// New creates a Cache rooted at DirName in the current working directory,
// creating the directory first if it does not already exist.
func New() (*Cache, error) {
	if err := os.MkdirAll(DirName, 0o755); err != nil {
		return nil, err
	}
	return &Cache{dir: DirName}, nil
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

// Get returns the cached response for key, if present and not expired.
// The second return value reports whether a live cache entry existed; a
// false with a nil error means a plain cache miss — including an entry
// that existed but was older than TTL, which Get also removes from disk
// on its way out, the same as if it had never been cached at all.
func (c *Cache) Get(key string) (*http.Response, bool, error) {
	path := c.path(key)

	if c.TTL > 0 {
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, false, nil
			}
			return nil, false, err
		}
		if time.Since(info.ModTime()) > c.TTL {
			os.Remove(path) // best-effort: a failed cleanup just leaves a stale, inert file behind
			return nil, false, nil
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, false, err
	}
	return resp, true, nil
}

// Set dumps resp, including its body, and stores it under key. A
// re-Set of an existing key resets its age for TTL purposes, same as
// writing a brand new entry — the file's mtime is what Get's TTL check
// reads, and a plain overwrite naturally updates it.
func (c *Cache) Set(key string, resp *http.Response) error {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path(key), dump, 0o644)
}

// Clear deletes every cached entry, without removing the cache
// directory itself — a manual invalidation, for a running proxy that
// needs to stop serving stale responses right now instead of waiting
// out TTL (or, with no TTL configured at all, the only way to ever
// evict anything). A cache directory that doesn't exist yet is treated
// as already empty, not an error.
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
	return nil
}
