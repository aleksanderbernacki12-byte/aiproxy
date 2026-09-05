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
)

// DirName is the cache subdirectory created inside the working directory.
const DirName = ".aiproxy_cache"

// Cache stores and retrieves cached HTTP responses on disk under dir.
type Cache struct {
	dir string
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

// Get returns the cached response for key, if present. The second return
// value reports whether a cache entry existed; a false with a nil error
// means a plain cache miss.
func (c *Cache) Get(key string) (*http.Response, bool, error) {
	data, err := os.ReadFile(c.path(key))
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

// Set dumps resp, including its body, and stores it under key.
func (c *Cache) Set(key string, resp *http.Response) error {
	dump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path(key), dump, 0o644)
}
