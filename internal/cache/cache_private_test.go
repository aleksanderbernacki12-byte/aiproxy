package cache_test

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"aiproxy/internal/cache"
)

func requirePOSIXPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits do not apply on Windows")
	}
}

func TestCache_NewDirectoryAndEntriesArePrivate(t *testing.T) {
	requirePOSIXPermissions(t)
	c := newTestCache(t)
	if err := c.Set("key1", testResponse("hello")); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(cache.DirName)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("cache dir mode = %04o, want 0700", perm)
	}
	fileInfo, err := os.Stat(filepath.Join(cache.DirName, "key1.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("cache entry mode = %04o, want 0600", perm)
	}
}

func TestCache_NewMigratesAnExistingPublicDirectory(t *testing.T) {
	requirePOSIXPermissions(t)
	t.Chdir(t.TempDir())
	if err := os.Mkdir(cache.DirName, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(cache.DirName, "old.bin")
	if err := os.WriteFile(entry, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cache.DirName, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(entry, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.New(); err != nil {
		t.Fatal(err)
	}
	dirInfo, _ := os.Stat(cache.DirName)
	fileInfo, _ := os.Stat(entry)
	if dirInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("after New: dir %04o, entry %04o; want 0700 and 0600", dirInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}
}

func TestCache_NewRemovesLeftoverTempFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.Mkdir(cache.DirName, 0o700); err != nil {
		t.Fatal(err)
	}
	leftover := filepath.Join(cache.DirName, ".tmp-123")
	if err := os.WriteFile(leftover, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(leftover); !os.IsNotExist(err) {
		t.Fatalf("leftover temp file still present (stat err = %v)", err)
	}
	c.MaxSizeBytes = 1
	if err := c.Set("only", testResponse("x")); err != nil {
		t.Fatal(err)
	}
	if _, hit, _, _ := c.Get("only", 0); !hit {
		t.Fatal("the only entry was evicted: the leftover temp file was counted toward the size budget")
	}
}

func TestCache_ConcurrentReadersNeverSeeAPartialEntry(t *testing.T) {
	c := newTestCache(t)
	bodies := [2]string{string(make([]byte, 256<<10)), "short body"}
	if err := c.Set("shared", testResponse(bodies[0])); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	errs := make(chan string, 64)
	for reader := 0; reader < 8; reader++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, hit, _, err := c.Get("shared", 0)
				if err != nil {
					errs <- "Get error: " + err.Error()
					return
				}
				if !hit {
					continue
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || (string(body) != bodies[0] && string(body) != bodies[1]) {
					errs <- "partial or corrupt entry read"
					return
				}
			}
		}()
	}
	for i := 0; i < 200; i++ {
		if err := c.Set("shared", testResponse(bodies[i%2])); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("Set %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
