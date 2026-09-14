package anonymizer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestSaltPersistsAndProducesStableHMAC(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".aiproxy_salt")
	now := time.Date(2026, time.September, 14, 10, 0, 0, 0, time.UTC)
	first, err := New(Config{Path: path, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	firstHash, err := first.Hash("local-user-42")
	if err != nil {
		t.Fatal(err)
	}
	otherHash, err := first.Hash("local-user-43")
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	if firstHash == otherHash {
		t.Fatal("different client IDs produced the same pseudonym")
	}
	decoded, err := hex.DecodeString(firstHash)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("hash = %q, want a SHA-256 hex digest", firstHash)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("salt file permissions = %04o, want 0600", info.Mode().Perm())
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if stringContains(contents, "local-user-42") {
		t.Fatal("salt file contains the client ID")
	}
	var record saltRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		t.Fatal(err)
	}
	if !record.CreatedAt.Equal(now) || record.Version != fileVersion {
		t.Fatalf("salt metadata = version %d at %s, want version %d at %s", record.Version, record.CreatedAt, fileVersion, now)
	}

	second, err := New(Config{Path: path, Now: func() time.Time { return now.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	restartedHash, err := second.Hash("local-user-42")
	if err != nil {
		t.Fatal(err)
	}
	if restartedHash != firstHash {
		t.Fatal("pseudonym changed before salt rotation")
	}
}

func TestExpiredSaltRotatesAndLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".aiproxy_salt")
	current := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return current }
	first, err := New(Config{Path: path, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	before, err := first.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	first.Close()

	current = current.Add(30 * 24 * time.Hour)
	var loggedAt time.Time
	second, err := New(Config{
		Path: path,
		Now:  now,
		OnRotation: func(createdAt time.Time) {
			loggedAt = createdAt
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := second.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	second.Close()
	if before == after {
		t.Fatal("expired salt did not change the client pseudonym")
	}
	if !loggedAt.Equal(current) {
		t.Fatalf("rotation log timestamp = %s, want %s", loggedAt, current)
	}

	third, err := New(Config{Path: path, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	persisted, err := third.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	if persisted != after {
		t.Fatal("rotated salt was not persisted")
	}
}

func TestBackgroundCheckerRotatesSalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".aiproxy_salt")
	var mu sync.Mutex
	current := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	rotated := make(chan struct{}, 1)
	a, err := New(Config{
		Path:          path,
		RotationAge:   30 * 24 * time.Hour,
		CheckInterval: time.Millisecond,
		Now:           now,
		OnRotation:    func(time.Time) { rotated <- struct{}{} },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	before, err := a.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	current = current.Add(31 * 24 * time.Hour)
	mu.Unlock()
	select {
	case <-rotated:
	case <-time.After(time.Second):
		t.Fatal("background checker did not rotate expired salt")
	}
	after, err := a.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("background rotation did not change the pseudonym")
	}
}

func TestFailedRotationKeepsExistingSalt(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".aiproxy_salt")
	current := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	a, err := New(Config{Path: path, Now: func() time.Time { return current }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	before, err := a.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(31 * 24 * time.Hour)
	a.random = errorReader{}
	if err := a.RotateIfNeeded(); err == nil {
		t.Fatal("rotation succeeded with an unavailable random source")
	}
	after, err := a.Hash("client")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("failed rotation replaced the active salt")
	}
}

func TestRejectsCorruptFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt")
	if err := os.WriteFile(corrupt, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Path: corrupt}); err == nil {
		t.Fatal("corrupt salt file was accepted")
	}
	if runtime.GOOS == "windows" {
		return
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Path: link}); err == nil {
		t.Fatal("salt symlink was accepted")
	}
}

func TestHashRejectsEmptyIDAndClosedState(t *testing.T) {
	a, err := New(Config{Path: filepath.Join(t.TempDir(), ".aiproxy_salt")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Hash(""); !errors.Is(err, ErrClientIDRequired) {
		t.Fatalf("empty client ID error = %v", err)
	}
	a.Close()
	if _, err := a.Hash("client"); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed anonymizer error = %v", err)
	}
}

func stringContains(haystack []byte, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if string(haystack[index:index+len(needle)]) == needle {
			return true
		}
	}
	return false
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}
