package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteExclusiveSecretFileSecuresAndNeverOverwrites(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "evidence.json")
	if err := writeExclusiveSecretFile(filename, []byte("raw evidence")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	// Windows access is governed by the destination directory's ACL, not
	// Unix mode bits. Content and exclusive creation are checked on every OS.
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o", info.Mode().Perm())
	}
	if err := writeExclusiveSecretFile(filename, []byte("replacement")); err == nil {
		t.Fatal("existing export was overwritten")
	}
	data, _ := os.ReadFile(filename)
	if string(data) != "raw evidence" {
		t.Fatalf("contents = %q", data)
	}
}
