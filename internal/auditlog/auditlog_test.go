package auditlog

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func writeChainedFile(t *testing.T, path string, key []byte, events []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	c := NewChain(key, "")
	for _, ev := range events {
		wrapped, err := c.Wrap([]byte(ev))
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if _, err := f.Write(append(wrapped, '\n')); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func TestChain_WrapProducesVerifiableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-key-1")
	events := []string{
		`{"time":"t1","level":"allow"}`,
		`{"time":"t2","level":"block","rule":"aws-access-key"}`,
		`{"time":"t3","level":"usage","tokens":42}`,
	}
	writeChainedFile(t, path, key, events)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	result, err := Verify(f, key)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("Verify reported broken at line %d: %v", result.Broken, result.Err)
	}
	if result.Lines != len(events) {
		t.Fatalf("Lines = %d, want %d", result.Lines, len(events))
	}
}

func TestChain_FirstLinePrevHashIsGenesis(t *testing.T) {
	c := NewChain([]byte("k"), "")
	wrapped, err := c.Wrap([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(wrapped, &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if env.PrevHash != Genesis {
		t.Fatalf("PrevHash = %q, want Genesis %q", env.PrevHash, Genesis)
	}
	if len(env.Hash) != 64 {
		t.Fatalf("Hash length = %d, want 64", len(env.Hash))
	}
}

func TestChain_EventFieldPreservesOriginalBytesExactly(t *testing.T) {
	c := NewChain([]byte("k"), "")
	original := `{"time":"t1","level":"allow","method":"GET"}`
	wrapped, err := c.Wrap([]byte(original))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	var env Envelope
	if err := json.Unmarshal(wrapped, &env); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(env.Event) != original {
		t.Fatalf("Event = %q, want %q", env.Event, original)
	}
}

func TestVerify_DetectsAlteredLineContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-key")
	writeChainedFile(t, path, key, []string{
		`{"level":"allow","method":"GET"}`,
		`{"level":"block","rule":"aws-access-key"}`,
		`{"level":"usage","tokens":1}`,
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	tampered := bytes.Replace(data, []byte(`"rule":"aws-access-key"`), []byte(`"rule":"harmless-rule"`), 1)
	if bytes.Equal(data, tampered) {
		t.Fatal("tamper replacement did not match anything in the file")
	}

	result, err := Verify(bytes.NewReader(tampered), key)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 2 {
		t.Fatalf("Broken = %d, want 2 (the altered line)", result.Broken)
	}
}

func TestVerify_DetectsDeletedLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-key")
	writeChainedFile(t, path, key, []string{
		`{"level":"allow","n":1}`,
		`{"level":"allow","n":2}`,
		`{"level":"allow","n":3}`,
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	withDeletion := lines[0] + "\n" + lines[2] + "\n" // line 2 (n:2) removed

	result, err := Verify(strings.NewReader(withDeletion), key)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 2 {
		t.Fatalf("Broken = %d, want 2 (the line whose prev_hash no longer matches)", result.Broken)
	}
	if result.Lines != 1 {
		t.Fatalf("Lines = %d, want 1 (only the first line verified before the break)", result.Lines)
	}
}

func TestVerify_DetectsReorderedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("test-key")
	writeChainedFile(t, path, key, []string{
		`{"level":"allow","n":1}`,
		`{"level":"allow","n":2}`,
	})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	swapped := lines[1] + "\n" + lines[0] + "\n"

	result, err := Verify(strings.NewReader(swapped), key)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 1 {
		t.Fatalf("Broken = %d, want 1 (the reordered first line's prev_hash won't be Genesis)", result.Broken)
	}
}

func TestVerify_WrongKeyBreaksEveryLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	writeChainedFile(t, path, []byte("the-real-key"), []string{
		`{"level":"allow"}`,
	})

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	result, err := Verify(f, []byte("a-different-key"))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 1 {
		t.Fatalf("Broken = %d, want 1", result.Broken)
	}
}

func TestVerify_EmptyFileVerifiesWithZeroLines(t *testing.T) {
	result, err := Verify(strings.NewReader(""), []byte("k"))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 0 || result.Lines != 0 {
		t.Fatalf("Result = %+v, want Broken=0 Lines=0", result)
	}
}

func TestVerify_SkipsBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("k")
	writeChainedFile(t, path, key, []string{`{"level":"allow"}`})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	withBlank := "\n" + string(data) + "\n"

	result, err := Verify(strings.NewReader(withBlank), key)
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 0 || result.Lines != 1 {
		t.Fatalf("Result = %+v, want Broken=0 Lines=1", result)
	}
}

func TestVerify_RejectsNonJSONLine(t *testing.T) {
	result, err := Verify(strings.NewReader("not json at all\n"), []byte("k"))
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Broken != 1 {
		t.Fatalf("Broken = %d, want 1", result.Broken)
	}
}

func TestRecoverPrevHash_NonexistentFileReturnsGenesis(t *testing.T) {
	dir := t.TempDir()
	got, err := RecoverPrevHash(filepath.Join(dir, "does-not-exist.jsonl"))
	if err != nil {
		t.Fatalf("RecoverPrevHash: %v", err)
	}
	if got != Genesis {
		t.Fatalf("got %q, want Genesis", got)
	}
}

func TestRecoverPrevHash_EmptyFileReturnsGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := RecoverPrevHash(path)
	if err != nil {
		t.Fatalf("RecoverPrevHash: %v", err)
	}
	if got != Genesis {
		t.Fatalf("got %q, want Genesis", got)
	}
}

func TestRecoverPrevHash_PreExistingPlainLogFallsBackToGenesis(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.jsonl")
	content := `{"time":"t1","level":"allow"}` + "\n" + `{"time":"t2","level":"block"}` + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := RecoverPrevHash(path)
	if err != nil {
		t.Fatalf("RecoverPrevHash: %v", err)
	}
	if got != Genesis {
		t.Fatalf("got %q, want Genesis (plain pre-existing log has no chain to resume)", got)
	}
}

func TestRecoverPrevHash_ResumesAnExistingChainAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("k")
	writeChainedFile(t, path, key, []string{
		`{"level":"allow","n":1}`,
		`{"level":"allow","n":2}`,
	})

	recovered, err := RecoverPrevHash(path)
	if err != nil {
		t.Fatalf("RecoverPrevHash: %v", err)
	}

	// Simulate a process restart: a fresh Chain seeded with the
	// recovered hash, appending one more line to the same file.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	c := NewChain(key, recovered)
	wrapped, err := c.Wrap([]byte(`{"level":"allow","n":3}`))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := f.Write(append(wrapped, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}
	f.Close()

	verifyFile, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer verifyFile.Close()
	result, err := Verify(verifyFile, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("chain broken at line %d after simulated restart: %v", result.Broken, result.Err)
	}
	if result.Lines != 3 {
		t.Fatalf("Lines = %d, want 3", result.Lines)
	}
}

func TestRecoverPrevHash_TruncatedLastLineIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("k")
	writeChainedFile(t, path, key, []string{`{"level":"allow"}`})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// Cut the last line in half — never terminated by a closing brace.
	cut := data[:len(data)-10]
	if err := os.WriteFile(path, cut, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := RecoverPrevHash(path); err == nil {
		t.Fatal("expected an error for a truncated last line, got nil")
	}
}

func TestRecoverPrevHash_TailReadWorksAcrossChunkBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("k")

	// Pad the file well past the 64KB internal chunk size used by
	// lastLine, so recovering the true last line requires reading back
	// across more than one chunk.
	var events []string
	padding := strings.Repeat("x", 2000)
	for i := 0; i < 100; i++ {
		events = append(events, `{"level":"allow","pad":"`+padding+`"}`)
	}
	writeChainedFile(t, path, key, events)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() < 150*1024 {
		t.Fatalf("test file too small (%d bytes) to exercise multi-chunk tail read", info.Size())
	}

	recovered, err := RecoverPrevHash(path)
	if err != nil {
		t.Fatalf("RecoverPrevHash: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	result, err := Verify(f, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("chain broken at line %d: %v", result.Broken, result.Err)
	}
	if recovered != Genesis && result.Lines != 100 {
		t.Fatalf("Lines = %d, want 100", result.Lines)
	}
}

func TestReadKeyFile_TrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("  my-secret-key\n\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	key, err := ReadKeyFile(path)
	if err != nil {
		t.Fatalf("ReadKeyFile: %v", err)
	}
	if string(key) != "my-secret-key" {
		t.Fatalf("key = %q, want %q", key, "my-secret-key")
	}
}

func TestReadKeyFile_EmptyFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte("   \n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := ReadKeyFile(path); err == nil {
		t.Fatal("expected an error for an all-whitespace key file, got nil")
	}
}

func TestReadKeyFile_MissingFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadKeyFile(filepath.Join(dir, "does-not-exist")); err == nil {
		t.Fatal("expected an error for a missing key file, got nil")
	}
}

// TestChain_SerializedConcurrentWrapProducesAValidChain mirrors how
// proxy.Server.appendToLogFile actually uses Chain: many goroutines
// racing to log, but every Wrap call serialized against the others (via
// an external lock, not one owned by Chain itself — see Chain's own
// doc comment on why locking only inside Wrap wouldn't be enough) with
// the resulting bytes written to the file inside that very same
// critical section. Run with -race to confirm there's no data race in
// Chain itself under that usage pattern.
func TestChain_SerializedConcurrentWrapProducesAValidChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	key := []byte("concurrent-key")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	c := NewChain(key, "")
	var mu sync.Mutex
	var wg sync.WaitGroup
	const n = 50
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev, _ := json.Marshal(map[string]int{"n": i})
			mu.Lock()
			defer mu.Unlock()
			wrapped, err := c.Wrap(ev)
			if err != nil {
				t.Errorf("Wrap: %v", err)
				return
			}
			if _, err := f.Write(append(wrapped, '\n')); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	wg.Wait()

	verifyFile, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer verifyFile.Close()
	result, err := Verify(verifyFile, key)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Broken != 0 {
		t.Fatalf("chain broken at line %d: %v", result.Broken, result.Err)
	}
	if result.Lines != n {
		t.Fatalf("Lines = %d, want %d", result.Lines, n)
	}
}
