// Package auditlog HMAC-chains the JSON lines aiproxy appends to its
// persistent log file: each line's hash covers the previous line's hash
// plus its own content, so any later edit, deletion, insertion, or
// reordering of historical lines is detectable — independently, using
// only the same key and the file itself, via Verify (see also the
// `aiproxy verify-log` command). It has no dependency on the proxy
// package; proxy.Server wires a Chain into its own log-writing path.
package auditlog

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Genesis is the fixed prev_hash of a chain's very first line — the
// same length as a real HMAC-SHA256 hex digest so prev_hash is always
// exactly 64 hex characters, never empty or a different shape for the
// first line than for every line after it.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Envelope is the on-disk shape of one HMAC-chained log line: the
// original event, verbatim, plus the chain linkage. Event is a
// json.RawMessage specifically so Verify can recompute a line's hash
// over the exact original bytes that were signed, rather than
// re-marshaling a decoded value and hoping key order comes out
// identical.
type Envelope struct {
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Event    json.RawMessage `json:"event"`
}

// Chain computes successive links of an HMAC hash chain. It is NOT safe
// for concurrent use: a chain's entire guarantee rests on each line's
// prev_hash matching the line physically before it in the file, so the
// caller must serialize each Wrap call together with the write it
// produces (see proxy.Server.appendToLogFile) under one lock. Locking
// only inside Wrap would still let two goroutines land their writes in
// a different order than they were chained in, corrupting the chain
// without any real tampering ever happening.
type Chain struct {
	key      []byte
	prevHash string
}

// NewChain starts (or resumes) a chain with key and the given prevHash
// — the hash of the last line already written, from RecoverPrevHash, or
// "" for a brand new chain (equivalent to Genesis).
func NewChain(key []byte, prevHash string) *Chain {
	if prevHash == "" {
		prevHash = Genesis
	}
	return &Chain{key: key, prevHash: prevHash}
}

// Wrap computes the next link for data — one already-marshaled JSON
// object — chained onto the chain's current position, advances the
// chain, and returns the resulting Envelope's own marshaled bytes.
func (c *Chain) Wrap(data []byte) ([]byte, error) {
	hash := c.hash(data)
	out, err := json.Marshal(Envelope{PrevHash: c.prevHash, Hash: hash, Event: json.RawMessage(data)})
	if err != nil {
		return nil, err
	}
	c.prevHash = hash
	return out, nil
}

func (c *Chain) hash(data []byte) string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(c.prevHash))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// ReadKeyFile reads and trims the HMAC key at path — the same file
// -audit-log-key-file points `aiproxy start` and `aiproxy verify-log`
// at. Trimming surrounding whitespace means a key created with a
// trailing newline (`echo "$(openssl rand -hex 32)" > key`, a text
// editor's own auto-newline) still reads back as the exact key bytes
// that were intended.
func ReadKeyFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("audit log key file: %w", err)
	}
	key := bytes.TrimSpace(data)
	if len(key) == 0 {
		return nil, fmt.Errorf("audit log key file: %s is empty", path)
	}
	return key, nil
}

// RecoverPrevHash returns the hash of the last chained line already in
// the file at path, so a process restart continues the same chain
// instead of silently starting a new one partway through an existing
// file. It returns Genesis when path doesn't exist yet, is empty, or
// its last line isn't a chained envelope at all — the latter meaning
// audit signing has just been turned on for the first time against a
// pre-existing plain log file: nothing written before that point was
// ever part of a chain, so the new chain honestly starts fresh right
// here, same as it would for a brand new file. A last line that *is*
// JSON but was clearly cut off mid-write (a crash between write calls)
// is reported as an error instead of silently discarded — an operator
// should look at that, not have it papered over.
func RecoverPrevHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Genesis, nil
		}
		return "", err
	}
	defer f.Close()

	line, err := lastLine(f)
	if err != nil {
		return "", fmt.Errorf("audit log: reading last line of %s: %w", path, err)
	}
	if len(line) == 0 {
		return Genesis, nil
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return "", fmt.Errorf("audit log: last line of %s is not valid JSON (possibly cut off mid-write): %w", path, err)
	}
	if env.Hash == "" {
		return Genesis, nil
	}
	return env.Hash, nil
}

// lastLine returns the last non-empty line of f, read backwards in
// bounded chunks so recovering chain state at startup costs a handful
// of small reads near the end of the file regardless of how large the
// log has grown, rather than loading the whole file into memory.
func lastLine(f *os.File) ([]byte, error) {
	const chunkSize = 64 * 1024

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	if size == 0 {
		return nil, nil
	}

	var tail []byte
	pos := size
	for {
		readSize := int64(chunkSize)
		if readSize > pos {
			readSize = pos
		}
		pos -= readSize
		buf := make([]byte, readSize)
		if _, err := f.ReadAt(buf, pos); err != nil {
			return nil, err
		}
		tail = append(buf, tail...)

		trimmed := bytes.TrimRight(tail, "\n")
		if idx := bytes.LastIndexByte(trimmed, '\n'); idx >= 0 {
			return trimmed[idx+1:], nil
		}
		if pos == 0 {
			return trimmed, nil
		}
	}
}

// Result summarizes one Verify pass.
type Result struct {
	// Lines is how many chained lines verified OK before Broken (or, if
	// the whole file verified, the file's total line count).
	Lines int

	// Broken, if non-zero, is the 1-indexed line number of the first
	// entry that failed to verify — every line at or after it is
	// unverified, since the chain is only as trustworthy as its first
	// broken link. Err explains what's wrong there.
	Broken int
	Err    error
}

// Verify reads r front-to-back as a stream of Envelope lines, checking
// that each one's prev_hash matches the line before it and that its
// hash is the correct HMAC (under key) of prev_hash plus its own event
// content — exactly what Chain.Wrap computed at write time. It stops at
// the first problem rather than trying to resynchronize, since past
// that point nothing more can be said about the file's integrity.
func Verify(r io.Reader, key []byte) (Result, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	prevHash := Genesis
	line := 0
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		line++

		var env Envelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return Result{Lines: line - 1, Broken: line, Err: fmt.Errorf("not a valid chained entry: %w", err)}, nil
		}
		if env.PrevHash != prevHash {
			return Result{Lines: line - 1, Broken: line, Err: fmt.Errorf(
				"prev_hash %q does not match the previous line's hash %q — a line was removed, inserted, reordered, or this is the wrong file or key",
				env.PrevHash, prevHash,
			)}, nil
		}

		c := &Chain{key: key, prevHash: env.PrevHash}
		want := c.hash(env.Event)
		if !hmac.Equal([]byte(want), []byte(env.Hash)) {
			return Result{Lines: line - 1, Broken: line, Err: fmt.Errorf(
				"hash does not match its content — this line was altered, or the wrong key was given",
			)}, nil
		}
		prevHash = env.Hash
	}
	if err := scanner.Err(); err != nil {
		return Result{}, fmt.Errorf("audit log: %w", err)
	}
	return Result{Lines: line}, nil
}
