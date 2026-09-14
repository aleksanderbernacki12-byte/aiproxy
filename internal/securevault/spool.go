package securevault

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	workSuffix    = ".work"
	retrySuffix   = ".retry"
	corruptSuffix = ".corrupt"
)

type spoolEntry struct {
	Version       int       `json:"version"`
	EventID       string    `json:"event_id"`
	Payload       []byte    `json:"payload"`
	CreatedAt     time.Time `json:"created_at"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
}

type spoolEnvelope struct {
	Version    int    `json:"version"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func prepareSpoolDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("securevault: create spool directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("securevault: inspect spool directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("securevault: spool path must be a real directory, not a symlink")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("securevault: secure spool directory permissions: %w", err)
	}
	return nil
}

func (v *Vault) writeEntry(entry spoolEntry, suffix string) (string, error) {
	target := entryPath(v.spoolDir, entry.EventID, suffix)
	if _, err := os.Lstat(target); err == nil {
		return "", fmt.Errorf("spool entry already exists: %s", entry.EventID)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	if err := v.writeEntryFile(target, entry); err != nil {
		return "", err
	}
	return target, nil
}

func (v *Vault) rewriteEntry(target string, entry spoolEntry) error {
	return v.writeEntryFile(target, entry)
}

func (v *Vault) writeEntryFile(target string, entry spoolEntry) error {
	plain, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	nonce, ciphertext, err := encryptAESGCM(v.spoolKey, plain, spoolAAD(entry.EventID), v.random)
	zero(plain)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(spoolEnvelope{Version: 1, Nonce: nonce, Ciphertext: ciphertext})
	if err != nil {
		return err
	}
	return atomicWriteFile(target, encoded)
}

func (v *Vault) readEntry(filename string) (spoolEntry, error) {
	var entry spoolEntry
	eventID, ok := eventIDFromPath(filename)
	if !ok {
		return entry, errors.New("invalid spool filename")
	}
	encoded, err := os.ReadFile(filename)
	if err != nil {
		return entry, err
	}
	var envelope spoolEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return entry, err
	}
	if envelope.Version != 1 {
		return entry, fmt.Errorf("unsupported spool version %d", envelope.Version)
	}
	block, err := aes.NewCipher(v.spoolKey)
	if err != nil {
		return entry, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return entry, err
	}
	plain, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, spoolAAD(eventID))
	if err != nil {
		return entry, err
	}
	defer zero(plain)
	if err := json.Unmarshal(plain, &entry); err != nil {
		return entry, err
	}
	if entry.Version != 1 || entry.EventID != eventID {
		return spoolEntry{}, errors.New("spool identity mismatch")
	}
	return entry, nil
}

func (v *Vault) recoverInterrupted() error {
	entries, err := os.ReadDir(v.spoolDir)
	if err != nil {
		return fmt.Errorf("securevault: inspect retry spool: %w", err)
	}
	for _, item := range entries {
		if item.IsDir() || !strings.HasSuffix(item.Name(), workSuffix) {
			continue
		}
		from := filepath.Join(v.spoolDir, item.Name())
		to := strings.TrimSuffix(from, workSuffix) + retrySuffix
		if _, err := os.Lstat(to); err == nil {
			return fmt.Errorf("securevault: both interrupted and retry entries exist for %s", item.Name())
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if err := renameAndSync(from, to); err != nil {
			return fmt.Errorf("securevault: recover interrupted entry %s: %w", item.Name(), err)
		}
	}
	return nil
}

func (v *Vault) indexExistingEntries() error {
	entries, err := os.ReadDir(v.spoolDir)
	if err != nil {
		return fmt.Errorf("securevault: index retry spool: %w", err)
	}
	for _, item := range entries {
		if item.IsDir() {
			continue
		}
		eventID, ok := eventIDFromPath(item.Name())
		if !ok {
			continue
		}
		if _, loaded := v.active.LoadOrStore(eventID, struct{}{}); loaded {
			return fmt.Errorf("securevault: duplicate spool entries exist for event_id %s", eventID)
		}
	}
	return nil
}

func countSpoolEntries(dir string) (pending, quarantined int64, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, 0, fmt.Errorf("securevault: count retry spool: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		switch {
		case strings.HasSuffix(entry.Name(), workSuffix), strings.HasSuffix(entry.Name(), retrySuffix):
			pending++
		case strings.HasSuffix(entry.Name(), corruptSuffix):
			quarantined++
		}
	}
	return pending, quarantined, nil
}

func (v *Vault) retryLoop() {
	defer v.workers.Done()
	ticker := time.NewTicker(v.retryInterval)
	defer ticker.Stop()
	v.retryDue()
	for {
		select {
		case <-ticker.C:
			v.retryDue()
		case <-v.stop:
			return
		}
	}
}

func (v *Vault) retryDue() {
	items, err := os.ReadDir(v.spoolDir)
	if err != nil {
		v.report(fmt.Errorf("securevault: scan retry spool: %w", err))
		return
	}
	for _, item := range items {
		if item.IsDir() || !strings.HasSuffix(item.Name(), retrySuffix) {
			continue
		}
		retryPath := filepath.Join(v.spoolDir, item.Name())
		entry, err := v.readEntry(retryPath)
		if err != nil {
			v.quarantine(retryPath, err)
			continue
		}
		if entry.NextAttemptAt.After(v.now()) {
			zero(entry.Payload)
			continue
		}
		workPath := entryPath(v.spoolDir, entry.EventID, workSuffix)
		if err := renameAndSync(retryPath, workPath); err != nil {
			v.report(fmt.Errorf("securevault: claim retry %s: %w", entry.EventID, err))
			zero(entry.Payload)
			continue
		}
		v.processEntry(workPath, entry)
		zero(entry.Payload)
	}
}

func (v *Vault) quarantine(filename string, cause error) {
	target := strings.TrimSuffix(filename, retrySuffix) + corruptSuffix
	if err := renameAndSync(filename, target); err != nil {
		v.report(fmt.Errorf("securevault: unreadable spool entry %s (%v), quarantine failed: %w", filepath.Base(filename), cause, err))
		return
	}
	v.spoolPending.Add(-1)
	v.quarantined.Add(1)
	v.localFailures.Add(1)
	v.lastFailureUnix.Store(v.now().UTC().Unix())
	v.report(fmt.Errorf("securevault: quarantined unreadable spool entry %s: %w", filepath.Base(filename), cause))
}

func spoolAAD(eventID string) []byte {
	return []byte("aiproxy-securevault-spool-v1\x00" + eventID)
}

func entryPath(dir, eventID, suffix string) string {
	return filepath.Join(dir, eventID+suffix)
}

func eventIDFromPath(filename string) (string, bool) {
	base := filepath.Base(filename)
	for _, suffix := range []string{workSuffix, retrySuffix, corruptSuffix} {
		if strings.HasSuffix(base, suffix) {
			id := strings.TrimSuffix(base, suffix)
			return id, validUUID(id)
		}
	}
	return "", false
}

func atomicWriteFile(target string, data []byte) (err error) {
	dir := filepath.Dir(target)
	tmp, err := os.CreateTemp(dir, ".securevault-tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}
	return syncDir(dir)
}

func renameAndSync(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return syncDir(filepath.Dir(to))
}

func removeAndSync(filename string) error {
	if err := os.Remove(filename); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return syncDir(filepath.Dir(filename))
}

func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		// Windows does not expose portable directory fsync semantics through
		// os.File. The file itself is still synced before every rename.
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
