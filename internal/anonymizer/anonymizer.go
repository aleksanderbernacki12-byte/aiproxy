// Package anonymizer creates short-lived, instance-local pseudonyms for client
// identifiers. Its secret salt never leaves the data plane.
package anonymizer

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	defaultFilename      = ".aiproxy_salt"
	defaultRotationAge   = 30 * 24 * time.Hour
	defaultCheckInterval = 24 * time.Hour
	saltSize             = 32
	fileVersion          = 1
)

var (
	ErrClientIDRequired = errors.New("anonymizer: client ID is required")
	ErrClosed           = errors.New("anonymizer: closed")
)

// Config controls local salt persistence and rotation. The defaults use a
// .aiproxy_salt file in the current directory and rotate it every 30 days.
type Config struct {
	Path          string
	RotationAge   time.Duration
	CheckInterval time.Duration
	Now           func() time.Time
	Random        io.Reader
	OnRotation    func(createdAt time.Time)
	OnError       func(error)
}

// Anonymizer safely shares the active salt between request goroutines and the
// background rotation loop.
type Anonymizer struct {
	path          string
	rotationAge   time.Duration
	checkInterval time.Duration
	now           func() time.Time
	random        io.Reader
	onRotation    func(time.Time)
	onError       func(error)

	mu        sync.RWMutex
	rotateMu  sync.Mutex
	salt      []byte
	createdAt time.Time
	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
	closed    bool
}

type saltRecord struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Salt      string    `json:"salt"`
}

// New loads or creates the local salt, rotates an expired salt immediately,
// and starts the daily age check.
func New(cfg Config) (*Anonymizer, error) {
	path := cfg.Path
	if path == "" {
		path = defaultFilename
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("anonymizer: resolve salt path: %w", err)
	}
	rotationAge := cfg.RotationAge
	if rotationAge <= 0 {
		rotationAge = defaultRotationAge
	}
	checkInterval := cfg.CheckInterval
	if checkInterval <= 0 {
		checkInterval = defaultCheckInterval
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	onRotation := cfg.OnRotation
	if onRotation == nil {
		onRotation = func(createdAt time.Time) {
			log.Printf("aiproxy: anonymizer salt rotated at %s", createdAt.UTC().Format(time.RFC3339))
		}
	}
	onError := cfg.OnError
	if onError == nil {
		onError = func(err error) { log.Printf("aiproxy: %v", err) }
	}

	a := &Anonymizer{
		path:          abs,
		rotationAge:   rotationAge,
		checkInterval: checkInterval,
		now:           now,
		random:        random,
		onRotation:    onRotation,
		onError:       onError,
		stop:          make(chan struct{}),
		done:          make(chan struct{}),
	}
	salt, createdAt, exists, err := a.load()
	if err != nil {
		return nil, err
	}
	if exists {
		a.salt = salt
		a.createdAt = createdAt
	} else if err := a.replaceSalt(now().UTC(), false); err != nil {
		return nil, err
	}
	if err := a.RotateIfNeeded(); err != nil {
		return nil, err
	}
	go a.rotationLoop()
	return a, nil
}

// Hash returns a lowercase HMAC-SHA256 pseudonym using the current local salt.
func (a *Anonymizer) Hash(clientID string) (string, error) {
	if clientID == "" {
		return "", ErrClientIDRequired
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return "", ErrClosed
	}
	mac := hmac.New(sha256.New, a.salt)
	_, _ = mac.Write([]byte(clientID))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// RotateIfNeeded replaces the salt once it reaches its configured maximum age.
func (a *Anonymizer) RotateIfNeeded() error {
	a.rotateMu.Lock()
	defer a.rotateMu.Unlock()
	a.mu.RLock()
	createdAt := a.createdAt
	closed := a.closed
	a.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if a.now().UTC().Sub(createdAt) < a.rotationAge {
		return nil
	}
	return a.replaceSalt(a.now().UTC(), true)
}

// Close stops the background checker. Hash calls already in progress finish.
func (a *Anonymizer) Close() {
	if a == nil {
		return
	}
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		close(a.stop)
		<-a.done
		a.mu.Lock()
		zero(a.salt)
		a.salt = nil
		a.mu.Unlock()
	})
}

func (a *Anonymizer) rotationLoop() {
	defer close(a.done)
	ticker := time.NewTicker(a.checkInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := a.RotateIfNeeded(); err != nil && !errors.Is(err, ErrClosed) {
				a.report(err)
			}
		case <-a.stop:
			return
		}
	}
}

func (a *Anonymizer) replaceSalt(createdAt time.Time, rotated bool) error {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(a.random, salt); err != nil {
		return fmt.Errorf("anonymizer: generate salt: %w", err)
	}
	if err := a.persist(salt, createdAt); err != nil {
		zero(salt)
		return err
	}
	a.mu.Lock()
	oldSalt := a.salt
	a.salt = salt
	a.createdAt = createdAt
	a.mu.Unlock()
	zero(oldSalt)
	if rotated {
		a.notifyRotation(createdAt)
	}
	return nil
}

func (a *Anonymizer) load() ([]byte, time.Time, bool, error) {
	info, err := os.Lstat(a.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, time.Time{}, false, nil
	}
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("anonymizer: inspect salt file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, time.Time{}, false, errors.New("anonymizer: salt path must be a regular file, not a symlink")
	}
	if info.Size() > 4096 {
		return nil, time.Time{}, false, errors.New("anonymizer: salt file is unexpectedly large")
	}
	contents, err := os.ReadFile(a.path)
	if err != nil {
		return nil, time.Time{}, false, fmt.Errorf("anonymizer: read salt file: %w", err)
	}
	var record saltRecord
	if err := json.Unmarshal(contents, &record); err != nil {
		return nil, time.Time{}, false, fmt.Errorf("anonymizer: decode salt file: %w", err)
	}
	if record.Version != fileVersion || record.CreatedAt.IsZero() {
		return nil, time.Time{}, false, errors.New("anonymizer: invalid salt file metadata")
	}
	if record.CreatedAt.After(a.now().UTC()) {
		return nil, time.Time{}, false, errors.New("anonymizer: salt timestamp is in the future")
	}
	salt, err := base64.StdEncoding.DecodeString(record.Salt)
	if err != nil || len(salt) != saltSize {
		return nil, time.Time{}, false, errors.New("anonymizer: invalid salt value")
	}
	if err := os.Chmod(a.path, 0o600); err != nil {
		zero(salt)
		return nil, time.Time{}, false, fmt.Errorf("anonymizer: secure salt file: %w", err)
	}
	return salt, record.CreatedAt.UTC(), true, nil
}

func (a *Anonymizer) persist(salt []byte, createdAt time.Time) error {
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("anonymizer: create salt directory: %w", err)
	}
	record := saltRecord{
		Version:   fileVersion,
		CreatedAt: createdAt.UTC(),
		Salt:      base64.StdEncoding.EncodeToString(salt),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("anonymizer: encode salt: %w", err)
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(dir, ".aiproxy_salt-*")
	if err != nil {
		return fmt.Errorf("anonymizer: create temporary salt file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("anonymizer: secure temporary salt file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		cleanup()
		return fmt.Errorf("anonymizer: write salt file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("anonymizer: sync salt file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("anonymizer: close salt file: %w", err)
	}
	if err := os.Rename(temporaryPath, a.path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("anonymizer: replace salt file: %w", err)
	}
	if err := os.Chmod(a.path, 0o600); err != nil {
		return fmt.Errorf("anonymizer: secure salt file: %w", err)
	}
	return nil
}

func (a *Anonymizer) notifyRotation(createdAt time.Time) {
	defer func() { _ = recover() }()
	a.onRotation(createdAt)
}

func (a *Anonymizer) report(err error) {
	defer func() { _ = recover() }()
	a.onError(err)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
