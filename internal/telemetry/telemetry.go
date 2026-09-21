package telemetry

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"aiproxy/internal/anonymizer"
)

const (
	defaultQueueSize        = 1024
	defaultBatchSize        = 100
	defaultFlushInterval    = time.Second
	defaultOperationTimeout = 10 * time.Second
	defaultInitialBackoff   = time.Second
	defaultMaxBackoff       = 5 * time.Minute
)

var (
	ErrClosed            = errors.New("telemetry: client is closed")
	ErrQueueFull         = errors.New("telemetry: queue is full")
	ErrInvalidEventID    = errors.New("telemetry: event_id must be a UUID")
	ErrInvalidClientHash = errors.New("telemetry: client_id_hash must be a SHA-256 hex digest")
	ErrClientIDRequired  = errors.New("telemetry: client_id is required")
	ErrDuplicateEvent    = errors.New("telemetry: event_id has already been recorded")
	ErrTenantKeyRequired = errors.New("telemetry: AIPROXY_TENANT_KEY is required")
)

const tenantKeyEnvironment = "AIPROXY_TENANT_KEY"

// HTTPDoer is implemented by *http.Client and allows deterministic transport
// tests without running a server.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config controls the local durable queue and the control-plane sender.
type Config struct {
	Endpoint     string
	DatabasePath string
	// MaxDatabaseBytes defaults to 256 MiB; excludes SQLite journal overhead.
	MaxDatabaseBytes int64
	PrivateKeyPath   string
	// SaltPath defaults to .aiproxy_salt beside DatabasePath.
	SaltPath string
	// HTTP clients are copied with redirects disabled. Other HTTPDoer
	// implementations must return redirects without following them.
	HTTPClient HTTPDoer
	Headers    http.Header

	QueueSize        int
	BatchSize        int
	FlushInterval    time.Duration
	OperationTimeout time.Duration
	InitialBackoff   time.Duration
	MaxBackoff       time.Duration

	// OnError is isolated on its own goroutine. Errors may be dropped when the
	// reporting channel is saturated so observability cannot apply backpressure
	// to LLM calls.
	OnError func(error)
}

// Client sequences, signs, persists, and delivers telemetry. All chain writes
// happen on one goroutine; HTTP delivery happens on another.
type Client struct {
	endpoint   string
	httpClient HTTPDoer
	headers    http.Header
	db         *sql.DB
	privateKey *ecdsa.PrivateKey
	keyID      string
	anonymizer *anonymizer.Anonymizer

	batchSize        int
	flushInterval    time.Duration
	operationTimeout time.Duration
	initialBackoff   time.Duration
	maxBackoff       time.Duration

	jobs                chan Submission
	wake                chan struct{}
	errors              chan error
	stop                chan struct{}
	sequenced           chan struct{}
	coreDone            chan struct{}
	errorDone           chan struct{}
	done                chan struct{}
	closed              atomic.Bool
	accepted            atomic.Uint64
	dropped             atomic.Uint64
	persistFailures     atomic.Uint64
	deliveryFailures    atomic.Uint64
	deliveredEvents     atomic.Uint64
	durablePending      atomic.Int64
	storageFullFailures atomic.Uint64
	databaseBytes       atomic.Int64
	databaseUsedBytes   atomic.Int64
	databaseLimitBytes  atomic.Int64
	storageMu           sync.Mutex
	lastDeliveredUnix   atomic.Int64
	lastFailureUnix     atomic.Int64
	submit              sync.RWMutex

	onError func(error)
	now     func() time.Time
}

// New loads the ECDSA P-256 private key, opens the SQLite queue, and starts the
// sequencer and sender. Network delivery runs only on the background sender.
func New(cfg Config) (*Client, error) {
	tenantKey := strings.TrimSpace(os.Getenv(tenantKeyEnvironment))
	if tenantKey == "" {
		return nil, ErrTenantKeyRequired
	}
	endpoint, err := validateEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	privateKey, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	identifier, err := keyID(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("telemetry: fingerprint public key: %w", err)
	}
	db, err := openStore(cfg.DatabasePath, cfg.MaxDatabaseBytes)
	if err != nil {
		return nil, err
	}
	onError := cfg.OnError
	if onError == nil {
		onError = func(err error) { log.Printf("aiproxy: %v", err) }
	}
	saltPath := strings.TrimSpace(cfg.SaltPath)
	if saltPath == "" {
		databasePath, pathErr := filepath.Abs(cfg.DatabasePath)
		if pathErr != nil {
			_ = db.Close()
			return nil, fmt.Errorf("telemetry: resolve anonymizer salt path: %w", pathErr)
		}
		saltPath = filepath.Join(filepath.Dir(databasePath), ".aiproxy_salt")
	}
	clientAnonymizer, err := anonymizer.New(anonymizer.Config{
		Path: saltPath,
		OnError: func(err error) {
			onError(fmt.Errorf("telemetry: client anonymizer: %w", err))
		},
	})
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("telemetry: initialize client anonymizer: %w", err)
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = defaultBatchSize
	}
	flushInterval := cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = defaultFlushInterval
	}
	operationTimeout := cfg.OperationTimeout
	if operationTimeout <= 0 {
		operationTimeout = defaultOperationTimeout
	}
	initialBackoff := cfg.InitialBackoff
	if initialBackoff <= 0 {
		initialBackoff = defaultInitialBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = defaultMaxBackoff
	}
	if maxBackoff < initialBackoff {
		clientAnonymizer.Close()
		_ = db.Close()
		return nil, errors.New("telemetry: maximum backoff must be at least the initial backoff")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	if client, ok := httpClient.(*http.Client); ok {
		copy := *client
		copy.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		httpClient = &copy
	}

	headers := cfg.Headers.Clone()
	headers.Set("Authorization", "Bearer "+tenantKey)
	c := &Client{
		endpoint:         endpoint,
		httpClient:       httpClient,
		headers:          headers,
		db:               db,
		privateKey:       privateKey,
		keyID:            identifier,
		anonymizer:       clientAnonymizer,
		batchSize:        batchSize,
		flushInterval:    flushInterval,
		operationTimeout: operationTimeout,
		initialBackoff:   initialBackoff,
		maxBackoff:       maxBackoff,
		jobs:             make(chan Submission, queueSize),
		wake:             make(chan struct{}, 1),
		errors:           make(chan error, queueSize),
		stop:             make(chan struct{}),
		sequenced:        make(chan struct{}),
		coreDone:         make(chan struct{}),
		errorDone:        make(chan struct{}),
		done:             make(chan struct{}),
		onError:          onError,
		now:              time.Now,
	}
	if pending, countErr := c.pendingCount(context.Background()); countErr == nil {
		c.durablePending.Store(int64(pending))
	} else {
		clientAnonymizer.Close()
		_ = db.Close()
		return nil, fmt.Errorf("telemetry: count initial pending events: %w", countErr)
	}
	c.refreshStorage()
	go c.sequenceLoop()
	go c.sendLoop()
	go c.errorLoop()
	go func() {
		<-c.coreDone
		<-c.errorDone
		c.anonymizer.Close()
		_ = c.db.Close()
		if c.privateKey != nil && c.privateKey.D != nil {
			c.privateKey.D.SetInt64(0)
		}
		c.privateKey = nil
		close(c.done)
	}()
	c.signalSender()
	return c, nil
}

// SubmitAsync anonymizes ClientID and accepts an event without waiting for
// signing, SQLite, or the network. On success ownership of Request, Response,
// Routing, Metrics, and ComplianceFlags transfers to Client; callers must not
// mutate them afterward.
func (c *Client) SubmitAsync(submission Submission) bool {
	if c == nil {
		return false
	}
	if !c.submit.TryRLock() {
		c.dropped.Add(1)
		c.report(ErrClosed)
		return false
	}
	defer c.submit.RUnlock()
	if c.closed.Load() {
		c.dropped.Add(1)
		c.report(ErrClosed)
		return false
	}
	if !validUUID(submission.EventID) {
		c.dropped.Add(1)
		c.report(ErrInvalidEventID)
		return false
	}
	clientID := submission.ClientID
	if clientID == "" {
		c.dropped.Add(1)
		clientID = submission.ClientIDHash
	}
	if clientID == "" {
		c.report(ErrClientIDRequired)
		return false
	}
	clientIDHash, err := c.anonymizer.Hash(clientID)
	if err != nil {
		c.dropped.Add(1)
		c.report(fmt.Errorf("telemetry: anonymize client_id: %w", err))
		return false
	}
	submission.ClientID = ""
	submission.ClientIDHash = ""
	submission.clientIDHash = clientIDHash
	if strings.TrimSpace(submission.ApplicationID) == "" {
		c.dropped.Add(1)
		c.report(errors.New("telemetry: application_id is required"))
		return false
	}
	if submission.Timestamp.IsZero() {
		submission.Timestamp = c.now().UTC()
	}
	select {
	case c.jobs <- submission:
		c.accepted.Add(1)
		return true
	default:
		c.dropped.Add(1)
		c.report(ErrQueueFull)
		return false
	}
}

// Shutdown attempts to persist all accepted submissions and stops the sender.
// Storage failures are reported asynchronously; successfully persisted events
// remain durable for the next New call using the same path.
func (c *Client) Shutdown(ctx context.Context) error {
	if c == nil {
		return nil
	}
	c.submit.Lock()
	if c.closed.CompareAndSwap(false, true) {
		close(c.stop)
	}
	c.submit.Unlock()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) sequenceLoop() {
	defer close(c.sequenced)
	for {
		select {
		case submission := <-c.jobs:
			c.persistSubmission(submission)
		case <-c.stop:
			for {
				select {
				case submission := <-c.jobs:
					c.persistSubmission(submission)
				default:
					return
				}
			}
		}
	}
}

func (c *Client) persistSubmission(submission Submission) {
	defer c.refreshStorage()
	defer zero(submission.Request)
	defer zero(submission.Response)
	defer func() {
		if recovered := recover(); recovered != nil {
			c.report(fmt.Errorf("telemetry: sequencer panic for %s: %v", submission.EventID, recovered))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), c.operationTimeout)
	err := c.persist(ctx, submission)
	cancel()
	if err != nil {
		c.persistFailures.Add(1)
		if storageFull(err) {
			c.storageFullFailures.Add(1)
			c.dropped.Add(1)
		}
		c.lastFailureUnix.Store(c.now().UTC().Unix())
		c.report(fmt.Errorf("telemetry: persist %s: %w", submission.EventID, err))
		return
	}
	c.durablePending.Add(1)
	c.signalSender()
}

// Snapshot returns a non-blocking point-in-time view. Pending includes both
// accepted in-memory submissions and durable SQLite rows.
func (c *Client) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return Snapshot{
		Accepted: c.accepted.Load(), Dropped: c.dropped.Load(),
		PersistFailures: c.persistFailures.Load(), DeliveryFailures: c.deliveryFailures.Load(),
		DeliveredEvents: c.deliveredEvents.Load(), Pending: c.durablePending.Load() + int64(len(c.jobs)),
		StorageFullFailures: c.storageFullFailures.Load(), DatabaseBytes: c.databaseBytes.Load(),
		DatabaseUsedBytes: c.databaseUsedBytes.Load(), DatabaseLimitBytes: c.databaseLimitBytes.Load(),
		LastDeliveredAt: unixTime(c.lastDeliveredUnix.Load()), LastFailureAt: unixTime(c.lastFailureUnix.Load()),
	}
}

func unixTime(value int64) *time.Time {
	if value == 0 {
		return nil
	}
	result := time.Unix(value, 0).UTC()
	return &result
}

func (c *Client) signalSender() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *Client) backoff(attempt int) time.Duration {
	delay := c.initialBackoff
	for index := 1; index < attempt; index++ {
		if delay >= c.maxBackoff/2 {
			return c.maxBackoff
		}
		delay *= 2
	}
	if delay > c.maxBackoff {
		return c.maxBackoff
	}
	return delay
}

func (c *Client) report(err error) {
	if err == nil {
		return
	}
	select {
	case c.errors <- err:
	default:
	}
}

func (c *Client) errorLoop() {
	defer close(c.errorDone)
	for {
		select {
		case err := <-c.errors:
			c.callErrorHandler(err)
		case <-c.coreDone:
			for {
				select {
				case err := <-c.errors:
					c.callErrorHandler(err)
				default:
					return
				}
			}
		}
	}
}

func (c *Client) callErrorHandler(err error) {
	if c.onError == nil {
		return
	}
	defer func() { _ = recover() }()
	c.onError(err)
}

func validateEndpoint(value string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errors.New("telemetry: endpoint must be an absolute HTTP or HTTPS URL")
	}
	if parsed.User != nil || parsed.Fragment != "" {
		return "", errors.New("telemetry: endpoint must not contain user information or a fragment")
	}
	return parsed.String(), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256HexLength {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

const sha256HexLength = 64

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := range len(value) {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if value[index] != '-' {
				return false
			}
			continue
		}
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func zero(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func jsonMarshal(value any) ([]byte, error) {
	encoded, err := canonicalJSON(value)
	if err != nil {
		return nil, fmt.Errorf("telemetry: encode payload: %w", err)
	}
	return encoded, nil
}
