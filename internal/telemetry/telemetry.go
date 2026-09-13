package telemetry

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	ErrDuplicateEvent    = errors.New("telemetry: event_id has already been recorded")
)

// HTTPDoer is implemented by *http.Client and allows deterministic transport
// tests without running a server.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Config controls the local durable queue and the control-plane sender.
type Config struct {
	Endpoint       string
	DatabasePath   string
	PrivateKeyPath string
	HTTPClient     HTTPDoer
	Headers        http.Header

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

	batchSize        int
	flushInterval    time.Duration
	operationTimeout time.Duration
	initialBackoff   time.Duration
	maxBackoff       time.Duration

	jobs      chan Submission
	wake      chan struct{}
	errors    chan error
	stop      chan struct{}
	sequenced chan struct{}
	coreDone  chan struct{}
	errorDone chan struct{}
	done      chan struct{}
	closed    atomic.Bool
	submit    sync.RWMutex

	onError func(error)
	now     func() time.Time
}

// New loads the ECDSA P-256 private key, opens the SQLite queue, and starts the
// sequencer and sender. Network delivery runs only on the background sender.
func New(cfg Config) (*Client, error) {
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
	db, err := openStore(cfg.DatabasePath)
	if err != nil {
		return nil, err
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
		_ = db.Close()
		return nil, errors.New("telemetry: maximum backoff must be at least the initial backoff")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	c := &Client{
		endpoint:         endpoint,
		httpClient:       httpClient,
		headers:          cfg.Headers.Clone(),
		db:               db,
		privateKey:       privateKey,
		keyID:            identifier,
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
		onError:          cfg.OnError,
		now:              time.Now,
	}
	go c.sequenceLoop()
	go c.sendLoop()
	go c.errorLoop()
	go func() {
		<-c.coreDone
		<-c.errorDone
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

// SubmitAsync accepts an event without waiting for hashing, signing, SQLite, or
// the network. On success ownership of Request, Response, Routing, Metrics, and
// ComplianceFlags transfers to Client; callers must not mutate them afterward.
func (c *Client) SubmitAsync(submission Submission) bool {
	if c == nil {
		return false
	}
	if !c.submit.TryRLock() {
		c.report(ErrClosed)
		return false
	}
	defer c.submit.RUnlock()
	if c.closed.Load() {
		c.report(ErrClosed)
		return false
	}
	if !validUUID(submission.EventID) {
		c.report(ErrInvalidEventID)
		return false
	}
	if !validSHA256(submission.ClientIDHash) {
		c.report(ErrInvalidClientHash)
		return false
	}
	if strings.TrimSpace(submission.ApplicationID) == "" {
		c.report(errors.New("telemetry: application_id is required"))
		return false
	}
	if submission.Timestamp.IsZero() {
		submission.Timestamp = c.now().UTC()
	}
	select {
	case c.jobs <- submission:
		return true
	default:
		c.report(ErrQueueFull)
		return false
	}
}

// Shutdown drains accepted submissions into SQLite and stops the sender. Any
// undelivered events remain durable for the next New call using the same path.
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
		c.report(fmt.Errorf("telemetry: persist %s: %w", submission.EventID, err))
		return
	}
	c.signalSender()
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
