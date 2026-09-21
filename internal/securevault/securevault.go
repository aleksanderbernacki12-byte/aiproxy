package securevault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	defaultQueueSize        = 256
	defaultWorkers          = 2
	defaultOperationTimeout = 30 * time.Second
	defaultInitialBackoff   = time.Second
	defaultMaxBackoff       = time.Hour
	defaultRetryInterval    = time.Second
	retentionYears          = 5

	ContentType = "application/vnd.aiproxy.securevault+json"
)

var (
	ErrClosed         = errors.New("securevault: vault is closed")
	ErrQueueFull      = errors.New("securevault: queue is full")
	ErrInvalidEventID = errors.New("securevault: event_id must be a UUID")
	ErrDuplicateEvent = errors.New("securevault: event_id is already queued or spooled")
)

// KMSClient is the subset of the AWS KMS client used by Vault. A
// *kms.Client satisfies this interface.
type KMSClient interface {
	GenerateDataKey(context.Context, *kms.GenerateDataKeyInput, ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

// S3Client is the subset of the AWS S3 client used by Vault. A *s3.Client
// satisfies this interface.
type S3Client interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

// Config configures a Vault. KMS, S3, KMSKeyID, Bucket, SpoolDir, and a
// 32-byte SpoolKey are required.
//
// SpoolKey encrypts work that must survive a KMS outage. It must be generated
// and retained by the customer (for example through the customer's secret
// manager), remain stable across restarts, and never be sent to the control
// plane. Vault copies the key during construction.
type Config struct {
	KMS      KMSClient
	S3       S3Client
	KMSKeyID string
	Bucket   string
	Prefix   string
	SpoolDir string
	SpoolKey []byte

	QueueSize        int
	Workers          int
	OperationTimeout time.Duration
	InitialBackoff   time.Duration
	MaxBackoff       time.Duration
	RetryInterval    time.Duration

	// OnError runs on a dedicated background goroutine. Error reporting can
	// therefore never delay StoreAsync. Errors may be dropped if the internal
	// reporting queue is saturated.
	OnError func(error)
}

type job struct {
	eventID  string
	request  *http.Request
	response *http.Response
}

// Vault owns the bounded in-memory queue, encrypted retry spool, and AWS
// workers. Construct one with New and stop it with Shutdown.
type Vault struct {
	kms      KMSClient
	s3       S3Client
	kmsKeyID string
	bucket   string
	prefix   string
	spoolDir string
	spoolKey []byte

	operationTimeout time.Duration
	initialBackoff   time.Duration
	maxBackoff       time.Duration
	retryInterval    time.Duration

	jobs             chan job
	errors           chan error
	stop             chan struct{}
	done             chan struct{}
	closed           atomic.Bool
	accepted         atomic.Uint64
	dropped          atomic.Uint64
	spoolPending     atomic.Int64
	quarantined      atomic.Int64
	localFailures    atomic.Uint64
	uploadFailures   atomic.Uint64
	uploaded         atomic.Uint64
	lastUploadedUnix atomic.Int64
	lastFailureUnix  atomic.Int64
	submit           sync.RWMutex
	active           sync.Map

	onError func(error)
	now     func() time.Time
	random  io.Reader

	workers sync.WaitGroup
}

// New validates config, secures the spool directory, recovers interrupted
// spool work, and starts the background workers. It performs no AWS calls.
func New(cfg Config) (*Vault, error) {
	if cfg.KMS == nil {
		return nil, errors.New("securevault: KMS client is required")
	}
	if cfg.S3 == nil {
		return nil, errors.New("securevault: S3 client is required")
	}
	if strings.TrimSpace(cfg.KMSKeyID) == "" {
		return nil, errors.New("securevault: KMS key ID is required")
	}
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("securevault: S3 bucket is required")
	}
	if strings.TrimSpace(cfg.SpoolDir) == "" {
		return nil, errors.New("securevault: spool directory is required")
	}
	if len(cfg.SpoolKey) != 32 {
		return nil, errors.New("securevault: spool key must be exactly 32 bytes")
	}

	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	workerCount := cfg.Workers
	if workerCount <= 0 {
		workerCount = defaultWorkers
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
		return nil, errors.New("securevault: maximum backoff must be at least the initial backoff")
	}
	retryInterval := cfg.RetryInterval
	if retryInterval <= 0 {
		retryInterval = defaultRetryInterval
	}

	if err := prepareSpoolDir(cfg.SpoolDir); err != nil {
		return nil, err
	}

	v := &Vault{
		kms:              cfg.KMS,
		s3:               cfg.S3,
		kmsKeyID:         cfg.KMSKeyID,
		bucket:           cfg.Bucket,
		prefix:           strings.Trim(cfg.Prefix, "/"),
		spoolDir:         cfg.SpoolDir,
		spoolKey:         append([]byte(nil), cfg.SpoolKey...),
		operationTimeout: operationTimeout,
		initialBackoff:   initialBackoff,
		maxBackoff:       maxBackoff,
		retryInterval:    retryInterval,
		jobs:             make(chan job, queueSize),
		errors:           make(chan error, queueSize),
		stop:             make(chan struct{}),
		done:             make(chan struct{}),
		onError:          cfg.OnError,
		now:              time.Now,
		random:           rand.Reader,
	}
	if err := v.recoverInterrupted(); err != nil {
		zero(v.spoolKey)
		return nil, err
	}
	if err := v.indexExistingEntries(); err != nil {
		zero(v.spoolKey)
		return nil, err
	}
	pending, quarantined, err := countSpoolEntries(v.spoolDir)
	if err != nil {
		zero(v.spoolKey)
		return nil, err
	}
	v.spoolPending.Store(pending)
	v.quarantined.Store(quarantined)

	v.workers.Add(workerCount + 2)
	for i := 0; i < workerCount; i++ {
		go v.worker()
	}
	go v.retryLoop()
	go v.errorLoop()
	go func() {
		v.workers.Wait()
		zero(v.spoolKey)
		close(v.done)
	}()
	return v, nil
}

// StoreAsync queues an unredacted request/response pair for encrypted archive.
// It never waits for KMS, S3, the disk spool, or queue capacity. It returns
// false when eventID is invalid, either message is nil, the queue is full, or
// the Vault is shutting down. A false result means the record was not accepted.
//
// Once accepted, ownership of request.Body and response.Body transfers to the
// Vault. Callers must submit only after normal response delivery is complete and
// must not concurrently read or close either body. This keeps raw-body capture
// entirely outside routing's critical path.
func (v *Vault) StoreAsync(eventID string, request *http.Request, response *http.Response) bool {
	if v == nil {
		return false
	}
	// TryRLock preserves the method's non-blocking contract even when Shutdown
	// is concurrently taking exclusive ownership of submission state.
	if !v.submit.TryRLock() {
		v.dropped.Add(1)
		v.report(ErrClosed)
		return false
	}
	defer v.submit.RUnlock()
	if v.closed.Load() {
		v.dropped.Add(1)
		v.report(ErrClosed)
		return false
	}
	if !validUUID(eventID) {
		v.dropped.Add(1)
		v.report(ErrInvalidEventID)
		return false
	}
	if request == nil || response == nil {
		v.dropped.Add(1)
		v.report(errors.New("securevault: request and response are required"))
		return false
	}
	eventID = strings.ToLower(eventID)
	if _, loaded := v.active.LoadOrStore(eventID, struct{}{}); loaded {
		v.dropped.Add(1)
		v.report(ErrDuplicateEvent)
		return false
	}
	select {
	case v.jobs <- job{eventID: eventID, request: request, response: response}:
		v.accepted.Add(1)
		return true
	default:
		v.dropped.Add(1)
		v.active.Delete(eventID)
		v.report(ErrQueueFull)
		return false
	}
}

// Shutdown stops accepting work, drains already accepted in-memory jobs to the
// encrypted spool, and stops retrying. It does not wait indefinitely for AWS;
// every individual operation is bounded by OperationTimeout. If ctx expires,
// Shutdown returns its error while the background shutdown continues.
func (v *Vault) Shutdown(ctx context.Context) error {
	if v == nil {
		return nil
	}
	v.submit.Lock()
	if v.closed.CompareAndSwap(false, true) {
		close(v.stop)
	}
	v.submit.Unlock()
	select {
	case <-v.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (v *Vault) worker() {
	defer v.workers.Done()
	for {
		select {
		case work := <-v.jobs:
			v.handleLiveSafely(work)
		case <-v.stop:
			for {
				select {
				case work := <-v.jobs:
					v.handleLiveSafely(work)
				default:
					return
				}
			}
		}
	}
}

func (v *Vault) handleLiveSafely(work job) {
	defer func() {
		if recovered := recover(); recovered != nil {
			v.localFailures.Add(1)
			v.lastFailureUnix.Store(v.now().UTC().Unix())
			v.report(fmt.Errorf("securevault: capture worker panic for %s: %v", work.eventID, recovered))
			v.active.Delete(work.eventID)
		}
	}()
	v.handleLive(work)
}

func (v *Vault) handleLive(work job) {
	payload, err := capture(work.eventID, work.request, work.response, v.now())
	if err != nil {
		v.localFailures.Add(1)
		v.lastFailureUnix.Store(v.now().UTC().Unix())
		v.report(fmt.Errorf("securevault: capture %s: %w", work.eventID, err))
		v.active.Delete(work.eventID)
		return
	}
	defer zero(payload)
	entry := spoolEntry{Version: 1, EventID: work.eventID, Payload: payload, CreatedAt: v.now().UTC()}
	workPath, err := v.writeEntry(entry, workSuffix)
	if err != nil {
		v.localFailures.Add(1)
		v.lastFailureUnix.Store(v.now().UTC().Unix())
		v.report(fmt.Errorf("securevault: spool %s: %w", work.eventID, err))
		v.active.Delete(work.eventID)
		return
	}
	v.spoolPending.Add(1)
	v.processEntry(workPath, entry)
}

func (v *Vault) processEntry(workPath string, entry spoolEntry) {
	err := v.uploadSafely(entry)
	if err == nil {
		if removeErr := removeAndSync(workPath); removeErr != nil {
			v.localFailures.Add(1)
			v.lastFailureUnix.Store(v.now().UTC().Unix())
			v.report(fmt.Errorf("securevault: remove completed spool entry %s: %w", entry.EventID, removeErr))
			return
		}
		v.active.Delete(entry.EventID)
		v.spoolPending.Add(-1)
		v.uploaded.Add(1)
		v.lastUploadedUnix.Store(v.now().UTC().Unix())
		return
	}
	v.uploadFailures.Add(1)
	v.lastFailureUnix.Store(v.now().UTC().Unix())
	v.report(fmt.Errorf("securevault: archive %s: %w", entry.EventID, err))
	entry.Attempts++
	entry.NextAttemptAt = v.now().UTC().Add(v.backoff(entry.Attempts))
	if writeErr := v.rewriteEntry(workPath, entry); writeErr != nil {
		v.localFailures.Add(1)
		v.lastFailureUnix.Store(v.now().UTC().Unix())
		v.report(fmt.Errorf("securevault: update retry state %s: %w", entry.EventID, writeErr))
		return
	}
	retryPath := entryPath(v.spoolDir, entry.EventID, retrySuffix)
	if renameErr := renameAndSync(workPath, retryPath); renameErr != nil {
		v.localFailures.Add(1)
		v.lastFailureUnix.Store(v.now().UTC().Unix())
		v.report(fmt.Errorf("securevault: schedule retry %s: %w", entry.EventID, renameErr))
	}
}

func (v *Vault) uploadSafely(entry spoolEntry) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("background worker panic: %v", recovered)
		}
	}()
	return v.upload(entry)
}

func (v *Vault) upload(entry spoolEntry) error {
	encryptionContext := map[string]string{
		"aiproxy:event_id": entry.EventID,
		"aiproxy:purpose":  "securevault",
	}
	keyOutput, err := func() (*kms.GenerateDataKeyOutput, error) {
		kmsCtx, cancelKMS := context.WithTimeout(context.Background(), v.operationTimeout)
		defer cancelKMS()
		return v.kms.GenerateDataKey(kmsCtx, &kms.GenerateDataKeyInput{
			KeyId:             aws.String(v.kmsKeyID),
			KeySpec:           kmstypes.DataKeySpecAes256,
			EncryptionContext: encryptionContext,
		})
	}()
	if err != nil {
		return fmt.Errorf("generate data key: %w", err)
	}
	if keyOutput == nil || len(keyOutput.Plaintext) != 32 || len(keyOutput.CiphertextBlob) == 0 {
		if keyOutput != nil {
			zero(keyOutput.Plaintext)
		}
		return errors.New("generate data key: KMS returned an invalid AES-256 data key")
	}
	plaintextKey := keyOutput.Plaintext
	defer zero(plaintextKey)

	nonce, ciphertext, err := encryptAESGCM(plaintextKey, entry.Payload, ObjectAssociatedData(entry.EventID), v.random)
	if err != nil {
		return fmt.Errorf("encrypt record: %w", err)
	}
	resolvedKMSKeyID := v.kmsKeyID
	if keyOutput.KeyId != nil && strings.TrimSpace(*keyOutput.KeyId) != "" {
		resolvedKMSKeyID = *keyOutput.KeyId
	}
	envelope := Envelope{
		Version:           1,
		EventID:           entry.EventID,
		Algorithm:         "AES-256-GCM",
		KMSKeyID:          resolvedKMSKeyID,
		EncryptionContext: encryptionContext,
		EncryptedDataKey:  append([]byte(nil), keyOutput.CiphertextBlob...),
		Nonce:             nonce,
		Ciphertext:        ciphertext,
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("encode encrypted record: %w", err)
	}

	retainUntil := v.now().UTC().AddDate(retentionYears, 0, 0)
	_, err = func() (*s3.PutObjectOutput, error) {
		s3Ctx, cancelS3 := context.WithTimeout(context.Background(), v.operationTimeout)
		defer cancelS3()
		return v.s3.PutObject(s3Ctx, &s3.PutObjectInput{
			Bucket:                    aws.String(v.bucket),
			Key:                       aws.String(v.objectKey(entry.EventID)),
			Body:                      bytes.NewReader(encoded),
			ContentLength:             aws.Int64(int64(len(encoded))),
			ContentType:               aws.String(ContentType),
			ObjectLockMode:            s3types.ObjectLockModeCompliance,
			ObjectLockRetainUntilDate: aws.Time(retainUntil),
			Metadata: map[string]string{
				"aiproxy-event-id":         entry.EventID,
				"aiproxy-envelope-version": "1",
			},
		})
	}()
	if err != nil {
		return fmt.Errorf("put S3 object: %w", err)
	}
	return nil
}

// Envelope is the self-contained encrypted object written to S3. A customer
// decrypts EncryptedDataKey with the configured KMS key and exact
// EncryptionContext, then opens Ciphertext with AES-256-GCM using Nonce and
// ObjectAssociatedData(event_id) as associated data.
type Envelope struct {
	Version           int               `json:"version"`
	EventID           string            `json:"event_id"`
	Algorithm         string            `json:"algorithm"`
	KMSKeyID          string            `json:"kms_key_id"`
	EncryptionContext map[string]string `json:"encryption_context"`
	EncryptedDataKey  []byte            `json:"encrypted_data_key"`
	Nonce             []byte            `json:"nonce"`
	Ciphertext        []byte            `json:"ciphertext"`
}

func (v *Vault) objectKey(eventID string) string {
	if v.prefix == "" {
		return eventID
	}
	return path.Join(v.prefix, eventID)
}

func (v *Vault) backoff(attempt int) time.Duration {
	delay := v.initialBackoff
	for i := 1; i < attempt; i++ {
		if delay >= v.maxBackoff/2 {
			return v.maxBackoff
		}
		delay *= 2
	}
	if delay > v.maxBackoff {
		return v.maxBackoff
	}
	return delay
}

func (v *Vault) report(err error) {
	if err == nil {
		return
	}
	select {
	case v.errors <- err:
	default:
	}
}

func (v *Vault) errorLoop() {
	defer v.workers.Done()
	for {
		select {
		case err := <-v.errors:
			v.callErrorHandler(err)
		case <-v.stop:
			for {
				select {
				case err := <-v.errors:
					v.callErrorHandler(err)
				default:
					return
				}
			}
		}
	}
}

func (v *Vault) callErrorHandler(err error) {
	if v.onError == nil {
		return
	}
	defer func() { _ = recover() }()
	v.onError(err)
}

func encryptAESGCM(key, plaintext, aad []byte, random io.Reader) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return nil, nil, err
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// ObjectAssociatedData returns the additional authenticated data bound to an
// S3 object's AES-GCM tag. Decryption must use this exact byte sequence.
func ObjectAssociatedData(eventID string) []byte {
	return []byte("aiproxy-securevault-object-v1\x00" + eventID)
}

func zero(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if value[i] != '-' {
				return false
			}
			continue
		}
		c := value[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
