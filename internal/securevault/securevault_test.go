package securevault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	eventOne   = "550e8400-e29b-41d4-a716-446655440000"
	eventTwo   = "550e8400-e29b-41d4-a716-446655440001"
	eventThree = "550e8400-e29b-41d4-a716-446655440002"
)

type fakeKMS struct {
	mu sync.Mutex

	calls       int
	failFor     int
	panicFor    int
	block       <-chan struct{}
	entered     chan struct{}
	enteredOnce sync.Once
	inputs      []*kms.GenerateDataKeyInput
	returned    [][]byte
}

func (f *fakeKMS) GenerateDataKey(ctx context.Context, input *kms.GenerateDataKeyInput, _ ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error) {
	f.mu.Lock()
	f.calls++
	call := f.calls
	copyInput := *input
	copyInput.EncryptionContext = cloneStrings(input.EncryptionContext)
	f.inputs = append(f.inputs, &copyInput)
	block := f.block
	entered := f.entered
	panicNow := call <= f.panicFor
	failNow := call <= f.failFor
	f.mu.Unlock()

	if entered != nil {
		f.enteredOnce.Do(func() { close(entered) })
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if panicNow {
		panic("synthetic KMS panic")
	}
	if failNow {
		return nil, errors.New("synthetic KMS outage")
	}
	plaintext := bytes.Repeat([]byte{0x2a}, 32)
	f.mu.Lock()
	f.returned = append(f.returned, plaintext)
	f.mu.Unlock()
	return &kms.GenerateDataKeyOutput{
		Plaintext:      plaintext,
		CiphertextBlob: []byte("kms-encrypted-data-key"),
		KeyId:          aws.String("arn:aws:kms:eu-north-1:111122223333:key/customer-key"),
	}, nil
}

func (f *fakeKMS) snapshot() (calls int, inputs []*kms.GenerateDataKeyInput, returned [][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, append([]*kms.GenerateDataKeyInput(nil), f.inputs...), append([][]byte(nil), f.returned...)
}

type putCall struct {
	bucket      string
	key         string
	contentType string
	contentLen  int64
	lockMode    s3types.ObjectLockMode
	retainUntil time.Time
	metadata    map[string]string
	body        []byte
}

type fakeS3 struct {
	mu sync.Mutex

	calls    []putCall
	failFor  int
	panicFor int
}

func (f *fakeS3) PutObject(ctx context.Context, input *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	body, err := io.ReadAll(input.Body)
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	f.mu.Lock()
	callNumber := len(f.calls) + 1
	call := putCall{
		bucket:      aws.ToString(input.Bucket),
		key:         aws.ToString(input.Key),
		contentType: aws.ToString(input.ContentType),
		contentLen:  aws.ToInt64(input.ContentLength),
		lockMode:    input.ObjectLockMode,
		metadata:    cloneStrings(input.Metadata),
		body:        append([]byte(nil), body...),
	}
	if input.ObjectLockRetainUntilDate != nil {
		call.retainUntil = *input.ObjectLockRetainUntilDate
	}
	f.calls = append(f.calls, call)
	panicNow := callNumber <= f.panicFor
	failNow := callNumber <= f.failFor
	f.mu.Unlock()
	if panicNow {
		panic("synthetic S3 panic")
	}
	if failNow {
		return nil, errors.New("synthetic S3 outage")
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) snapshot() []putCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]putCall(nil), f.calls...)
}

func testConfig(dir string, kmsClient KMSClient, s3Client S3Client) Config {
	return Config{
		KMS:              kmsClient,
		S3:               s3Client,
		KMSKeyID:         "alias/customer-securevault",
		Bucket:           "customer-evidence",
		Prefix:           "raw",
		SpoolDir:         dir,
		SpoolKey:         bytes.Repeat([]byte{0x71}, 32),
		QueueSize:        8,
		Workers:          1,
		OperationTimeout: 200 * time.Millisecond,
		InitialBackoff:   20 * time.Millisecond,
		MaxBackoff:       100 * time.Millisecond,
		RetryInterval:    5 * time.Millisecond,
	}
}

func exchange(eventID string) (*http.Request, *http.Response) {
	request := httptest.NewRequest(http.MethodPost, "https://llm.example/v1/chat?tenant=local", strings.NewReader(`{"prompt":"unredacted Alice@example.com"}`))
	request.Header.Set("Authorization", "Bearer customer-upstream-secret")
	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Proto:      "HTTP/1.1",
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"answer":"unredacted response for Alice"}`)),
		Request:    request,
	}
	response.Header.Set("X-Provider-Request-ID", eventID)
	return request, response
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func shutdown(t *testing.T, vault *Vault) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := vault.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestStoreAsync_EnvelopeEncryptionAndFiveYearComplianceLock(t *testing.T) {
	kmsClient := &fakeKMS{}
	s3Client := &fakeS3{}
	vault, err := New(testConfig(t.TempDir(), kmsClient, s3Client))
	if err != nil {
		t.Fatal(err)
	}
	fixed := time.Date(2026, time.September, 13, 12, 0, 0, 0, time.UTC)
	vault.now = func() time.Time { return fixed }
	request, response := exchange(eventOne)
	if !vault.StoreAsync(eventOne, request, response) {
		t.Fatal("StoreAsync rejected valid work")
	}
	eventually(t, func() bool { return len(s3Client.snapshot()) == 1 })
	shutdown(t, vault)

	kmsCalls, kmsInputs, returnedKeys := kmsClient.snapshot()
	if kmsCalls != 1 {
		t.Fatalf("GenerateDataKey calls = %d, want 1", kmsCalls)
	}
	if aws.ToString(kmsInputs[0].KeyId) != "alias/customer-securevault" || kmsInputs[0].KeySpec != kmstypes.DataKeySpecAes256 {
		t.Fatalf("KMS input key/spec = %q/%q", aws.ToString(kmsInputs[0].KeyId), kmsInputs[0].KeySpec)
	}
	if kmsInputs[0].EncryptionContext["aiproxy:event_id"] != eventOne || kmsInputs[0].EncryptionContext["aiproxy:purpose"] != "securevault" {
		t.Fatalf("unexpected encryption context: %#v", kmsInputs[0].EncryptionContext)
	}
	if len(returnedKeys) != 1 || !allZero(returnedKeys[0]) {
		t.Fatal("plaintext DEK was not erased after encryption")
	}

	call := s3Client.snapshot()[0]
	if call.bucket != "customer-evidence" || call.key != "raw/"+eventOne {
		t.Fatalf("S3 destination = %s/%s", call.bucket, call.key)
	}
	if call.contentType != ContentType || call.contentLen != int64(len(call.body)) {
		t.Fatalf("content type/length = %q/%d", call.contentType, call.contentLen)
	}
	if call.lockMode != s3types.ObjectLockModeCompliance {
		t.Fatalf("ObjectLockMode = %q, want COMPLIANCE", call.lockMode)
	}
	if want := fixed.AddDate(5, 0, 0); !call.retainUntil.Equal(want) {
		t.Fatalf("retain until = %s, want %s", call.retainUntil, want)
	}
	if call.metadata["aiproxy-event-id"] != eventOne || call.metadata["aiproxy-envelope-version"] != "1" {
		t.Fatalf("unexpected S3 metadata: %#v", call.metadata)
	}

	var envelope Envelope
	if err := json.Unmarshal(call.body, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.EventID != eventOne || envelope.Algorithm != "AES-256-GCM" || envelope.KMSKeyID != "arn:aws:kms:eu-north-1:111122223333:key/customer-key" {
		t.Fatalf("unexpected envelope: %#v", envelope)
	}
	plain := openObject(t, bytes.Repeat([]byte{0x2a}, 32), envelope)
	if bytes.Contains(call.body, []byte("Alice@example.com")) || bytes.Contains(call.body, []byte("customer-upstream-secret")) {
		t.Fatal("S3 object exposes raw request data")
	}
	var record archiveRecord
	if err := json.Unmarshal(plain, &record); err != nil {
		t.Fatal(err)
	}
	if record.EventID != eventOne || string(record.Request.Body) != `{"prompt":"unredacted Alice@example.com"}` || string(record.Response.Body) != `{"answer":"unredacted response for Alice"}` {
		t.Fatalf("decrypted archive did not preserve the exchange: %#v", record)
	}
	if record.Request.Headers.Get("Authorization") != "Bearer customer-upstream-secret" {
		t.Fatal("decrypted archive did not preserve request headers")
	}
	restored, err := io.ReadAll(response.Body)
	if err != nil || string(restored) != `{"answer":"unredacted response for Alice"}` {
		t.Fatalf("response body was not restored: %q, %v", restored, err)
	}
}

func TestStoreAsync_NeverWaitsForKMSOrQueueCapacity(t *testing.T) {
	releaseKMS := make(chan struct{})
	kmsClient := &fakeKMS{block: releaseKMS, entered: make(chan struct{})}
	s3Client := &fakeS3{}
	cfg := testConfig(t.TempDir(), kmsClient, s3Client)
	cfg.QueueSize = 1
	vault, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	req1, resp1 := exchange(eventOne)
	if !vault.StoreAsync(eventOne, req1, resp1) {
		t.Fatal("first item rejected")
	}
	select {
	case <-kmsClient.entered:
	case <-time.After(time.Second):
		t.Fatal("worker never entered KMS")
	}
	req2, resp2 := exchange(eventTwo)
	if !vault.StoreAsync(eventTwo, req2, resp2) {
		t.Fatal("second item should fit the queue")
	}

	result := make(chan bool, 1)
	go func() {
		req3, resp3 := exchange(eventThree)
		result <- vault.StoreAsync(eventThree, req3, resp3)
	}()
	select {
	case accepted := <-result:
		if accepted {
			t.Fatal("full queue unexpectedly accepted a third item")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("StoreAsync blocked while KMS and the queue were unavailable")
	}
	close(releaseKMS)
	shutdown(t, vault)
}

func TestStoreAsync_KMSFailureUsesEncryptedSpoolAndRetries(t *testing.T) {
	kmsClient := &fakeKMS{failFor: 1}
	s3Client := &fakeS3{}
	cfg := testConfig(t.TempDir(), kmsClient, s3Client)
	cfg.InitialBackoff = 250 * time.Millisecond
	cfg.MaxBackoff = 250 * time.Millisecond
	vault, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request, response := exchange(eventOne)
	if !vault.StoreAsync(eventOne, request, response) {
		t.Fatal("StoreAsync rejected work")
	}
	retryPath := entryPath(cfg.SpoolDir, eventOne, retrySuffix)
	eventually(t, func() bool {
		_, err := os.Stat(retryPath)
		return err == nil
	})
	raw, err := os.ReadFile(retryPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("Alice@example.com")) || bytes.Contains(raw, []byte("customer-upstream-secret")) {
		t.Fatal("retry spool contains unencrypted raw data")
	}
	info, err := os.Stat(retryPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("spool permissions = %#o, want 0600", info.Mode().Perm())
	}
	entry, err := vault.readEntry(retryPath)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Attempts != 1 || entry.NextAttemptAt.Sub(entry.CreatedAt) < cfg.InitialBackoff {
		t.Fatalf("retry state = attempts %d, next %s, created %s", entry.Attempts, entry.NextAttemptAt, entry.CreatedAt)
	}
	eventually(t, func() bool { return len(s3Client.snapshot()) == 1 })
	eventually(t, func() bool {
		_, err := os.Stat(retryPath)
		return errors.Is(err, os.ErrNotExist)
	})
	shutdown(t, vault)
	if calls, _, _ := kmsClient.snapshot(); calls != 2 {
		t.Fatalf("KMS calls = %d, want initial failure plus one retry", calls)
	}
}

func TestStoreAsync_S3FailureAndWorkerPanicAreRetried(t *testing.T) {
	tests := []struct {
		name string
		kms  *fakeKMS
		s3   *fakeS3
	}{
		{"S3 error", &fakeKMS{}, &fakeS3{failFor: 1}},
		{"KMS panic", &fakeKMS{panicFor: 1}, &fakeS3{}},
		{"S3 panic", &fakeKMS{}, &fakeS3{panicFor: 1}},
	}
	for index, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t.TempDir(), tc.kms, tc.s3)
			vault, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			eventID := []string{eventOne, eventTwo, eventThree}[index]
			request, response := exchange(eventID)
			if !vault.StoreAsync(eventID, request, response) {
				t.Fatal("StoreAsync rejected work")
			}
			eventually(t, func() bool {
				calls := tc.s3.snapshot()
				if tc.s3.failFor > 0 || tc.s3.panicFor > 0 {
					return len(calls) >= 2
				}
				return len(calls) == 1
			})
			shutdown(t, vault)
			kmsCalls, _, _ := tc.kms.snapshot()
			if kmsCalls < 2 {
				t.Fatalf("KMS calls = %d, want a retried attempt", kmsCalls)
			}
		})
	}
}

func TestVault_RetrySpoolSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	failedKMS := &fakeKMS{failFor: 100}
	firstS3 := &fakeS3{}
	cfg := testConfig(dir, failedKMS, firstS3)
	cfg.InitialBackoff = 20 * time.Millisecond
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	request, response := exchange(eventOne)
	if !first.StoreAsync(eventOne, request, response) {
		t.Fatal("StoreAsync rejected work")
	}
	retryPath := entryPath(dir, eventOne, retrySuffix)
	eventually(t, func() bool {
		_, err := os.Stat(retryPath)
		return err == nil
	})
	shutdown(t, first)

	recoveredKMS := &fakeKMS{}
	recoveredS3 := &fakeS3{}
	cfg.KMS = recoveredKMS
	cfg.S3 = recoveredS3
	second, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return len(recoveredS3.snapshot()) == 1 })
	shutdown(t, second)
	if recoveredS3.snapshot()[0].key != "raw/"+eventOne {
		t.Fatalf("recovered object key = %q", recoveredS3.snapshot()[0].key)
	}
}

func TestStoreAsync_RejectsInvalidInputAndClosedVault(t *testing.T) {
	vault, err := New(testConfig(t.TempDir(), &fakeKMS{}, &fakeS3{}))
	if err != nil {
		t.Fatal(err)
	}
	request, response := exchange(eventOne)
	if vault.StoreAsync("../../not-a-uuid", request, response) {
		t.Fatal("invalid event ID was accepted")
	}
	if vault.StoreAsync(eventOne, nil, response) || vault.StoreAsync(eventOne, request, nil) {
		t.Fatal("nil exchange was accepted")
	}
	shutdown(t, vault)
	if vault.StoreAsync(eventOne, request, response) {
		t.Fatal("closed vault accepted work")
	}
}

func TestStoreAsync_RejectsDuplicateEventWhileFirstIsQueuedOrSpooled(t *testing.T) {
	releaseKMS := make(chan struct{})
	kmsClient := &fakeKMS{block: releaseKMS, entered: make(chan struct{})}
	vault, err := New(testConfig(t.TempDir(), kmsClient, &fakeS3{}))
	if err != nil {
		t.Fatal(err)
	}
	request, response := exchange(eventOne)
	if !vault.StoreAsync(eventOne, request, response) {
		t.Fatal("first event was rejected")
	}
	select {
	case <-kmsClient.entered:
	case <-time.After(time.Second):
		t.Fatal("worker never entered KMS")
	}
	duplicateRequest, duplicateResponse := exchange(eventOne)
	if vault.StoreAsync(eventOne, duplicateRequest, duplicateResponse) {
		t.Fatal("duplicate event ID was accepted")
	}
	close(releaseKMS)
	shutdown(t, vault)
}

func TestStoreAsync_ConcurrentShutdownNeverLosesAcceptedWork(t *testing.T) {
	kmsClient := &fakeKMS{}
	s3Client := &fakeS3{}
	cfg := testConfig(t.TempDir(), kmsClient, s3Client)
	cfg.QueueSize = 256
	cfg.Workers = 4
	vault, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 100
	start := make(chan struct{})
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			eventID := "550e8400-e29b-41d4-a716-" + formatUUIDTail(i)
			request, response := exchange(eventID)
			if vault.StoreAsync(eventID, request, response) {
				accepted.Add(1)
			}
		}(i)
	}
	close(start)
	shutdown(t, vault)
	wg.Wait()
	if got := int32(len(s3Client.snapshot())); got != accepted.Load() {
		t.Fatalf("uploaded = %d, accepted = %d", got, accepted.Load())
	}
}

func TestVault_BackoffDoublesAndCaps(t *testing.T) {
	vault := &Vault{initialBackoff: time.Second, maxBackoff: 5 * time.Second}
	wants := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i, want := range wants {
		if got := vault.backoff(i + 1); got != want {
			t.Fatalf("attempt %d backoff = %s, want %s", i+1, got, want)
		}
	}
}

func TestNew_RequiresCustomerOwnedEncryptionConfiguration(t *testing.T) {
	base := testConfig(t.TempDir(), &fakeKMS{}, &fakeS3{})
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"KMS client", func(c *Config) { c.KMS = nil }},
		{"S3 client", func(c *Config) { c.S3 = nil }},
		{"KMS key", func(c *Config) { c.KMSKeyID = "" }},
		{"bucket", func(c *Config) { c.Bucket = "" }},
		{"spool directory", func(c *Config) { c.SpoolDir = "" }},
		{"spool key", func(c *Config) { c.SpoolKey = []byte("too short") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if vault, err := New(cfg); err == nil {
				shutdown(t, vault)
				t.Fatal("New unexpectedly accepted invalid config")
			}
		})
	}
}

func openObject(t *testing.T, key []byte, envelope Envelope) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, ObjectAssociatedData(envelope.EventID))
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func cloneStrings(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}

func allZero(input []byte) bool {
	for _, value := range input {
		if value != 0 {
			return false
		}
	}
	return true
}

func formatUUIDTail(value int) string {
	const hex = "0123456789abcdef"
	result := []byte("000000000000")
	for index := len(result) - 1; value > 0; index-- {
		result[index] = hex[value&15]
		value >>= 4
	}
	return string(result)
}
