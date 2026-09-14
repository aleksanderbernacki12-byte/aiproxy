package telemetry

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	eventOne = "550e8400-e29b-41d4-a716-446655440000"
	eventTwo = "550e8400-e29b-41d4-a716-446655440001"
)

type httpCall struct {
	body    []byte
	header  http.Header
	method  string
	url     string
	context context.Context
}

type fakeHTTP struct {
	mu sync.Mutex

	calls      []httpCall
	failFor    int
	panicFor   int
	statusCode int
	block      <-chan struct{}
	entered    chan struct{}
	once       sync.Once
}

func (f *fakeHTTP) Do(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.calls = append(f.calls, httpCall{
		body:    append([]byte(nil), body...),
		header:  request.Header.Clone(),
		method:  request.Method,
		url:     request.URL.String(),
		context: request.Context(),
	})
	callNumber := len(f.calls)
	fail := callNumber <= f.failFor
	panicNow := callNumber <= f.panicFor
	status := f.statusCode
	block := f.block
	entered := f.entered
	f.mu.Unlock()
	if entered != nil {
		f.once.Do(func() { close(entered) })
	}
	if block != nil {
		select {
		case <-block:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
	}
	if panicNow {
		panic("synthetic HTTP client panic")
	}
	if fail {
		return nil, errors.New("synthetic control-plane outage")
	}
	if status == 0 {
		status = http.StatusAccepted
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("accepted")),
		Header:     make(http.Header),
	}, nil
}

func (f *fakeHTTP) snapshot() []httpCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := make([]httpCall, len(f.calls))
	copy(result, f.calls)
	return result
}

func writePrivateKey(t *testing.T, dir string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "telemetry-key.pem")
	if err := os.WriteFile(filename, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return key, filename
}

func testConfig(dir, keyPath string, transport HTTPDoer) Config {
	return Config{
		Endpoint:         "https://control.example/api/telemetry",
		DatabasePath:     filepath.Join(dir, "telemetry.sqlite"),
		PrivateKeyPath:   keyPath,
		HTTPClient:       transport,
		Headers:          http.Header{"Authorization": {"Bearer instance-token"}},
		QueueSize:        32,
		BatchSize:        2,
		FlushInterval:    5 * time.Millisecond,
		OperationTimeout: 250 * time.Millisecond,
		InitialBackoff:   20 * time.Millisecond,
		MaxBackoff:       80 * time.Millisecond,
	}
}

func testSubmission(eventID string, timestamp time.Time) Submission {
	return Submission{
		EventID:       eventID,
		Timestamp:     timestamp,
		ClientIDHash:  strings.Repeat("a", 64),
		ApplicationID: "legal-assistant",
		Routing: map[string]any{
			"provider": "customer-azure",
			"model":    "gpt-enterprise",
		},
		ComplianceFlags: map[string]bool{"pii_detected": true, "pii_redacted": true, "policy_passed": true},
		Metrics: map[string]any{
			"latency_ms":   42,
			"input_tokens": 12,
		},
		Request:  []byte(`{"prompt":"Alice@example.com"}`),
		Response: []byte(`{"answer":"private customer response"}`),
	}
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before timeout")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func shutdown(t *testing.T, client *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func decodeBatch(t *testing.T, body []byte) []Payload {
	t.Helper()
	var payloads []Payload
	if err := json.Unmarshal(body, &payloads); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	return payloads
}

func TestSubmitAsync_ExactSignedPayloadAndOrderedHashChain(t *testing.T) {
	dir := t.TempDir()
	privateKey, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{}
	cfg := testConfig(dir, keyPath, transport)
	cfg.FlushInterval = time.Hour
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Date(2026, time.September, 13, 12, 0, 0, 123, time.FixedZone("CEST", 2*60*60))
	first := testSubmission(eventOne, timestamp)
	second := testSubmission(eventTwo, timestamp.Add(time.Second))
	firstHash := HashExchange(first.Request, first.Response)
	secondHash := HashExchange(second.Request, second.Response)
	if !client.SubmitAsync(first) || !client.SubmitAsync(second) {
		t.Fatal("valid submissions were rejected")
	}
	eventually(t, func() bool { return len(transport.snapshot()) == 1 })
	shutdown(t, client)

	calls := transport.snapshot()
	if calls[0].method != http.MethodPost || calls[0].url != cfg.Endpoint {
		t.Fatalf("request = %s %s", calls[0].method, calls[0].url)
	}
	if calls[0].header.Get("Content-Type") != "application/json" || calls[0].header.Get("X-Aiproxy-Batch-Size") != "2" {
		t.Fatalf("unexpected headers: %#v", calls[0].header)
	}
	if calls[0].header.Get("Authorization") != "Bearer instance-token" {
		t.Fatal("configured control-plane authorization was not sent")
	}
	if bytes.Contains(calls[0].body, []byte("Alice@example.com")) || bytes.Contains(calls[0].body, []byte("private customer response")) {
		t.Fatal("control-plane payload contains raw request or response data")
	}

	var rawBatch []map[string]json.RawMessage
	if err := json.Unmarshal(calls[0].body, &rawBatch); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"application_id", "client_id_hash", "compliance_flags", "cryptography", "event_id", "metrics", "routing", "timestamp"}
	for _, raw := range rawBatch {
		var gotKeys []string
		for key := range raw {
			gotKeys = append(gotKeys, key)
		}
		slicesSort(gotKeys)
		if !reflect.DeepEqual(gotKeys, wantKeys) {
			t.Fatalf("top-level keys = %v, want %v", gotKeys, wantKeys)
		}
	}

	payloads := decodeBatch(t, calls[0].body)
	if len(payloads) != 2 {
		t.Fatalf("batch size = %d, want 2", len(payloads))
	}
	if !payloads[0].ComplianceFlags["pii_detected"] || !payloads[0].ComplianceFlags["pii_redacted"] {
		t.Fatalf("PII compliance flags = %#v, want detected and redacted", payloads[0].ComplianceFlags)
	}
	if payloads[0].Cryptography.RequestResponseHash != firstHash || payloads[1].Cryptography.RequestResponseHash != secondHash {
		t.Fatal("request/response commitment mismatch")
	}
	if payloads[0].Cryptography.PreviousEventHash != "" {
		t.Fatalf("genesis previous hash = %q, want empty", payloads[0].Cryptography.PreviousEventHash)
	}
	if payloads[1].Cryptography.PreviousEventHash != payloads[0].Cryptography.EventHash {
		t.Fatal("second event does not link to first event hash")
	}
	for _, payload := range payloads {
		if payload.Cryptography.HashAlgorithm != HashAlgorithm || payload.Cryptography.SignatureAlgorithm != SignatureAlgorithm {
			t.Fatalf("unexpected algorithms: %#v", payload.Cryptography)
		}
		if err := Verify(payload, &privateKey.PublicKey); err != nil {
			t.Fatalf("verify %s: %v", payload.EventID, err)
		}
	}
	if !payloads[0].Timestamp.Equal(timestamp) || payloads[0].Timestamp.Location() != time.UTC {
		t.Fatalf("timestamp = %s, want UTC equivalent of %s", payloads[0].Timestamp, timestamp)
	}

	tampered := payloads[1]
	tampered.ApplicationID = "attacker-modified"
	if err := Verify(tampered, &privateKey.PublicKey); err == nil {
		t.Fatal("tampered payload passed signature verification")
	}

	databaseBytes, err := os.ReadFile(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(databaseBytes, []byte("Alice@example.com")) || bytes.Contains(databaseBytes, []byte("private customer response")) {
		t.Fatal("SQLite queue contains raw request or response data")
	}
	info, err := os.Stat(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("SQLite permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSender_FailureRetriesIdenticalFIFOEventBatch(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{failFor: 1}
	cfg := testConfig(dir, keyPath, transport)
	cfg.BatchSize = 3
	cfg.FlushInterval = 100 * time.Millisecond
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for index, eventID := range []string{eventOne, eventTwo, "550e8400-e29b-41d4-a716-446655440002"} {
		if !client.SubmitAsync(testSubmission(eventID, time.Now().Add(time.Duration(index)*time.Millisecond))) {
			t.Fatalf("submission %d rejected", index)
		}
	}
	eventually(t, func() bool { return len(transport.snapshot()) >= 2 })
	shutdown(t, client)

	calls := transport.snapshot()
	if !bytes.Equal(calls[0].body, calls[1].body) {
		t.Fatal("retry changed the signed event batch")
	}
	payloads := decodeBatch(t, calls[1].body)
	if len(payloads) != 3 {
		t.Fatalf("retry batch size = %d, want 3", len(payloads))
	}
	for index := 1; index < len(payloads); index++ {
		if payloads[index].Cryptography.PreviousEventHash != payloads[index-1].Cryptography.EventHash {
			t.Fatalf("event %d broke FIFO hash chain", index)
		}
	}
}

func TestSender_HTTPClientPanicIsRetriedWithoutCrashingProcess(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{panicFor: 1}
	cfg := testConfig(dir, keyPath, transport)
	cfg.BatchSize = 1
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !client.SubmitAsync(testSubmission(eventOne, time.Now())) {
		t.Fatal("submission rejected")
	}
	eventually(t, func() bool { return len(transport.snapshot()) >= 2 })
	shutdown(t, client)
	if !bytes.Equal(transport.snapshot()[0].body, transport.snapshot()[1].body) {
		t.Fatal("panic retry changed signed event")
	}
}

func TestClient_SQLiteQueueAndChainHeadSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	privateKey, keyPath := writePrivateKey(t, dir)
	failedTransport := &fakeHTTP{failFor: 100}
	cfg := testConfig(dir, keyPath, failedTransport)
	cfg.BatchSize = 1
	firstClient, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !firstClient.SubmitAsync(testSubmission(eventOne, time.Now())) {
		t.Fatal("first submission rejected")
	}
	eventually(t, func() bool { return len(failedTransport.snapshot()) >= 1 })
	shutdown(t, firstClient)
	firstPayload := decodeBatch(t, failedTransport.snapshot()[0].body)[0]

	recoveredTransport := &fakeHTTP{}
	cfg.HTTPClient = recoveredTransport
	secondClient, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return len(recoveredTransport.snapshot()) >= 1 })
	if !secondClient.SubmitAsync(testSubmission(eventTwo, time.Now().Add(time.Second))) {
		t.Fatal("second submission rejected")
	}
	eventually(t, func() bool { return len(recoveredTransport.snapshot()) >= 2 })
	shutdown(t, secondClient)

	recoveredFirst := decodeBatch(t, recoveredTransport.snapshot()[0].body)[0]
	secondPayload := decodeBatch(t, recoveredTransport.snapshot()[1].body)[0]
	if recoveredFirst.EventID != eventOne || !reflect.DeepEqual(recoveredFirst, firstPayload) {
		t.Fatal("restart did not resend the exact persisted signed event")
	}
	if secondPayload.Cryptography.PreviousEventHash != firstPayload.Cryptography.EventHash {
		t.Fatal("restart lost the persisted hash-chain head")
	}
	if err := Verify(secondPayload, &privateKey.PublicKey); err != nil {
		t.Fatalf("verify post-restart event: %v", err)
	}
}

func TestSequencer_ConcurrentSubmissionsProduceOneLinearChain(t *testing.T) {
	dir := t.TempDir()
	privateKey, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{}
	cfg := testConfig(dir, keyPath, transport)
	const eventCount = 50
	cfg.QueueSize = eventCount
	cfg.BatchSize = eventCount
	cfg.FlushInterval = time.Hour
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var accepted atomic.Int32
	var workers sync.WaitGroup
	for index := 0; index < eventCount; index++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			<-start
			eventID := "550e8400-e29b-41d4-a716-" + uuidTail(index)
			if client.SubmitAsync(testSubmission(eventID, time.Now())) {
				accepted.Add(1)
			}
		}(index)
	}
	close(start)
	workers.Wait()
	if accepted.Load() != eventCount {
		t.Fatalf("accepted = %d, want %d", accepted.Load(), eventCount)
	}
	eventually(t, func() bool { return len(transport.snapshot()) == 1 })
	shutdown(t, client)

	payloads := decodeBatch(t, transport.snapshot()[0].body)
	if len(payloads) != eventCount {
		t.Fatalf("batch size = %d, want %d", len(payloads), eventCount)
	}
	seenHashes := make(map[string]struct{}, eventCount)
	for index, payload := range payloads {
		if err := Verify(payload, &privateKey.PublicKey); err != nil {
			t.Fatalf("verify event %d: %v", index, err)
		}
		if _, duplicate := seenHashes[payload.Cryptography.EventHash]; duplicate {
			t.Fatalf("duplicate event hash at position %d", index)
		}
		seenHashes[payload.Cryptography.EventHash] = struct{}{}
		if index == 0 {
			if payload.Cryptography.PreviousEventHash != "" {
				t.Fatal("first concurrent event is not the chain genesis")
			}
			continue
		}
		if payload.Cryptography.PreviousEventHash != payloads[index-1].Cryptography.EventHash {
			t.Fatalf("chain fork or gap at position %d", index)
		}
	}
}

func TestSubmitAsync_NeverWaitsForBlockedControlPlane(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	blocked := make(chan struct{})
	transport := &fakeHTTP{block: blocked, entered: make(chan struct{})}
	cfg := testConfig(dir, keyPath, transport)
	cfg.BatchSize = 1
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !client.SubmitAsync(testSubmission(eventOne, time.Now())) {
		t.Fatal("first submission rejected")
	}
	select {
	case <-transport.entered:
	case <-time.After(time.Second):
		t.Fatal("sender never reached control plane")
	}
	started := time.Now()
	if !client.SubmitAsync(testSubmission(eventTwo, time.Now())) {
		t.Fatal("second submission rejected while sender was blocked")
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("SubmitAsync waited %s for the control plane", elapsed)
	}
	close(blocked)
	shutdown(t, client)
}

func TestSubmitAsync_FullQueueReturnsImmediately(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	cfg := testConfig(dir, keyPath, &fakeHTTP{})
	cfg.QueueSize = 1
	cfg.OperationTimeout = time.Second
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	transaction, err := client.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if !client.SubmitAsync(testSubmission(eventOne, time.Now())) {
		t.Fatal("first submission rejected")
	}
	eventually(t, func() bool { return len(client.jobs) == 0 })
	if !client.SubmitAsync(testSubmission(eventTwo, time.Now())) {
		t.Fatal("second submission should fill the queue")
	}
	third := testSubmission("550e8400-e29b-41d4-a716-446655440002", time.Now())
	started := time.Now()
	if client.SubmitAsync(third) {
		t.Fatal("full queue accepted a third submission")
	}
	if elapsed := time.Since(started); elapsed > 50*time.Millisecond {
		t.Fatalf("full queue blocked SubmitAsync for %s", elapsed)
	}
	if err := transaction.Rollback(); err != nil {
		t.Fatal(err)
	}
	shutdown(t, client)
}

func TestShutdown_DrainsAcceptedEventsToSQLiteDuringOutage(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{failFor: 100}
	cfg := testConfig(dir, keyPath, transport)
	cfg.BatchSize = 100
	cfg.FlushInterval = time.Hour
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	const eventCount = 20
	for index := 0; index < eventCount; index++ {
		eventID := "550e8400-e29b-41d4-a716-" + uuidTail(index)
		if !client.SubmitAsync(testSubmission(eventID, time.Now())) {
			t.Fatalf("submission %d rejected", index)
		}
	}
	shutdown(t, client)

	db, err := openStore(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM telemetry_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != eventCount {
		t.Fatalf("durable events = %d, want %d", count, eventCount)
	}
}

func TestClient_RejectsInvalidInputsDuplicateAndClosedState(t *testing.T) {
	dir := t.TempDir()
	_, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{}
	cfg := testConfig(dir, keyPath, transport)
	cfg.BatchSize = 1
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	invalidUUID := testSubmission("../not-a-uuid", time.Now())
	if client.SubmitAsync(invalidUUID) {
		t.Fatal("invalid UUID accepted")
	}
	invalidHash := testSubmission(eventOne, time.Now())
	invalidHash.ClientIDHash = "raw-customer-id"
	if client.SubmitAsync(invalidHash) {
		t.Fatal("raw client ID accepted as hash")
	}
	valid := testSubmission(eventOne, time.Now())
	if !client.SubmitAsync(valid) {
		t.Fatal("valid submission rejected")
	}
	eventually(t, func() bool { return len(transport.snapshot()) == 1 })
	duplicate := testSubmission(eventOne, time.Now())
	if !client.SubmitAsync(duplicate) {
		t.Fatal("duplicate should be asynchronously checked against durable history")
	}
	eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		count, err := client.pendingCount(ctx)
		return err == nil && count == 0
	})
	shutdown(t, client)
	if client.SubmitAsync(testSubmission(eventTwo, time.Now())) {
		t.Fatal("closed client accepted work")
	}
}

func uuidTail(value int) string {
	const digits = "0123456789abcdef"
	result := []byte("000000000000")
	for index := len(result) - 1; value > 0; index-- {
		result[index] = digits[value&15]
		value >>= 4
	}
	return string(result)
}

func slicesSort(values []string) {
	for index := 1; index < len(values); index++ {
		for cursor := index; cursor > 0 && values[cursor] < values[cursor-1]; cursor-- {
			values[cursor], values[cursor-1] = values[cursor-1], values[cursor]
		}
	}
}
