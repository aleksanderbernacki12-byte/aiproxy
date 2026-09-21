package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStorageBudgetPreservesChainAndRecoversAfterDelivery(t *testing.T) {
	dir := t.TempDir()
	key, keyPath := writePrivateKey(t, dir)
	transport := &fakeHTTP{statusCode: http.StatusServiceUnavailable}
	cfg := testConfig(t, dir, keyPath, transport)
	cfg.MaxDatabaseBytes = MinMaxDatabaseBytes
	cfg.BatchSize = 1000
	cfg.FlushInterval = time.Hour
	cfg.OnError = func(error) {}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shutdown(t, client) })
	var stored int64
	var rejectedID, head string
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("550e8400-e29b-41d4-a716-%012d", i)
		submission := testSubmission(id, time.Now())
		submission.Metrics["padding"] = strings.Repeat("x", 64<<10)
		if !client.SubmitAsync(submission) {
			t.Fatal("in-memory admission failed")
		}
		eventually(t, func() bool { return client.Snapshot().Pending == stored+1 || client.Snapshot().StorageFullFailures > 0 })
		// Pending can include the in-memory item; wait for durable sequencing.
		eventually(t, func() bool {
			return client.durablePending.Load() == stored+1 || client.Snapshot().StorageFullFailures > 0
		})
		if client.Snapshot().StorageFullFailures > 0 {
			rejectedID = id
			break
		}
		stored++
		if err := client.db.QueryRow(`SELECT previous_event_hash FROM telemetry_state`).Scan(&head); err != nil {
			t.Fatal(err)
		}
	}
	if rejectedID == "" || stored == 0 {
		t.Fatal("database did not fill with retained events")
	}
	eventually(t, func() bool { return client.Snapshot().Dropped == 1 && client.Snapshot().DatabaseUsedBytes > 0 })
	var after string
	if err := client.db.QueryRow(`SELECT previous_event_hash FROM telemetry_state`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != head {
		t.Fatal("failed insert advanced the chain")
	}
	var rejectedCount int
	if err := client.db.QueryRow(`SELECT COUNT(*) FROM telemetry_event_ids WHERE event_id = ?`, rejectedID).Scan(&rejectedCount); err != nil {
		t.Fatal(err)
	}
	if rejectedCount != 0 {
		t.Fatal("failed event reserved a deduplication ID")
	}
	info, err := os.Stat(cfg.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > cfg.MaxDatabaseBytes {
		t.Fatalf("database exceeded budget: %d", info.Size())
	}
	shutdown(t, client)
	client, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if client.Snapshot().Pending != stored || client.Snapshot().DatabaseLimitBytes != cfg.MaxDatabaseBytes {
		t.Fatalf("restart lost queue or budget: %+v", client.Snapshot())
	}
	// Force a replacement connection: the budget must survive pool recycling.
	client.db.SetMaxIdleConns(0)
	var pageSize, maxPages int64
	if err := client.db.QueryRow(`SELECT page_size, max_page_count FROM pragma_page_size(), pragma_max_page_count()`).Scan(&pageSize, &maxPages); err != nil {
		t.Fatal(err)
	}
	client.db.SetMaxIdleConns(1)
	if pageSize*maxPages != cfg.MaxDatabaseBytes {
		t.Fatal("replacement connection lost budget")
	}
	transport.mu.Lock()
	transport.statusCode = http.StatusAccepted
	transport.mu.Unlock()
	eventually(t, func() bool { client.flush(true, false); return client.Snapshot().Pending == 0 })
	// Reuse the rejected ID: it must link to the last accepted event, even
	// though that predecessor was delivered and its payload removed.
	if !client.SubmitAsync(testSubmission(rejectedID, time.Now())) {
		t.Fatal("submission rejected after recovery")
	}
	eventually(t, func() bool { return client.durablePending.Load() == 1 })
	events, err := client.loadBatch(context.Background())
	if err != nil || len(events) != 1 {
		t.Fatalf("recovered batch: %v (%d events)", err, len(events))
	}
	var payload Payload
	if err := json.Unmarshal(events[0].payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Cryptography.PreviousEventHash != head {
		t.Fatal("recovered event does not link to durable chain")
	}
	if err := Verify(payload, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestStorageBudgetValidationAndExistingDatabase(t *testing.T) {
	for _, budget := range []int64{-1, 1, MinMaxDatabaseBytes - 1} {
		if _, err := openStore(filepath.Join(t.TempDir(), "queue.sqlite"), budget); err == nil {
			t.Fatalf("accepted invalid budget %d", budget)
		}
	}
	filename := filepath.Join(t.TempDir(), "queue.sqlite")
	db, err := openStore(filename, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE padding (data BLOB); INSERT INTO padding VALUES (zeroblob(2097152))`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if smaller, err := openStore(filename, MinMaxDatabaseBytes); err == nil {
		smaller.Close()
		t.Fatal("silently accepted an existing database above budget")
	}
	db, err = openStore(filename, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var size int
	if err := db.QueryRow(`SELECT length(data) FROM padding`).Scan(&size); err != nil || size != 2097152 {
		t.Fatalf("existing data changed after rejected budget: size=%d err=%v", size, err)
	}
}
