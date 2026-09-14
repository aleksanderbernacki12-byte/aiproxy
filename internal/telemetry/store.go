package telemetry

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS telemetry_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    previous_event_hash TEXT NOT NULL
);
INSERT OR IGNORE INTO telemetry_state(singleton, previous_event_hash) VALUES (1, '');
CREATE TABLE IF NOT EXISTS telemetry_event_ids (
    event_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    payload BLOB NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(event_id) REFERENCES telemetry_event_ids(event_id)
);
`

func openStore(filename string) (*sql.DB, error) {
	if strings.TrimSpace(filename) == "" {
		return nil, errors.New("telemetry: SQLite database path is required")
	}
	abs, err := filepath.Abs(filename)
	if err != nil {
		return nil, fmt.Errorf("telemetry: resolve SQLite path: %w", err)
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("telemetry: create SQLite directory: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("telemetry: SQLite path must be a regular file, not a symlink")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("telemetry: inspect SQLite database: %w", err)
	}

	db, err := sql.Open("sqlite", abs)
	if err != nil {
		return nil, fmt.Errorf("telemetry: open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	cleanup := func(cause error) (*sql.DB, error) {
		_ = db.Close()
		return nil, cause
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;`); err != nil {
		return cleanup(fmt.Errorf("telemetry: configure SQLite: %w", err))
	}
	if _, err := db.Exec(schema); err != nil {
		return cleanup(fmt.Errorf("telemetry: initialize SQLite schema: %w", err))
	}
	if err := os.Chmod(abs, 0o600); err != nil {
		return cleanup(fmt.Errorf("telemetry: secure SQLite permissions: %w", err))
	}
	return db, nil
}

func (c *Client) persist(ctx context.Context, submission Submission) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var previousHash string
	if err := tx.QueryRowContext(ctx, `SELECT previous_event_hash FROM telemetry_state WHERE singleton = 1`).Scan(&previousHash); err != nil {
		return err
	}
	payload := Payload{
		EventID:         strings.ToLower(submission.EventID),
		Timestamp:       submission.Timestamp.UTC(),
		ClientIDHash:    strings.ToLower(submission.ClientIDHash),
		ApplicationID:   submission.ApplicationID,
		Routing:         submission.Routing,
		ComplianceFlags: submission.ComplianceFlags,
		Metrics:         submission.Metrics,
		Cryptography: Cryptography{
			HashAlgorithm:       HashAlgorithm,
			RequestResponseHash: HashExchange(submission.Request, submission.Response),
			PreviousEventHash:   previousHash,
			SignatureAlgorithm:  SignatureAlgorithm,
			KeyID:               c.keyID,
		},
	}
	if payload.Routing == nil {
		payload.Routing = map[string]any{}
	}
	if payload.ComplianceFlags == nil {
		payload.ComplianceFlags = PIIComplianceFlags(false)
	}
	if _, ok := payload.ComplianceFlags["pii_detected"]; !ok {
		payload.ComplianceFlags["pii_detected"] = false
	}
	if _, ok := payload.ComplianceFlags["pii_redacted"]; !ok {
		payload.ComplianceFlags["pii_redacted"] = false
	}
	if payload.Metrics == nil {
		payload.Metrics = map[string]any{}
	}
	payload, err = finalizePayload(payload, c.privateKey)
	if err != nil {
		return err
	}
	encoded, err := jsonMarshal(payload)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telemetry_event_ids(event_id, created_at) VALUES (?, ?)`,
		payload.EventID, c.now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ErrDuplicateEvent
		}
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO telemetry_events(event_id, payload) VALUES (?, ?)`,
		payload.EventID, encoded,
	); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE telemetry_state SET previous_event_hash = ? WHERE singleton = 1`,
		payload.Cryptography.EventHash,
	); err != nil {
		return err
	}
	return tx.Commit()
}

func (c *Client) loadBatch(ctx context.Context) ([]queuedEvent, error) {
	rows, err := c.db.QueryContext(ctx,
		`SELECT sequence, payload, attempts, next_attempt_at FROM telemetry_events ORDER BY sequence LIMIT ?`,
		c.batchSize,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []queuedEvent
	var firstNext int64
	for rows.Next() {
		var event queuedEvent
		var nextAttempt int64
		if err := rows.Scan(&event.sequence, &event.payload, &event.attempts, &nextAttempt); err != nil {
			return nil, err
		}
		if len(events) == 0 {
			firstNext = nextAttempt
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(events) > 0 && firstNext > c.now().UnixNano() {
		return nil, nil
	}
	return events, nil
}

func (c *Client) markDelivered(ctx context.Context, events []queuedEvent) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		if _, err := tx.ExecContext(ctx, `DELETE FROM telemetry_events WHERE sequence = ?`, event.sequence); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c *Client) markFailed(ctx context.Context, events []queuedEvent) error {
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, event := range events {
		attempts := event.attempts + 1
		next := c.now().Add(c.backoff(attempts)).UnixNano()
		if _, err := tx.ExecContext(ctx,
			`UPDATE telemetry_events SET attempts = ?, next_attempt_at = ? WHERE sequence = ?`,
			attempts, next, event.sequence,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (c *Client) pendingCount(ctx context.Context) (int, error) {
	var count int
	err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM telemetry_events`).Scan(&count)
	return count, err
}
