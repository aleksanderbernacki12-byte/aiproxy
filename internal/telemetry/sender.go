package telemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

func (c *Client) sendLoop() {
	defer close(c.coreDone)
	ticker := time.NewTicker(c.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.wake:
			c.flush(false, false)
		case <-ticker.C:
			c.flush(true, false)
		case <-c.sequenced:
			c.flush(true, true)
			return
		}
	}
}

func (c *Client) flush(force, shuttingDown bool) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), c.operationTimeout)
		count, err := c.pendingCount(ctx)
		cancel()
		if err != nil {
			c.report(fmt.Errorf("telemetry: count pending events: %w", err))
			return
		}
		if count == 0 || (!force && count < c.batchSize) {
			return
		}
		ctx, cancel = context.WithTimeout(context.Background(), c.operationTimeout)
		events, err := c.loadBatch(ctx)
		cancel()
		if err != nil {
			c.report(fmt.Errorf("telemetry: load batch: %w", err))
			return
		}
		if len(events) == 0 {
			return
		}
		err = c.deliverSafely(events)
		var rejected *rejectedError
		if errors.As(err, &rejected) {
			// One event in the batch is refused for good; send them one at a
			// time so only that event is set aside.
			if !c.deliverIndividually(events) {
				return
			}
			continue
		}
		if err != nil {
			c.deliveryFailures.Add(1)
			c.lastFailureUnix.Store(c.now().UTC().Unix())
			c.report(err)
			ctx, cancel = context.WithTimeout(context.Background(), c.operationTimeout)
			markErr := c.markFailed(ctx, events)
			cancel()
			if markErr != nil {
				c.report(fmt.Errorf("telemetry: save retry state: %w", markErr))
			}
			return
		}
		ctx, cancel = context.WithTimeout(context.Background(), c.operationTimeout)
		err = c.markDelivered(ctx, events)
		cancel()
		if err != nil {
			c.report(fmt.Errorf("telemetry: remove delivered batch: %w", err))
			return
		}
		c.recordDelivered(len(events))
		if shuttingDown {
			// Continue flushing all immediately deliverable shutdown work. A
			// failed batch remains in SQLite for the next process start.
			force = true
		}
	}
}

func (c *Client) recordDelivered(count int) {
	c.durablePending.Add(-int64(count))
	c.refreshStorage()
	// Timestamp first: a Snapshot that sees the delivered count must also see when.
	c.lastDeliveredUnix.Store(c.now().UTC().Unix())
	c.deliveredEvents.Add(uint64(count))
}

// deliverIndividually sends a rejected batch one event at a time, in queue
// order, quarantining each event the control plane still rejects. It stops
// at the first transient failure, leaving that event and the rest queued
// with backoff, and reports whether the flush may continue.
func (c *Client) deliverIndividually(events []queuedEvent) bool {
	for index, event := range events {
		err := c.deliverSafely([]queuedEvent{event})
		var rejected *rejectedError
		ctx, cancel := context.WithTimeout(context.Background(), c.operationTimeout)
		switch {
		case err == nil:
			err = c.markDelivered(ctx, []queuedEvent{event})
			cancel()
			if err != nil {
				c.report(fmt.Errorf("telemetry: remove delivered event: %w", err))
				return false
			}
			c.recordDelivered(1)
		case errors.As(err, &rejected):
			c.report(err)
			err = c.quarantine(ctx, event, rejected.status)
			cancel()
			if err != nil {
				c.report(fmt.Errorf("telemetry: quarantine rejected event: %w", err))
				return false
			}
			c.durablePending.Add(-1)
			c.refreshStorage()
			c.rejectedEvents.Add(1)
		default:
			c.deliveryFailures.Add(1)
			c.lastFailureUnix.Store(c.now().UTC().Unix())
			c.report(err)
			markErr := c.markFailed(ctx, events[index:])
			cancel()
			if markErr != nil {
				c.report(fmt.Errorf("telemetry: save retry state: %w", markErr))
			}
			return false
		}
	}
	return true
}

// rejectedError is a response that retrying the same payload cannot fix.
type rejectedError struct {
	status int
}

func (e *rejectedError) Error() string {
	return fmt.Sprintf("telemetry: control plane rejected the batch with HTTP %d", e.status)
}

func permanentRejection(status int) bool {
	return status == http.StatusBadRequest || status == http.StatusRequestEntityTooLarge || status == http.StatusUnprocessableEntity
}

func (c *Client) deliverSafely(events []queuedEvent) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errors.New("telemetry: control-plane client panic")
		}
	}()
	return c.deliver(events)
}

func (c *Client) deliver(events []queuedEvent) error {
	var body bytes.Buffer
	body.WriteByte('[')
	for index, event := range events {
		if index > 0 {
			body.WriteByte(',')
		}
		body.Write(event.payload)
	}
	body.WriteByte(']')

	ctx, cancel := context.WithTimeout(context.Background(), c.operationTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		return fmt.Errorf("telemetry: create control-plane request: %w", err)
	}
	for key, values := range c.headers {
		for _, value := range values {
			request.Header.Add(key, value)
		}
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Aiproxy-Batch-Size", strconv.Itoa(len(events)))

	response, err := c.httpClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		// Transport errors (including url.Error) and custom clients can embed
		// URLs, credentials, or payloads. Never expose their arbitrary text.
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			return fmt.Errorf("telemetry: send control-plane batch: %w", context.DeadlineExceeded)
		case errors.Is(err, context.Canceled):
			return fmt.Errorf("telemetry: send control-plane batch: %w", context.Canceled)
		default:
			return errors.New("telemetry: send control-plane batch: transport failure")
		}
	}
	if response == nil {
		return errors.New("telemetry: control plane returned a nil response")
	}
	if response.Body != nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	}
	if permanentRejection(response.StatusCode) {
		return &rejectedError{status: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("telemetry: control plane returned HTTP %d", response.StatusCode)
	}
	return nil
}
