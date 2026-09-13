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
		if err := c.deliverSafely(events); err != nil {
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
		if shuttingDown {
			// Continue flushing all immediately deliverable shutdown work. A
			// failed batch remains in SQLite for the next process start.
			force = true
		}
	}
}

func (c *Client) deliverSafely(events []queuedEvent) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("telemetry: control-plane client panic: %v", recovered)
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
		return fmt.Errorf("telemetry: send control-plane batch: %w", err)
	}
	if response == nil {
		return errors.New("telemetry: control plane returned a nil response")
	}
	if response.Body != nil {
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("telemetry: control plane returned HTTP %d", response.StatusCode)
	}
	return nil
}
