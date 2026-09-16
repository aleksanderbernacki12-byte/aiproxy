package telemetry

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type senderFunc func(*http.Request) (*http.Response, error)

func (f senderFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func TestDeliveryErrorsDoNotExposeTransportSecrets(t *testing.T) {
	const secret = "private-tenant-credential"
	for _, tc := range []struct {
		name       string
		cause      error
		panicValue bool
		want       string
	}{
		{"transport", errors.New(secret), false, "transport failure"},
		{"timeout", context.DeadlineExceeded, false, "context deadline exceeded"},
		{"canceled", context.Canceled, false, "context canceled"},
		{"panic", nil, true, "control-plane client panic"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &Client{
				endpoint:         "https://control.example/ingest?token=" + secret,
				operationTimeout: time.Second,
				httpClient: senderFunc(func(r *http.Request) (*http.Response, error) {
					if tc.panicValue {
						panic(secret)
					}
					return nil, &url.Error{Op: "Post", URL: r.URL.String(), Err: fmt.Errorf("%s: %w", secret, tc.cause)}
				}),
			}
			err := client.deliverSafely([]queuedEvent{{payload: []byte(`{}`)}})
			if err == nil || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unsafe or unexpected error: %v", err)
			}
			if tc.cause == context.DeadlineExceeded || tc.cause == context.Canceled {
				if !errors.Is(err, tc.cause) {
					t.Fatalf("error lost context classification: %v", err)
				}
			}
		})
	}
}
