package securevault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type archiveRecord struct {
	Version    int              `json:"version"`
	EventID    string           `json:"event_id"`
	CapturedAt time.Time        `json:"captured_at"`
	Request    archivedRequest  `json:"request"`
	Response   archivedResponse `json:"response"`
}

type archivedRequest struct {
	Method        string      `json:"method"`
	URL           string      `json:"url"`
	Protocol      string      `json:"protocol"`
	Host          string      `json:"host"`
	RemoteAddress string      `json:"remote_address,omitempty"`
	Headers       http.Header `json:"headers"`
	Trailers      http.Header `json:"trailers,omitempty"`
	Body          []byte      `json:"body"`
}

type archivedResponse struct {
	StatusCode int         `json:"status_code"`
	Status     string      `json:"status"`
	Protocol   string      `json:"protocol"`
	Headers    http.Header `json:"headers"`
	Trailers   http.Header `json:"trailers,omitempty"`
	Body       []byte      `json:"body"`
}

func capture(eventID string, request *http.Request, response *http.Response, capturedAt time.Time) ([]byte, error) {
	requestBody, err := copyRequestBody(request)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	responseBody, err := readAndRestore(&response.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	requestURL := ""
	if request.URL != nil {
		requestURL = request.URL.String()
	}
	record := archiveRecord{
		Version:    1,
		EventID:    eventID,
		CapturedAt: capturedAt.UTC(),
		Request: archivedRequest{
			Method:        request.Method,
			URL:           requestURL,
			Protocol:      request.Proto,
			Host:          request.Host,
			RemoteAddress: request.RemoteAddr,
			Headers:       request.Header.Clone(),
			Trailers:      request.Trailer.Clone(),
			Body:          requestBody,
		},
		Response: archivedResponse{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Protocol:   response.Proto,
			Headers:    response.Header.Clone(),
			Trailers:   response.Trailer.Clone(),
			Body:       responseBody,
		},
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("encode raw exchange: %w", err)
	}
	return encoded, nil
}

func copyRequestBody(request *http.Request) ([]byte, error) {
	if request.Body == nil {
		return nil, nil
	}
	if request.GetBody != nil {
		body, err := request.GetBody()
		if err != nil {
			return nil, err
		}
		defer body.Close()
		return io.ReadAll(body)
	}
	return readAndRestore(&request.Body)
}

func readAndRestore(body *io.ReadCloser) ([]byte, error) {
	if body == nil || *body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(*body)
	if err != nil {
		return nil, err
	}
	if err := (*body).Close(); err != nil {
		return nil, err
	}
	*body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
