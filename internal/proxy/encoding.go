package proxy

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"strings"
)

var (
	errUnsupportedContentEncoding = errors.New("unsupported content encoding")
	errDecodedBodyTooLarge        = errors.New("decoded request body too large")
)

// decodeRequestBody returns the body rules must scan and the upstream must
// receive. A gzip body is inflated (bounded by maxBytes after inflation) and
// forwarded plain, with Content-Encoding removed; any other encoding cannot
// be scanned and is rejected.
func decodeRequestBody(r *http.Request, body []byte, maxBytes int64) ([]byte, error) {
	encoding := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
		return body, nil
	case "gzip", "x-gzip":
	default:
		return nil, errUnsupportedContentEncoding
	}
	reader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(decoded)) > maxBytes {
		return nil, errDecodedBodyTooLarge
	}
	r.Header.Del("Content-Encoding")
	r.Header.Del("Content-Length")
	r.ContentLength = int64(len(decoded))
	return decoded, nil
}

// identityEncoded reports whether a stored response is plain. Entries cached
// before responses were always decompressed may hold gzip bytes that were
// never scanned; those are treated as misses.
func identityEncoded(header http.Header) bool {
	encoding := strings.ToLower(strings.TrimSpace(header.Get("Content-Encoding")))
	return encoding == "" || encoding == "identity"
}
