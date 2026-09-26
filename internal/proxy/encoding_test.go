package proxy

import (
	"net/http"
	"testing"
)

func TestIdentityEncoded(t *testing.T) {
	cases := map[string]bool{"": true, "identity": true, " Identity ": true, "gzip": false, "br": false}
	for encoding, want := range cases {
		header := http.Header{}
		if encoding != "" {
			header.Set("Content-Encoding", encoding)
		}
		if got := identityEncoded(header); got != want {
			t.Errorf("identityEncoded(%q) = %v, want %v", encoding, got, want)
		}
	}
}
