package proxy

import (
	"net/http"
	"testing"
	"time"
)

func TestNewListenerServer_SetsHeaderAndIdleTimeouts(t *testing.T) {
	server := newListenerServer(&Server{}, "127.0.0.1:0", http.NotFoundHandler(), nil)
	if server.ReadHeaderTimeout != 10*time.Second || server.IdleTimeout != 120*time.Second {
		t.Fatalf("ReadHeaderTimeout=%v IdleTimeout=%v, want 10s and 120s", server.ReadHeaderTimeout, server.IdleTimeout)
	}
	if server.ReadTimeout != 0 || server.WriteTimeout != 0 {
		t.Fatalf("ReadTimeout=%v WriteTimeout=%v, want 0: long uploads and streams are legitimate", server.ReadTimeout, server.WriteTimeout)
	}
}
