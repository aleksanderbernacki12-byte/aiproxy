package proxy_test

import (
	"fmt"
	"net/http"
	"testing"

	"aiproxy/internal/semcache"
)

// TestSemanticCache_TargetCountCappedAgainstQueryStringVariation
// reproduces, end-to-end through the real proxy handler, the DoS this
// file exists to close: semanticPartitionTarget (proxy.go) folds
// resolvedDestination — built from the client's own r.URL.RawQuery —
// into semcache.Index's target key, and a single authenticated client
// fully controls that query string. Before the total-target cap
// existed, a client varying its own request's query string across
// requests would grow semcache.Index's internal target map (ix.rings)
// by one freshly allocated ring per distinct value it sent, without
// limit. This test sends far more distinct query strings than the
// index's configured maxTargets and asserts the tracked target count
// never exceeds that cap.
func TestSemanticCache_TargetCountCappedAgainstQueryStringVariation(t *testing.T) {
	const maxTargets = 3
	const distinctDestinations = 20

	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "answer from "+r.URL.RawQuery)
	})
	idx := semcache.NewIndex(semcache.DefaultIndexSize, maxTargets)
	s.SemanticIndex = idx
	s.SemanticCacheThreshold = 0.5

	body := `{"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	for i := 0; i < distinctDestinations; i++ {
		path := fmt.Sprintf("/chat?variant=%d", i)
		got := partitionCall(s, "POST", path, body, nil)
		if got.Code != 200 {
			t.Fatalf("request %d: unexpected status %d: %s", i, got.Code, got.Body.String())
		}
	}

	if n := idx.TargetCount(); n != maxTargets {
		t.Fatalf("TargetCount = %d after %d distinct query-string destinations, want exactly %d (either the cap isn't enforced, or these requests never reached the semantic cache at all)", n, distinctDestinations, maxTargets)
	}
}
