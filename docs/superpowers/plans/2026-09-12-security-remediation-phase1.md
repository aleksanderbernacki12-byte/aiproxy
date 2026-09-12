# Security Remediation Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close review findings #1, #2, #3, #6 from `docs/reviews/2026-09-12-v0.74.1-system-review.md`: cache/coalescing/semantic-cache identity leaks across clients, cached/replayed responses bypassing the current rules engine, and ordinary client keys controlling admin operations.

**Architecture:** Four largely-independent mechanisms, all touching `internal/proxy/proxy.go`'s `ServeHTTP`: (1) a SHA256 partition identity folded into the cache/coalescing/semantic-cache keys, (2) a shared re-evaluation helper called by every replay path before it releases stored bytes to a client, (3) a "structural remainder" hash added to the semantic cache's match requirements, (4) a new admin-key concept and auth-check path fully separate from ordinary proxy client keys.

**Tech Stack:** Go 1.27, standard library only (`crypto/sha256`, `encoding/json`, `net/http`), the existing `internal/cache`, `internal/coalesce`, `internal/semcache`, `internal/idempotency`, `internal/rules`, `internal/config`, `internal/cli` packages.

**Reference:** the design spec at `docs/superpowers/specs/2026-09-12-security-remediation-phase1-design.md` and the review at `docs/reviews/2026-09-12-v0.74.1-system-review.md`. Reproduction tests already committed at `docs/reviews/2026-09-12-v0.74.1-repro/review_findings_test.go.txt` — only these four matter for this phase: `TestReview_CacheMustIsolateCredentials`, `TestReview_CacheMustEnforceClientRules`, `TestReview_SemanticCacheMustRespectModelAndStream`, `TestReview_ClientKeyMustNotControlDrain`. The other 8 belong to later phases — do not port them in this plan.

---

### Task 1: `cache.Key` gains a partition identity parameter

**Files:**
- Modify: `internal/cache/cache.go:133-145`
- Test: `internal/cache/cache_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cache/cache_test.go` (create the file if it doesn't exist yet — check first with `ls internal/cache/*_test.go`; if one exists, add this test function to it):

```go
func TestKey_DifferentPartitionsProduceDifferentKeys(t *testing.T) {
	a := Key("GET", "https://api.example.com/v1/chat", []byte(`{"x":1}`), "partition-alice")
	b := Key("GET", "https://api.example.com/v1/chat", []byte(`{"x":1}`), "partition-bob")
	if a == b {
		t.Fatalf("same method/url/body but different partitionID produced identical keys: %q", a)
	}
}

func TestKey_SamePartitionAndInputsProduceSameKey(t *testing.T) {
	a := Key("GET", "https://api.example.com/v1/chat", []byte(`{"x":1}`), "partition-alice")
	b := Key("GET", "https://api.example.com/v1/chat", []byte(`{"x":1}`), "partition-alice")
	if a != b {
		t.Fatalf("identical inputs produced different keys: %q vs %q", a, b)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cache -run TestKey_ -v`
Expected: FAIL — `too many arguments in call to Key`

- [ ] **Step 3: Update `Key`'s signature and doc comment**

Replace lines 133-145 of `internal/cache/cache.go`:

```go
// Key computes the cache key for a request: the hex-encoded SHA256 hash
// of the HTTP method, the fully-resolved target URL, the entire request
// body, and partitionID — an opaque, caller-computed identity string
// that must differ between two callers whenever their responses could
// legitimately differ (different proxy client, different upstream
// credential; see proxy.partitionIdentity, this cache's only caller).
// Without partitionID, two different callers requesting the exact same
// method/URL/body would share one cache entry regardless of who they
// are or what credential they authenticate to the upstream with — see
// docs/reviews/2026-09-12-v0.74.1-system-review.md finding #1. NUL bytes
// separate every field so that, for example, method "GETX" + url "Y"
// cannot collide with method "GET" + url "XY".
func Key(method, targetURL string, body []byte, partitionID string) string {
	h := sha256.New()
	h.Write([]byte(method))
	h.Write([]byte{0})
	h.Write([]byte(targetURL))
	h.Write([]byte{0})
	h.Write(body)
	h.Write([]byte{0})
	h.Write([]byte(partitionID))
	return hex.EncodeToString(h.Sum(nil))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/cache -run TestKey_ -v`
Expected: PASS

- [ ] **Step 5: Find and update every other call site**

Run: `grep -rn "cache\.Key(\|[^.]Key(" internal/cache internal/proxy | grep -v _test.go`

This will surface the one production call site in `internal/proxy/proxy.go` (~line 2992) — do NOT fix it yet, that's Task 2 (it needs `partitionIdentity`, which doesn't exist until Task 2 writes it). For now, confirm `go build ./...` fails only at that one call site with a "not enough arguments" error, so you know Task 1 hasn't silently broken anything else.

Run: `go build ./... 2>&1 | grep -v "not enough arguments in call to cache.Key"`
Expected: no other output — the only build error anywhere in the repo is that one known call site.

- [ ] **Step 6: Commit**

```bash
git add internal/cache/cache.go internal/cache/cache_test.go
git commit -m "Add partition identity to cache.Key (review finding #1)"
```

---

### Task 2: `partitionIdentity` helper and wiring into the cache/coalescing call site

**Files:**
- Modify: `internal/proxy/proxy.go` (new helper near `checkProxyAuth`, ~line 2306; call site ~line 2992)
- Test: `internal/proxy/partition_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `internal/proxy/partition_test.go`:

```go
package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func partitionTestServer(t *testing.T, handler http.HandlerFunc) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c
	return s
}

func partitionCall(s *proxy.Server, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestCache_IsolatesByUpstreamCredential_NoProxyKeysConfigured(t *testing.T) {
	// Regression for review finding #1: even with NO proxy_api_key(s)
	// configured at all (auth.label == "" for every caller), two
	// different callers presenting two different personal upstream
	// credentials must never share a cache entry.
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private response for "+r.Header.Get("Authorization"))
	})
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer alice-upstream"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Authorization": "Bearer bob-upstream"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if strings.Contains(b.Body.String(), "alice-upstream") {
		t.Fatalf("caller with a different upstream credential received the other caller's cached response: %q", b.Body.String())
	}
}

func TestCache_SameCredentialStillHits(t *testing.T) {
	// Sanity check the fix isn't a blanket cache-bust: the SAME caller
	// (same auth.label, same upstream credential) must still get a real
	// cache hit on a repeat request.
	calls := 0
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, "answer")
	})
	headers := map[string]string{"Authorization": "Bearer alice-upstream"}
	partitionCall(s, "GET", "/account", "", headers)
	second := partitionCall(s, "GET", "/account", "", headers)
	if second.Header().Get("Age") == "" {
		t.Fatalf("expected second identical call to be a cache hit (Age header set), got status %d body %q", second.Code, second.Body.String())
	}
	if calls != 1 {
		t.Fatalf("expected upstream to be called exactly once, got %d", calls)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy -run 'TestCache_IsolatesByUpstreamCredential|TestCache_SameCredentialStillHits' -v`
Expected: FAIL — `TestCache_IsolatesByUpstreamCredential_NoProxyKeysConfigured` fails with Bob's response containing "alice-upstream" (build itself won't even succeed yet since Task 1 left `cache.Key`'s one call site broken — fix that as part of this task before the test can run at all).

- [ ] **Step 2b: Add the `partitionIdentity` helper**

Add this function in `internal/proxy/proxy.go` immediately after `checkProxyAuth` (after line 2306, right before the `errorResponse` type):

```go
// partitionIdentity returns a SHA256 hash identifying which "identity"
// auth/r represents, for use as part of the cache/coalescing/semantic-
// cache key — see docs/reviews/2026-09-12-v0.74.1-system-review.md
// finding #1. Two dimensions make two callers genuinely different: this
// proxy's own notion of who's calling (auth.label, from
// Server.ProxyAPIKey/ProxyAPIKeys) and the actual credential the caller
// presents to authenticate to the *upstream* API (Authorization/
// X-Api-Key) — since Rewrite never touches headers (see its own doc
// comment), aiproxy is a bring-your-own-key passthrough, so two callers
// can share one proxy key configuration yet carry two different
// personal upstream credentials and still must never share a cached
// response. Proxy-Authorization is folded in too even though
// checkProxyAuth already consumed it into auth.label, purely so this
// function needs no special-casing for the "auth disabled entirely"
// case (auth.label == "") — the raw header value still differs per
// caller in the disabled-auth case only if the caller happens to send
// one anyway, which is harmless either way. Hashed, never stored or
// logged in plaintext, exactly like idempotency's own bodyHash.
func partitionIdentity(auth clientAuth, r *http.Request) string {
	h := sha256.New()
	h.Write([]byte(auth.label))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("Authorization")))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("X-Api-Key")))
	h.Write([]byte{0})
	h.Write([]byte(r.Header.Get("Proxy-Authorization")))
	return hex.EncodeToString(h.Sum(nil))
}
```

Check the existing imports at the top of `internal/proxy/proxy.go` — `crypto/sha256` and `encoding/hex` are likely already imported (used elsewhere, e.g. by the idempotency body-hash call around line 2913: `sha256.Sum256(body)`). Run `goimports -l internal/proxy/proxy.go` after this edit; if it reports the file, run `goimports -w internal/proxy/proxy.go` to fix imports automatically.

- [ ] **Step 2c: Wire it into the cache-key call site**

In `ServeHTTP`, change (around line 2992):

```go
		cacheKey = cache.Key(r.Method, targets[0].ResolveReference(destURL).String(), body)
```

to:

```go
		cacheKey = cache.Key(r.Method, targets[0].ResolveReference(destURL).String(), body, partitionIdentity(auth, r))
```

- [ ] **Step 3: Run test to verify it passes**

Run: `go test ./internal/proxy -run 'TestCache_IsolatesByUpstreamCredential|TestCache_SameCredentialStillHits' -v`
Expected: PASS

- [ ] **Step 4: Run the full proxy suite to check nothing else broke**

Run: `go test ./internal/proxy/... -count=1`
Expected: PASS — every existing cache/coalescing test was written against a single caller identity, so partitioning by an identity that's constant within any one test should change nothing about whether those tests still hit the cache the same way. If any existing test fails, read it first: it likely means that test itself makes two calls with different headers (e.g. different Idempotency-Key or Proxy-Authorization) and previously relied on them still sharing a cache entry — that reliance was exactly finding #1's bug, so fix the test's expectation, not the new code.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/partition_test.go
git commit -m "Partition cache/coalescing by client and upstream credential (review finding #1)"
```

---

### Task 3: `extractPromptText` returns a structural remainder

**Files:**
- Modify: `internal/proxy/proxy.go:1575-1671` (delete `promptFields`, rewrite `extractPromptText`)
- Modify: `internal/proxy/semanticcache_internal_test.go` (update all 12 call sites to the new 3-return signature)

- [ ] **Step 1: Update the existing tests' call sites first**

`internal/proxy/semanticcache_internal_test.go` has 12 calls shaped like `text, ok := extractPromptText(body)` or `if _, ok := extractPromptText(body); ok {`. Change every one of them to capture (and ignore) the new middle return value:

```go
text, _, ok := extractPromptText(body)
```

and

```go
if _, _, ok := extractPromptText(body); ok {
```

Run `grep -n "extractPromptText(body)" internal/proxy/semanticcache_internal_test.go` first to see the exact line numbers and confirm you've caught all 12.

- [ ] **Step 2: Run test to verify it fails**

Run: `go build ./internal/proxy/... 2>&1`
Expected: FAIL — `too many arguments to return`-shaped errors, since the tests now expect 3 return values but `extractPromptText` still only returns 2. (This intentionally fails at compile time, not test-run time — that's expected for a signature change.)

- [ ] **Step 3: Replace `promptFields`/`extractPromptText` with the remainder-producing version**

Delete lines 1575-1671 of `internal/proxy/proxy.go` (the `promptFields` type, its doc comment, and the old `extractPromptText`) and replace with:

```go
// contentBlock is one entry of a "content blocks" array, e.g.
// [{"type":"text","text":"..."}] — the shape both OpenAI and Anthropic
// use for multi-part (text + image, etc.) message content.
type contentBlock struct {
	Text string `json:"text"`
}

// extractPromptText returns the concatenated text aiproxy recognizes in
// body for semantic caching's approximate similarity check (messages[].
// content, then prompt, then input, exactly as before this function
// gained a third return value), and the "structural remainder": body
// with just that free text blanked out to JSON null, leaving every
// other field — model, stream, message roles, tools, response_format,
// generation parameters, and anything else aiproxy doesn't specifically
// recognize — byte-for-byte reproducible from the original (map key
// order is Go's own deterministic sorted-key json.Marshal output, so
// two requests that differ only in field order still produce identical
// remainders). remainder is the mandatory *exact*-match requirement
// semantic caching checks before it ever consults approximate text
// similarity — see docs/reviews/2026-09-12-v0.74.1-system-review.md
// finding #3: without it, a request to a different model, or with
// streaming toggled, could receive a cached answer generated under
// completely different parameters just because its prompt text was
// similar. ok is false, and both other return values are zero, exactly
// when body isn't a JSON object at all; a body that IS a JSON object
// but has no recognizable prompt text still returns a real remainder
// (there is nothing to blank, so it's just body's own canonicalized
// bytes) — the semantic cache's own caller only ever consults remainder
// when text was actually found, so this asymmetry is harmless.
//
// Decoding stays defensive at every level, same discipline as before:
// messages is decoded as a raw array and each message decoded on its
// own, content accepts either a plain JSON string or a JSON array of
// content blocks, and one malformed message or block is skipped (left
// out of the extracted text, left unblanked in the remainder) rather
// than aborting the whole body.
func extractPromptText(body []byte) (text string, remainder []byte, ok bool) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return "", nil, false
	}

	var b strings.Builder
	writeChunk := func(s string) {
		if s == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(s)
	}

	if rawMessages, hasMessages := top["messages"]; hasMessages {
		var messages []json.RawMessage
		if err := json.Unmarshal(rawMessages, &messages); err == nil {
			blanked := make([]json.RawMessage, len(messages))
			copy(blanked, messages)
			for i, rawMsg := range messages {
				var msg map[string]json.RawMessage
				if err := json.Unmarshal(rawMsg, &msg); err != nil {
					continue
				}
				rawContent, hasContent := msg["content"]
				if !hasContent {
					continue
				}
				var asString string
				if err := json.Unmarshal(rawContent, &asString); err == nil {
					writeChunk(asString)
				} else {
					var blocks []json.RawMessage
					if err := json.Unmarshal(rawContent, &blocks); err == nil {
						for _, rawBlock := range blocks {
							var blk contentBlock
							if err := json.Unmarshal(rawBlock, &blk); err == nil {
								writeChunk(blk.Text)
							}
						}
					}
				}
				msg["content"] = json.RawMessage("null")
				if reMarshaled, err := json.Marshal(msg); err == nil {
					blanked[i] = reMarshaled
				}
			}
			if reMarshaled, err := json.Marshal(blanked); err == nil {
				top["messages"] = reMarshaled
			}
		}
	}

	if rawPrompt, hasPrompt := top["prompt"]; hasPrompt {
		var prompt string
		if err := json.Unmarshal(rawPrompt, &prompt); err == nil {
			writeChunk(prompt)
		}
		top["prompt"] = json.RawMessage("null")
	}
	if rawInput, hasInput := top["input"]; hasInput {
		var input string
		if err := json.Unmarshal(rawInput, &input); err == nil {
			writeChunk(input)
		}
		top["input"] = json.RawMessage("null")
	}

	remainder, err := json.Marshal(top)
	if err != nil {
		return "", nil, false
	}
	if b.Len() == 0 {
		return "", remainder, false
	}
	return b.String(), remainder, true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy -run TestExtractPromptText -v` (or whatever the existing test function names are — `grep -n "^func Test" internal/proxy/semanticcache_internal_test.go` to get exact names first)
Expected: PASS — every existing extraction test (text content, order, malformed-input handling) behaves identically to before, since the extraction logic itself is unchanged; only the remainder computation is new.

- [ ] **Step 5: Add remainder-specific tests**

Append to `internal/proxy/semanticcache_internal_test.go`:

```go
func TestExtractPromptText_RemainderPreservesNonTextFields(t *testing.T) {
	body := []byte(`{"model":"gpt-4","stream":true,"temperature":0.7,"messages":[{"role":"user","content":"hello"}]}`)
	_, remainder, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected text to be found")
	}
	var decoded map[string]any
	if err := json.Unmarshal(remainder, &decoded); err != nil {
		t.Fatalf("remainder is not valid JSON: %v, %q", err, remainder)
	}
	if decoded["model"] != "gpt-4" {
		t.Fatalf("remainder lost model field: %q", remainder)
	}
	if decoded["stream"] != true {
		t.Fatalf("remainder lost stream field: %q", remainder)
	}
	if decoded["temperature"] != 0.7 {
		t.Fatalf("remainder lost temperature field: %q", remainder)
	}
}

func TestExtractPromptText_RemainderBlanksMessageContentButKeepsRole(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"secret system prompt"}]}`)
	_, remainder, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected text to be found")
	}
	if strings.Contains(string(remainder), "secret system prompt") {
		t.Fatalf("remainder leaked message content verbatim: %q", remainder)
	}
	var decoded struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(remainder, &decoded); err != nil {
		t.Fatalf("remainder is not valid JSON: %v", err)
	}
	if len(decoded.Messages) != 1 || decoded.Messages[0].Role != "system" {
		t.Fatalf("remainder lost message role: %q", remainder)
	}
}

func TestExtractPromptText_DifferentModelProducesDifferentRemainder(t *testing.T) {
	a := []byte(`{"model":"model-a","stream":false,"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"model":"model-b","stream":true,"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different model/stream produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_DifferentToolsProduceDifferentRemainder(t *testing.T) {
	a := []byte(`{"tools":[{"name":"get_weather"}],"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"tools":[{"name":"get_stock_price"}],"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different tool definitions produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_DifferentResponseFormatProducesDifferentRemainder(t *testing.T) {
	a := []byte(`{"response_format":{"type":"text"},"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"response_format":{"type":"json_object"},"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different response_format produced identical remainders: %q", remainderA)
	}
}
```

- [ ] **Step 6: Run all new tests to verify they pass**

Run: `go test ./internal/proxy -run TestExtractPromptText -v`
Expected: PASS (all 5 new tests plus every pre-existing extraction test)

- [ ] **Step 7: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/semanticcache_internal_test.go
git commit -m "extractPromptText returns a structural remainder for exact-match semantic cache scoping (review finding #3)"
```

---

### Task 4: `semcache.Index` requires an exact remainder-hash match before similarity

**Files:**
- Modify: `internal/semcache/semcache.go:87-194`
- Test: `internal/semcache/semcache_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/semcache/semcache_test.go` (check `ls internal/semcache/*_test.go` for the existing file to add to):

```go
func TestIndex_FindBest_RequiresExactRemainderHashMatch(t *testing.T) {
	ix := NewIndex(10)
	fp := Fingerprint("explain the capital of Sweden")
	ix.Add("target-a", fp, "remainder-hash-x", "cache-key-1")

	// Same target, same (near-)identical fingerprint, but a DIFFERENT
	// remainder hash (e.g. a different model or streaming flag) must
	// never be treated as a match, however high the text similarity is.
	if _, _, ok := ix.FindBest("target-a", fp, "remainder-hash-y", 0.5); ok {
		t.Fatal("FindBest matched despite a different remainder hash")
	}

	// The exact same remainder hash must still match.
	if key, _, ok := ix.FindBest("target-a", fp, "remainder-hash-x", 0.5); !ok || key != "cache-key-1" {
		t.Fatalf("FindBest failed to match identical remainder hash: key=%q ok=%v", key, ok)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/semcache -run TestIndex_FindBest_RequiresExactRemainderHashMatch -v`
Expected: FAIL — `not enough arguments in call to ix.Add` / `ix.FindBest`

- [ ] **Step 3: Update `entry`, `Add`, and `FindBest`**

In `internal/semcache/semcache.go`, change the `entry` struct (lines 86-90):

```go
// entry is one recorded fingerprint/cache-key pair inside a ring.
type entry struct {
	fingerprint   []uint64
	remainderHash string
	cacheKey      string
}
```

Change `Add` (lines 159-170):

```go
// Add records fp/remainderHash/cacheKey under target, evicting that
// target's oldest entry first if it's already at maxSize. remainderHash
// is an exact-match requirement FindBest checks before it ever
// considers fingerprint similarity — see FindBest's own doc comment.
func (ix *Index) Add(target string, fp []uint64, remainderHash, cacheKey string) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, ok := ix.rings[target]
	if !ok {
		r = newRing(ix.maxSize)
		ix.rings[target] = r
	}
	r.add(entry{fingerprint: fp, remainderHash: remainderHash, cacheKey: cacheKey})
}
```

Change `FindBest` (lines 172-194):

```go
// FindBest returns the highest-similarity entry recorded under target
// that has an EXACTLY matching remainderHash and is at or above
// threshold, or ok=false if none qualifies (target has no entries, none
// share remainderHash, or none reach threshold among those that do).
// remainderHash is checked first, before Similarity is even computed —
// see docs/reviews/2026-09-12-v0.74.1-system-review.md finding #3: two
// requests with similar prompt text but a different model, streaming
// mode, tool set, or generation parameters must never be treated as
// interchangeable just because their extracted text happens to match.
func (ix *Index) FindBest(target string, fp []uint64, remainderHash string, threshold float64) (cacheKey string, similarity float64, ok bool) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	r, exists := ix.rings[target]
	if !exists {
		return "", 0, false
	}
	var best float64
	var bestKey string
	found := false
	r.forEach(func(e entry) {
		if e.remainderHash != remainderHash {
			return
		}
		sim := Similarity(fp, e.fingerprint)
		if sim >= threshold && (!found || sim > best) {
			best = sim
			bestKey = e.cacheKey
			found = true
		}
	})
	return bestKey, best, found
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/semcache -run TestIndex_FindBest_RequiresExactRemainderHashMatch -v`
Expected: PASS

- [ ] **Step 5: Run the full semcache suite**

Run: `go test ./internal/semcache/... -count=1 -v`
Expected: every pre-existing test now fails to compile (`not enough arguments`) — fix each call site in `internal/semcache/semcache_test.go` the same way Task 3 fixed `semanticcache_internal_test.go`: add a `remainderHash` argument. For any pre-existing test that doesn't care about remainder matching at all, use a constant non-empty string (e.g. `"rh"`) for every `Add`/`FindBest` call in that test so the new exact-match gate is satisfied uniformly and the test keeps checking whatever it originally checked (similarity/eviction/capacity behavior).

Run again: `go test ./internal/semcache/... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/semcache/semcache.go internal/semcache/semcache_test.go
git commit -m "Require exact remainder-hash match before semantic similarity (review finding #3)"
```

---

### Task 5: Wire `partitionIdentity` and the remainder hash into the semantic cache call site

**Files:**
- Modify: `internal/proxy/proxy.go` (semantic-cache lookup ~line 3036-3072, and the two `Index.Add` call sites in `bufferResponse`/`streamResponse`, ~lines 3368-3369 and ~3443-3444)
- Modify: `internal/proxy/proxy.go` (`requestContextInfo` struct and its one construction site, to carry the remainder hash through to the `Add` call sites the same way `semanticFingerprint` already does)

- [ ] **Step 1: Write the failing test**

Add to `internal/proxy/partition_test.go` (created in Task 2):

```go
func TestSemanticCache_IsolatesByUpstreamCredential(t *testing.T) {
	// Regression for review finding #1 applied to the semantic cache
	// specifically: same prompt text, same target, but two different
	// upstream credentials must never produce a semantic-cache hit
	// across them.
	s := partitionTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		fmt.Fprint(w, "answer to: "+string(b)+" for "+r.Header.Get("Authorization"))
	})
	s.SemanticCacheThreshold = 0.5
	body := `{"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	partitionCall(s, "POST", "/chat", body, map[string]string{"Authorization": "Bearer alice-upstream"})
	got := partitionCall(s, "POST", "/chat", body, map[string]string{"Authorization": "Bearer bob-upstream"})
	if got.Header().Get("X-Semantic-Cache-Hit") == "true" {
		t.Fatalf("different upstream credential received a semantic cache hit meant for another caller: %s", got.Body.String())
	}
}
```

`SemanticIndex` also needs to be set on `s` for this test to exercise the semantic path at all — add that inside `partitionTestServer` unconditionally (it's harmless for tests that never set a threshold, since `s.getSemanticCacheThreshold() > 0` gates every use of it): open `internal/proxy/partition_test.go` and add to `partitionTestServer`, right after `s.Cache = c`:

```go
	s.SemanticIndex = semcache.NewIndex(100)
```

(add `"aiproxy/internal/semcache"` to the import block).

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy -run TestSemanticCache_IsolatesByUpstreamCredential -v`
Expected: FAIL — Bob's request gets `X-Semantic-Cache-Hit: true` against Alice's cached answer.

- [ ] **Step 3: Update `requestContextInfo` to carry the remainder hash**

Find `requestContextInfo`'s struct definition (`grep -n "semanticFingerprint " internal/proxy/proxy.go` to find it — it's a field on that struct, documented around line 164). Add a sibling field right next to it:

```go
	// semanticFingerprint holds this request's own extracted-prompt
	// fingerprint (see semcache.Fingerprint), computed once in ServeHTTP
	// ...
	semanticFingerprint []uint64

	// semanticRemainderHash is the SHA256 hash of this request's own
	// "structural remainder" (see extractPromptText) — the exact-match
	// requirement Index.Add/FindBest both key on alongside
	// semanticFingerprint's approximate similarity. Empty exactly when
	// semanticFingerprint is nil (no prompt text was extracted, or
	// semantic caching isn't enabled).
	semanticRemainderHash string
```

- [ ] **Step 4: Update the semantic-cache lookup in `ServeHTTP`**

Replace the block at (originally) lines 3036-3073:

```go
		if threshold := s.getSemanticCacheThreshold(); threshold > 0 {
			if text, extracted := extractPromptText(body); extracted {
				semanticFingerprintForReqCtx = semcache.Fingerprint(text)
				if idx := s.getSemanticIndex(); idx != nil {
					if candidateKey, similarity, found := idx.FindBest(targetLabel, semanticFingerprintForReqCtx, threshold); found {
```

with:

```go
		if threshold := s.getSemanticCacheThreshold(); threshold > 0 {
			if text, remainder, extracted := extractPromptText(body); extracted {
				semanticFingerprintForReqCtx = semcache.Fingerprint(text)
				remainderSum := sha256.Sum256(remainder)
				semanticRemainderHashForReqCtx = hex.EncodeToString(remainderSum[:])
				if idx := s.getSemanticIndex(); idx != nil {
					semanticTarget := targetLabel + "\x00" + partitionIdentity(auth, r)
					if candidateKey, similarity, found := idx.FindBest(semanticTarget, semanticFingerprintForReqCtx, semanticRemainderHashForReqCtx, threshold); found {
```

Declare the new local variable alongside the existing ones just above this block (`grep -n "var semanticFingerprintForReqCtx" internal/proxy/proxy.go` to find the exact line):

```go
	var semanticFingerprintForReqCtx []uint64
	var semanticRemainderHashForReqCtx string
```

Add `semanticRemainderHash: semanticRemainderHashForReqCtx,` to the `reqCtx := requestContextInfo{...}` literal, next to the existing `semanticFingerprint: semanticFingerprintForReqCtx,` line.

- [ ] **Step 5: Update both `Index.Add` call sites**

In `bufferResponse` (~line 3368-3369):

```go
			} else if idx := s.getSemanticIndex(); idx != nil && reqCtx.semanticFingerprint != nil {
				idx.Add(reqCtx.targetLabel, reqCtx.semanticFingerprint, reqCtx.cacheKey)
			}
```

becomes:

```go
			} else if idx := s.getSemanticIndex(); idx != nil && reqCtx.semanticFingerprint != nil {
				idx.Add(reqCtx.targetLabel+"\x00"+reqCtx.clientLabel, reqCtx.semanticFingerprint, reqCtx.semanticRemainderHash, reqCtx.cacheKey)
			}
```

Wait — use the SAME composite target the lookup used. The lookup composed `targetLabel + "\x00" + partitionIdentity(auth, r)`, not `targetLabel + "\x00" + reqCtx.clientLabel` (`clientLabel` is only `auth.label`, missing the upstream-credential half of the identity). Since `partitionIdentity` needs `r *http.Request`, and `bufferResponse`/`streamResponse` only receive `reqCtx` (not the original `r`), add the fully-composed value to `requestContextInfo` instead of recomputing it. Add one more field next to `semanticRemainderHash`:

```go
	// semanticTargetPartition is targetLabel + "\x00" + partitionIdentity
	// (see partitionIdentity), precomputed once in ServeHTTP where r is
	// still available, since bufferResponse/streamResponse only ever see
	// reqCtx, not the original request. Empty exactly when
	// semanticFingerprint is nil.
	semanticTargetPartition string
```

In `ServeHTTP`, right where `semanticTarget` was computed in Step 4 above, keep that local variable but also stash it: rename the local to `semanticTargetForReqCtx` for clarity and assign it into `reqCtx`:

```go
				if idx := s.getSemanticIndex(); idx != nil {
					semanticTargetForReqCtx = targetLabel + "\x00" + partitionIdentity(auth, r)
					if candidateKey, similarity, found := idx.FindBest(semanticTargetForReqCtx, semanticFingerprintForReqCtx, semanticRemainderHashForReqCtx, threshold); found {
```

(declare `var semanticTargetForReqCtx string` alongside the other two new locals in Step 4, and add `semanticTargetPartition: semanticTargetForReqCtx,` to the `reqCtx` literal).

Now both `Add` call sites become:

```go
				idx.Add(reqCtx.semanticTargetPartition, reqCtx.semanticFingerprint, reqCtx.semanticRemainderHash, reqCtx.cacheKey)
```

(one in `bufferResponse` ~line 3369, one in `streamResponse`'s `onComplete` closure ~line 3444 — both currently read `idx.Add(reqCtx.targetLabel, reqCtx.semanticFingerprint, reqCtx.cacheKey)`; replace both identically).

- [ ] **Step 6: Run test to verify it passes**

Run: `go test ./internal/proxy -run TestSemanticCache_IsolatesByUpstreamCredential -v`
Expected: PASS

- [ ] **Step 7: Run the full proxy suite**

Run: `go test ./internal/proxy/... -count=1`
Expected: PASS. If any pre-existing semantic-cache test fails, check whether it makes two calls with different `Proxy-Authorization`/`Authorization` headers while expecting them to still share a semantic-cache hit — same reasoning as Task 2's Step 4, fix the test's expectation rather than the new isolation behavior.

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/proxy.go
git commit -m "Partition semantic cache by client/upstream credential, wire remainder hash through (review findings #1, #3)"
```

---

### Task 6: `checkReplayPolicy` — re-evaluate current rules before serving any stored response

**Files:**
- Modify: `internal/proxy/proxy.go` (new helper near `bufferResponse`; four call sites in `ServeHTTP`)
- Test: `internal/proxy/replaypolicy_test.go` (new)

This is the highest-value, highest-risk task in this phase — read the whole task before starting, and do not skip the "must not re-forward upstream" test for idempotency.

- [ ] **Step 1: Write the failing tests**

Create `internal/proxy/replaypolicy_test.go`:

```go
package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestReplayPolicy_ExactCacheHit_BlockedByRuleAddedAfterCaching(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "the answer contains FUTURE_SECRET")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c

	// First call: no block rule yet, gets cached normally.
	first := partitionCall(s, "GET", "/chat", "", nil)
	if first.Code != 200 {
		t.Fatalf("expected first call to succeed, got %d: %s", first.Code, first.Body.String())
	}

	// A block rule is added AFTER the response was already cached —
	// simulating a config reload that tightens policy.
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "future-secret", Pattern: regexp.MustCompile("FUTURE_SECRET"), Action: rules.Block})

	second := partitionCall(s, "GET", "/chat", "", nil)
	if second.Code == 200 {
		t.Fatalf("cached response bypassed a rule added after it was cached: status=%d body=%q", second.Code, second.Body.String())
	}
}

func TestReplayPolicy_Coalescing_BlockedByCurrentRules(t *testing.T) {
	release := make(chan struct{})
	var served atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		served.Add(1)
		fmt.Fprint(w, "contains COALESCE_SECRET")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	// The block rule for the response body exists from the start here —
	// this specifically proves coalesced replay (not just exact cache)
	// re-checks current rules, since a coalesced Replay branch never
	// even calls bufferResponse's own live check.
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "coalesce-secret", Pattern: regexp.MustCompile("COALESCE_SECRET"), Action: rules.Block})
	s := proxy.New("unused", u, engine)
	s.Logger = log.New(io.Discard, "", 0)
	s.Coalescer = coalesceGroupForTest(t)

	done := make(chan *httptest.ResponseRecorder, 2)
	go func() { done <- partitionCall(s, "GET", "/chat", "", nil) }()
	time.Sleep(50 * time.Millisecond) // let the first request claim Own before the second arrives
	go func() { done <- partitionCall(s, "GET", "/chat", "", nil) }()
	time.Sleep(50 * time.Millisecond) // let the second request start waiting (coalesce.Claim) before releasing upstream
	close(release)

	r1, r2 := <-done, <-done
	for _, r := range []*httptest.ResponseRecorder{r1, r2} {
		if r.Code == 200 {
			t.Fatalf("a request (owner or coalesced replay) received a blocked body: status=%d body=%q", r.Code, r.Body.String())
		}
	}
}

func TestReplayPolicy_IdempotencyReplay_BlockedWithoutReForwardingUpstream(t *testing.T) {
	var executions atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		executions.Add(1)
		fmt.Fprint(w, "contains IDEMPOTENT_SECRET")
	}))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.Idempotency = idempotency.NewRegistry(time.Minute, time.Second)

	headers := map[string]string{"Idempotency-Key": "op-1"}
	first := partitionCall(s, "POST", "/charge", `{}`, headers)
	if first.Code != 200 {
		t.Fatalf("expected first call to succeed, got %d", first.Code)
	}
	if executions.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream execution after first call, got %d", executions.Load())
	}

	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "idempotent-secret", Pattern: regexp.MustCompile("IDEMPOTENT_SECRET"), Action: rules.Block})

	second := partitionCall(s, "POST", "/charge", `{}`, headers)
	if second.Code == 200 {
		t.Fatalf("idempotency replay bypassed a rule added after the original call: status=%d", second.Code)
	}
	if executions.Load() != 1 {
		t.Fatalf("a policy-rejected idempotency replay re-forwarded the request upstream: %d total executions (a real charge operation must never run twice)", executions.Load())
	}
}
```

`coalesceGroupForTest` doesn't exist yet — add this small helper to the same file:

```go
func coalesceGroupForTest(t *testing.T) *coalesce.Group {
	t.Helper()
	return coalesce.NewGroup(5 * time.Second)
}
```

(add `"aiproxy/internal/coalesce"` to the import block). `partitionCall` is already defined in `internal/proxy/partition_test.go` (Task 2) — no need to redefine it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy -run TestReplayPolicy_ -v`
Expected: all three FAIL — the cached/coalesced/replayed response is served with status 200 despite a rule that should block it, and idempotency's second execution count check fails only if the current code actually re-forwards (verify by reading the failure: this specific test may currently pass with `executions.Load() == 1` simply because idempotency Replay already skips forwarding today — the FAILURE this test is really pinned on is `second.Code == 200`, i.e. the replay isn't blocked at all; keep the re-forward assertion as a regression guard for the fix in Step 3, which must not accidentally introduce a re-forward where none exists today).

- [ ] **Step 3: Write `checkReplayPolicy`**

Add this helper in `internal/proxy/proxy.go`, right before `bufferResponse` (~line 3324):

```go
// checkReplayPolicy re-evaluates body — a previously-produced response
// about to be served from the exact-match cache, request coalescing,
// the semantic cache, or an idempotency replay — against the CURRENT
// rules engine, exactly as bufferResponse does for a response that just
// arrived live from upstream. Every one of ServeHTTP's replay paths
// must call this before writing stored bytes to a client: a response
// that was fine to store under an older policy — or before a rule
// existed at all — must never bypass a rule that would block or redact
// it today. See docs/reviews/2026-09-12-v0.74.1-system-review.md
// finding #2.
//
// allowed is false exactly when action is rules.Block — the caller must
// write the standard block response (see writeError's use at every call
// site below) and must NOT fall through to forwarding the request
// upstream: for idempotency replay specifically, a policy rejection on
// replay must never re-execute an operation that may have side effects
// (see finding #2's own idempotency-specific note, and finding #8's
// related concern about failover risking a duplicate execution from a
// different angle). When allowed is true, resultBody is what the
// caller should actually serve — unchanged from body for an Allow
// result, redacted for a Redact result.
func (s *Server) checkReplayPolicy(method, reqURL, requestID, targetLabel, clientLabel string, body []byte) (allowed bool, resultBody []byte, ruleName string) {
	action, ruleName, scannedBody, dryRunHits := s.getEngine().EvaluateResponse(body, targetLabel, clientLabel)
	s.handleResponseDryRunHits(dryRunHits, method, reqURL, requestID)
	switch action {
	case rules.Block:
		s.Stats.RecordResponseBlock(targetLabel, ruleName)
		s.logResponseBlock(method, reqURL, ruleName, requestID)
		s.notifyWebhook("response_block", method, reqURL, ruleName, requestID)
		return false, nil, ruleName
	case rules.Redact:
		s.Stats.RecordResponseRedact(targetLabel, ruleName)
		s.logResponseRedact(method, reqURL, ruleName, requestID)
		s.notifyWebhook("response_redact", method, reqURL, ruleName, requestID)
		return true, scannedBody, ruleName
	default:
		return true, body, ""
	}
}
```

- [ ] **Step 4: Wire it into the exact-match cache-hit branch**

Replace the whole cache-hit block in `ServeHTTP` (originally lines 2993-3026):

```go
		if cached, hit, age, err := cch.Get(cacheKey, ttl); err == nil && hit {
			defer cached.Body.Close()
			copyHeader(w.Header(), cached.Header)
			w.Header().Set("Age", strconv.Itoa(int(age.Seconds())))
			stale := cch.IsStale(age, ttl)
			w.WriteHeader(cached.StatusCode)
			if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
				cachedBody, readErr := io.ReadAll(cached.Body)
				w.Write(cachedBody)
				if readErr == nil {
					idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: cached.StatusCode, Header: cached.Header.Clone(), Body: cachedBody})
				}
			} else {
				io.Copy(w, cached.Body)
			}
			s.Stats.RecordCacheHit(targetLabel)
			if stale {
				s.Stats.RecordStaleCacheHit(targetLabel)
			}
			s.logCacheHit(r.Method, r.URL.String(), requestID, age, stale)
			return
		}
```

with:

```go
		if cached, hit, age, err := cch.Get(cacheKey, ttl); err == nil && hit {
			defer cached.Body.Close()
			cachedBody, readErr := io.ReadAll(cached.Body)
			if readErr != nil {
				writeError(w, r, http.StatusBadGateway, "cache_read_failed", "failed to read cached response", "")
				return
			}
			allowed, servedBody, ruleName := s.checkReplayPolicy(r.Method, r.URL.String(), requestID, targetLabel, auth.label, cachedBody)
			if !allowed {
				writeError(w, r, http.StatusForbidden, "response_block", "response blocked by aiproxy rules", ruleName)
				return
			}
			copyHeader(w.Header(), cached.Header)
			w.Header().Set("Age", strconv.Itoa(int(age.Seconds())))
			w.Header().Set("Content-Length", strconv.Itoa(len(servedBody)))
			stale := cch.IsStale(age, ttl)
			w.WriteHeader(cached.StatusCode)
			w.Write(servedBody)
			if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
				idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: cached.StatusCode, Header: cached.Header.Clone(), Body: servedBody})
			}
			s.Stats.RecordCacheHit(targetLabel)
			if stale {
				s.Stats.RecordStaleCacheHit(targetLabel)
			}
			s.logCacheHit(r.Method, r.URL.String(), requestID, age, stale)
			return
		}
```

- [ ] **Step 5: Wire it into the semantic-cache-hit branch**

Replace the semantic-cache-hit block (inside the `if candidateKey, similarity, found := idx.FindBest(...); found {` from Task 5):

```go
						if cached, hit, age, err := cch.Get(candidateKey, ttl); err == nil && hit {
							defer cached.Body.Close()
							copyHeader(w.Header(), cached.Header)
							w.Header().Set("Age", strconv.Itoa(int(age.Seconds())))
							w.Header().Set("X-Semantic-Cache-Hit", "true")
							w.Header().Set("X-Semantic-Cache-Similarity", strconv.FormatFloat(similarity, 'f', 2, 64))
							w.WriteHeader(cached.StatusCode)
							if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
								cachedBody, readErr := io.ReadAll(cached.Body)
								w.Write(cachedBody)
								if readErr == nil {
									idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: cached.StatusCode, Header: cached.Header.Clone(), Body: cachedBody})
								}
							} else {
								io.Copy(w, cached.Body)
							}
							s.Stats.RecordSemanticCacheHit(targetLabel)
							s.logSemanticCacheHit(r.Method, r.URL.String(), requestID, similarity)
							return
						}
```

with:

```go
						if cached, hit, age, err := cch.Get(candidateKey, ttl); err == nil && hit {
							defer cached.Body.Close()
							cachedBody, readErr := io.ReadAll(cached.Body)
							if readErr != nil {
								writeError(w, r, http.StatusBadGateway, "cache_read_failed", "failed to read cached response", "")
								return
							}
							allowed, servedBody, ruleName := s.checkReplayPolicy(r.Method, r.URL.String(), requestID, targetLabel, auth.label, cachedBody)
							if !allowed {
								writeError(w, r, http.StatusForbidden, "response_block", "response blocked by aiproxy rules", ruleName)
								return
							}
							copyHeader(w.Header(), cached.Header)
							w.Header().Set("Age", strconv.Itoa(int(age.Seconds())))
							w.Header().Set("Content-Length", strconv.Itoa(len(servedBody)))
							w.Header().Set("X-Semantic-Cache-Hit", "true")
							w.Header().Set("X-Semantic-Cache-Similarity", strconv.FormatFloat(similarity, 'f', 2, 64))
							w.WriteHeader(cached.StatusCode)
							w.Write(servedBody)
							if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
								idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: cached.StatusCode, Header: cached.Header.Clone(), Body: servedBody})
							}
							s.Stats.RecordSemanticCacheHit(targetLabel)
							s.logSemanticCacheHit(r.Method, r.URL.String(), requestID, similarity)
							return
						}
```

- [ ] **Step 6: Wire it into the coalescing-replay branch**

Replace:

```go
			switch resp, outcome := coalescer.Claim(cacheKey); outcome {
			case coalesce.Replay:
				copyHeader(w.Header(), resp.Header)
				w.WriteHeader(resp.StatusCode)
				w.Write(resp.Body)
				if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
					idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: resp.Body})
				}
				s.Stats.RecordCoalescedRequest(targetLabel)
				s.logCoalescedRequest(r.Method, r.URL.String(), requestID)
				return
```

with:

```go
			switch resp, outcome := coalescer.Claim(cacheKey); outcome {
			case coalesce.Replay:
				allowed, servedBody, ruleName := s.checkReplayPolicy(r.Method, r.URL.String(), requestID, targetLabel, auth.label, resp.Body)
				if !allowed {
					writeError(w, r, http.StatusForbidden, "response_block", "response blocked by aiproxy rules", ruleName)
					return
				}
				copyHeader(w.Header(), resp.Header)
				w.Header().Set("Content-Length", strconv.Itoa(len(servedBody)))
				w.WriteHeader(resp.StatusCode)
				w.Write(servedBody)
				if idem := s.getIdempotency(); idem != nil && idempotencyKey != "" {
					idem.Store(auth.label, idempotencyKey, &idempotency.Response{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: servedBody})
				}
				s.Stats.RecordCoalescedRequest(targetLabel)
				s.logCoalescedRequest(r.Method, r.URL.String(), requestID)
				return
```

- [ ] **Step 7: Wire it into the idempotency-replay branch**

Replace (in the `switch resp, outcome := idem.Claim(...)` near the top of `ServeHTTP`):

```go
			case idempotency.Replay:
				copyHeader(w.Header(), resp.Header)
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(resp.StatusCode)
				w.Write(resp.Body)
				s.Stats.RecordIdempotencyReplay()
				s.logIdempotencyReplay(r.Method, r.URL.String(), requestID, idempotencyKey)
				return
```

with:

```go
			case idempotency.Replay:
				allowed, servedBody, ruleName := s.checkReplayPolicy(r.Method, r.URL.String(), requestID, "", auth.label, resp.Body)
				if !allowed {
					writeError(w, r, http.StatusForbidden, "response_block", "response blocked by aiproxy rules", ruleName)
					return
				}
				copyHeader(w.Header(), resp.Header)
				w.Header().Set("Content-Length", strconv.Itoa(len(servedBody)))
				w.Header().Set("Idempotency-Replayed", "true")
				w.WriteHeader(resp.StatusCode)
				w.Write(servedBody)
				s.Stats.RecordIdempotencyReplay()
				s.logIdempotencyReplay(r.Method, r.URL.String(), requestID, idempotencyKey)
				return
```

Note the `targetLabel` argument is `""` here specifically: the idempotency check happens before route resolution (`targetLabel` isn't computed yet at that point in `ServeHTTP` — see the comment above the idempotency block: "with no need to know which target this request would otherwise have gone to"). An empty target label only affects which `Stats.RecordResponseBlock`/`RecordResponseRedact` bucket the re-check's own accounting lands in and which `BodyRegexRule.Targets` scoping applies (a rule scoped to a specific target won't match with `targetLabel == ""`, same as `inScope`'s existing empty-list-matches-everything behavior for a rule with no `Targets` set, but a rule that DOES set `Targets` will not fire here) — this is a real, narrow limitation worth a one-line code comment (add it directly above this call site) rather than a silent gap:

```go
				// targetLabel is "" here (idempotency is checked before
				// route resolution) — a rule scoped to a specific target
				// via Targets won't fire against an idempotency replay
				// specifically. A rule with no Targets set (the common
				// case, including every built-in secret/prompt-injection
				// rule) is unaffected, since inScope treats an empty
				// Targets list as matching every target.
```

- [ ] **Step 8: Run all replay-policy tests to verify they pass**

Run: `go test ./internal/proxy -run TestReplayPolicy_ -v`
Expected: PASS, all three.

- [ ] **Step 9: Run the full proxy suite**

Run: `go test ./internal/proxy/... -race -count=1`
Expected: PASS. Pay close attention to any pre-existing cache/coalescing/idempotency/semantic-cache test that asserted an exact response body or exact headers for a replay — `Content-Length` is now explicitly set on every replay path (it wasn't touched by the coalescing/idempotency replay paths before), which is a correctness fix but could make a test asserting a stale/absent `Content-Length` expectation fail; update the test's expectation rather than removing the new header write.

- [ ] **Step 10: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/replaypolicy_test.go
git commit -m "Re-evaluate current rules before serving any cached/coalesced/idempotent replay (review finding #2)"
```

---

### Task 7: `AdminAPIKey`/`AdminAPIKeys` config plumbing

**Files:**
- Modify: `internal/config/config.go` (new fields, mirroring `ProxyAPIKey`/`ProxyAPIKeys`)
- Modify: `internal/cli/cli.go` (`compileProxyAPIKeys` → `compileAPIKeys` rename with a field-name parameter; `liveConfig` struct; `buildLiveConfig`; `runStart`'s cold-start assignment; `ReloadConfig` call site)
- Modify: `internal/proxy/proxy.go` (`Server.AdminAPIKey`/`AdminAPIKeys` fields; `ReloadConfig` signature)

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestBuildLiveConfig_AdminAPIKeysCompileSeparatelyFromProxyKeys(t *testing.T) {
	cfg := &config.Config{
		AdminAPIKey:  "admin-secret",
		AdminAPIKeys: []config.ProxyAPIKeyEntry{{Name: "ops", Key: "ops-secret"}},
	}
	lc, errs := buildLiveConfig(cfg)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if lc.adminAPIKey != "admin-secret" {
		t.Fatalf("adminAPIKey = %q, want %q", lc.adminAPIKey, "admin-secret")
	}
	if len(lc.adminAPIKeys) != 1 || lc.adminAPIKeys[0].Name != "ops" {
		t.Fatalf("adminAPIKeys = %+v, want one entry named 'ops'", lc.adminAPIKeys)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/cli -run TestBuildLiveConfig_AdminAPIKeysCompileSeparatelyFromProxyKeys -v`
Expected: FAIL to compile — `config.Config` has no field `AdminAPIKey`/`AdminAPIKeys`, `liveConfig` has no field `adminAPIKey`/`adminAPIKeys`.

- [ ] **Step 3: Add config fields**

In `internal/config/config.go`, immediately after the `ProxyAPIKeys` field (after line 828):

```go
	// AdminAPIKey, if set, is required — via the same "Proxy-Authorization:
	// Bearer <key>" header and constant-time comparison as ProxyAPIKey —
	// to reach any of the five admin paths (GET /_aiproxy/stats,
	// /_aiproxy/metrics, /_aiproxy/dashboard, POST /_aiproxy/cache/clear,
	// GET/POST/DELETE /_aiproxy/drain). Once AdminAPIKey or AdminAPIKeys
	// is set, ProxyAPIKey/ProxyAPIKeys stop working against these paths
	// entirely — there is no fallback to accepting an ordinary client
	// key, regardless of whether -admin-addr is also set. Empty (the
	// default when the field is absent) means every admin path still
	// accepts ProxyAPIKey/ProxyAPIKeys instead, unchanged from before
	// this field existed — see
	// docs/reviews/2026-09-12-v0.74.1-system-review.md finding #6 for
	// why this is a real gap in a shared/multi-tenant deployment, and
	// `aiproxy validate`'s own warning when both this and AdminAPIKeys
	// are unset.
	AdminAPIKey string `json:"admin_api_key,omitempty"`

	// AdminAPIKeys lists additional named admin keys beyond AdminAPIKey,
	// the same relationship ProxyAPIKeys has to ProxyAPIKey. Reuses
	// ProxyAPIKeyEntry's shape as-is even though an admin key has no
	// practical use for MaxRequestsPerMinute/MaxTokensPerMinute/
	// CostBudget/CostBudgetHardStop — introducing a separate, narrower
	// type purely to omit fields that are simply never set on an admin
	// key would be more code for no behavioral difference.
	AdminAPIKeys []ProxyAPIKeyEntry `json:"admin_api_keys,omitempty"`
```

- [ ] **Step 4: Rename `compileProxyAPIKeys` to `compileAPIKeys` with a field-name parameter**

In `internal/cli/cli.go`, change the function signature and every hardcoded `"proxy_api_keys"` string inside its body (lines 2352-2362 onward — read the full function body first with `sed -n '2352,2420p' internal/cli/cli.go` to see every occurrence, since the doc comment above listed only the first few):

```go
// compileAPIKeys validates and resolves a config file's proxy_api_keys
// or admin_api_keys list into proxy.ProxyKey values, ready for
// Server.ProxyAPIKeys/AdminAPIKeys. fieldName ("proxy_api_keys" or
// "admin_api_keys") is used only to prefix error messages so they name
// the actual field that's wrong, regardless of which one this call is
// validating. Every entry needs a non-empty, unique name (it's the
// stats/log attribution label, so a collision would silently merge two
// different callers' numbers together — "default" is reserved for the
// anonymous top-level proxy_api_key, so it's rejected here too, even
// for an admin_api_keys entry, for the same collision reason) and a
// non-empty, unique key; max_requests_per_minute, if set, must not be
// negative and compiles into that key's own dedicated limiter, checked
// instead of whatever route/global limiter would otherwise apply for
// that caller.
func compileAPIKeys(fieldName string, entries []config.ProxyAPIKeyEntry, costPer1KTokens float64) ([]proxy.ProxyKey, []error) {
```

Inside the body, replace every literal `"proxy_api_keys:` with `fieldName + ":` — for example:

```go
			errs = append(errs, fmt.Errorf("proxy_api_keys: name must not be empty"))
```

becomes:

```go
			errs = append(errs, fmt.Errorf("%s: name must not be empty", fieldName))
```

Apply the same `fmt.Errorf("proxy_api_keys: ...")` → `fmt.Errorf("%s: ...", fieldName, ...)` transformation to every error in the function body (there are roughly 8-10; `grep -n '"proxy_api_keys' internal/cli/cli.go` after this step should show zero remaining literal occurrences inside the function body — only the doc comment and unrelated config-field doc comments elsewhere in the file may still legitimately mention the literal string).

- [ ] **Step 5: Update the two existing `compileProxyAPIKeys` call sites**

Line 683 (`buildLiveConfig`):

```go
	proxyAPIKeys, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
```

becomes:

```go
	proxyAPIKeys, proxyKeyErrs := compileAPIKeys("proxy_api_keys", cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
```

and immediately after (still in `buildLiveConfig`, near where `lc.proxyAPIKeys = proxyAPIKeys` is assigned at what was line 685), add:

```go
	adminAPIKeys, adminKeyErrs := compileAPIKeys("admin_api_keys", cfg.AdminAPIKeys, 0)
	errs = append(errs, adminKeyErrs...)
	lc.adminAPIKey = cfg.AdminAPIKey
	lc.adminAPIKeys = adminAPIKeys
```

(check the exact local variable name `buildLiveConfig` uses to accumulate errors — likely `errs` given the function returns `(*liveConfig, []error)`; `grep -n "errs = append(errs" internal/cli/cli.go | head -5` to confirm the pattern already in use nearby, and match it).

Line 1414 (`runValidate`):

```go
	_, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
	for _, e := range proxyKeyErrs {
		problems = append(problems, e.Error())
	}
```

becomes:

```go
	_, proxyKeyErrs := compileAPIKeys("proxy_api_keys", cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
	for _, e := range proxyKeyErrs {
		problems = append(problems, e.Error())
	}
	_, adminKeyErrs := compileAPIKeys("admin_api_keys", cfg.AdminAPIKeys, 0)
	for _, e := range adminKeyErrs {
		problems = append(problems, e.Error())
	}
```

- [ ] **Step 6: Add `adminAPIKey`/`adminAPIKeys` to `liveConfig`, `Server`, and both wiring points**

In `internal/cli/cli.go`, add to the `liveConfig` struct (next to `proxyAPIKeys []proxy.ProxyKey`, line 560):

```go
	adminAPIKey  string
	adminAPIKeys []proxy.ProxyKey
```

In `internal/proxy/proxy.go`, add to the `Server` struct, right after the `ProxyAPIKeys` field (after line 677 — find it via `grep -n "ProxyAPIKeys \[\]ProxyKey" internal/proxy/proxy.go`):

```go
	// AdminAPIKey, if set, is required to reach any of the five admin
	// paths (stats, metrics, dashboard, cache-clear, drain) — checked by
	// checkAdminAuth instead of checkProxyAuth, completely independent
	// of ProxyAPIKey/ProxyAPIKeys. See config.Config.AdminAPIKey's own
	// doc comment for the fail-closed behavior once this (or
	// AdminAPIKeys) is set at all.
	AdminAPIKey string

	// AdminAPIKeys lists additional named admin keys beyond AdminAPIKey,
	// the same relationship ProxyAPIKeys has to ProxyAPIKey. Reuses
	// ProxyKey's shape as-is — see config.Config.AdminAPIKeys' own doc
	// comment for why.
	AdminAPIKeys []ProxyKey
```

In `internal/cli/cli.go`'s `runStart` (next to line 217-218):

```go
	server.ProxyAPIKey = lc.proxyAPIKey
	server.ProxyAPIKeys = lc.proxyAPIKeys
	server.AdminAPIKey = lc.adminAPIKey
	server.AdminAPIKeys = lc.adminAPIKeys
```

- [ ] **Step 7: Extend `ReloadConfig`'s signature and its one call site**

In `internal/proxy/proxy.go`, `ReloadConfig`'s parameter list (line 2133) is one long list ending in `..., semanticIndex *semcache.Index, semanticCacheThreshold float64)`. Add two more parameters at the end:

```go
func (s *Server) ReloadConfig(engine *rules.Engine, lim *limiter.Limiter, cch *cache.Cache, costPer1KTokens, costBudget float64, maxBodyBytes int64, webhookURL *url.URL, webhooks []WebhookTarget, proxyAPIKey string, proxyAPIKeys []ProxyKey, logFile *os.File, routes []Route, modelRoutes []ModelRoute, ipAllowList, ipDenyList []*net.IPNet, tokenLim *limiter.TokenLimiter, geoIPTable *geoip.Table, countryAllowList, countryDenyList []string, anomalyDetector *anomaly.Registry, anomalyDryRun bool, upstreamTransport *http.Transport, upstreamTotalTimeout time.Duration, targetBreaker *breaker.Registry, cors *CORSConfig, healthCheckInterval time.Duration, healthCheckPath string, targetCostRates map[string]float64, ipLimiter *iplimiter.Registry, cacheTTL time.Duration, targetCacheTTL map[string]time.Duration, targetCacheEnabled map[string]bool, targetShadowURL map[string]*url.URL, targetShadowSampleRate map[string]float64, costBudgetHardStop bool, idempotencyRegistry *idempotency.Registry, coalescer *coalesce.Group, semanticIndex *semcache.Index, semanticCacheThreshold float64, adminAPIKey string, adminAPIKeys []ProxyKey) {
```

Inside the function body, find where `s.ProxyAPIKeys = proxyAPIKeys` is assigned (line 2155) and add right after it:

```go
	s.ProxyAPIKeys = proxyAPIKeys
	s.AdminAPIKey = adminAPIKey
	s.AdminAPIKeys = adminAPIKeys
```

In `internal/cli/cli.go`, the single production `server.ReloadConfig(...)` call site (line 523) — add `lc.adminAPIKey, lc.adminAPIKeys` at the end of the argument list, matching the two new trailing parameters.

This signature change breaks every OTHER call site too — run `grep -rn "\.ReloadConfig(" internal/` right now, before touching anything else, to get the full list. As of this task there are 20 total: the one production call site above, plus 19 test call sites across `internal/proxy/proxy_test.go`, `internal/proxy/semanticcache_test.go`, `internal/proxy/idempotency_test.go`, and `internal/proxy/coalesce_test.go` (re-run the `grep` yourself rather than trusting this exact count — earlier tasks in this plan may have added a `ReloadConfig` call of their own). Every one of the 19 test calls ends with a literal `..., nil, nil, nil, 0)`-shaped tail (idempotencyRegistry, coalescer, semanticIndex, semanticCacheThreshold — sometimes non-nil/non-zero values for the specific field that test exercises, but always exactly 4 trailing values before the final `)`). For each one, insert `, "", nil` immediately before that final closing `)`, appending the two new `adminAPIKey string, adminAPIKeys []ProxyKey` arguments as empty/nil (no existing test in this list is about admin keys — Task 8's own tests construct a `Server` directly and set `s.AdminAPIKey`/`s.AdminAPIKeys` as struct fields instead of going through `ReloadConfig`, so none of these 19 need a real value here).

Do this call-site-by-call-site with your editor, not a blind repo-wide `sed` — a long positional-argument call is exactly the shape where a regex substitution can silently corrupt an unrelated line. After editing all 20, confirm you got every one:

Run: `go build ./... 2>&1 | grep ReloadConfig`
Expected: no output at all — every call site now supplies the right argument count.

- [ ] **Step 8: Add a `ReloadConfig` hot-swap test for the new admin fields**

Mirror the existing `TestServer_ReloadConfig_SwapsProxyAPIKeysLive` (`internal/proxy/proxy_test.go`, ~line 7153) exactly — same shape, but swapping in an admin key instead of a proxy key, and asserting against an admin path instead of ordinary traffic. Create `internal/proxy/adminauth_test.go` now with this one test (Task 8, which runs after this task, appends its own admin-auth tests to this same file — do not let Task 8 overwrite this one):

```go
func TestServer_ReloadConfig_SwapsAdminAPIKeyLive(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	engine := rules.NewEngine(rules.Allow)
	srv := proxy.New("unused", targetURL, engine)
	srv.AdminAPIKey = "old-admin-key"
	srv.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(srv)
	defer frontend.Close()

	srv.ReloadConfig(engine, nil, nil, 0, 0, 0, nil, nil, "", nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, false, proxy.NewUpstreamTransport(0), 0, nil, nil, 0, "", nil, nil, 0, nil, nil, nil, nil, false, nil, nil, nil, 0, "new-admin-key", nil)

	do := func(key string) int {
		req, err := http.NewRequest(http.MethodGet, frontend.URL+"/_aiproxy/stats", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("Proxy-Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	if code := do("old-admin-key"); code == http.StatusOK {
		t.Fatalf("old admin key still worked after reload: status %d", code)
	}
	if code := do("new-admin-key"); code != http.StatusOK {
		t.Fatalf("new admin key rejected after reload: status %d", code)
	}
}
```

(add whatever imports this file doesn't already have — `net/http/httptest`, `net/url`, `log`, `io`, `aiproxy/internal/rules` — check `internal/proxy/adminauth_test.go`'s existing import block from Task 8 first if that task already ran).

- [ ] **Step 9: Run tests to verify they pass**

Run: `go test ./internal/cli -run TestBuildLiveConfig_AdminAPIKeysCompileSeparatelyFromProxyKeys -v && go test ./internal/proxy -run TestServer_ReloadConfig_SwapsAdminAPIKeyLive -v`
Expected: PASS, both.

- [ ] **Step 10: Run the full cli and proxy suites**

Run: `go build ./... && go test ./internal/cli/... ./internal/proxy/... -count=1`
Expected: PASS. This was a large mechanical signature change touching a very long parameter list across 20 call sites (Step 7) — a build failure here almost always means one of them was missed; re-run `go build ./... 2>&1 | grep ReloadConfig` to find it.

- [ ] **Step 11: Commit**

```bash
git add internal/config/config.go internal/cli/cli.go internal/cli/cli_test.go internal/proxy/proxy.go internal/proxy/adminauth_test.go
git commit -m "Add AdminAPIKey/AdminAPIKeys config plumbing, independent of ProxyAPIKey(s) (review finding #6)"
```

---

### Task 8: `checkAdminAuth` and the network/auth-check split

**Files:**
- Modify: `internal/proxy/proxy.go` (`checkNetworkAndAuthAccess` split; new `checkAdminAuth`, `checkNetworkAndAdminAuthAccess`; `ServeHTTP`/`adminMux.ServeHTTP` dispatch)
- Test: `internal/proxy/adminauth_test.go` (already exists from Task 7 — append to it)

- [ ] **Step 1: Write the failing test**

`internal/proxy/adminauth_test.go` already exists (Task 7 created it with `TestServer_ReloadConfig_SwapsAdminAPIKeyLive`) — append these tests and helper to the same file, do not overwrite it. The code block below repeats a full `package`/`import` header for readability here in the plan, but when you actually edit the file, merge its `import` block with the one already there instead of writing two — Go rejects a file with the `package` line or any import path declared twice:

```go
package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func adminAuthTestServer(t *testing.T) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	return s
}

func TestAdminAuth_OrdinaryProxyKeyCannotReachDrain(t *testing.T) {
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "POST", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code == 200 {
		t.Fatalf("ordinary proxy client key reached /_aiproxy/drain: %s", got.Body.String())
	}
}

func TestAdminAuth_AdminKeyCanReachDrain(t *testing.T) {
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "GET", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer admin-secret"})
	if got.Code != 200 {
		t.Fatalf("admin key rejected from /_aiproxy/drain: status=%d body=%q", got.Code, got.Body.String())
	}
}

func TestAdminAuth_AdminKeyCannotReachOrdinaryProxyTraffic(t *testing.T) {
	// An admin key is not a proxy key: it must not be usable to send
	// ordinary proxied traffic when proxy_api_key(s) are configured.
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "GET", "/chat", "", map[string]string{"Proxy-Authorization": "Bearer admin-secret"})
	if got.Code == 200 {
		t.Fatalf("admin key was accepted for ordinary proxy traffic: %s", got.Body.String())
	}
}

func TestAdminAuth_NoAdminKeyConfigured_OrdinaryProxyKeyStillWorksForAdminPaths(t *testing.T) {
	// Backward compatibility: a deployment that hasn't adopted
	// admin_api_key/admin_api_keys yet keeps today's behavior.
	s := adminAuthTestServer(t)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	got := partitionCall(s, "GET", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code != 200 {
		t.Fatalf("expected backward-compatible admin access with no admin key configured, got status=%d body=%q", got.Code, got.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy -run TestAdminAuth_ -v`
Expected: `TestAdminAuth_OrdinaryProxyKeyCannotReachDrain` and `TestAdminAuth_AdminKeyCanReachDrain` FAIL (today's code has no notion of `AdminAPIKey` at all, so `checkProxyAuth` accepts the ordinary client key for `/_aiproxy/drain` and rejects the never-configured-as-a-proxy-key "admin-secret"). The other two should already PASS by coincidence (today's single-key-set behavior), confirming they're genuine backward-compatibility guards, not new behavior.

- [ ] **Step 3: Split `checkNetworkAndAuthAccess`**

In `internal/proxy/proxy.go`, replace the whole `checkNetworkAndAuthAccess` function (lines 2703-2790) with three functions: a shared network-only gate, and two thin auth-specific wrappers.

```go
// checkNetworkAccess runs the three independent network-level gates
// every request — whether ordinary proxy traffic or a request for the
// admin surface — must pass before any credential is even checked: the
// IP allow/deny list, the GeoIP country allow/deny list, and the per-IP
// rate limiter, in that order, responding and returning false at the
// first one that rejects the request. No opinion on which credential
// (if any) the caller must present — see checkNetworkAndAuthAccess and
// checkNetworkAndAdminAuthAccess, its only two callers, for that.
//
// CORS handling — applying Access-Control-Allow-Origin and friends, and
// short-circuiting a preflight entirely — runs first, before any of the
// three gates: see corsPreflightRequest's doc comment for why.
//
// requestID is this request's own correlation ID — see
// resolveRequestID — already resolved and already stamped as the
// X-Request-Id response header by the caller before this runs, so it's
// available for every rejection this function can produce too.
func (s *Server) checkNetworkAccess(w http.ResponseWriter, r *http.Request, requestID string) bool {
	w.Header().Set(requestIDHeader, requestID)
	if cors := s.getCORSConfig(); cors != nil {
		applyCORSHeaders(cors, w.Header(), r)
		if corsPreflightRequest(r) {
			handleCORSPreflight(cors, w, r)
			return false
		}
	}
	if !s.checkIPAccess(r) {
		s.Stats.RecordIPDenied()
		s.logIPDenied(r.RemoteAddr, r.Method, r.URL.String(), requestID)
		s.notifyIPDeniedWebhook(r.RemoteAddr, r.Method, r.URL.String(), requestID)
		writeError(w, r, http.StatusForbidden, "ip_denied", "access denied", "")
		return false
	}
	if allowed, country := s.checkCountryAccess(r); !allowed {
		s.Stats.RecordCountryDenied()
		s.logCountryDenied(r.RemoteAddr, country, r.Method, r.URL.String(), requestID)
		s.notifyCountryDeniedWebhook(r.RemoteAddr, country, r.Method, r.URL.String(), requestID)
		writeError(w, r, http.StatusForbidden, "country_denied", "access denied", "")
		return false
	}

	if ipLimiter := s.getIPLimiter(); ipLimiter != nil {
		ip := clientIP(r)
		if ip == nil {
			s.Stats.RecordIPRateLimited()
			s.logIPRateLimited(r.RemoteAddr, r.Method, r.URL.String(), requestID)
			s.notifyIPRateLimitedWebhook(r.RemoteAddr, r.Method, r.URL.String(), requestID)
			writeError(w, r, http.StatusTooManyRequests, "ip_rate_limited", "rate limit exceeded", "")
			return false
		}
		ipStr := ip.String()
		allowed := ipLimiter.Allow(ipStr)
		max, remaining, resetIn := ipLimiter.Info(ipStr)
		setRateLimitHeaders(w, "Ip", max, remaining, resetIn)
		if !allowed {
			s.Stats.RecordIPRateLimited()
			s.logIPRateLimited(r.RemoteAddr, r.Method, r.URL.String(), requestID)
			s.notifyIPRateLimitedWebhook(r.RemoteAddr, r.Method, r.URL.String(), requestID)
			w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(resetIn)))
			writeError(w, r, http.StatusTooManyRequests, "ip_rate_limited", "rate limit exceeded", "")
			return false
		}
	}
	return true
}

// checkNetworkAndAuthAccess runs checkNetworkAccess, then ordinary
// proxy_api_key/proxy_api_keys authentication (checkProxyAuth) — used
// for every request except the five admin paths; see
// checkNetworkAndAdminAuthAccess for those.
func (s *Server) checkNetworkAndAuthAccess(w http.ResponseWriter, r *http.Request, requestID string) (clientAuth, bool) {
	if !s.checkNetworkAccess(w, r, requestID) {
		return clientAuth{}, false
	}
	auth, ok := s.checkProxyAuth(r)
	if !ok {
		s.Stats.RecordUnauthorized()
		s.logUnauthorized(r.Method, r.URL.String(), requestID)
		s.notifyWebhook("unauthorized", r.Method, r.URL.String(), "", requestID)
		w.Header().Set("Proxy-Authenticate", strings.TrimSpace(proxyAuthScheme))
		writeError(w, r, http.StatusProxyAuthRequired, "unauthorized", "proxy authentication required", "")
		return clientAuth{}, false
	}
	return auth, true
}

// checkNetworkAndAdminAuthAccess runs checkNetworkAccess, then
// checkAdminAuth instead of checkProxyAuth — used for exactly the five
// admin paths (statsPath, metricsPath, dashboardPath, cacheClearPath,
// drainPath), in both ServeHTTP and adminMux.ServeHTTP, so the two
// dispatch paths keep sharing identical network-level gating while
// diverging only on which credential they require. See
// docs/reviews/2026-09-12-v0.74.1-system-review.md finding #6.
func (s *Server) checkNetworkAndAdminAuthAccess(w http.ResponseWriter, r *http.Request, requestID string) (clientAuth, bool) {
	if !s.checkNetworkAccess(w, r, requestID) {
		return clientAuth{}, false
	}
	auth, ok := s.checkAdminAuth(r)
	if !ok {
		s.Stats.RecordUnauthorized()
		s.logUnauthorized(r.Method, r.URL.String(), requestID)
		s.notifyWebhook("unauthorized", r.Method, r.URL.String(), "", requestID)
		w.Header().Set("Proxy-Authenticate", strings.TrimSpace(proxyAuthScheme))
		writeError(w, r, http.StatusProxyAuthRequired, "unauthorized", "proxy authentication required", "")
		return clientAuth{}, false
	}
	return auth, true
}
```

- [ ] **Step 4: Write `checkAdminAuth`**

Add right after `checkProxyAuth` (after line 2306, before `partitionIdentity` if Task 2 already placed it there — either order is fine, just keep both together):

```go
// checkAdminAuth reports whether r is allowed to reach the admin
// surface, mirroring checkProxyAuth's constant-time comparison logic
// exactly but against Server.AdminAPIKey/AdminAPIKeys instead of
// ProxyAPIKey/ProxyAPIKeys — entirely independent credential sets, so
// an ordinary client key never authenticates here and an admin key
// never authenticates against checkProxyAuth. Backward compatible by
// design: when neither AdminAPIKey nor AdminAPIKeys is configured, this
// falls back to checkProxyAuth's own result unchanged — a deployment
// that hasn't adopted admin_api_key/admin_api_keys yet keeps today's
// behavior (any valid proxy key still reaches the admin surface) rather
// than being locked out by a config it never opted into. Once either is
// configured, that fallback stops: see config.Config.AdminAPIKey's own
// doc comment for the fail-closed reasoning.
func (s *Server) checkAdminAuth(r *http.Request) (clientAuth, bool) {
	s.mu.RLock()
	adminAPIKey, adminAPIKeys := s.AdminAPIKey, s.AdminAPIKeys
	s.mu.RUnlock()
	if adminAPIKey == "" && len(adminAPIKeys) == 0 {
		return s.checkProxyAuth(r)
	}

	got := r.Header.Get("Proxy-Authorization")
	if !strings.HasPrefix(got, proxyAuthScheme) {
		return clientAuth{}, false
	}
	got = strings.TrimPrefix(got, proxyAuthScheme)
	gotBytes := []byte(got)

	if adminAPIKey != "" && subtle.ConstantTimeCompare(gotBytes, []byte(adminAPIKey)) == 1 {
		return clientAuth{label: "default"}, true
	}
	for _, k := range adminAPIKeys {
		if subtle.ConstantTimeCompare(gotBytes, []byte(k.Key)) == 1 {
			return clientAuth{label: k.Name}, true
		}
	}
	return clientAuth{}, false
}
```

Check how `getProxyAPIKeys` (line 1822) reads `s.ProxyAPIKey`/`s.ProxyAPIKeys` — it's very likely guarded by a mutex for hot-reload safety (`grep -n "func (s \*Server) getProxyAPIKeys" -A 5 internal/proxy/proxy.go` to see the exact lock field name, e.g. `s.mu`). Use the *same* lock `getProxyAPIKeys` uses, not a newly-invented one — if it's a named field other than `s.mu`, or if it's a different accessor pattern entirely (a `getAdminAPIKeys()`-style method the way `getCoalescer()`/`getSemanticIndex()` exist for other reloadable fields), follow that exact existing convention instead of the sketch above. Add a matching `getAdminAPIKeys() (string, []ProxyKey)` accessor alongside `getProxyAPIKeys` if that's the pattern in use, and call it from `checkAdminAuth` instead of touching `s.AdminAPIKey`/`s.AdminAPIKeys` directly.

- [ ] **Step 5: Update `ServeHTTP` and `adminMux.ServeHTTP` dispatch**

In `ServeHTTP`, the five admin-path checks currently happen AFTER a single `checkNetworkAndAuthAccess` call shared with ordinary traffic (lines 2845-2868). Restructure so the admin paths are checked, and gated, before the ordinary-traffic auth call:

```go
	requestID := resolveRequestID(r)

	if isReservedAdminPath(r.URL.Path) {
		auth, ok := s.checkNetworkAndAdminAuthAccess(w, r, requestID)
		if !ok {
			return
		}
		switch r.URL.Path {
		case statsPath:
			s.serveStats(w, r)
		case metricsPath:
			s.serveMetrics(w, r)
		case dashboardPath:
			s.serveDashboard(w, r)
		case cacheClearPath:
			s.serveCacheClear(w, r)
		case drainPath:
			s.serveDrain(w, r)
		}
		_ = auth // admin requests are not attributed the way client traffic is; see serveStats/serveDrain for their own accounting, if any
		return
	}

	auth, ok := s.checkNetworkAndAuthAccess(w, r, requestID)
	if !ok {
		return
	}
```

Check `isReservedAdminPath`'s exact definition (`grep -n "func isReservedAdminPath" -A 5 internal/proxy/proxy.go`) — it should already list exactly `statsPath, metricsPath, dashboardPath, cacheClearPath, drainPath` (used today at line 2835 for the `AdminAddr`-set case); reuse it here rather than re-listing the five paths a third time. If `serveStats`/`serveDrain`/etc. take no `auth` parameter today (check their signatures — they almost certainly don't, since admin operations were never previously attributed to a specific caller), drop the `_ = auth` line entirely rather than introducing a genuinely unused variable; only keep it if `go vet`/the compiler actually flags `auth` as unused after removing it, which shouldn't happen since the `if !ok { return }` check itself consumes it as the tuple's first value regardless — declare it as `_, ok := s.checkNetworkAndAdminAuthAccess(...)` instead so there's no unused-variable question in the first place.

Now update `adminMux.ServeHTTP` (lines 2802-2825) identically — it currently calls the plain `checkNetworkAndAuthAccess`; change that one call to `checkNetworkAndAdminAuthAccess`:

```go
func (h adminMux) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := h.server
	if r.URL.Path == healthzPath {
		s.serveHealthz(w, r)
		return
	}
	if _, ok := s.checkNetworkAndAdminAuthAccess(w, r, resolveRequestID(r)); !ok {
		return
	}
	// ... existing switch on statsPath/metricsPath/dashboardPath/cacheClearPath/drainPath unchanged below
```

- [ ] **Step 6: Run all admin-auth tests to verify they pass**

Run: `go test ./internal/proxy -run TestAdminAuth_ -v`
Expected: PASS, all four.

- [ ] **Step 7: Run the full proxy suite**

Run: `go test ./internal/proxy/... -race -count=1`
Expected: PASS — pay special attention to any pre-existing drain/stats/dashboard/cache-clear test, since the dispatch restructuring in Step 5 changes control flow (admin paths now short-circuit before `checkNetworkAndAuthAccess` runs at all) even though the net authorization behavior for a proxy-key-only deployment is unchanged (Step 4's fallback).

- [ ] **Step 8: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/adminauth_test.go
git commit -m "Add checkAdminAuth, gate the five admin paths independently of ordinary proxy keys (review finding #6)"
```

---

### Task 9: `aiproxy validate` warns when no admin key is configured

**Files:**
- Modify: `internal/cli/cli.go` (`runValidate`, after the `len(problems) > 0` early-return block, before the success summary)

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/cli_test.go`:

```go
func TestExecute_Validate_NoAdminKeyConfigured_WarnsAboutAdminPathExposure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(configPath, []byte(`{"proxy_api_key":"secret"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"validate", "-config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "admin_api_key") {
		t.Fatalf("expected a warning mentioning admin_api_key, got: %q", stdout.String())
	}
}

func TestExecute_Validate_AdminKeyConfigured_NoWarning(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "aiproxy.json")
	if err := os.WriteFile(configPath, []byte(`{"proxy_api_key":"secret","admin_api_key":"admin-secret"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := Execute([]string{"validate", "-config", configPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), "WARNING") {
		t.Fatalf("expected no warning with admin_api_key configured, got: %q", stdout.String())
	}
}
```

Check the exact existing helper used by other `runValidate` tests in this file for invoking validate and capturing output (`grep -n "func TestExecute_Validate_" internal/cli/cli_test.go | head -3`, then read one to confirm whether it's really a top-level `Execute([]string{...}, ...)` call or some other harness) — match whatever pattern is already established rather than the `Execute(...)` sketch above if it differs.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cli -run 'TestExecute_Validate_NoAdminKeyConfigured|TestExecute_Validate_AdminKeyConfigured' -v`
Expected: `TestExecute_Validate_NoAdminKeyConfigured_WarnsAboutAdminPathExposure` FAILs (no such warning exists yet); the other passes trivially (no warning text exists anywhere yet, so "no WARNING substring" is vacuously true) — that's fine, it becomes a real regression guard once Step 3 adds the warning.

- [ ] **Step 3: Add the warning**

In `runValidate`, right after the success line `fmt.Fprintf(stdout, "%s is valid.\n", loadedFrom)` (originally line 1434) and before the summary field dump, add:

```go
	if cfg.AdminAPIKey == "" && len(cfg.AdminAPIKeys) == 0 {
		fmt.Fprintln(stdout, "WARNING: admin_api_key/admin_api_keys are not set — /_aiproxy/drain, /_aiproxy/cache/clear, /_aiproxy/stats, /_aiproxy/metrics, and /_aiproxy/dashboard currently accept any configured proxy_api_key/proxy_api_keys (or, if none are configured, anyone who can reach the proxy at all). Set admin_api_key or admin_api_keys to require a separate credential for these operations.")
	}
```

Also add one line to the summary field dump (next to the existing `additional proxy keys:` line at what was line 1462):

```go
	fmt.Fprintf(stdout, "  admin authentication:    %v\n", cfg.AdminAPIKey != "" || len(cfg.AdminAPIKeys) > 0)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cli -run 'TestExecute_Validate_NoAdminKeyConfigured|TestExecute_Validate_AdminKeyConfigured' -v`
Expected: PASS, both.

- [ ] **Step 5: Run the full cli suite**

Run: `go test ./internal/cli/... -count=1`
Expected: PASS. If any pre-existing `runValidate`-output-snapshot-style test breaks because it did an exact full-stdout comparison, update its expected string to include the new warning line/summary field — do not remove the warning to make an old snapshot pass.

- [ ] **Step 6: Commit**

```bash
git add internal/cli/cli.go internal/cli/cli_test.go
git commit -m "aiproxy validate warns when no admin key is configured (review finding #6)"
```

---

### Task 10: Port the four relevant review reproduction tests as permanent regression tests

**Files:**
- Create: `internal/proxy/reviewfindings_test.go`

The four tests below are adapted from `docs/reviews/2026-09-12-v0.74.1-repro/review_findings_test.go.txt`, updated for this phase's new function signatures, and trimmed to only the four findings this phase actually covers (do NOT port `TestReview_SemanticCacheMustRespectModelAndStream`'s sibling tests from later findings — those stay in the `.txt` file for their own future phases). These are largely redundant with tests already written in Tasks 2/6/8 above using different helper names — that's intentional: this file exists specifically so the review's own named tests (referenced by name in the review document) become permanent, greppable regression coverage under their original names, not just equivalent coverage under this plan's own helper names.

- [ ] **Step 1: Write the tests**

Create `internal/proxy/reviewfindings_test.go`:

```go
package proxy_test

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/cache"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
)

func reviewServer(t *testing.T, handler http.HandlerFunc) *proxy.Server {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	u, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", u, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	return s
}

func reviewCache(t *testing.T, s *proxy.Server) {
	t.Helper()
	t.Chdir(t.TempDir())
	c, err := cache.New()
	if err != nil {
		t.Fatal(err)
	}
	s.Cache = c
}

func TestReview_CacheMustIsolateCredentials(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "private response for "+r.Header.Get("Authorization"))
	})
	reviewCache(t, s)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "alice", Key: "alice-proxy"}, {Name: "bob", Key: "bob-proxy"}}
	a := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer alice-proxy", "Authorization": "Bearer alice-upstream"})
	b := partitionCall(s, "GET", "/account", "", map[string]string{"Proxy-Authorization": "Bearer bob-proxy", "Authorization": "Bearer bob-upstream"})
	if a.Code != 200 || b.Code != 200 {
		t.Fatalf("unexpected status %d/%d", a.Code, b.Code)
	}
	if strings.Contains(b.Body.String(), "alice-upstream") {
		t.Fatalf("Bob received Alice's cached response: %q", b.Body.String())
	}
}

func TestReview_CacheMustEnforceClientRules(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "allowed answer") })
	reviewCache(t, s)
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "alice", Key: "alice-proxy"}, {Name: "bob", Key: "bob-proxy"}}
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "bob-restriction", Pattern: regexp.MustCompile("restricted"), Action: rules.Block, Keys: []string{"bob"}})
	partitionCall(s, "POST", "/chat", "restricted", map[string]string{"Proxy-Authorization": "Bearer alice-proxy"})
	b := partitionCall(s, "POST", "/chat", "restricted", map[string]string{"Proxy-Authorization": "Bearer bob-proxy"})
	if b.Code != 403 {
		t.Fatalf("Bob bypassed key-scoped block through cache: status %d, body %q", b.Code, b.Body.String())
	}
}

func TestReview_SemanticCacheMustRespectModelAndStream(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { b, _ := io.ReadAll(r.Body); fmt.Fprint(w, string(b)) })
	reviewCache(t, s)
	s.SemanticIndex = semcache.NewIndex(100)
	s.SemanticCacheThreshold = 0.99
	a := `{"model":"model-a","stream":false,"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	b := `{"model":"model-b","stream":true,"messages":[{"role":"user","content":"Explain the capital of Sweden"}]}`
	partitionCall(s, "POST", "/chat", a, nil)
	got := partitionCall(s, "POST", "/chat", b, nil)
	if got.Header().Get("X-Semantic-Cache-Hit") == "true" {
		t.Fatalf("model-b stream request replayed model-a non-stream response: %s", got.Body.String())
	}
}

func TestReview_ClientKeyMustNotControlDrain(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	s.ProxyAPIKeys = []proxy.ProxyKey{{Name: "ordinary-client", Key: "client-key"}}
	s.AdminAPIKey = "admin-secret"
	got := partitionCall(s, "POST", "/_aiproxy/drain", "", map[string]string{"Proxy-Authorization": "Bearer client-key"})
	if got.Code == 200 {
		t.Fatalf("ordinary proxy client can initiate global drain: %s", got.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they pass immediately**

Run: `go test ./internal/proxy -run TestReview_ -v`
Expected: PASS, all four — every fix they exercise was already implemented and tested (under different test names/helpers) in Tasks 2, 5, 6, and 8. This task adds no new production code, only permanent, review-referenceable regression coverage under the review's own original test names.

If any of the four fails, that's a real signal a fix from an earlier task is incomplete for this specific input shape — do not adapt the test to match broken behavior; go back to the relevant earlier task and fix the underlying code.

- [ ] **Step 3: Verify against the ORIGINAL, unmodified reproduction file to confirm these really are the same four checks**

Run: `diff <(sed -n '55,69p;71,81p;83,95p;121,128p' docs/reviews/2026-09-12-v0.74.1-repro/review_findings_test.go.txt) /dev/null` — this won't produce a clean diff (the ported versions use `partitionCall`/updated `AdminAPIKey` instead of the original's own inline helpers), so instead just read both side by side once and confirm the four ported functions assert the same thing the original four do. This is a manual sanity check, not an automated step.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/reviewfindings_test.go
git commit -m "Port the 4 Phase-1 review reproduction tests as permanent regression coverage"
```

---

### Task 11: README documentation

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Document `admin_api_key`/`admin_api_keys`**

Find the README's existing documentation of `proxy_api_key`/`proxy_api_keys` (`grep -n "proxy_api_key" README.md | head -5`) and add a new subsection immediately after it, following that section's existing style (a short paragraph plus a config example):

```markdown
### Admin authentication

`admin_api_key` and `admin_api_keys` gate the five admin paths — `GET
/_aiproxy/stats`, `/_aiproxy/metrics`, `/_aiproxy/dashboard`, `POST
/_aiproxy/cache/clear`, and `GET`/`POST`/`DELETE` `/_aiproxy/drain` —
completely independently of `proxy_api_key`/`proxy_api_keys`. Once either is
set, an ordinary client proxy key stops working against these paths
entirely: there is no fallback, regardless of whether `-admin-addr` is also
configured. Leave both unset to keep today's behavior (any configured proxy
key, or no authentication at all if none is configured, can reach the admin
surface) — `aiproxy validate` warns when this is the case.

```jsonc
{
  "admin_api_key": "a-separate-secret-from-any-client-key",
  "admin_api_keys": [
    { "name": "ops-oncall", "key": "..." }
  ]
}
```
```

- [ ] **Step 2: Extend the cache/coalescing/semantic-cache sections**

Find the README's `### Semantic cache` section (added in the prior feature cycle) and the response-cache/coalescing documentation, and add one sentence to each:

To the cache section: "Cache entries are partitioned by the authenticated client and the credential presented to the upstream target — two different callers, or two different upstream credentials from the same caller, never share a cached response."

To the coalescing section (if it's a separate subsection; otherwise fold into the same sentence as the cache one, since coalescing reuses the cache's own key): "Request coalescing shares the cache's own partitioning, so two different callers' concurrent identical requests are never collapsed into one."

To the semantic cache section: "A semantic cache hit additionally requires an exact match on everything except the prompt text itself — model, streaming mode, message roles, tool definitions, response format, and generation parameters all must agree; only the free-text prompt content is matched approximately."

Add one more sentence, wherever the README already documents cache/coalescing/semantic-cache/idempotency behavior generally: "Every cached, coalesced, or idempotency-replayed response is re-checked against the currently active rules before being served — a response that was fine to store under an older policy, or before a rule existed, is blocked or redacted exactly as a live response would be if it no longer passes."

- [ ] **Step 3: Verify formatting**

Run: `grep -c "^#" README.md` before and after to confirm no heading levels were accidentally broken, and visually skim the diff (`git diff README.md`) for stray Markdown issues.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "Document admin_api_key/admin_api_keys and Phase 1 cache/replay isolation behavior"
```

---

### Task 12: Full verification and self-review

**Files:** none (verification only)

- [ ] **Step 1: Full test suite, race detector on**

Run: `go test ./... -race -count=1`
Expected: PASS, every package.

- [ ] **Step 2: Vet and build**

Run: `go vet ./... && go build ./...`
Expected: clean, no output, exit code 0.

- [ ] **Step 3: Re-run the review's own original (unmodified) reproduction tests one more time, against this branch, to confirm all four Phase-1-relevant ones now pass**

```bash
cp docs/reviews/2026-09-12-v0.74.1-repro/review_findings_test.go.txt /tmp/review_findings_test.go
```

Edit the copy at `/tmp/review_findings_test.go` to delete every test function EXCEPT `TestReview_CacheMustIsolateCredentials`, `TestReview_CacheMustEnforceClientRules`, `TestReview_SemanticCacheMustRespectModelAndStream`, and `TestReview_ClientKeyMustNotControlDrain` (the other 8 reference later-phase behavior and would still legitimately fail — that's expected and correct, not a regression). Also delete now-unused imports/helpers the trimmed file no longer needs (`sync/atomic`, `idempotency`, the failover-specific test), and add `s.AdminAPIKey = "admin-secret"` to `TestReview_ClientKeyMustNotControlDrain`'s setup exactly as Task 10 did (the original review file predates `AdminAPIKey` and would otherwise test against a `Server` with no admin key configured at all, where the fail-open backward-compatibility behavior in Task 8 would make it pass for the wrong reason — an ordinary key succeeding because no admin key exists yet, not because it was correctly rejected).

```bash
cp /tmp/review_findings_test.go internal/proxy/tmp_original_review_check_test.go
go test ./internal/proxy -run '^TestReview_' -count=1 -v
rm internal/proxy/tmp_original_review_check_test.go
```

Expected: all four PASS. Remove the temporary file immediately after — `reviewfindings_test.go` (Task 10) is the permanent version; this step is a one-time sanity check that the plan's ported tests weren't accidentally weaker than the review's originals, not a file to leave behind.

- [ ] **Step 4: Confirm no stray files from verification remain**

Run: `git status --short`
Expected: clean working tree (everything committed in Tasks 1-11; nothing untracked left over from Step 3 above).

- [ ] **Step 5: Report**

Summarize: all 12 tasks complete, full suite green under `-race`, the four Phase-1-relevant original review reproduction tests independently re-verified to now pass. Ready for the final holistic reviewer (per subagent-driven-development) and then `finishing-a-development-branch`.
