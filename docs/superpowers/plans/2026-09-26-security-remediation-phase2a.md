# Phase 2A: Log-safe URLs and Usage on Blocked Responses — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop request/upstream URLs from leaking credentials into logs, webhooks and Secure Vault evidence (review #9), and account for upstream token usage even when a response is blocked or redacted (review #10).

**Architecture:** One masking layer in a new `internal/proxy/logurl.go` (`logSafeURL`, `logSafeRawURL`, `logSafeError`) backed by a new `rules.Engine.MaskSecrets`. Every log/notify call site switches to it; rule evaluation and routing keep raw URLs. Usage accounting moves to the raw upstream bytes in `bufferResponse` and `streamTee.onComplete`.

**Tech Stack:** Go 1.27, standard library only. Spec: `docs/superpowers/specs/2026-09-26-security-remediation-phase2a-design.md`.

**Branch:** `security-phase2a` in `~/aiproxy`. Run all commands from the repo root.

---

## File structure

| File | Change | Responsibility |
|---|---|---|
| `internal/rules/rules.go` | modify | add `Engine.MaskSecrets` |
| `internal/rules/rules_test.go` | modify | tests for `MaskSecrets` |
| `internal/proxy/logurl.go` | create | `logSafeURL`, `logSafeRawURL`, `logSafeError` |
| `internal/proxy/logurl_test.go` | create | internal (`package proxy`) unit tests for the helpers |
| `internal/proxy/proxy.go` | modify | call sites, `ErrorHandler`, breaker/failover/shadow/webhook logs, usage accounting |
| `internal/proxy/reviewfindings_test.go` | modify | ported review tests #9 and #10 |
| `internal/proxy/logsafety_test.go` | create | end-to-end leak tests (JSON log, compliance URL, webhook, upstream error, shadow) |
| `internal/proxy/usageaccounting_test.go` | create | redact-in-usage and blocked-stream accounting tests |

---

### Task 1: `rules.Engine.MaskSecrets`

**Files:**
- Modify: `internal/rules/rules.go` (add method after `BodyRegexRules()`)
- Test: `internal/rules/rules_test.go`

- [ ] **Step 1: Write the failing test** — append to `internal/rules/rules_test.go` (check the file's package line first; if it is `package rules_test`, prefix identifiers with `rules.` as shown; if `package rules`, drop the prefix):

```go
func TestEngine_MaskSecrets_MasksEveryBodyRuleRegardlessOfActionScopeOrDryRun(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "blocker", Pattern: regexp.MustCompile(`BLOCK_[0-9]+`), Action: rules.Block})
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "redactor", Pattern: regexp.MustCompile(`REDACT_[0-9]+`), Action: rules.Redact})
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "dry", Pattern: regexp.MustCompile(`DRY_[0-9]+`), Action: rules.Block, DryRun: true})
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "scoped", Pattern: regexp.MustCompile(`SCOPED_[0-9]+`), Action: rules.Block, Targets: []string{"elsewhere"}})

	got := engine.MaskSecrets("/v1/BLOCK_1/REDACT_2/DRY_3/SCOPED_4/plain")
	want := "/v1/[REDACTED:blocker]/[REDACTED:redactor]/[REDACTED:dry]/[REDACTED:scoped]/plain"
	if got != want {
		t.Fatalf("MaskSecrets = %q, want %q", got, want)
	}
}

func TestEngine_MaskSecrets_NoRulesAndNilEngineReturnInputUnchanged(t *testing.T) {
	if got := rules.NewEngine(rules.Allow).MaskSecrets("/v1/chat"); got != "/v1/chat" {
		t.Fatalf("empty engine changed input: %q", got)
	}
	var engine *rules.Engine
	if got := engine.MaskSecrets("/v1/chat"); got != "/v1/chat" {
		t.Fatalf("nil engine changed input: %q", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/rules -run MaskSecrets`
Expected: FAIL — `engine.MaskSecrets undefined`.

- [ ] **Step 3: Implement** — add to `internal/rules/rules.go` after `BodyRegexRules()`:

```go
// MaskSecrets replaces every match of every body regex rule in s with
// "[REDACTED:<rule name>]", regardless of the rule's action, dry-run flag,
// or target/client scoping. It is for log output only and never affects
// policy decisions: a log line must not carry a secret just because the
// rule that recognizes it is scoped elsewhere or only in dry-run.
func (e *Engine) MaskSecrets(s string) string {
	if e == nil {
		return s
	}
	for _, rule := range e.bodyRules {
		if rule.Pattern == nil {
			continue
		}
		s = rule.Pattern.ReplaceAllLiteralString(s, "[REDACTED:"+rule.Name+"]")
	}
	return s
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/rules -run MaskSecrets -v`
Expected: PASS (both tests).

- [ ] **Step 5: Commit**

```bash
git add internal/rules/rules.go internal/rules/rules_test.go
git commit -m "feat(rules): add MaskSecrets for log-only secret masking"
```

---

### Task 2: Log-safe URL and error helpers

**Files:**
- Create: `internal/proxy/logurl.go`
- Test: `internal/proxy/logurl_test.go` (`package proxy`, internal, so unexported helpers are reachable)

- [ ] **Step 1: Write the failing test** — create `internal/proxy/logurl_test.go`:

```go
package proxy

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/rules"
)

func logURLTestServer() *Server {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "path-key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{8,}`), Action: rules.Block})
	target, _ := url.Parse("http://upstream.invalid")
	return New("unused", target, engine)
}

func TestLogSafeURL(t *testing.T) {
	s := logURLTestServer()
	cases := []struct{ name, in, want string }{
		{"relative path and query", "/chat?api_key=FAKE&model=gpt", "/chat?api_key=REDACTED&model=REDACTED"},
		{"userinfo and fragment dropped", "https://user:pass@host.example/v1?x=1#frag", "https://host.example/v1?x=REDACTED"},
		{"empty value stays empty", "/v1?flag=&k=v", "/v1?flag=&k=REDACTED"},
		{"repeated key keeps both", "/v1?k=a&k=b", "/v1?k=REDACTED&k=REDACTED"},
		{"path secret masked", "/bot/sk-ABCDEFGH1234/send", "/bot/[REDACTED:path-key]/send"},
		{"no query untouched", "/v1/chat/completions", "/v1/chat/completions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			before := u.String()
			if got := s.logSafeURL(u); got != tc.want {
				t.Fatalf("logSafeURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if u.String() != before {
				t.Fatalf("logSafeURL mutated its input: %q -> %q", before, u.String())
			}
		})
	}
	if got := s.logSafeURL(nil); got != "" {
		t.Fatalf("logSafeURL(nil) = %q, want empty", got)
	}
}

func TestLogSafeRawURL(t *testing.T) {
	s := logURLTestServer()
	if got := s.logSafeRawURL("https://gen.example/v1?key=FAKE"); got != "https://gen.example/v1?key=REDACTED" {
		t.Fatalf("logSafeRawURL = %q", got)
	}
	if got := s.logSafeRawURL("http://[::1:bad"); got != "[unparseable URL]" {
		t.Fatalf("logSafeRawURL(unparseable) = %q", got)
	}
}

func TestLogSafeError(t *testing.T) {
	s := logURLTestServer()
	err := &url.Error{Op: "Post", URL: "https://up.example/chat?api_key=FAKE", Err: errors.New("connection refused")}
	got := s.logSafeError(err)
	if strings.Contains(got, "FAKE") || !strings.Contains(got, "Post") || !strings.Contains(got, "connection refused") {
		t.Fatalf("logSafeError = %q", got)
	}
	plain := errors.New("plain failure")
	if got := s.logSafeError(plain); got != "plain failure" {
		t.Fatalf("logSafeError(plain) = %q", got)
	}
	if got := s.logSafeError(nil); got != "" {
		t.Fatalf("logSafeError(nil) = %q", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/proxy -run 'TestLogSafe'`
Expected: FAIL — `s.logSafeURL undefined` (build failure).

- [ ] **Step 3: Implement** — create `internal/proxy/logurl.go`:

```go
package proxy

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// logSafeURL returns u in a form that is safe to write to any log line,
// webhook payload, or Secure Vault evidence record: userinfo and fragment
// removed, every query value replaced with REDACTED (keys kept, since a
// denylist of parameter names misses credentials under unexpected names),
// and the path passed through the configured secret patterns. Policy code
// must keep using the raw URL.
func (s *Server) logSafeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	masked := *u
	masked.User = nil
	masked.Fragment = ""
	masked.RawFragment = ""
	masked.RawQuery = maskQueryValues(u.RawQuery)
	masked.Path = s.getEngine().MaskSecrets(u.Path)
	masked.RawPath = ""
	return masked.String()
}

// logSafeRawURL is logSafeURL for a URL held as a string, such as a
// configured target or a *url.Error's URL.
func (s *Server) logSafeRawURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[unparseable URL]"
	}
	return s.logSafeURL(u)
}

// logSafeError renders err for a log line. A *url.Error, which every
// http.Client and RoundTrip failure returns, prints its full request URL
// including the query, so its URL is masked.
func (s *Server) logSafeError(err error) string {
	if err == nil {
		return ""
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Sprintf("%s %s: %v", urlErr.Op, s.logSafeRawURL(urlErr.URL), urlErr.Err)
	}
	return err.Error()
}

func maskQueryValues(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	parts := strings.Split(rawQuery, "&")
	for index, part := range parts {
		if key, value, _ := strings.Cut(part, "="); value != "" {
			parts[index] = key + "=REDACTED"
		}
	}
	return strings.Join(parts, "&")
}
```

Note: `maskQueryValues` works on the raw query so key order and repeated keys survive exactly, and the key itself is never decoded or re-encoded.

- [ ] **Step 4: Run to verify it passes**

Run: `go test ./internal/proxy -run 'TestLogSafe' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/logurl.go internal/proxy/logurl_test.go
git commit -m "feat(proxy): add log-safe URL and error rendering helpers"
```

---

### Task 3: Use log-safe request URLs at every log, webhook and compliance call site

**Files:**
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/reviewfindings_test.go`
- Create: `internal/proxy/logsafety_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/reviewfindings_test.go` (add `"bytes"` to its imports):

```go
func TestReview_QueryCredentialsMustNotEnterLogs(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") })
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	req := httptest.NewRequest("GET", "/chat?api_key=FAKE_PRIVATE_VALUE", nil)
	s.ServeHTTP(httptest.NewRecorder(), req)
	if strings.Contains(buf.String(), "FAKE_PRIVATE_VALUE") {
		t.Fatalf("query credential logged verbatim: %q", buf.String())
	}
}
```

Create `internal/proxy/logsafety_test.go`:

```go
package proxy_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

const leakedValue = "FAKE_PRIVATE_VALUE"

func TestLogSafety_JSONLogFormatHasNoQueryValue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	s.LogFormat = proxy.LogFormatJSON
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	if strings.Contains(buf.String(), leakedValue) {
		t.Fatalf("JSON log contains query value: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "api_key=REDACTED") {
		t.Fatalf("JSON log lost the masked key: %s", buf.String())
	}
}

func TestLogSafety_BlockWebhookPayloadHasNoQueryValue(t *testing.T) {
	payloads := make(chan string, 4)
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		payloads <- string(body)
	}))
	defer hook.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "deny-chat", PathPrefix: "/chat", Action: rules.Block})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	hookURL, _ := url.Parse(hook.URL)
	s.WebhookURL = hookURL
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	select {
	case payload := <-payloads:
		if strings.Contains(payload, leakedValue) {
			t.Fatalf("webhook payload contains query value: %s", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no webhook delivered")
	}
}

func TestLogSafety_ComplianceEventCarriesMaskedURL(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	recorder := &capturingComplianceRecorder{events: make(chan proxy.ComplianceEvent, 1)}
	s := proxy.New("unused", target, rules.NewEngine(rules.Allow))
	s.Logger = log.New(io.Discard, "", 0)
	s.ComplianceRecorder = recorder
	frontend := httptest.NewServer(s)
	defer frontend.Close()
	request, _ := http.NewRequest(http.MethodPost, frontend.URL+"/v1/chat?api_key="+leakedValue, strings.NewReader(`{"prompt":"hi"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Aiproxy-Client-Id", "employee-42")
	request.Header.Set("X-Aiproxy-Application-Id", "legal-assistant")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	select {
	case event := <-recorder.events:
		if strings.Contains(event.RequestURL, leakedValue) || !strings.Contains(event.RequestURL, "api_key=REDACTED") {
			t.Fatalf("compliance RequestURL = %q", event.RequestURL)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no compliance event recorded")
	}
}
```

Before running, confirm three names against the code and adjust the test (not the product) if they differ: the path-rule fields (`grep -n "type Rule struct" -A15 internal/rules/rules.go`), the webhook field on `Server` (`grep -n "WebhookURL" internal/proxy/proxy.go | head -3`), and the client/application headers that `TestComplianceRecorderCapturesRawExchangeAfterLocalRedaction` in `compliance_test.go` sends (copy them exactly).

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/proxy -run 'TestReview_QueryCredentials|TestLogSafety_' -v`
Expected: FAIL — each reports the leaked value.

- [ ] **Step 3: Implement the call-site switch**

Run this rewrite (it only touches lines that call `s.log*`, `s.notify*` or `s.handle*DryRunHits` with the raw request URL, plus the `reqCtx` field; the `rules.Request{URL: r.URL.String()}` lines use the capitalized field and are not matched):

```bash
python3 - <<'EOF'
import pathlib, re
path = pathlib.Path("internal/proxy/proxy.go")
source = path.read_text()
call = re.compile(r"^(\s*s\.(?:log|notify|handle)[A-Za-z]*\(.*)r\.URL\.String\(\)(.*)$", re.M)
count = 0
while True:
    source, replaced = call.subn(r"\1s.logSafeURL(r.URL)\2", source)
    count += replaced
    if replaced == 0:
        break
source, context_count = re.subn(r"(\n\s*url:\s+)r\.URL\.String\(\),", r"\1s.logSafeURL(r.URL),", source)
path.write_text(source)
print("call sites:", count, "reqCtx:", context_count)
EOF
grep -n "r\.URL\.String()" internal/proxy/proxy.go
```

Expected: `reqCtx: 1`, and the remaining `r.URL.String()` lines are only `URL: r.URL.String(),` inside `rules.Request{...}` literals. If any other line remains, inspect it: switch it only if it feeds a log, webhook, dry-run report or compliance event.

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/proxy -run 'TestReview_|TestLogSafety_' -v`
Expected: PASS.

- [ ] **Step 5: Run the whole package**

Run: `go test ./internal/proxy`
Expected: PASS. A failing existing test that asserted a raw query string in a log line or webhook payload is now asserting the old leak; update its expectation to the masked form (`key=REDACTED`) and note it in the commit message. Do not change product code to satisfy it.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/reviewfindings_test.go internal/proxy/logsafety_test.go
git commit -m "fix(proxy): mask request URLs in logs, webhooks and compliance evidence

Review finding #9: query credentials reached ALLOW/LATENCY logs, webhook
payloads and the WORM Secure Vault verbatim."
```

---

### Task 4: Mask URLs in upstream, failover, breaker, shadow and webhook error logs

**Files:**
- Modify: `internal/proxy/proxy.go` (`recordBreakerFailure`, `recordBreakerSuccess`, failover log call in `failoverTransport.RoundTrip`, `mirrorToShadow`, `postWebhook`, `reverseProxy` construction)
- Test: `internal/proxy/logsafety_test.go`

- [ ] **Step 1: Write the failing tests** — append to `internal/proxy/logsafety_test.go`:

```go
func TestLogSafety_UnreachableUpstreamLogsNoQueryValueAndReturns502(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL, _ := url.Parse(dead.URL)
	dead.Close()
	s := proxy.New("unused", deadURL, rules.NewEngine(rules.Allow))
	var buf bytes.Buffer
	s.Logger = log.New(&buf, "", 0)
	var stdBuf bytes.Buffer
	log.SetOutput(&stdBuf)
	t.Cleanup(func() { log.SetOutput(io.Discard) })
	recorder := httptest.NewRecorder()
	s.ServeHTTP(recorder, httptest.NewRequest("GET", "/chat?api_key="+leakedValue, nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", recorder.Code)
	}
	if strings.Contains(buf.String()+stdBuf.String(), leakedValue) {
		t.Fatalf("upstream error leaked query value: server=%q std=%q", buf.String(), stdBuf.String())
	}
	if !strings.Contains(buf.String(), "aiproxy: upstream:") {
		t.Fatalf("upstream error not logged through server logger: %q", buf.String())
	}
}

func TestLogSafety_WebhookDeliveryErrorOmitsURL(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadHook, _ := url.Parse(dead.URL + "/services/T000/B000/" + leakedValue + "?token=" + leakedValue)
	dead.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{Name: "deny-chat", PathPrefix: "/chat", Action: rules.Block})
	s := proxy.New("unused", target, engine)
	var buf syncBuffer
	s.Logger = log.New(&buf, "", 0)
	s.WebhookURL = deadHook
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/chat", nil))
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "delivery failed") {
		if time.Now().After(deadline) {
			t.Fatalf("no webhook delivery error logged: %q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(buf.String(), leakedValue) {
		t.Fatalf("webhook error leaked its URL: %q", buf.String())
	}
}
```

`syncBuffer` already exists in `proxy_test.go` (used by the streaming tests); reuse it.

Add to `internal/proxy/logurl_test.go` (internal package, so it can call the unexported breaker and shadow paths directly):

```go
func TestLogSafety_BreakerAndShadowLogsMaskConfiguredURLs(t *testing.T) {
	s := logURLTestServer()
	var buf strings.Builder
	s.Logger = log.New(&buf, "", 0)
	s.logTargetEjected(s.logSafeRawURL("https://gen.example/v1?key=FAKE_PRIVATE_VALUE"))
	shadow, _ := url.Parse("http://127.0.0.1:1")
	s.mirrorToShadow(shadow, "POST", "/chat", "api_key=FAKE_PRIVATE_VALUE", http.Header{}, nil, "default", "req-1")
	if strings.Contains(buf.String(), "FAKE_PRIVATE_VALUE") {
		t.Fatalf("breaker/shadow log leaked: %q", buf.String())
	}
}
```

(Add `"log"` and `"net/http"` to that file's imports.) The breaker half of this test passes as soon as call sites pass masked values; it guards Step 3's `recordBreaker*` change together with the grep check in Step 4.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/proxy -run 'TestLogSafety_' -v`
Expected: FAIL for the upstream (leak via std logger, no `aiproxy: upstream:` line), webhook (URL in `%v`) and shadow cases.

- [ ] **Step 3: Implement**

a) `reverseProxy` construction (`s.reverseProxy = &httputil.ReverseProxy{`, around line 981): add the field

```go
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// Replaces the default handler, which prints the full upstream
			// URL (client query included) to the process-wide logger.
			s.logError("aiproxy: upstream: %s", s.logSafeError(err))
			w.WriteHeader(http.StatusBadGateway)
		},
```

b) `recordBreakerFailure` / `recordBreakerSuccess`: the breaker key stays raw; only the log and webhook get the masked form:

```go
func (s *Server) recordBreakerFailure(tb *breaker.Registry, target string) {
	if tb.RecordFailure(target) {
		s.Stats.RecordTargetEjected()
		safeTarget := s.logSafeRawURL(target)
		s.logTargetEjected(safeTarget)
		s.notifyTargetEjectedWebhook(safeTarget)
	}
}

func (s *Server) recordBreakerSuccess(tb *breaker.Registry, target string) {
	if tb.RecordSuccess(target) {
		s.Stats.RecordTargetRecovered()
		safeTarget := s.logSafeRawURL(target)
		s.logTargetRecovered(safeTarget)
		s.notifyTargetRecoveredWebhook(safeTarget)
	}
}
```

c) The failover log call in `failoverTransport.RoundTrip`:

```go
			t.server.logFailover(reqCtx.method, reqCtx.url, t.server.logSafeRawURL(candidate.String()), t.server.logSafeRawURL(next.String()), reqCtx.requestID)
```

d) `mirrorToShadow`: both `s.logShadowError(targetLabel, shadowURL.String(), err, requestID)` calls become

```go
		s.logShadowError(targetLabel, s.logSafeURL(shadowURL), err, requestID)
```

and inside `logShadowError`, change the message line to

```go
	msg := fmt.Sprintf("mirroring %s to %s: %s", targetLabel, shadowURL, s.logSafeError(err))
```

e) `postWebhook`: replace the error branch with

```go
		if err != nil {
			// Never the URL, not even masked: a webhook URL (Slack's
			// especially) carries its credential in the path.
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
			}
			s.logError("aiproxy: webhook (%s): delivery failed: %v", label, err)
			return
		}
```

Ensure `errors` is imported in `proxy.go` (`grep -n '"errors"' internal/proxy/proxy.go`).

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/proxy -run 'TestLogSafety_|TestLogSafe' -v`
Expected: PASS.

Then: `grep -n 'logTargetEjected(target)\|logTargetRecovered(target)\|shadowURL.String(), err' internal/proxy/proxy.go`
Expected: no output.

- [ ] **Step 5: Run the whole package**

Run: `go test ./internal/proxy`
Expected: PASS. Same rule as Task 3 Step 5 for existing tests that asserted raw URLs in these lines.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/logsafety_test.go internal/proxy/logurl_test.go
git commit -m "fix(proxy): keep URLs out of upstream, breaker, shadow and webhook error logs

The default ReverseProxy error handler printed the full upstream URL,
including the client's query, to the process-wide logger; url.Error
text did the same for shadow mirrors and webhook deliveries."
```

---

### Task 5: Account for usage on blocked and redacted responses

**Files:**
- Modify: `internal/proxy/proxy.go` (`bufferResponse`, `streamTee` `onComplete` in the streaming setup)
- Modify: `internal/proxy/reviewfindings_test.go`
- Create: `internal/proxy/usageaccounting_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/reviewfindings_test.go`:

```go
func TestReview_BlockedResponseMustStillAccountForUsage(t *testing.T) {
	s := reviewServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answer":"SECRET_A","usage":{"total_tokens":123}}`)
	})
	s.Engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "fake-secret", Pattern: regexp.MustCompile("SECRET_A"), Action: rules.Block})
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", "/chat", strings.NewReader(`{"prompt":"hello"}`)))
	if rec.Code != 403 {
		t.Fatalf("expected blocked response, got %d", rec.Code)
	}
	if n := s.Stats.Snapshot().TotalTokens; n != 123 {
		t.Fatalf("upstream used 123 tokens, but blocked response recorded %d", n)
	}
}
```

Create `internal/proxy/usageaccounting_test.go`:

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
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

func TestUsage_RedactRuleInsideUsageObjectStillCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"answer":"hi","usage":{"total_tokens":77}}`)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "numbers", Pattern: regexp.MustCompile(`\b77\b`), Action: rules.Redact})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	s.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/chat", strings.NewReader(`{"prompt":"x"}`)))
	if n := s.Stats.Snapshot().TotalTokens; n != 77 {
		t.Fatalf("TotalTokens = %d, want 77", n)
	}
}

func TestUsage_StreamBlockedAfterUsageEventStillCounts(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":11}}}\n\n")
		flusher.Flush()
		time.Sleep(20 * time.Millisecond)
		fmt.Fprint(w, "data: {\"delta\":{\"text\":\"AKIAABCDEFGHIJKLMNOP\"}}\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "aws-access-key", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Action: rules.Block})
	s := proxy.New("unused", target, engine)
	s.Logger = log.New(io.Discard, "", 0)
	frontend := httptest.NewServer(s)
	defer frontend.Close()
	response, err := http.Post(frontend.URL+"/v1/messages", "application/json", strings.NewReader(`{"stream":true}`))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	deadline := time.Now().Add(2 * time.Second)
	for s.Stats.Snapshot().TotalTokens != 11 {
		if time.Now().After(deadline) {
			t.Fatalf("TotalTokens = %d, want 11", s.Stats.Snapshot().TotalTokens)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/proxy -run 'TestReview_BlockedResponse|TestUsage_' -v`
Expected: FAIL — blocked records 0; redact records 0 (the redacted body no longer parses to 77); stream records 0.

- [ ] **Step 3: Implement**

a) In `bufferResponse`, right after `rawResponseStatus := resp.StatusCode`, add

```go
	// Upstream spend happened whether or not the client gets this body,
	// and a redaction must not be able to hide the usage object.
	s.logUsageFromBody(reqCtx, rawResponseBody)
```

and delete the later `s.logUsageFromBody(reqCtx, body)` line (just before the compliance wrapper), so usage is accounted exactly once.

b) In the streaming setup's `tee.onComplete = func(data, rawData []byte, cleanEOF bool) {`, change `s.logUsageFromBody(reqCtx, data)` to

```go
		// rawData: a stream cut short by a Block rule still consumed
		// whatever usage the upstream reported before the cut.
		s.logUsageFromBody(reqCtx, rawData)
```

- [ ] **Step 4: Run to verify they pass**

Run: `go test ./internal/proxy -run 'TestReview_BlockedResponse|TestUsage_' -v`
Expected: PASS.

- [ ] **Step 5: Run the whole package**

Run: `go test ./internal/proxy`
Expected: PASS.

If an existing test fails, check whether it waits for the `[USAGE]` log line
as a signal that the cache write has landed (see the "cache first, log
second" comment in `bufferResponse`). Moving accounting earlier breaks that
ordering. In that case, undo step 3a and instead:
- in the block branch, call `s.logUsageFromBody(reqCtx, rawResponseBody)`
  immediately before its `return nil`;
- keep the original call at its original position, changing only its
  argument from `body` to `rawResponseBody`.

Re-run until green.

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/reviewfindings_test.go internal/proxy/usageaccounting_test.go
git commit -m "fix(proxy): count upstream token usage on blocked and redacted responses

Review finding #10: bufferResponse returned on block before accounting,
and redaction or a cut-short stream could hide the usage object, so
token limits and cost budgets undercounted real upstream spend."
```

---

### Task 6: Docs and full verification

**Files:**
- Modify: `README.md` (logging section) and `docs/reviews/2026-09-12-v0.74.1-system-review.md` is **not** edited (historical record).

- [ ] **Step 1: Document the behavior change** — find the logging section: `grep -n -i "^#.*log" README.md`. Add under it:

```markdown
Request URLs in logs, webhook payloads and Secure Vault evidence are masked:
URL userinfo and fragments are removed, every query value is replaced with
`REDACTED` (parameter names are kept), and secrets in the path are masked
with your configured secret rules. Rules and routing still see the full URL.

Token usage reported by the upstream counts toward rate limits and cost
budgets even when aiproxy blocks or redacts the response.
```

- [ ] **Step 2: Full verification**

Run: `gofmt -l internal && go vet ./... && go test -race ./...`
Expected: no gofmt output, vet clean, all packages `ok`.

- [ ] **Step 3: Confirm the review reproductions**

Run: `go test ./internal/proxy -run '^TestReview_' -v 2>&1 | grep -E '^(--- |ok|FAIL)'`
Expected: every `TestReview_*` PASS, including `QueryCredentialsMustNotEnterLogs` and `BlockedResponseMustStillAccountForUsage`.

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: describe log URL masking and usage accounting on blocked responses"
```
