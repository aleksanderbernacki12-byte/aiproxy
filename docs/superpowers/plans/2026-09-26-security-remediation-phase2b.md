# Phase 2B: Complete Rule Evaluation, Decoded Content, SSE — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rules see what the upstream and the client actually see: decompressed, decoded, reassembled, and every rule, not only the first match.

**Architecture:** Compression is removed at the proxy edge (`Rewrite` drops `Accept-Encoding`; gzip request bodies are inflated). The rules engine evaluates all body/header rules and adds a JSON token pass (`internal/rules/jsonscan.go`). `streamTee` gets a WHATWG boundary finder and a hold-back text window.

**Tech Stack:** Go 1.27 stdlib. Spec: `docs/superpowers/specs/2026-09-26-security-remediation-phase2b-design.md`. Branch: `security-phase2b`.

Each task: failing test first, minimal implementation, `go test` for the package, `go test -race ./internal/...` before commit, one commit per task.

---

### Task 1: Compression (spec §1)
- Tests (`internal/proxy/compression_test.go`): gzip response containing an AWS key with a Block rule → 403; gzip response with `usage.total_tokens` → counted; client `Accept-Encoding: gzip` never reaches upstream; gzip request body with secret → 403; gzip request body without secret → upstream receives plain body and no `Content-Encoding`; `Content-Encoding: br` request → 415 `unsupported_content_encoding`; cache entry stored with `Content-Encoding: gzip` → miss.
- Implement: `pr.Out.Header.Del("Accept-Encoding")` in `Rewrite`; after reading the request body in `ServeHTTP`, a `decodeRequestBody` helper (gzip/x-gzip via `gzip.NewReader` + `io.LimitReader(max+1)`; identity/empty passthrough; else 415) that also deletes `Content-Encoding` and fixes `Content-Length`/`r.ContentLength`; cache-hit and coalesce-hit branches skip entries whose `Content-Encoding` is non-identity.

### Task 2: Complete rule evaluation (spec §2, #4)
- Port `TestReview_RedactionMustContinueToLaterBlock` into `internal/rules/rules_test.go` (review test file is package `proxy_test`; the rules one belongs with rules).
- Tests: redact-then-block → Block with block rule name; two redacts both applied, name = first; body redact + header block → Block; header redact + body redact → both applied; response: same for `EvaluateResponse`; dry-run collected for all matches.
- Implement: rewrite the body/header phase of `Evaluate`, `EvaluateResponse`, `evaluateHeaders` to collect then decide. Update doc comments on `Engine`, `Evaluate`, `EvaluateResponse`.

### Task 3: Decoded JSON (spec §3, #5 buffered)
- Port `TestReview_JSONEscapingMustNotBypassSecretRule` into `reviewfindings_test.go`.
- Tests in `internal/rules/jsonscan_test.go`: `{"p":"SECRET_A"}` + Block → Block; + Redact → body is valid JSON, decoded value `[REDACTED:r]`, key order preserved, numbers unchanged (`1.50`, `1e3`); no match → identical bytes; invalid JSON → raw only; nested arrays/objects; key containing escaped secret.
- Implement `jsonscan.go`: `decodedStrings(body) ([]string, bool)` and `redactJSON(body, apply func(string) (string, bool)) ([]byte, bool, error)` using `json.Decoder.Token()` with `UseNumber`, re-encoding tokens with correct `,`/`:` placement (track a stack of container kinds and element counts). Wire into `Evaluate`/`EvaluateResponse` after the raw pass.

### Task 4: SSE boundaries (spec §4, #11)
- Port `TestReview_StreamMustRecognizeCRLFBoundaries` into an internal test (`package proxy`, file `sse_internal_test.go`).
- Tests for `lastEventBoundary([]byte, atEOF bool) int`: LF, CRLF, CR, mixed, `\r` at end (not boundary unless atEOF), `\r\n` split across two reads via streamTee.
- Implement `lastEventBoundary` and use it in `processCompleteBatch`.

### Task 5: Reassembled stream text (spec §5, #5 streams)
- Port `TestReview_StreamMustScanReassembledText` into `sse_internal_test.go`.
- Tests: secret split across two OpenAI deltas → blocked, client receives neither; Anthropic `delta.text` split → blocked; redact rule spanning events → stream ends; holdback 0 → per-event behavior (split secret passes, documents the limit); short stream under window delivered complete at EOF; text of `id`/`model` fields is not concatenated.
- Implement: `eventText(event []byte) string` (keys per spec); streamTee holds `[]heldEvent{bytes, textLen}`, `releasedTail string`; after each batch, append events, scan `releasedTail + heldText` with `engine.MatchesReassembled(text, target, key)` (new rules method returning Block/cross-event-redact decision and rule name), then release events from the front while the text after them ≥ holdback; at EOF release all after a final scan.
- Config: `StreamScanHoldbackChars *int` in `internal/config`, default 256, validation `>= 0`, plumbed into `Server` via a getter like other reloadable settings; document in `docs` config reference if one exists (`grep -rn "cache_ttl_seconds" docs README.md | head`).

### Task 6: Docs and verification
- README: compression, all-rules evaluation, JSON decoding, stream hold-back + limit, new config key.
- `gofmt -l internal && go vet ./... && go test -race ./...`; every `TestReview_*` passes (12/12 of the review's tests are then ported and green).
