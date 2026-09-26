# Security remediation, Phase 2B — complete rule evaluation, decoded content, SSE

Date: 2026-09-26
Status: approved (owner: both behaviors on by default, no legacy switch)

## Purpose

Closes review findings #4, #5 and #11 of
`docs/reviews/2026-09-12-v0.74.1-system-review.md`, plus a compression bypass
found while designing this phase. All reproduce on `main` (d176b74):
`TestReview_RedactionMustContinueToLaterBlock`,
`TestReview_JSONEscapingMustNotBypassSecretRule`,
`TestReview_StreamMustScanReassembledText`,
`TestReview_StreamMustRecognizeCRLFBoundaries`.

**New finding (compression bypass).** The proxy forwards the client's
`Accept-Encoding` upstream. When the upstream answers `Content-Encoding: gzip`
the response rules scan compressed bytes, so a secret in the response reaches
the client. Verified with a probe test: a gzip response containing an AWS key
passed a Block rule with status 200. The OpenAI/Anthropic SDKs send
`Accept-Encoding: gzip` by default, so response scanning, usage accounting,
cache and compliance evidence all see compressed bytes for most real clients.

This is a policy change: configurations that only redacted before may now
block, and streams are slightly delayed. The owner chose to ship it as the
default with no switch back.

## Scope

In scope:

1. Compression: responses are always scanned decompressed; request bodies with
   a content encoding are decoded or rejected.
2. #4: every body/header rule is evaluated; Block wins; all redactions apply.
3. #5: rules also run against decoded JSON strings, with structural
   redaction; streams are scanned on reassembled text with a hold-back window.
4. #11: SSE event boundaries per the WHATWG spec (LF, CRLF, CR).

Out of scope:

- A list of every matched rule in logs/stats. Logs, stats and webhooks keep
  reporting one deciding rule name (the first Block, else the first Redact, in
  registration order), so per-rule counters keep their meaning.
- Brotli/zstd decoding.
- Path rules: still first match wins (Allow exempts, Block rejects).

## Design

### 1. Compression

**Responses.** `Rewrite` deletes `Accept-Encoding` from the outbound request.
The upstream transport (a clone of `http.DefaultTransport`, compression not
disabled) then requests gzip itself and transparently decompresses it,
removing `Content-Encoding`/`Content-Length`. Every consumer (rules, usage,
cache, idempotency, coalescing, compliance, client) sees plain bytes. Cost:
the proxy→client leg is uncompressed.

Cached entries written before this change may hold compressed bodies. A cached
or coalesced response whose stored `Content-Encoding` is anything other than
empty/`identity` is treated as a miss and re-fetched.

**Requests.** A request body with `Content-Encoding: gzip` (or `x-gzip`) is
decompressed (bounded by the existing max body size, applied to the
decompressed size), scanned, and forwarded decompressed without the
`Content-Encoding` header. Any other non-identity encoding gets
`415 unsupported_content_encoding`, because it cannot be scanned.

### 2. Complete rule evaluation (#4)

`Engine.Evaluate` (request) and `Engine.EvaluateResponse`:

- Path rules unchanged.
- Every in-scope, non-dry-run body rule is checked against the body and every
  scanned header value, all against the **original** content.
- If any Block rule matched anywhere → `Block`, rule name = first matching
  Block rule in registration order (body before headers).
- Otherwise every matching Redact rule is applied, in registration order, to
  the body and to each matching header value → `Redact`, rule name = first
  matching Redact rule.
- Dry-run rules keep being collected for every match.

### 3. Decoded JSON (#5, buffered bodies)

New `internal/rules/jsonscan.go`. When a body (request or buffered response)
is valid JSON:

- Every string token (keys and values), decoded, is checked by the same
  rules. A Block match → Block.
- Redact rules that match a decoded string are applied to that string, and the
  body is re-encoded by a token-level rewriter that preserves key order,
  numbers (`UseNumber`) and structure. The body is only rewritten when a
  decoded redaction happened; otherwise the original bytes are forwarded
  unchanged.
- Raw-byte scanning (§2) runs first, so behavior for plain text is unchanged.
- Non-JSON bodies are scanned raw only.

### 4. SSE event boundaries (#11)

`streamTee.processCompleteBatch` finds the last event boundary as the last
blank line, where a line ends with `\r\n`, `\n` or `\r`. A trailing `\r` at
the end of the buffer is not a boundary yet (it may be the start of `\r\n`),
except at EOF.

### 5. Reassembled stream text (#5, streams)

Per stream, the tee extracts the generated text of each event: string values
under the keys `content`, `text`, `delta` (when a string), `partial_json`,
`arguments`, `thinking` and `reasoning_content`, in document order. These
cover OpenAI Chat Completions and Responses, Anthropic Messages, and Gemini.

- Events are held back until at least `stream_scan_holdback_chars`
  (config, default 256, `0` disables hold-back) characters of later text have
  arrived, or the stream ends.
- Before any event is released, block rules and redact rules run over the
  reassembled text of the held events plus the last `holdback` characters
  already released.
- A Block match, or a Redact match that spans more than one event, ends the
  stream exactly like today's streaming Block (the client never receives the
  held events). A Redact match inside one event is still redacted in place by
  the per-event scan.
- Per-event raw and decoded-JSON scanning (§2, §3) still runs on each batch.

Documented limit: a secret longer than the hold-back window, split across
events, can have its first part released before the rest arrives.

**Config.** `stream_scan_holdback_chars` (int, ≥ 0, default 256) in the config
file, validated in `aiproxy validate`, hot-reloadable like other rule
settings.

## Testing

- Port the four review tests.
- Compression: gzip response with secret is blocked; gzip response usage is
  counted; stored gzip cache entry is a miss; gzip request body with secret is
  blocked; `br` request body → 415.
- #4: redact-then-block → Block; two redact rules both applied; body redact +
  header block → Block; dry-run hits collected for every match.
- JSON: `\u` escape blocked; escaped secret redacted structurally with key
  order preserved; non-matching JSON forwarded byte-identical.
- SSE: CRLF, CR and LF boundaries; `\r` at buffer end waits; split `\r\n`
  across reads.
- Stream reassembly: secret split across two deltas blocked before either is
  delivered; holdback 0 restores per-event behavior; short stream shorter than
  the window is delivered at EOF.
- `go test -race ./...`, `go vet ./...`.

## Behavior changes (release notes)

- Responses are always decompressed before scanning; clients receive them
  uncompressed. Compressed request bodies other than gzip are rejected (415).
- All secret rules are evaluated. A request or response matching both a
  redact and a block rule is now blocked.
- Secrets hidden with JSON escapes are detected.
- Streams are held back by up to 256 characters of text so secrets split
  across events are caught (`stream_scan_holdback_chars`).
