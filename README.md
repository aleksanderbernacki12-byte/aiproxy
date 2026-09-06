# aiproxy

[![Test](https://github.com/aleksanderbernacki12-byte/aiproxy/actions/workflows/test.yml/badge.svg)](https://github.com/aleksanderbernacki12-byte/aiproxy/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/aleksanderbernacki12-byte/aiproxy)](https://github.com/aleksanderbernacki12-byte/aiproxy/releases/latest)
[![License: MIT](https://img.shields.io/github/license/aleksanderbernacki12-byte/aiproxy)](LICENSE)

aiproxy is a local reverse proxy that sits between your machine and an
HTTPS API. It reads every outgoing request in cleartext, checks the body
against a set of security rules, and blocks anything that looks like a
leaked secret — AWS access keys, OpenAI API keys, GitHub tokens, and any
custom patterns you define — before it ever leaves your machine over the
new HTTPS connection to the real target.

## Starting the proxy

```
aiproxy start --target https://api.example.com
```

- `--target` (required): the default HTTPS URL to forward allowed
  requests to — see [Multi-target routing](#multi-target-routing) for
  sending different paths to different upstreams instead.
- `--addr`: local address to listen on (default `127.0.0.1:8080`).
- `--config`: path to a JSON config file (custom rules, rate limit,
  cache, cost estimation, extra target routes; default: `aiproxy.json`
  in the working directory, if present).

Point your client at `http://127.0.0.1:8080` instead of the real API.
Allowed requests are logged in green (`[ALLOW] POST /endpoint`); blocked
ones in bright red (`[BLOCK] POST /endpoint - Triggered rule: <name>`);
requests rejected by the rate limiter in yellow (`[CIRCUIT BREAKER]
POST /endpoint - Rate limit exceeded`); responses served from the local
cache in purple (`[CACHE HIT] POST /endpoint`); and, whenever a response
carries a `usage.total_tokens` field (as LLM APIs typically do), a blue
usage line (`[USAGE] POST /endpoint - Tokens used: <n>`). The value that
matched a rule is never written to the log — only the rule's name.

Streaming responses (`Content-Type: text/event-stream`, the format LLM
chat APIs use when `stream: true`) are relayed to the client chunk by
chunk as they arrive, not buffered until the response finishes — usage
extraction and caching still run once the stream completes, from an
accumulated copy, without adding any delay to the streaming itself. A
stream cut short by a dropped connection is never cached.

Stopping the proxy (Ctrl+C) prints a session summary: how many requests
were allowed, blocked, rate-limited, served from cache, and the total
tokens used across the run — plus an estimated cost line, if you've set
`cost_per_1k_tokens`.

## Custom rules, rate limiting, caching, and cost estimation

Drop an `aiproxy.json` file in the working directory (or point `--config`
at one) to add your own body-content rules on top of the built-in AWS,
OpenAI, and GitHub token checks, cap how many requests the proxy forwards
per minute — a local circuit breaker against runaway/looping clients —
cache responses to disk to save time and API costs on repeated calls,
and/or price the shutdown summary's token total in your own currency:

```json
{
  "custom_rules": [
    { "name": "mitt-företag-hemlighet", "pattern": "SECRET_[0-9]+" }
  ],
  "max_requests_per_minute": 60,
  "cache_enabled": true,
  "cost_per_1k_tokens": 0.03
}
```

Each `pattern` is a Go regular expression, compiled once at startup. Any
request whose body matches it is blocked with a 403. `max_requests_per_minute`
is optional; when it is 0 or omitted, the rate limiter is disabled. Once
the limit is hit, further requests get a 429 until the 1-minute window
rolls forward.

`cache_enabled` is optional and off by default. When true, every 200 OK
response is stored under `.aiproxy_cache/` in the working directory,
keyed by a SHA256 hash of the request method, target URL, and body. An
identical request served later is answered straight from that file and
never reaches the upstream target. `.aiproxy_cache/` is already listed in
`.gitignore`.

`cost_per_1k_tokens` is optional and off by default (no cost line at
all). aiproxy has no built-in, inevitably-stale pricing table — you tell
it what rate applies to your own usage (whatever your provider actually
charges you per 1,000 tokens, in whatever currency), and the summary
just multiplies that by the total tokens tracked during the run.

## Multi-target routing

By default every request goes to `--target`. Add a `targets` list to
`aiproxy.json` to route specific path prefixes to other upstreams
instead — useful for putting more than one provider behind a single
aiproxy instance:

```json
{
  "targets": [
    { "prefix": "/openai", "url": "https://api.openai.com" },
    { "prefix": "/anthropic", "url": "https://api.anthropic.com" }
  ]
}
```

A request to `/openai/v1/chat/completions` is forwarded to
`https://api.openai.com/v1/chat/completions` — the matched prefix is
stripped before the request reaches the upstream. Anything that doesn't
match any prefix still falls back to `--target`, so `--target` stays
required even when `targets` is set. Prefixes are checked in the order
they're listed, first match wins, so list more specific prefixes first
if any could overlap. Every other feature — rules, rate limiting,
caching, usage tracking — applies uniformly regardless of which target a
request was routed to; caching in particular keys on the resolved
destination, so identical bodies sent to different providers are never
confused with each other.

## Installing

```
curl -fsSL https://raw.githubusercontent.com/aleksanderbernacki12-byte/aiproxy/main/install.sh | sh
```

This detects your OS/architecture, downloads the matching binary from
the [latest release](https://github.com/aleksanderbernacki12-byte/aiproxy/releases/latest),
verifies it against the release's published `SHA256SUMS` before
installing (refusing to proceed on a mismatch), and installs it to
`/usr/local/bin` (override with `AIPROXY_INSTALL_DIR`). No Go toolchain
required.

If you'd rather build from source — or the release download fails for
some reason — clone the repo and run the same script; it automatically
falls back to a local build when it detects it's sitting inside a
checkout with `go` available:

```
git clone https://github.com/aleksanderbernacki12-byte/aiproxy && cd aiproxy
./install.sh
```

## Building from source

```
make build      # current platform
make build-all  # macOS (arm64 + amd64), Linux (amd64), Windows (amd64)
```

## License

MIT — see [LICENSE](LICENSE).
