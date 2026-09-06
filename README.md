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
- `--log-format`: `text` (default) or `json` — see
  [Structured JSON logging](#structured-json-logging).

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
`cost_per_1k_tokens`. If more than one [target](#multi-target-routing)
was actually used during the run, the summary also breaks those same
counts down per target (labeled by the matched prefix, or `default` for
the fallback `--target`), each with its own cost line when
`cost_per_1k_tokens` is set:

```
=== aiproxy session summary ===
Requests allowed:    5
Requests blocked:    0
Rate-limited (429):  0
Cache hits:          0
Total tokens used:   0
=== per-target breakdown ===
[/postman] allowed=3 blocked=0 rate-limited=0 cache-hits=0 tokens=0
[default] allowed=2 blocked=0 rate-limited=0 cache-hits=0 tokens=0
```

A single-target run (no `targets` configured) leaves this section out
entirely — it would just repeat the block above under a different label.

## Structured JSON logging

```
aiproxy start --target https://api.example.com --log-format json
```

With `--log-format json`, every event above is logged as one JSON object
per line on stderr instead of a colored text line — safe to pipe into a
log aggregator or `jq` without ever hitting a non-JSON line, including
the shutdown summary (emitted as the same JSON shape `GET /_aiproxy/stats`
serves, instead of the multi-line text block):

```
{"time":"2026-01-01T12:00:00Z","level":"allow","method":"GET","url":"/get"}
{"time":"2026-01-01T12:00:01Z","level":"block","method":"POST","url":"/x","rule":"aws-access-key"}
{"time":"2026-01-01T12:00:02Z","level":"usage","method":"POST","url":"/chat","tokens":42}
{"allowed":2,"blocked":1,"rate_limited":0,"cache_hits":0,"total_tokens":42,"per_target":{"default":{"allowed":2,"blocked":1,"rate_limited":0,"cache_hits":0,"total_tokens":42}}}
```

`level` is one of `allow`, `block`, `rate_limited`, `usage`, `cache_hit`,
or `error` (an internal problem unrelated to any specific request, e.g.
a failed cache write) — `method`/`url`/`rule`/`tokens` appear only where
relevant. This only affects the ongoing per-request log stream on
stderr; the one-time startup notices (`loaded N custom rule(s)`, `route:
...`, `aiproxy listening on ...`) still print as plain text on stdout,
since they're low-volume, human-oriented setup notices rather than part
of the structured stream a script would actually parse — the two are
already on separate streams, so piping just stderr gives you a clean,
pure-JSON feed.

## Reloading config without restarting

```
kill -HUP <aiproxy-pid>
```

Sending `SIGHUP` re-reads the same config file `--config` (or the
default `aiproxy.json`) pointed at on startup, and applies it live:
custom rules, the rate limit, the cache, cost estimation, and target
routes all take effect for the next request, with no dropped
connections and no restart. Every one of these is logged (as `reload` on
success, or `reload_error` on failure, under `--log-format json`).

If the reloaded file has any problem — a bad regex, a bad target, a
cache directory that can't be created — the reload is refused and the
proxy keeps running on its last-known-good configuration; it never
crashes or blanks out its rules because of a bad edit. `--target`,
`--addr`, and `--log-format` are startup-only and unaffected by a
reload — those still require a real restart.

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
if any could overlap. Rules, caching, and usage tracking apply uniformly
regardless of which target a request was routed to; caching in
particular keys on the resolved destination, so identical bodies sent to
different providers are never confused with each other.

Each target can also be given its own rate limit, overriding the
top-level `max_requests_per_minute` for just that target's traffic:

```json
{
  "max_requests_per_minute": 60,
  "targets": [
    { "prefix": "/openai", "url": "https://api.openai.com", "max_requests_per_minute": 20 },
    { "prefix": "/anthropic", "url": "https://api.anthropic.com" }
  ]
}
```

Here `/openai` gets its own dedicated 20-requests-per-minute budget,
independent of everything else — heavy traffic to it can never throttle
`/anthropic` or the default target. `/anthropic` has no override, so it
keeps sharing the top-level 60-requests-per-minute limiter with the
default target, exactly as if `targets[].max_requests_per_minute` didn't
exist. Omit or set it to 0 for a target that should just share the
top-level limiter (or share "no limit at all", if the top-level field is
itself unset).

## Live stats

```
curl http://127.0.0.1:8080/_aiproxy/stats
```

`GET /_aiproxy/stats` is a reserved, proxy-internal path handled directly
by aiproxy — it never reaches any upstream target, and answering it is
never itself counted in the stats it reports. It returns the same
counters as the shutdown summary, as JSON, live, so a long-running proxy
can be monitored without waiting for Ctrl+C:

```json
{
  "allowed": 42,
  "blocked": 1,
  "rate_limited": 0,
  "cache_hits": 5,
  "total_tokens": 3100,
  "estimated_cost": 0.062,
  "per_target": {
    "/openai": { "allowed": 30, "blocked": 1, "rate_limited": 0, "cache_hits": 5, "total_tokens": 3100, "estimated_cost": 0.062 },
    "default": { "allowed": 12, "blocked": 0, "rate_limited": 0, "cache_hits": 0, "total_tokens": 0 }
  }
}
```

`estimated_cost` (overall and per target) is included only when
`cost_per_1k_tokens` is set. `per_target` always reflects every target
used so far — unlike the printed shutdown summary, which leaves the
breakdown out entirely for a single-target run, the JSON endpoint stays
structurally the same shape regardless of how many targets are in play,
since that predictability matters more for something meant to be parsed
by a script or dashboard. Any method other than `GET` gets a 405.
Because the path is reserved, an upstream that genuinely needs to be
reached at `/_aiproxy/stats` itself cannot be — route it through a
different prefix if that ever comes up.

## Validating a config file

```
aiproxy validate --config aiproxy.json
```

Checks `aiproxy.json` for problems without starting the proxy: every
`custom_rules` pattern must compile, every `targets` entry needs a
well-formed, unique prefix and a valid HTTPS URL, and the numeric fields
can't be negative. It reports every problem it finds in one pass rather
than stopping at the first, and exits non-zero if there were any. With
no `--config` given it checks `aiproxy.json` in the working directory,
same as `start` — and if that file simply doesn't exist, that's not an
error, just a note that aiproxy would run with only its built-in rules.

## Installing

On macOS or Linux, via [Homebrew](https://brew.sh):

```
brew install aleksanderbernacki12-byte/aiproxy/aiproxy
```

This installs from the [aiproxy tap](https://github.com/aleksanderbernacki12-byte/homebrew-aiproxy),
which downloads the matching release binary and verifies it against the
same checksums as `install.sh` below.

On Windows, via [Scoop](https://scoop.sh):

```powershell
scoop bucket add aiproxy https://github.com/aleksanderbernacki12-byte/scoop-aiproxy
scoop install aiproxy
```

This installs from the [aiproxy bucket](https://github.com/aleksanderbernacki12-byte/scoop-aiproxy),
which likewise downloads the matching release binary and verifies it
against a checksum. Both the Homebrew formula and the Scoop manifest are
regenerated automatically by the release pipeline on every tagged
release — neither is ever hand-edited.

Otherwise:

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
