# aiproxy

[![Test](https://github.com/aleksanderbernacki12-byte/aiproxy/actions/workflows/test.yml/badge.svg)](https://github.com/aleksanderbernacki12-byte/aiproxy/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/aleksanderbernacki12-byte/aiproxy)](https://github.com/aleksanderbernacki12-byte/aiproxy/releases/latest)
[![License: MIT](https://img.shields.io/github/license/aleksanderbernacki12-byte/aiproxy)](LICENSE)

aiproxy is a local reverse proxy that sits between your machine and an
HTTPS API. It reads every outgoing request — and the response coming
back — in cleartext, checks the body and headers against a set of
security rules, and blocks or masks anything that looks like a leaked
secret — cloud and API provider keys, GitHub tokens, private key
material, and any custom patterns you define — before it ever leaves
your machine, or ever reaches your client, respectively.

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
requests forwarded with a matched secret masked out — see
[Redacting instead of blocking](#redacting-instead-of-blocking) — in
cyan (`[REDACT] POST /endpoint - Triggered rule: <name>`); requests
rejected by the rate limiter in yellow (`[CIRCUIT BREAKER] POST
/endpoint - Rate limit exceeded`); responses served from the local cache
in purple (`[CACHE HIT] POST /endpoint`); and, whenever a response
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
`cost_per_1k_tokens` is set; if any rule ever matched, it's also broken
down per rule name — which rule is actually responsible, across both
requests and [responses](#scanning-responses-too):

```
=== aiproxy session summary ===
Requests allowed:    5
Requests blocked:    1
Requests redacted:   0
Rate-limited (429):  0
Cache hits:          0
Total tokens used:   0
Responses blocked:   0
Responses redacted:  0
=== per-target breakdown ===
[/postman] allowed=3 blocked=1 redacted=0 rate-limited=0 cache-hits=0 tokens=0 response-blocked=0 response-redacted=0
[default] allowed=2 blocked=0 redacted=0 rate-limited=0 cache-hits=0 tokens=0 response-blocked=0 response-redacted=0
=== per-rule breakdown ===
[aws-access-key] blocked=1 redacted=0 response-blocked=0 response-redacted=0
```

A single-target run (no `targets` configured) leaves the per-target
section out entirely — it would just repeat the block above under a
different label. The per-rule section, unlike that one, is left out only
when no rule has ever matched at all — even a single rule's own numbers
are never redundant with the totals above, since those totals already
conflate every rule together.

## Built-in secret patterns

No config needed — these block by default the moment aiproxy starts:

| Rule name           | Detects                                                       |
| -------------------- | -------------------------------------------------------------- |
| `aws-access-key`     | AWS access key IDs (`AKIA...`)                                  |
| `openai-api-key`     | OpenAI API keys (`sk-...`)                                      |
| `anthropic-api-key`  | Anthropic (Claude) API keys (`sk-ant-...`)                      |
| `github-token`       | GitHub personal access tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_...`) |
| `private-key`        | PEM private key blocks (RSA, EC, OpenSSH, DSA, encrypted, PGP)  |
| `slack-token`        | Slack bot/user/app/legacy tokens (`xoxb-`/`xoxp-`/`xoxa-`/`xoxr-`/`xoxs-...`) |
| `stripe-api-key`     | Stripe live secret keys (`sk_live_...`)                         |
| `google-api-key`     | Google API keys (`AIza...`)                                     |
| `npm-access-token`   | npm access tokens (`npm_...`)                                   |
| `jwt`                | Generic JSON Web Tokens (`eyJ...`.`...`.`...`, three base64url parts) |

Each one can be switched independently to
[redact](#redacting-instead-of-blocking) instead of block, or turned off
entirely, via `builtin_rule_actions` — see that section below. `jwt` in
particular is the one most likely to need `"off"`: a JWT showing up in a
request body isn't always a leak the way the others are — it can be a
legitimate ID token or session token a client is meant to send — so
turn it off if it's flagging traffic you already know is fine.

Every pattern above — and every `custom_rules` entry — is checked
against request headers too, not just the body: a secret pasted into an
`X-...` debug header, for example, is caught exactly the same way as one
in the JSON payload. Three headers are always exempt from this scanning,
regardless of rule configuration: `Authorization`, `Proxy-Authorization`,
and `X-Api-Key`. Those are exactly where a client legitimately puts its
own credential for the upstream API on every single request (Anthropic's
Messages API uses `X-Api-Key`; OpenAI, Vertex AI, and most others use a
bearer token in `Authorization`) — scanning them against patterns built
to catch a *leaked* key would block all normal traffic, since a real
credential is deliberately shaped exactly like what those patterns
detect. A `redact` rule matched in a header masks only that header's
value, the same way it masks a match in the body.

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

`level` is one of `allow`, `block`, `redact`, `response_block`,
`response_redact`, `rate_limited`, `usage`, `cache_hit`, or `error` (an
internal problem unrelated to any specific request, e.g. a failed cache
write) — `method`/`url`/`rule`/`tokens` appear only where relevant. This only affects the ongoing per-request log stream on
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
custom rules, path rules, the rate limit, the cache, cost estimation,
the max request body size, the webhook alert URL, and target routes all
take effect for the next request, with no dropped connections and no
restart. Every one of these is logged (as `reload` on success, or
`reload_error` on failure, under `--log-format json`).

If the reloaded file has any problem — a bad regex, a bad target, a
cache directory that can't be created — the reload is refused and the
proxy keeps running on its last-known-good configuration; it never
crashes or blanks out its rules because of a bad edit. `--target`,
`--addr`, and `--log-format` are startup-only and unaffected by a
reload — those still require a real restart.

## Custom rules, rate limiting, caching, and cost estimation

Drop an `aiproxy.json` file in the working directory (or point `--config`
at one) to add your own content rules — checked against the body and
headers alike, see [Built-in secret patterns](#built-in-secret-patterns)
— on top of the built-in ones, cap how many
requests the proxy forwards per minute — a local circuit breaker against
runaway/looping clients — cache responses to disk to save time and API
costs on repeated calls, and/or price the shutdown summary's token total
in your own currency:

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
request whose body or headers match it is blocked with a 403 by default
(the [same three headers](#built-in-secret-patterns) exempt from the
built-in patterns are exempt here too) — see
[Redacting instead of blocking](#redacting-instead-of-blocking) for the
alternative. `max_requests_per_minute` is optional; when it is 0 or
omitted, the rate limiter is disabled. Once the limit is hit, further
requests get a 429 until the 1-minute window rolls forward.

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

`max_body_size_bytes` caps how large a single request body aiproxy will
buffer in memory before rejecting it with a 413 — every request is read
fully into memory so the rule engine can inspect it, so this bounds the
worst case for a proxy that's meant to sit in front of untrusted client
traffic. Unlike every other field above, it does **not** default to
"disabled" when absent: aiproxy applies a built-in 10 MiB limit instead,
generous enough for a normal chat/completion payload (including a
reasonably sized embedded image or document) without leaving the limit
actually unbounded. Set it explicitly if your traffic needs more:

```json
{
  "max_body_size_bytes": 26214400
}
```

`aiproxy validate` reports the limit that will actually apply — the
configured value, or the built-in default if the field is absent — not
just the raw config.

## Redacting instead of blocking

A blocked request never reaches the upstream at all — sometimes that's
too blunt, e.g. a client that occasionally includes a stale test key
alongside other content you don't want to lose. Give a custom rule
`"action": "redact"` instead of the default `"block"` to mask the match
and forward the request rather than rejecting it:

```json
{
  "custom_rules": [
    { "name": "internal-token", "pattern": "TOKEN_[0-9]+", "action": "redact" }
  ]
}
```

Every occurrence of the matched pattern — in the body, or in the one
header the match was actually found in — is replaced with
`[REDACTED:<rule name>]` before the request is forwarded — the original
value never reaches the upstream target, and never reaches the log
either. Redacted requests are counted separately from allowed ones in
the stats summary, `GET /_aiproxy/stats`, and the `[REDACT]` log line
(cyan; `"redact"` under `--log-format json`).

The [built-in secret patterns](#built-in-secret-patterns) block by
default too, but each can be switched to redact independently via
`builtin_rule_actions` — or turned off entirely with `"off"`, the one
action value that only makes sense here (a custom rule you don't want
is simply left out of `custom_rules`; a built-in rule has no such list
to leave it out of):

```json
{
  "builtin_rule_actions": {
    "aws-access-key": "redact",
    "jwt": "off"
  }
}
```

Any built-in rule not listed keeps blocking. `builtin_rule_actions` keys
must be one of the built-in rule names listed above (`aiproxy validate`
catches a typo here the same way it catches a bad regex), and values are
`"block"`, `"redact"`, or `"off"` — the first two are the same pair as
`custom_rules[].action`, which has no `"off"` value of its own.

## Scanning responses too

Every built-in pattern and every `custom_rules` entry runs against
what comes back from the model as well as what goes out to it — no
separate config, same rules, same `block`/`redact`/`off` actions. This
guards against a secret leaking the other direction: a model echoing
something back it shouldn't (a prompt injection, a completion that
repeats earlier context verbatim), or an upstream error message
reflecting request data. A response match is a distinct outcome from a
request match — `response_blocked`/`response_redacted` in
`GET /_aiproxy/stats` and the Prometheus endpoint, a `[RESPONSE BLOCK]`
/ `[RESPONSE REDACT]` log line (`"response_block"`/`"response_redact"`
under `--log-format json`), and its own webhook event — since a leak
coming back is a meaningfully different signal from one caught going
out, even though the underlying rule is identical.

A blocked non-streaming response never reaches the client at all — it
gets a 403 with a generic message in place of the real body, the same
way a blocked request never reaches the upstream. A streamed (SSE)
response is scanned one event at a time as it arrives, so a match is
still caught without buffering the whole reply first: `redact` masks
the secret in that one event and the stream continues normally, but
`block` can only end the stream from that point on, not erase what
already reached the client — by the time a chunk can even be inspected,
the response's 200 status and headers are already sent. A response a
`block` rule cut short ends the connection abnormally rather than
looking like a short-but-complete answer, and — same as any other
incomplete stream — is never written to the cache. A secret split
exactly across two streamed chunks is a known limitation of scanning
one event at a time; in practice a model's individual text deltas are
almost always more than a couple of bytes.

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

## Path-based endpoint rules

`targets` picks which upstream a path goes to; `path_rules` decides
whether it's allowed through at all, by path alone, independent of what
it contains:

```json
{
  "path_rules": [
    { "name": "block-admin", "prefix": "/admin", "action": "block" },
    { "name": "health-check", "prefix": "/health", "action": "allow" }
  ]
}
```

`block` rejects every request under `prefix` outright with a 403,
before it's even scanned. `allow` does the opposite: it exempts every
request under `prefix` from every other rule — built-in, custom, and
response scanning included — for an endpoint you already know is safe
(a health check, a status page) and don't want tripping a false
positive. Unlike `custom_rules[].action`, `action` has no default when
it's absent — block and allow are opposite intents, so `aiproxy
validate` rejects a `path_rules` entry that doesn't say which one it
means, rather than silently guessing. Prefixes must be unique (checked
the same way as `targets[].prefix`) and are matched before any
body/header content is scanned, so an `allow` entry is a genuine,
complete opt-out — use it deliberately.

## Example: proxying Claude traffic

Point `--target` straight at the Anthropic API — nothing Claude-specific
to configure, the `anthropic-api-key` built-in rule already covers it:

```
aiproxy start --target https://api.anthropic.com
```

```json
{
  "cache_enabled": true,
  "cost_per_1k_tokens": 3.0,
  "max_requests_per_minute": 50
}
```

(`cost_per_1k_tokens` is one flat rate applied to input+output combined;
Claude prices those two separately, so pick a blended estimate for your
actual input/output mix rather than quoting either rate directly.)

Token usage tracking works out of the box too: `/v1/messages` responses
report `usage.input_tokens`/`usage.output_tokens` instead of OpenAI's
single `usage.total_tokens`, and aiproxy sums the two automatically —
same for a streaming response, where Anthropic splits the same count
across two different SSE events (`message_start` and `message_delta`)
instead of repeating a running total in each one like OpenAI's stream
does. Nothing to configure either way; both provider shapes are just
recognized.

Running Claude and OpenAI traffic through one instance is the
[multi-target routing](#multi-target-routing) example above, unchanged:

```json
{
  "targets": [
    { "prefix": "/openai", "url": "https://api.openai.com" },
    { "prefix": "/anthropic", "url": "https://api.anthropic.com" }
  ]
}
```

**Amazon Bedrock and Google Vertex AI** are a different story, because
of how each authenticates rather than anything about Claude itself.
Vertex AI uses a bearer token (`Authorization: Bearer <token>`) — a
plain header, unaffected by a reverse proxy sitting in the middle — so
pointing `--target` at your Vertex endpoint works the same as the direct
API. Bedrock instead uses AWS SigV4, which signs a hash of the exact
request body the client sends; forwarding that request unmodified
through any proxy still validates, but a `builtin_rule_actions`/
`custom_rules` entry set to `"redact"` rewrites the body after the
client already signed it, and Bedrock will reject the mutated request
with a signature error. If you proxy Bedrock traffic, either leave every
rule on the default `"block"` (which never forwards a mutated body — a
rejected request from aiproxy has nothing to invalidate) or don't run
redact rules on that route at all.

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
  "response_blocked": 0,
  "response_redacted": 1,
  "estimated_cost": 0.062,
  "per_target": {
    "/openai": { "allowed": 30, "blocked": 1, "rate_limited": 0, "cache_hits": 5, "total_tokens": 3100, "estimated_cost": 0.062 },
    "default": { "allowed": 12, "blocked": 0, "rate_limited": 0, "cache_hits": 0, "total_tokens": 0 }
  },
  "per_rule": {
    "aws-access-key": { "blocked": 1, "redacted": 0, "response_blocked": 0, "response_redacted": 0 },
    "openai-api-key": { "blocked": 0, "redacted": 0, "response_blocked": 0, "response_redacted": 1 }
  }
}
```

`estimated_cost` (overall and per target) is included only when
`cost_per_1k_tokens` is set. `per_target` always reflects every target
used so far — unlike the printed shutdown summary, which leaves the
breakdown out entirely for a single-target run, the JSON endpoint stays
structurally the same shape regardless of how many targets are in play,
since that predictability matters more for something meant to be parsed
by a script or dashboard. `per_rule` breaks the same four block/redact
outcomes down by which named rule (built-in, custom, or path) actually
matched — combining its request-side and response-side hits under the
one name, since which target the match happened to route through
doesn't change which rule is responsible for it — so you can see which
rule fires the most (worth checking for false positives) or catches the
most real leaks. Any method other than `GET` gets a 405. Because the
path is reserved, an upstream that genuinely needs to be reached at
`/_aiproxy/stats` itself cannot be — route it through a different
prefix if that ever comes up.

## Prometheus metrics

The same counters are also available at `GET /_aiproxy/metrics` in
Prometheus's text exposition format, for scraping instead of polling
`/_aiproxy/stats`:

```
aiproxy_requests_allowed_total{target="default"} 42
aiproxy_requests_blocked_total{target="default"} 1
aiproxy_requests_redacted_total{target="default"} 0
aiproxy_requests_rate_limited_total{target="default"} 0
aiproxy_cache_hits_total{target="default"} 5
aiproxy_tokens_used_total{target="default"} 3100
aiproxy_responses_blocked_total{target="default"} 0
aiproxy_responses_redacted_total{target="default"} 1
aiproxy_estimated_cost{target="default"} 0.062
aiproxy_rule_blocked_total{rule="aws-access-key"} 1
aiproxy_rule_redacted_total{rule="aws-access-key"} 0
aiproxy_rule_response_blocked_total{rule="aws-access-key"} 0
aiproxy_rule_response_redacted_total{rule="aws-access-key"} 0
aiproxy_rule_response_redacted_total{rule="openai-api-key"} 1
```

(`# HELP`/`# TYPE` lines omitted above for brevity — the real response
has them.) Every target seen so far gets its own `target="..."` series,
always, even in a single-target run — a scrape needs the same shape
every time, unlike the shutdown summary's noise-avoiding suppression.
`aiproxy_estimated_cost` is included only when `cost_per_1k_tokens` is
set, same as the JSON endpoint's `estimated_cost`. The `aiproxy_rule_*`
series mirror `per_rule` from the JSON endpoint: one `rule="<name>"`
series per rule that has ever matched, for every rule seen so far — not
tied to any target label, since a rule's identity doesn't depend on
which target the request routed to. Point Prometheus at it with:

```yaml
scrape_configs:
  - job_name: aiproxy
    metrics_path: /_aiproxy/metrics
    static_configs:
      - targets: ["127.0.0.1:8080"]
```

`metrics_path` has to be set explicitly — the endpoint deliberately
isn't served at the ecosystem's usual bare `/metrics`, since that's
exactly the kind of path a self-hosted LLM gateway upstream might
already be using for its own metrics. Same reserved-path rules as
`/_aiproxy/stats` apply: never forwarded upstream, never counted in the
stats it reports, and any method other than `GET` gets a 405.

## Webhook alerts

Stats and metrics are pull-based — something has to go and look at them.
Set `webhook_url` to get pushed a real-time alert instead, the moment a
rule matches — on a request going out, a
[response](#scanning-responses-too) coming back, or the
[rate limiter](#custom-rules-rate-limiting-caching-and-cost-estimation)
tripping:

```json
{
  "webhook_url": "https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXXXXXXXXXXXXXX"
}
```

Every alertable event — `block`, `redact`, `response_block`,
`response_redact`, or `rate_limited` — POSTs this JSON body to that URL:

```json
{
  "text": "[BLOCK] POST /v1/messages - Triggered rule: aws-access-key",
  "event": "block",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "aws-access-key",
  "time": "2026-01-01T12:00:00Z"
}
```

A `rate_limited` alert — fired the moment the circuit breaker rejects a
request, the same signal you'd want in real time for an agent loop stuck
retrying — carries an empty `rule`, since no scanning rule was involved:

```json
{
  "text": "[RATE_LIMITED] POST /v1/messages - Rate limit exceeded",
  "event": "rate_limited",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "time": "2026-01-01T12:00:00Z"
}
```

`text` alone is already a valid Slack incoming webhook payload — point
`webhook_url` straight at one and it just works, no separate Slack
integration needed. The rest of the fields serve any other endpoint that
wants the event structured instead of parsed back out of a sentence.
Like every log line in this README, the payload carries only the rule
name that matched — never the secret itself.

Delivery happens on its own goroutine with a 5-second timeout, so a
slow or unreachable webhook endpoint never delays the request that
triggered it; a delivery failure is logged as an internal error and
otherwise ignored — there's no retry. Unlike `--target` and
`targets[].url`, `webhook_url` accepts plain `http` as well as `https`
(it still has to be a well-formed URL with a host) — a webhook payload
never carries a secret, only a method/url/rule name, so a local or
internal-network receiver with no TLS in front of it is a perfectly
reasonable target. It's hot-reloadable via
[SIGHUP](#reloading-config-without-restarting) like everything else in
this section. Neither the startup notice nor `aiproxy validate`'s
summary ever print the URL itself — a webhook URL, Slack's especially,
typically embeds a bearer credential directly in its path, so it gets
the same treatment as every other secret aiproxy handles.

## Validating a config file

```
aiproxy validate --config aiproxy.json
```

Checks `aiproxy.json` for problems without starting the proxy: every
`custom_rules` pattern must compile, every `targets` entry needs a
well-formed, unique prefix and a valid HTTPS URL, every
`builtin_rule_actions` key must name a real built-in rule with a valid
action, and the numeric fields can't be negative. It reports every
problem it finds in one pass rather than stopping at the first, and
exits non-zero if there were any. With
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

As a container image, from [GHCR](https://github.com/aleksanderbernacki12-byte/aiproxy/pkgs/container/aiproxy):

```
docker run --rm -p 8080:8080 \
  ghcr.io/aleksanderbernacki12-byte/aiproxy:latest \
  start --target https://api.openai.com --addr 0.0.0.0:8080
```

`--addr 0.0.0.0:8080` is required — the default `127.0.0.1:8080` only
listens inside the container's own network namespace, unreachable
through the `-p` port mapping. To use a config file, mount it into the
image's working directory (`/config`):

```
docker run --rm -p 8080:8080 -v "$(pwd)/aiproxy.json:/config/aiproxy.json" \
  ghcr.io/aleksanderbernacki12-byte/aiproxy:latest \
  start --target https://api.openai.com --addr 0.0.0.0:8080
```

Images are built for `linux/amd64` and `linux/arm64` and published on
every tagged release, alongside the `latest` tag; both are built
directly from that release's own source, not repackaged from one of the
other install methods.

As a `.deb` or `.rpm` package, downloaded from the
[releases page](https://github.com/aleksanderbernacki12-byte/aiproxy/releases/latest)
(`amd64` and `arm64`, for Debian/Ubuntu and Fedora/RHEL respectively):

```
sudo dpkg -i aiproxy_<version>_amd64.deb   # Debian/Ubuntu
sudo rpm -i aiproxy_<version>_amd64.rpm    # Fedora/RHEL
```

Both install the binary to `/usr/bin/aiproxy` and recommend
`ca-certificates` (needed to verify the upstream's TLS certificate on
the new HTTPS connection) without hard-requiring it, so installing
aiproxy itself never fails on a system that happens to already manage
that some other way. Built and checksummed by the same release pipeline
as everything else — verify against the release's `SHA256SUMS` the same
way `install.sh` does below.

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
