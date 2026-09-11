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
- `--tls-cert`/`--tls-key`: PEM certificate/key file paths — see
  [Serving over TLS](#serving-over-tls). Both or neither; plain HTTP by
  default.
- `--audit-log-key-file`: path to a secret key file — see
  [Audit log signing](#audit-log-signing). Requires `log_file` to be
  configured; off by default.
- `--admin-addr`: address for a second listener serving only
  `/_aiproxy/stats`/`metrics`/`dashboard`/`cache/clear` — see
  [Isolating the admin surface on its own port](#isolating-the-admin-surface-on-its-own-port).
  Must differ from `--addr`; everything stays on `--addr` by default.

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
usage line (`[USAGE] POST /endpoint - Tokens used: <n>`). Every request
that actually reaches the upstream also gets a dim `[LATENCY] POST
/endpoint - <n>ms` line right after it, once the response comes back —
how long that one specific call took, so a single slow request is
visible directly in the log without polling
[`/_aiproxy/stats`](#live-stats) or
[`/_aiproxy/metrics`](#prometheus-metrics). It's logged for every
outcome that reaches upstream — including a response that then goes on
to be blocked or redacted — never just for a plain allow; a request
[blocked](#custom-rules-rate-limiting-caching-and-cost-estimation),
[rate-limited](#custom-rules-rate-limiting-caching-and-cost-estimation),
or served from [cache](#custom-rules-rate-limiting-caching-and-cost-estimation)
never reaches the upstream at all, so none of those get a latency line.
The value that matched a rule is never written to the log — only the
rule's name.

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

## Serving over TLS

aiproxy listens on plain HTTP by default — the right choice for the
common case of running as a localhost process or a same-host sidecar,
where nothing ever leaves the machine. Set `--tls-cert`/`--tls-key` to
have it terminate TLS itself instead, for reaching it directly over a
network:

```
aiproxy start --target https://api.example.com --addr 0.0.0.0:8443 --tls-cert cert.pem --tls-key key.pem
```

Both flags point at PEM files (a certificate and its matching private
key) and must be set together — passing just one is rejected immediately
at startup with exit code 2, before `--target` or any config file is
even loaded, the same way an invalid `--log-format` is. Neither is
hot-reloadable via [SIGHUP](#reloading-config-without-restarting): unlike
every `aiproxy.json` field, rebinding a listener's TLS setup live is a
meaningfully different operation than the atomic in-process swap SIGHUP
already does for everything else, so a renewed certificate on disk (e.g.
from `certbot renew`) needs a restart to take effect — the same
limitation a plain `net/http` server has. If you need automatic
certificate rotation with no downtime, put a real reverse proxy or load
balancer in front of aiproxy instead and let it handle TLS.

## Restricting access by IP

`ip_allow_list` and `ip_deny_list` restrict which client IPs may reach
the proxy at all — a network-level complement to
[`proxy_api_key`](#authenticating-requests-to-the-proxy), checked
*before* it (and before anything else, including `GET /_aiproxy/stats`
and `/_aiproxy/metrics`):

```json
{
  "ip_allow_list": ["10.0.0.0/8", "192.168.1.5"],
  "ip_deny_list": ["10.0.5.0/24"]
}
```

Each entry is CIDR notation (`10.0.0.0/8`) or a single IP address
(`192.168.1.5`, treated as that address's own full-width `/32` — or
`/128` for IPv6). A request whose remote IP matches any `ip_deny_list`
entry is always rejected with a 403, *even if it also matches
`ip_allow_list`* — useful for carving an exception out of a broader
allow range (allow the whole office network, deny one compromised
subnet inside it). If `ip_allow_list` is non-empty, a request must match
one of its entries to get through at all; if it's empty (the default),
every IP is allowed unless `ip_deny_list` denies it — the same
"allow-list absent means allow everyone" default every other list-based
setting in aiproxy uses.

The match is always against the actual TCP peer address
(`r.RemoteAddr`) — **never** a client-supplied header like
`X-Forwarded-For`, which any caller could set to whatever value they
want, defeating the whole point of an IP-based check. If you run
aiproxy behind another reverse proxy or load balancer, every request
will appear to come from *that* proxy's own IP, not the original
client's — plan your allow/deny ranges around whatever actually
terminates the TCP connection to aiproxy, or run aiproxy directly on the
connection path if you need per-client IP filtering to mean anything.

A denied request is counted (`GET /_aiproxy/stats`'s top-level
`ip_denied` field, never broken down per target — the same reasoning as
`unauthorized`, since a rejected request never resolves one — and the
Prometheus endpoint's unlabeled `aiproxy_ip_denied_total`), logged
(`[IP DENIED]`, bright red — the same color as `[UNAUTHORIZED]`), and,
if `webhook_url` is set, [alerted](#webhook-alerts) with an `ip_denied`
event carrying the denied `remote_ip`. Hot-reloadable via
[SIGHUP](#reloading-config-without-restarting) like everything else in
this README.

### Per-IP rate limiting

`max_requests_per_minute`/`max_tokens_per_minute` (and their per-key
overrides) only ever protect callers that actually authenticate with a
[`proxy_api_key`](#authenticating-requests-to-the-proxy) — without one
configured, or for a caller that never presents a key, every
unidentified request shares one pool. `max_requests_per_minute_per_ip`
gives every distinct caller IP its own dedicated budget instead,
independent of identity entirely:

```json
{
  "max_requests_per_minute_per_ip": 30
}
```

Checked as a third, independent network-layer gate alongside
`ip_allow_list`/`ip_deny_list` — after them, but still *before* proxy
authentication, so a single noisy or malicious caller IP can't
monopolize the proxy, key or no key. The match is against the same
`r.RemoteAddr` TCP peer address `ip_allow_list` uses, with the same
caveat about running behind another reverse proxy or load balancer.
A rejected request gets the same [`X-RateLimit-*`
headers](#rate-limit-response-headers) as every other breaker
(`X-RateLimit-{Limit,Remaining,Reset}-Ip` plus `Retry-After`), is
counted separately from the identity-based breaker (`GET
/_aiproxy/stats`'s `ip_rate_limited` field and the Prometheus
endpoint's `aiproxy_ip_rate_limited_total`, both global-only — an
IP-rejected request never resolves a target to break it down by), and
logged/alerted under its own `ip_rate_limited` level/event, distinct
from `rate_limited` for the same reason `token_rate_limited` is: a
different breaker tripping for a different reason.

Unlike a per-target or per-key limiter, the number of distinct IPs a
real deployment sees over time is unbounded — aiproxy periodically
forgets an IP's own state once it's gone idle for a while (about two
minutes with no requests from it) rather than remembering every caller
it has ever seen for the life of the process. Zero/absent (the
default) disables this entirely — the exact behavior aiproxy has
always had.

## GeoIP-based blocking

`country_allow_list` and `country_deny_list` restrict which client
*countries* may reach the proxy — checked right after
[`ip_allow_list`/`ip_deny_list`](#restricting-access-by-ip), as a fully
independent gate: a request must pass *both* checks, and an IP that's
explicitly `ip_allow_list`-ed is **not** an exemption from a
country-level deny, or vice versa — the two dimensions never interact,
by design, to keep precedence simple to reason about.

```json
{
  "geoip_ranges_file": "geoip.csv",
  "country_allow_list": ["SE", "NO", "DK", "FI"],
  "country_deny_list": ["KP"]
}
```

`geoip_ranges_file` points at a plain CSV file mapping IP ranges to
2-letter country codes, one `cidr_or_ip,country_code` pair per line —
`#` comments and blank lines are ignored:

```
# example geoip.csv
1.2.3.0/24,US
5.6.7.0/24,SE
8.8.8.8,US
```

aiproxy defines this simple format itself rather than parsing
MaxMind's proprietary `.mmdb` binary database or its own multi-file CSV
export (which requires joining a *Blocks* file against a *Locations*
file by `geoname_id`) — keeping this feature usable with any
IP-to-country data source and keeping the project's stdlib-only, zero
Go-module-dependency discipline intact. If you already have a MaxMind
GeoLite2 account, a one-time join of `GeoLite2-Country-Blocks-IPv4.csv`
against `GeoLite2-Country-Locations-en.csv` (on `geoname_id`, keeping
just the network and `country_iso_code` columns) produces a file in
exactly this shape; any other IP-geolocation data source, or a small
hand-maintained list for a narrow blocklist use case, works just as
well.

`country_allow_list`/`country_deny_list` each hold 2-letter ISO
3166-1 alpha-2 codes (case-insensitive, normalized to uppercase). A
request whose resolved country matches any `country_deny_list` entry
is always rejected with a 403, *even if it also matches
`country_allow_list`* — the same "deny always wins" precedence
`ip_deny_list` already uses. If `country_allow_list` is non-empty, a
request's resolved country must match one of its entries; if it's
empty (the default), every country is allowed unless
`country_deny_list` denies it. `geoip_ranges_file` is required whenever
either list is set — `aiproxy validate` rejects the combination
otherwise, since there'd be nothing to resolve a country from.

An IP that can't be resolved to any country at all — not covered by
any range in `geoip_ranges_file` — is denied whenever either list is
configured, the same "can't evaluate it, so deny" rule already applied
to an unparseable remote IP by the IP allow/deny check. The same
caveat about the match being against the real TCP peer address, never
`X-Forwarded-For`, applies here too — see
[Restricting access by IP](#restricting-access-by-ip).

A denied request is counted (`GET /_aiproxy/stats`'s top-level
`country_denied` field, never broken down per target, and the
Prometheus endpoint's unlabeled `aiproxy_country_denied_total`), logged
(`[COUNTRY DENIED]`, bright red), and, if `webhook_url` is set,
[alerted](#webhook-alerts) with a `country_denied` event carrying the
denied `remote_ip` and its resolved `country`. Hot-reloadable via
[SIGHUP](#reloading-config-without-restarting) like `ip_allow_list`/
`ip_deny_list` — unlike [TLS](#serving-over-tls) or
[audit log signing](#audit-log-signing), this is ordinary config data,
not process-level listener/key setup.

## Authenticating requests to the proxy

By default, anyone who can reach the proxy's listen address can use it —
including as an open relay to whatever upstream you've pointed it at,
riding on the client's own `Authorization`/`X-Api-Key` credential.
That's fine on `127.0.0.1` with nothing else on the box, but not once
the proxy is reachable from anywhere else. Set `proxy_api_key` to
require a shared secret before a request is even looked at:

```json
{
  "proxy_api_key": "a-long-random-string-only-you-and-your-clients-know"
}
```

Every caller now has to send it back as a
`Proxy-Authorization: Bearer <key>` header — the standard HTTP header
for authenticating *to a proxy itself* (RFC 7235), distinct from
`Authorization`/`X-Api-Key`, which still carry the client's own
credential straight through to the real upstream API untouched:

```
curl https://your-aiproxy-host/v1/chat/completions \
  -H "Proxy-Authorization: Bearer a-long-random-string-only-you-and-your-clients-know" \
  -H "Authorization: Bearer sk-your-real-openai-key" \
  -d '...'
```

The key is compared in constant time, and the check runs before
anything else — before rules, the rate limiter, the cache, and even
`GET /_aiproxy/stats`/`/_aiproxy/metrics`, which need the same header
too once this is set (a Prometheus scrape config's `authorization:
{ type: Bearer, credentials: ... }` sends exactly this). A missing or
wrong key gets a `407 Proxy Authentication Required` with a
`Proxy-Authenticate: Bearer` response header, logged as `[UNAUTHORIZED]`
(`"unauthorized"` under `--log-format json`), counted in
`GET /_aiproxy/stats`'s `unauthorized` field and the Prometheus
endpoint's `aiproxy_unauthorized_total` (both global-only, like
[dry-run](#dry-run-mode-for-rules) — a rejected request never gets far
enough to resolve a target), and — if `webhook_url` is set — POSTed as
its own `unauthorized` event, with an empty `rule` (no scanning rule was
involved) and a `text` that never echoes the key back. Empty (the
default when `proxy_api_key` is absent) disables the check entirely —
the same fully-open behavior as before this existed. It's hot-reloadable
via [SIGHUP](#reloading-config-without-restarting) like everything else
in this section, and, like `webhook_url`, is never printed to the
terminal or a log line — only whether it's set (`aiproxy validate`'s
`proxy authentication:` line, the startup notice).

### Multiple named keys, with per-key stats and rate limits

`proxy_api_key` is one shared secret for everyone. Set `proxy_api_keys`
instead (or alongside it) to give several agents or teams their own key
— each shows up under its own name in stats and logs, and can optionally
get its own dedicated rate limit:

```json
{
  "proxy_api_keys": [
    { "name": "team-a", "key": "team-a-long-random-key" },
    { "name": "team-b", "key": "team-b-long-random-key", "max_requests_per_minute": 60 }
  ]
}
```

Every entry needs a `name` (unique, and never `"default"` — reserved for
the anonymous `proxy_api_key`, if that's also set) and a `key` (also
unique — two entries can't share one, since there'd be no way to tell
which name a request authenticated with it should attribute to);
`aiproxy validate` rejects either kind of collision, plus an empty name
or key. `proxy_api_key`, if set, keeps working completely unchanged — a
single, anonymous key labeled `"default"` wherever a named key would be
labeled by its own name — and combines freely with `proxy_api_keys`;
neither requires the other.

`max_requests_per_minute` on one of these entries gives that key its own
dedicated rate limit, checked *instead of* whatever
[route](#multi-target-routing) or the server-wide `max_requests_per_minute`
would otherwise apply — a caller's own budget is authoritative regardless
of which route they hit. A key with no override just shares whatever
route/global limiter would otherwise apply, same as before this field
existed. `max_tokens_per_minute` works exactly the same way for
[the token-based breaker](#token-based-rate-limiting). Unlike those two,
[`anomaly_multiplier`](#anomaly-based-rate-limiting) has no per-key
override to set here — it's a single server-wide setting — but each
named key still gets its own independent baseline to be measured
against, purely from its own observed traffic.

Every request authenticated with a named key is attributed by that name
— in `GET /_aiproxy/stats`'s `per_client` field, the Prometheus
endpoint's `aiproxy_client_*_total{client="..."}` series (and
`aiproxy_client_estimated_cost`, when `cost_per_1k_tokens` is set), and
the shutdown summary's `=== per-client breakdown ===` section:

```json
{
  "per_client": {
    "default": { "allowed": 12, "blocked": 0, "redacted": 0, "rate_limited": 0, "token_rate_limited": 0, "anomaly_detected": 0, "total_tokens": 0 },
    "team-a": { "allowed": 40, "blocked": 1, "redacted": 0, "rate_limited": 0, "token_rate_limited": 0, "anomaly_detected": 0, "total_tokens": 3100 },
    "team-b": { "allowed": 8, "blocked": 0, "redacted": 0, "rate_limited": 2, "token_rate_limited": 0, "anomaly_detected": 1, "total_tokens": 0 }
  }
}
```

A deliberately smaller set of fields than `per_target`: no cache-hit,
failover, or latency breakdown — those are inherently about which
target/route a request went through, not who called it. `per_client` is
only ever populated when at least one key is actually configured — no
bucket for a fully open proxy, since there's no caller identity to
attribute anything to. Names are never secret and appear freely in
stats/logs/the startup notice; the keys themselves get the same
treatment `proxy_api_key` always has — never printed anywhere, not even
in an error message, which instead identifies a failed webhook delivery
or similar by position (`webhook_url`, `webhooks[N]`) rather than value.
Hot-reloadable via [SIGHUP](#reloading-config-without-restarting) like
everything else in this section.

#### Per-key cost budgets

`cost_budget` (see [cost budget alerts](#custom-rules-rate-limiting-caching-and-cost-estimation))
is a single, server-wide threshold. Add `cost_budget` to one of
`proxy_api_keys`' own entries to give that key its own, independent
threshold instead:

```json
{
  "cost_per_1k_tokens": 0.03,
  "proxy_api_keys": [
    { "name": "team-a", "key": "team-a-long-random-key", "cost_budget": 25 },
    { "name": "team-b", "key": "team-b-long-random-key" }
  ]
}
```

Once `team-a`'s own running cost — its own `per_client` token count,
priced at the top-level `cost_per_1k_tokens` — reaches or passes 25,
aiproxy logs and webhook-alerts a `budget_exceeded` event carrying
`"client": "team-a"`, exactly once, same one-shot-per-process semantics
as the server-wide budget. `team-b` has no budget of its own here, so
its usage is only ever reflected in the server-wide budget (if one is
set) and in its own `per_client` stats — same as before this field
existed. A key's own budget and the server-wide one are entirely
independent: either, both, or neither can fire for the same request,
and each is alert-only — nothing is ever blocked, throttled, or
otherwise changed by crossing it. Same rule as the top-level
`cost_budget`: setting this on a key without the top-level
`cost_per_1k_tokens` also being set is a config error, since there's no
rate to price that key's tokens at. Hot-reloadable via
[SIGHUP](#reloading-config-without-restarting), like every other field
on a `proxy_api_keys` entry.

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
{"time":"2026-01-01T12:00:00Z","level":"allow","method":"GET","url":"/get","request_id":"a1b2c3d4-..."}
{"time":"2026-01-01T12:00:00Z","level":"latency","method":"GET","url":"/get","request_id":"a1b2c3d4-...","duration_ms":214}
{"time":"2026-01-01T12:00:01Z","level":"block","method":"POST","url":"/x","request_id":"e5f6a7b8-...","rule":"aws-access-key"}
{"time":"2026-01-01T12:00:02Z","level":"usage","method":"POST","url":"/chat","request_id":"a1b2c3d4-...","tokens":42}
{"allowed":2,"blocked":1,"rate_limited":0,"cache_hits":0,"total_tokens":42,"per_target":{"default":{"allowed":2,"blocked":1,"rate_limited":0,"cache_hits":0,"total_tokens":42}}}
```

`level` is one of `allow`, `block`, `redact`, `response_block`,
`response_redact`, `rate_limited`, `unauthorized`, `ip_denied`,
`country_denied`, `anomaly_detected`, `dry_run_block`, `dry_run_redact`,
`response_dry_run_block`, `response_dry_run_redact`,
`usage`, `latency`, `budget_exceeded`, `failover`, `target_ejected`,
`target_recovered`, `cache_hit`,
`server_error` (a low-level connection problem from Go's own HTTP
server, most commonly a TLS handshake failure from something other than
a real client — a stray plain-HTTP health check or port scan — hitting
a [TLS-enabled](#serving-over-tls) listener; routed through this same
event stream instead of the process's raw stderr specifically so it
can't break the "every line is valid JSON" guarantee), or
`error` (an internal problem unrelated to any specific request, e.g. a
failed cache write) — `method`/`url`/`rule`/`tokens` appear only where
relevant, `duration_ms` only on `latency` (present even when it's
genuinely `0` — a fast local response — since that's a real
measurement, not the field being absent), `cost`/`budget` only on
`budget_exceeded`, and `failed_target`/`next_target` only on `failover`.
`request_id` appears on every event actually tied to one specific
client request — see [Request correlation
IDs](#request-correlation-ids) — and is absent on the handful of
events that aren't (`target_ejected`/`target_recovered`, `error`).
This only affects the ongoing per-request log stream on
stderr; the one-time startup notices (`loaded N custom rule(s)`, `route:
...`, `aiproxy listening on ...`) still print as plain text on stdout,
since they're low-volume, human-oriented setup notices rather than part
of the structured stream a script would actually parse — the two are
already on separate streams, so piping just stderr gives you a clean,
pure-JSON feed.

## Structured error responses

Every rejection aiproxy itself produces — a block, a rate limit, an
unauthorized request, and so on — has always sent a plain-text body, the
same way `net/http`'s own `http.Error` always has. A client that sends
`Accept: application/json` — the way virtually every JSON REST client
does, including every LLM provider SDK this proxy fronts — gets a
structured body instead, automatically, with no config needed:

```
curl -H "Accept: application/json" http://127.0.0.1:8080/v1/chat
```

```json
{
  "error": "block",
  "message": "blocked by aiproxy rules",
  "rule": "aws-access-key"
}
```

`error` is a stable, machine-readable identifier — the exact same
vocabulary already used everywhere else in aiproxy (log `level`, webhook
`event`, and stats field names): `ip_denied`, `country_denied`,
`unauthorized`, `body_too_large`, `bad_request`, `block`,
`rate_limited`, `token_rate_limited`, `anomaly_detected`,
`method_not_allowed`, `cache_disabled`, `cache_clear_failed`,
`response_block`, or `not_found`. `rule` is only ever present on a
`block` (or `response_block`) rejection — the matched rule's name, never
the secret it matched, same discipline every log line and webhook alert
already follows.

A plain `curl` with no `Accept` header (or any other client that never
explicitly names `application/json`) gets exactly the same plain-text
body aiproxy has always produced — this is deliberately **not** "always
JSON now": a bare wildcard like `Accept: */*` (curl's own actual
default) doesn't count as asking for JSON, only an Accept header that
actually lists `application/json` (with a non-zero quality value) does.
Nothing about existing integrations changes unless they start asking for
it.

This applies uniformly to every rejection reason above, to the 404
`GET`/`POST` produces for an unknown path, and to a
[response-side rule match](#scanning-responses-too) — the synthetic body
substituted for a blocked upstream response gets the same treatment,
negotiated against the original client's own Accept header. It does
*not* apply mid-stream: a block that trips partway through an
already-started SSE response has no clean body to rewrite either way
(the 200 status and headers are already sent) — see
[Scanning responses too](#scanning-responses-too) for why that's an
inherent limitation of streaming, not something content negotiation
could fix.

## Request correlation IDs

Every request gets a unique ID — echoed back as `X-Request-Id` on
every response aiproxy produces, whatever the outcome (forwarded,
cached, blocked, rate-limited, any other rejection), and included as
`request_id` on every log line and webhook payload that one request
produces. No config needed — this is always on:

```
curl -i http://127.0.0.1:8080/v1/chat
< X-Request-Id: 3fa85f64-5717-4562-b3fc-2c963f66afa6
```

If the client already sent its own `X-Request-Id` (a gateway further
upstream, say, that generates one per hop), aiproxy reuses it verbatim
instead of generating a new one — so a single ID can trace a request
across every hop it passed through, not just aiproxy's own. A
client-supplied value is only trusted when it's safe to log and echo
back as-is (letters, digits, and `-_.:`, up to 128 characters — the
same shape a UUID, ULID, or W3C `traceparent`-style ID already fits
inside); anything else is silently replaced with a freshly generated
one rather than rejecting the request over what's ultimately a logging
nicety. With no client-supplied ID, aiproxy generates its own — a
random UUIDv4 — so there's always a real, unique ID to correlate on.

This is the one piece of information that ties a client's own logs
(they already have the ID, either because they sent it or because they
read it off the response) to aiproxy's own — invaluable once you're
trying to explain to a client "here's exactly what happened to *this*
one request" out of a busy shared log stream. It's carried through to
every [structured JSON log line](#structured-json-logging) as
`request_id` and every [webhook alert](#webhook-alerts) the same way,
so grepping one ID out of `--log-format json` output (or a durable
[log file](#persistent-log-file), which always includes it regardless
of `--log-format`) surfaces every line that one request produced. The
handful of events with no single request to attribute
(`target_ejected`/`target_recovered`, an internal `error`) simply omit
it, same as `method`/`url` already do for those. The plain colored
terminal text format doesn't repeat the ID inline on each line — it's
meant for a human watching live output, where the ID would mostly be
visual noise; for actual correlation, use `--log-format json` or the
log file, both of which always carry it.

## Persistent log file

`--log-format` only controls what the terminal shows for as long as
aiproxy is actually running. Set `log_file` to also get every event —
including the shutdown summary — durably appended to a file on disk, so
there's still something to go back and grep through after the process
has exited or been restarted:

```json
{
  "log_file": "/var/log/aiproxy.jsonl"
}
```

The file always gets one JSON object per line, in the exact same shape
`--log-format json` prints to the terminal — regardless of what
`--log-format` is actually set to. A durable record meant to be
`grep`/`jq`-ed later has no use for colored, human-oriented text, so
this doesn't follow the terminal's own formatting choice the way
everything else does. The file is opened in append mode (created if it
doesn't already exist) and never truncated.

aiproxy has no log rotation logic of its own — `log_file` is reopened
on every [SIGHUP](#reloading-config-without-restarting) reload,
*unconditionally*, even when the path hasn't changed, which is exactly
what lets an external tool like `logrotate` handle rotation instead: it
renames the current file out of the way and signals the process, and
the next reload's fresh handle creates a new file at that same path,
with the previous handle closed right after the swap so a long-running
proxy reloaded repeatedly never leaks file descriptors. This is the same
convention nginx and PostgreSQL use for their own log files.

## Audit log signing

```
aiproxy start --target https://api.example.com --config aiproxy.json --audit-log-key-file audit.key
```

`log_file` gives you a durable record, but a plain JSON-lines file on
disk is trivial to edit after the fact — anyone with write access can
delete or doctor a `block` line and there'd be no way to tell.
`-audit-log-key-file` (a CLI flag, not a config field — see below) HMAC
hash-chains every line appended to `log_file`: each line's `hash`
covers the line before it's own hash plus its own content, so any
later edit, deletion, insertion, or reordering breaks the chain from
that point forward. It requires `log_file` to be set — there's nothing
to chain otherwise — and rejects startup immediately, before doing
anything else, if it isn't.

The key itself is a plain secret file, not committed to the repo:

```
openssl rand -hex 32 > audit.key
chmod 600 audit.key
```

Once enabled, each line's shape changes from the flat, plain event to
a chained envelope wrapping it:

```json
{"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"1ebc00a935a9d30583ebf63896f6fc8cbe6fda88fbe872ceffd0f441af9ee94a","event":{"time":"2026-01-01T12:00:00Z","level":"allow","method":"POST","url":"/post"}}
{"prev_hash":"1ebc00a935a9d30583ebf63896f6fc8cbe6fda88fbe872ceffd0f441af9ee94a","hash":"6e9440d1ceb70ab604fb629c2f9c244cf746fb46d55076bbcf4edfc5ed497bb","event":{"time":"2026-01-01T12:00:01Z","level":"block","method":"POST","url":"/post","rule":"aws-access-key"}}
```

`event` is the exact same object `--log-format json` prints and a plain
`log_file` would have stored — audit signing only wraps it, it never
changes what's actually recorded. The very first line in a chain always
has `prev_hash` set to 64 zeros; every line after that has the previous
line's own `hash`.

Check a log file's integrity with the same key:

```
aiproxy verify-log --audit-log-key-file audit.key /var/log/aiproxy.jsonl
```

This reports `OK` and how many lines verified, or the first line where
the chain breaks and why (hash mismatch — that line's content was
altered, or `prev_hash` mismatch — a line was removed, inserted, or
reordered) — everything after the break is unverified, since the
chain's trustworthiness only extends as far as its first broken link.

A restart continues the same chain instead of silently starting a new
one: on startup, aiproxy reads the last line already in `log_file` and
resumes from its hash, so a log file that spans several process
lifetimes (or several `logrotate`-rotated files, in order) still
verifies as one continuous chain. Turning audit signing on for the
first time against a `log_file` that already has plain, unchained
content in it starts the chain fresh at that point — there's no way to
retroactively chain lines written before signing was ever enabled.

Like [TLS](#serving-over-tls), this is a CLI flag rather than a
`log_file`-style config field, and it's not hot-reloadable via SIGHUP:
rotating the signing key is a meaningfully different, riskier operation
than the atomic in-process field swaps SIGHUP already does for every
other tunable, so it needs a restart — which, per the paragraph above,
continues the existing chain under the new key rather than starting
over.

## Reloading config without restarting

```
kill -HUP <aiproxy-pid>
```

Sending `SIGHUP` re-reads the same config file `--config` (or the
default `aiproxy.json`) pointed at on startup, and applies it live:
custom rules, path rules, the rate limit, the cache, cost estimation,
the cost budget, the max request body size, the webhook alert URL,
additional `webhooks` destinations, the proxy API key, additional named
`proxy_api_keys`, `log_file` (see
[persistent log file](#persistent-log-file)
for why this one is reopened unconditionally, not just when its path
changes), and target routes all take effect for the next request,
with no dropped connections and no restart. Every one of these is logged
(as `reload` on success, or `reload_error` on failure, under
`--log-format json`).

If the reloaded file has any problem — a bad regex, a bad target, a
cache directory that can't be created — the reload is refused and the
proxy keeps running on its last-known-good configuration; it never
crashes or blanks out its rules because of a bad edit. `--target`,
`--addr`, and `--log-format` are startup-only and unaffected by a
reload — those still require a real restart.

### Seeing exactly what a reload changed

A successful reload's log line doesn't just say "reload succeeded" — it
reports exactly which config fields actually changed, compared to
whatever was running immediately before:

```
[RELOAD] aiproxy: reloaded config from aiproxy.json: max_requests_per_minute: 60 -> 100; cache_enabled: false -> true
```

A reload that finds nothing different says so plainly instead
(`... (no changes)`) rather than repeating an empty diff. When there
*is* a diff, it's also delivered as a `config_changed`
[webhook alert](#webhook-alerts) carrying the same summary in `text` —
useful for keeping an audit trail of who changed what in production
without needing shell access to grep the log file.

A `custom_rules`, `targets`, `proxy_api_keys`, `webhooks`, or any other
list/map field is only ever reported as an entry count (`"2 entries ->
3 entries"`), never its actual contents — this keeps a long rule or
route list from producing an unreadable diff line, and, more
importantly, means a list of named keys or webhook destinations can
never leak one of its own entries' secret values through a diff.
`proxy_api_key` and `webhook_url` get the same treatment for the same
reason, redacted to `(hidden)` on both sides even though they're plain
strings: reporting *that* a credential changed is useful, echoing it
into a log file or a webhook payload never is.

## Referencing environment variables in config

Any string field in `aiproxy.json` — `proxy_api_key` and `webhook_url`
are the obvious candidates, but nothing is special-cased — can reference
an environment variable instead of embedding the actual value in the
file, so a secret never has to be committed to a repo alongside the rest
of the config:

```json
{
  "proxy_api_key": "${AIPROXY_KEY}",
  "webhook_url": "${AIPROXY_WEBHOOK_URL}"
}
```

`${NAME}` is replaced with the current process's environment variable
`NAME` before the file is even parsed as JSON, so it works the same way
in every field. A reference to a variable that isn't set is a hard
error, the same class of problem as a config file that isn't valid
JSON — `aiproxy start` refuses to start and `aiproxy validate` reports it
immediately, rather than silently substituting an empty string, which
could quietly turn `proxy_api_key`'s entire auth check off or break a
webhook URL without any obvious sign anything was wrong.

Double the dollar sign (`$$`) to get a literal `$` without attempting
substitution — the way to stop a field from being treated as a reference
at all. A `custom_rules` pattern that actually wants to match a literal
`${` in request bodies (catching an env-var-style secret reference
leaking through, for example) doesn't need this: writing the dollar sign
regex-escaped as `\$\{...\}`, which a Go regex needs anyway since a bare
`$` is an end-of-string anchor and not a literal character, already
keeps the `$` from being immediately followed by `{` in the raw file, so
it's left untouched on its own. Every other bare `$` — the common case,
an end-of-line regex anchor — is likewise never touched; only `${` and
`$$` are ever treated specially.

Values are resolved once, from whatever environment the process was
actually started in — [SIGHUP](#reloading-config-without-restarting)
re-reads and re-expands the config file, but reads it against that same
original environment, since a running process's own environment can't
be changed out from under it. Changing what a `${...}` reference
resolves to always needs a real restart, not just a reload.

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

### Scoping a custom rule to a target or key

By default a custom rule applies to every request, regardless of which
[target](#multi-target-routing) it's routed to or which
[named proxy key](#multiple-named-keys-with-per-key-stats-and-rate-limits)
made it. `targets` and/or `keys` narrow a rule down to only the traffic
you actually want it checked against — useful when a pattern is only
ever meaningful for one upstream (an internal API token that should
never reach one provider but is a completely normal value to send to
another) or only relevant for one caller (a team-specific secret format
that would otherwise be a constant false positive for everyone else):

```json
{
  "custom_rules": [
    {
      "name": "internal-token",
      "pattern": "ITKN_[0-9]+",
      "targets": ["/openai", "model:fast"],
      "keys": ["mobile-app"]
    }
  ],
  "targets": [{ "prefix": "/openai", "url": "https://api.openai.com" }],
  "model_routes": [{ "name": "fast", "models": ["gpt-4*"], "url": "https://api.openai.com" }],
  "proxy_api_keys": [{ "name": "mobile-app", "key": "..." }]
}
```

Both are optional lists of labels — the same ones already used
everywhere else in stats, logs, and the Prometheus endpoint: `"default"`
for the fallback `--target` or the anonymous top-level `proxy_api_key`,
a `targets[].prefix` entry, `"model:<name>"` for a `model_routes[]`
entry, or a `proxy_api_keys[].name`. Leaving either out (the default)
means the rule applies regardless of that dimension, unchanged from
before these fields existed; setting both means a request must match
*both* to trigger the rule, not either one alone. A request that misses
the scope is treated exactly as if the rule didn't exist at all — it
falls through to whatever other rule or the default action would
otherwise apply, not merely "not logged." The scope applies identically
to response scanning (see
[Scanning responses too](#scanning-responses-too)): a rule scoped to one
target only ever inspects that target's own responses.

Referencing a target, model route, or key that isn't actually configured
is a config error, caught by both a cold start and
`aiproxy validate` — the same typo protection `builtin_rule_actions`
already gets — rather than silently compiling a rule that can never
match anything.

### Token-based rate limiting

`max_requests_per_minute` counts requests — a second, independent
breaker, `max_tokens_per_minute`, instead caps how many *tokens* upstream
responses have reported using within a rolling minute, for traffic where
a handful of huge completions matter more than how many calls were made:

```json
{
  "max_tokens_per_minute": 100000
}
```

Optional and disabled by default, same as `max_requests_per_minute`.
Unlike a request's cost in the plain circuit breaker, a request's own
token cost isn't known until *its own response* has come back — so this
breaker can only ever reject a request based on usage already recorded
from earlier ones, never its own. In practice that means the very first
request into an empty window is always let through regardless of size,
and a single very large response can push the window over budget by more
than `max_tokens_per_minute` before the *next* request gets rejected —
the same tradeoff every commercial LLM API's own per-minute token limit
makes, since there's no way to reserve tokens for a cost nobody knows
yet. A rejected request gets a 429, logged as `[TOKEN LIMIT]` (yellow;
`"token_rate_limited"` under `--log-format json`) and counted separately
from `max_requests_per_minute` rejections in stats, the Prometheus
endpoint, and [webhook alerts](#webhook-alerts) — the two breakers trip
for different reasons, so they're never folded into one counter.

Like `max_requests_per_minute`, it can be overridden per target, per
[model route](#model-based-routing), and per
[named proxy key](#multiple-named-keys-with-per-key-stats-and-rate-limits)
with their own `max_tokens_per_minute` — whichever is most specific for a
given request takes precedence, with the exact same precedence order as
the request-count breaker.

### Rate-limit response headers

Whenever `max_requests_per_minute` and/or `max_tokens_per_minute` is
configured (server-wide, per-target, per-model-route, or per-named-key —
whichever ends up effective for a given request), every response that
actually reaches the limiter carries a matching pair of headers:

```
X-RateLimit-Limit-Requests: 60
X-RateLimit-Remaining-Requests: 57
X-RateLimit-Reset-Requests: 42s
X-RateLimit-Limit-Tokens: 100000
X-RateLimit-Remaining-Tokens: 88000
X-RateLimit-Reset-Tokens: 12s
```

No config flag — this applies automatically the moment either limiter
is configured, deliberately mirroring OpenAI's own
`x-ratelimit-{limit,remaining}-{requests,tokens}` header shape rather
than inventing a new one, since that's already the exact convention
this proxy's own callers — people building against LLM APIs — are used
to reading. They appear on a **successful** response too, not only a
rejected one, so a well-behaved client can back off proactively once
it sees `Remaining` getting low, before ever actually hitting a 429. A
request that never reaches the limiter at all — an [IP/country
deny](#restricting-access-by-ip), a failed
[proxy auth](#authenticating-requests-to-the-proxy) check, a
[blocked rule](#built-in-secret-patterns), or a [cache
hit](#custom-rules-rate-limiting-caching-and-cost-estimation) — never
carries these headers either, since there's no limiter state to report
for a request that never actually asked the limiter anything.

A rejected (429) response additionally carries the standard
`Retry-After` header (an integer number of seconds, always rounded
*up* — never a value a client could wait out and still retry too
early) — the same header every real HTTP-aware client already knows
how to honor, so a caller doesn't need to parse `X-RateLimit-Reset-*`
itself just to know when to try again.

### Anomaly-based rate limiting

`max_requests_per_minute`/`max_tokens_per_minute` are both fixed,
absolute thresholds — a caller well under either can still be a runaway
agent loop, just one that hasn't yet reached the configured ceiling.
`anomaly_multiplier` instead flags a
[named proxy client](#multiple-named-keys-with-per-key-stats-and-rate-limits)
whose current minute's request count spikes to a multiple of *that
client's own* recent baseline — a relative complement to the two fixed
breakers above, catching a client that's suddenly far faster than it
itself normally is, regardless of where that falls against any absolute
cap:

```json
{
  "anomaly_multiplier": 50
}
```

The baseline is an exponential moving average of a client's own past
per-minute request counts, established from real traffic — there's no
warm-up config, it just starts learning from the first request onward.
A brand new client (or the very first minute of a fresh process) has no
baseline yet, so nothing is ever flagged during that initial window,
regardless of how much traffic arrives; only once at least one full
minute has completed does a spike become detectable. A small built-in
floor (a handful of requests) also means a client whose baseline is
naturally near zero never gets flagged over an essentially meaningless
ratio (2 requests against a 0.1/minute baseline, say). Optional and
disabled by default (zero/absent).

Only meaningful for an identified caller: [`proxy_api_key`/`proxy_api_keys`](#authenticating-requests-to-the-proxy)
configured, since there's no notion of "this caller's own baseline"
without one — a fully anonymous, unauthenticated proxy is completely
unaffected by `anomaly_multiplier`, the same way it's unaffected by any
other per-client setting. Each named key (including the anonymous
`"default"` one, if `proxy_api_key` alone is set) gets its own
independent baseline; one client spiking never affects another's.

A flagged request gets a 429, logged as `[ANOMALY]` (yellow;
`"anomaly_detected"` under `--log-format json`, carrying the client's
current-window `rate` and the `baseline` it was compared against),
counted separately from `rate_limited`/`token_rate_limited` in stats
(`GET /_aiproxy/stats`'s `anomaly_detected` field, top-level and per
client — never per target, since this is fundamentally about which
*caller*, not which target), the Prometheus endpoint's unlabeled
`aiproxy_anomaly_detected_total`, and
[webhook alerts](#webhook-alerts). Set `anomaly_dry_run: true` to only
log/count/alert what *would* have been rejected, without actually
blocking anything — the same escape hatch a
[custom rule's own `dry_run`](#dry-run-mode-for-rules) gives a new,
untrusted rule: a statistical threshold is inherently more prone to a
false positive than an exact pattern match, so tuning
`anomaly_multiplier` against real traffic before trusting it to enforce
anything is the recommended way to turn this on. `aiproxy validate`
rejects `anomaly_dry_run` set without `anomaly_multiplier` — there's
nothing to dry-run otherwise.

`cache_enabled` is optional and off by default. When true, every 200 OK
response is stored under `.aiproxy_cache/` in the working directory,
keyed by a SHA256 hash of the request method, target URL, and body. An
identical request served later is answered straight from that file and
never reaches the upstream target. `.aiproxy_cache/` is already listed in
`.gitignore`.

Set `cache_ttl_seconds` alongside it to expire an entry a fixed time
after it was written, instead of caching forever:

```json
{
  "cache_enabled": true,
  "cache_ttl_seconds": 300
}
```

A request whose matching entry is older than that is treated as a plain
cache miss and forwarded upstream again — the stale file is removed from
disk at that point too, not left behind. Re-caching the same key (a
fresh upstream hit after expiry) resets its age, same as writing a brand
new entry. Zero or absent (the default) means entries never expire on
their own, the same behavior as before this field existed.
`aiproxy validate` rejects `cache_ttl_seconds` set without
`cache_enabled` — a TTL for a cache that's off has nothing to expire.

### Seeing how fresh a cache hit actually is

Every cache hit carries a real `Age` header — the standard HTTP header
(RFC 7234) for exactly this, in seconds — so a client can always tell
how old the response it just got actually is, no config required:

```
< HTTP/1.1 200 OK
< Age: 42
```

`Age` is present on every hit regardless of whether `cache_ttl_seconds`
is even set — "how old is this" doesn't need an expiry policy to be a
meaningful question. When `cache_ttl_seconds` *is* set, aiproxy also
flags a hit as getting stale once its age crosses 80% of the TTL: a
distinct `[CACHE HIT - STALE]` log line (yellow, instead of the usual
purple) and its own `stale_cache_hits` count in `GET /_aiproxy/stats`
and the Prometheus endpoint's `aiproxy_stale_cache_hits_total`,
alongside the ordinary `cache_hits` every hit already gets. This is
purely informational — a stale-flagged hit is still served exactly the
same as any other; nothing about caching behavior itself changes, and
an entry is only ever actually evicted once it's fully past
`cache_ttl_seconds` (see above), not at this earlier warning point. The
80% threshold isn't configurable — one reasonable default rather than
another knob to tune per deployment.

### Capping the cache's disk usage

`.aiproxy_cache/` has no size limit by default — left running long enough
against varied traffic, it can grow without bound. Set `cache_max_size_bytes`
to cap the total size of every entry combined:

```json
{
  "cache_enabled": true,
  "cache_max_size_bytes": 104857600
}
```

Once writing a new entry would push the total over this limit, the
least-recently-*used* entries are deleted — oldest-used first — until
there's room again. "Used" means actually read back with a cache hit
(via `GET`ing it, i.e. a repeat request), not just written — an entry
Set long ago but hit constantly survives in favor of one written
recently but never read again. This tracking lives in memory, separate
from `cache_ttl_seconds`'s own on-disk timestamp: a cache hit never
resets an entry's TTL clock, so the two features don't interact. A
single entry larger than `cache_max_size_bytes` on its own is never
deleted immediately after being cached — there's nothing else left to
evict it in favor of, and caching a response can never itself fail
purely because of the size policy. `aiproxy validate` rejects
`cache_max_size_bytes` set without `cache_enabled`, same reasoning as
`cache_ttl_seconds`; zero or absent (the default) means the cache stays
unbounded, same behavior as before this field existed. A restart
correctly picks up whatever was already on disk — the very first write
after starting still evicts against the *real* existing total, not an
empty in-memory count that would otherwise let the directory keep
growing past the configured limit indefinitely.

Without a size cap — or even with one, for immediate effect instead of
waiting it out — clear every cached entry right now with:

```
curl -X POST http://127.0.0.1:8080/_aiproxy/cache/clear
```

A third reserved, proxy-internal path alongside `/_aiproxy/stats` and
`/_aiproxy/metrics`, `POST`-only since it actually mutates state rather
than just reading it. Responds `{"cleared": true}` on success, a 404 if
`cache_enabled` isn't set (nothing to clear), and honors
`proxy_api_key` exactly like the read-only endpoints if configured — if
anything, a mutating endpoint deserves at least as much protection.

### Per-target cache settings

`cache_enabled`/`cache_ttl_seconds` are global by default — every
target shares one policy. `targets[].cache_enabled`/
`targets[].cache_ttl_seconds` (and the equivalent `model_routes[]`
fields) override them for just one target's own traffic:

```json
{
  "cache_enabled": true,
  "cache_ttl_seconds": 300,
  "targets": [
    { "prefix": "/volatile", "url": "https://api.example.com", "cache_enabled": false },
    { "prefix": "/stable", "url": "https://api.example.com", "cache_ttl_seconds": 3600 }
  ]
}
```

`/volatile`'s own responses are never cached at all, even though
caching is on server-wide — useful for a target whose responses change
too quickly to be worth caching, or are too sensitive to ever persist
to disk. `/stable`'s own entries get a full hour instead of the
5-minute server default. Any target with no override of its own just
keeps sharing the top-level setting, unchanged from before per-target
overrides existed.

`cache_enabled: true` on a target only ever narrows *back* into the
already-on server-wide policy — it can't turn caching on for one
target when `cache_enabled` itself is unset or false at the top level.
Standing up the real on-disk `.aiproxy_cache/` directory is always a
top-level decision; `aiproxy validate` rejects any target/model route
that sets `cache_enabled`/`cache_ttl_seconds` without the top-level
`cache_enabled` also being true, the same "requires" pattern
`cache_ttl_seconds` itself already follows at the top level.
`cache_max_size_bytes`, by contrast, stays global-only — a size cap is
inherently a whole-cache-directory budget shared across every entry
regardless of target, not something that makes sense to scope per
target the way TTL/enabled do.

`cost_per_1k_tokens` is optional and off by default (no cost line at
all). aiproxy has no built-in, inevitably-stale pricing table — you tell
it what rate applies to your own usage (whatever your provider actually
charges you per 1,000 tokens, in whatever currency), and the summary
just multiplies that by the total tokens tracked during the run.

Set `cost_budget` alongside it to get notified once the running total
cost reaches or passes a threshold — a real-time signal for an agent
loop quietly running up a bill, without waiting for the shutdown summary
or polling stats yourself:

```json
{
  "cost_per_1k_tokens": 0.03,
  "cost_budget": 10
}
```

This is visibility only, never enforcement — a request that pushes the
cost over budget is still forwarded and answered completely normally.
Once crossed, it's logged (`[BUDGET EXCEEDED]`, yellow;
`"budget_exceeded"` under `--log-format json`), [webhook-alerted](#webhook-alerts)
if `webhook_url` is set, and reported in `GET /_aiproxy/stats`'s
`cost_budget` field and the Prometheus endpoint's `aiproxy_cost_budget`
gauge — but only **once** for the life of the running process, not on
every request past the threshold; a budget alert is meant to be a single
"you've gone over" notice, not a recurring one. `aiproxy validate`
rejects `cost_budget` set without `cost_per_1k_tokens` — a budget with no
rate to price tokens at has nothing to compare against.

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
itself unset). `targets[].max_tokens_per_minute` works exactly the same
way for [the token-based breaker](#token-based-rate-limiting).

`targets[].cost_per_1k_tokens` (and `model_routes[].cost_per_1k_tokens`)
works the same way again, for [cost estimation](#custom-rules-rate-limiting-caching-and-cost-estimation)
— genuinely necessary once traffic is actually routed across providers
with different real pricing, where a single global rate would misprice
every target that doesn't happen to match it:

```json
{
  "cost_per_1k_tokens": 0.03,
  "targets": [
    { "prefix": "/anthropic", "url": "https://api.anthropic.com", "cost_per_1k_tokens": 0.08 },
    { "prefix": "/openai", "url": "https://api.openai.com" }
  ]
}
```

`/anthropic`'s own tokens are priced at its own 0.08 rate; `/openai`
has no override, so it keeps sharing the top-level 0.03 rate. A target
can set its own rate even when the top-level `cost_per_1k_tokens` is
itself unset, pricing only that one target while leaving everything
else unpriced. This affects every cost figure that breaks down by
target — the `per_target` entries in `GET /_aiproxy/stats`, each
target's own `aiproxy_estimated_cost{target="..."}` Prometheus series,
and the shutdown summary's per-target breakdown — and the **total**
cost everywhere it's shown (the summary's own top-line figure,
`estimated_cost` at the top of the stats JSON, `cost_budget`
crossing) is always the true sum of every target's own tokens at its
own rate, never the combined token count priced at one flat rate,
which would silently misprice it the moment any target's rate
diverges from the default. The one exception is
[per-key cost tracking](#multiple-named-keys-with-per-key-stats-and-rate-limits):
a named proxy key's own traffic isn't necessarily confined to one
target, so its cost is always priced at the server-wide default rate
regardless of any per-target overrides — a known, accepted
approximation for that one narrower dimension.

### Failover across multiple upstreams

Give a target `urls` instead of `url` for an ordered list of candidate
upstreams instead of a single one — useful for putting a backup provider
(or a second region of the same one) behind a route that would otherwise
go down with its primary:

```json
{
  "targets": [
    { "prefix": "/openai", "urls": ["https://api.openai.com", "https://backup.example.com"] }
  ]
}
```

A request tries the first URL, and only moves on to the next if that
attempt never got a response at all — a dial, TLS, or timeout failure
meaning the candidate was genuinely unreachable. It never retries a
*different* candidate just because one answered with an HTTP-level error
(a 5xx): by the time a backend has responded at all, it may already have
started acting on the request, and blindly replaying that against a
different backend risks a duplicate side effect — a duplicate, possibly
billed, LLM call being the textbook case for this proxy. `url` and
`urls` are mutually exclusive; set exactly one per target. This only
applies to `targets[]` entries — the fallback `--target` stays a single
URL with no failover of its own.

Each attempt is logged (`[FAILOVER]`, bright yellow;
`"failover"` under `--log-format json`) and, if `webhook_url` is set,
[alerted](#webhook-alerts) with the failed and next candidate URLs —
worth knowing about in real time, since it means a provider is down.
It's also counted, broken down by target like most other counters (not
global-only the way `unauthorized` and dry-run are — a failover is
always about one specific route's own candidate list): `GET
/_aiproxy/stats`'s `failover` field, and the Prometheus endpoint's
`aiproxy_failover_total{target="..."}`. A request whose every candidate
turns out to be unreachable still just gets an error response, the same
as forwarding to a single, entirely-down target has always produced —
this adds a chance to recover before that happens, not a guarantee
against it.

### Weighted traffic splitting

`urls` is an ordered *failover* list — candidates meant to be
interchangeable backups of the very same logical destination, only
falling back when one is actually unreachable. `weighted_urls`, set
instead, deliberately *splits* traffic between candidates by
configured proportion, even while everything is healthy — a canary
rollout, or an A/B comparison between two genuinely different
destinations (a new model, a different provider):

```json
{
  "targets": [
    {
      "prefix": "/chat",
      "weighted_urls": [
        { "url": "https://api.openai.com", "weight": 90 },
        { "url": "https://api.newmodel.com", "weight": 10 }
      ]
    }
  ]
}
```

One candidate is chosen at random, in proportion to its own `weight`
relative to the others, fresh for every request — weights don't need
to add up to 100 or any particular total, only their relative
proportions to each other matter (`{90, 10}` and `{9, 1}` behave
identically). Across many requests, the actual traffic split
approximates the configured ratio. `url`, `urls`, and `weighted_urls`
are mutually exclusive; set exactly one per target (or `model_routes[]`
entry — the same field works there too).

The chosen candidate still gets exactly the same
[failover](#failover-across-multiple-upstreams) and [target
ejection](#automatically-deprioritizing-a-failing-candidate) protection
every other route already has: if it happens to be unreachable, aiproxy
still tries the rest, in their declared order, rather than failing the
request outright — the same "never refuse a genuine attempt when a
healthier alternative exists" principle ejection itself already
established. In practice this means a real outage on the smaller side
of a split can temporarily skew the actual ratio toward the healthier
side, favoring uptime over strict adherence to the configured
proportion, for as long as the outage lasts.

The [cache](#custom-rules-rate-limiting-caching-and-cost-estimation)
key for a weighted route is computed from whichever candidate was
*actually chosen* for that specific request, not a single fixed
identity the way a plain failover list's own cache key always is — a
90/10 split between two real, different models must never let one
candidate's cached response leak into a request that was "supposed" to
go to the other, since (unlike failover's own interchangeable
candidates) a weighted split's whole point is that they're genuinely
different destinations. There's no separate per-candidate breakdown in
stats/logs for a weighted route beyond what every other multi-candidate
route already gets (the aggregate `targets[].prefix` label) — if you
need to compare metrics between the two sides of a split directly, give
each its own separate route/prefix instead.

### Automatically deprioritizing a failing candidate

Failover already moves a request on to the next candidate URL when one
turns out to be unreachable — but on the *next* request, it still tries
the same known-bad candidate first, all over again, paying the same
connection cost (or [timeout](#configurable-upstream-timeouts)) before
falling back to the one that actually works. `target_ejection_threshold`
and `target_ejection_cooldown_seconds` add a small circuit breaker on
top of failover to stop that:

```json
{
  "target_ejection_threshold": 5,
  "target_ejection_cooldown_seconds": 30
}
```

Once a candidate URL has failed `target_ejection_threshold` times in a
row with a transport-level error (dial, TLS, or timeout — never an
HTTP-level error response; the exact same "only a genuinely unreachable
candidate counts" rule failover itself already applies), it's
temporarily deprioritized for `target_ejection_cooldown_seconds`: a
route with more than one candidate tries a healthier one first instead,
only falling back to the deprioritized one if every healthier candidate
also turns out to be genuinely unreachable. **Deprioritized never means
refused.** A single-target route (no `urls` failover list configured at
all), or a route whose every candidate is currently deprioritized,
always still makes a real attempt against it — ejection only ever helps
skip ahead to a better option *when one actually exists*; it never
manufactures a synthetic failure on its own. Both settings are optional
and independent of every other target's own ejection state (each
candidate URL is tracked separately); both must be set together, and
both default to disabled.

A candidate's very first failure right after `target_ejection_cooldown_seconds`
elapses starts counting fresh toward the threshold again — a target
that's still genuinely down keeps getting correctly re-deprioritized
after each cooldown, not silently forgotten about after the first time.
Crossing the threshold logs `[TARGET EJECTED]` (bright red) and, if
`webhook_url` is set, [alerts](#webhook-alerts) with the affected URL; a
later success against a deprioritized candidate logs `[TARGET
RECOVERED]` (green) and alerts the same way. Both are counted
global-only (not broken down per target, the same way `unauthorized` and
the anomaly counters are) via `GET /_aiproxy/stats`'s
`targets_ejected`/`targets_recovered` fields and the Prometheus
endpoint's `aiproxy_targets_ejected_total`/`aiproxy_targets_recovered_total`
— the affected URL itself is only ever in the log line and webhook
payload, since which specific candidate tripped isn't a route-label-shaped
dimension the way most other counters are.

### Proactive target health checks

Ejection above is purely *reactive* — a candidate only gets
deprioritized after a real client request happens to hit it and fail.
`target_health_check_interval_seconds` adds a proactive check on top:

```json
{
  "target_ejection_threshold": 3,
  "target_ejection_cooldown_seconds": 30,
  "target_health_check_interval_seconds": 15,
  "target_health_check_path": "/health"
}
```

Once set, aiproxy probes every currently configured candidate URL
(`--target` plus every `targets[]`/`model_routes[]` candidate,
deduplicated) in the background on this interval, independent of real
traffic — so a dead target is discovered and deprioritized *before* a
real request ever has to fail against it first. A probe counts as
healthy the moment it gets back **any** HTTP response at all, whatever
the status code — the same "only a genuine transport-level failure
counts" rule [ejection](#automatically-deprioritizing-a-failing-candidate)
itself already applies — since an arbitrary upstream LLM API has no
universal unauthenticated health-check convention to match a specific
status against, but completing the HTTP exchange at all still proves
the candidate is genuinely reachable. `target_health_check_path`, if
set, probes that path on every candidate instead of each one's own
configured URL — useful for probing a dedicated lightweight endpoint
rather than hitting a heavier default route on every cycle.

A health check's result feeds directly into the exact same breaker
`target_ejection_threshold` already configures — a failed probe is
recorded exactly like a real request's own transport-level failure, a
successful one clears it exactly like a real request's own success — so
`target_health_check_interval_seconds` **requires**
`target_ejection_threshold`/`target_ejection_cooldown_seconds` to
already be set: there's no breaker for a health check to report into
otherwise. There's no separate threshold, cooldown, log line, stats
counter, or webhook event for a health check specifically — a target
crossing the threshold from a failed probe logs `[TARGET EJECTED]` and
alerts exactly the same way a target crossing it from a real request's
own failure already does, since from that point on it's the exact same
breaker state either way. Both settings are ordinary, optional,
hot-reloadable-via-SIGHUP `aiproxy.json` fields; zero/absent (the
default) disables proactive checking entirely, leaving aiproxy exactly
as reactive as it's always been.

### Configurable upstream timeouts

By default, forwarding a request to an upstream uses Go's own
unlimited-by-default HTTP client behavior — no cap on how long aiproxy
will wait for a response, or on how long a slow/hung upstream can hold a
connection open. Two independent, optional settings add limits:

```json
{
  "upstream_response_timeout_seconds": 30,
  "upstream_total_timeout_seconds": 300
}
```

`upstream_response_timeout_seconds` caps how long aiproxy waits for an
upstream to *begin* responding (its status line and headers) before
giving up — this catches a hung or dead upstream that accepted the
connection but never answers at all. It never affects an upstream that
starts responding promptly, no matter how long the response body or
stream itself then takes to finish; a long but genuinely active LLM
completion is never cut short by this setting alone.

`upstream_total_timeout_seconds` caps the *entire* round trip instead —
connecting, headers, and reading the complete response or stream,
across every [failover](#failover-across-multiple-upstreams) candidate
tried for it — aborting the request if it's still running past that
point. Unlike the response-only timeout, this **can** cut off a
legitimately long-running streaming completion that's still actively
sending data; only set it when a hard ceiling on total request duration
is actually wanted, independent of whether the upstream is still making
progress.

The two are deliberately independent — set either, both, or neither.
Both default to `0` (unlimited), the same behavior aiproxy has always
had. A request an upstream timeout aborts gets a `502`-class error
response, the same one a completely unreachable target has always
produced; there's no separate counter or webhook event for a timeout
specifically, since (like every other transport-level forwarding
failure) it isn't attributable to a rule or breaker aiproxy itself
enforced.

### Model-based routing

`targets` routes by URL path prefix; `model_routes` routes by the
request body's own `"model"` field instead — useful when one
OpenAI-compatible client (or one aiproxy endpoint) sends requests for
several different providers' models without using a different path
convention per provider:

```json
{
  "model_routes": [
    { "name": "anthropic", "models": ["claude-*"], "url": "https://api.anthropic.com" },
    { "name": "openai", "models": ["gpt-*", "o1*"], "url": "https://api.openai.com" }
  ]
}
```

A request whose body is `{"model": "claude-3-opus-20240229", ...}` goes
to `https://api.anthropic.com`, with the client's own path forwarded
completely unchanged — unlike `targets[].prefix`, there's no prefix to
strip, since a model route is about *which upstream* gets the traffic,
not *which URL space* the client used to ask for it. `models` is a list
of glob patterns (`path.Match` syntax: `*`, `?`, `[...]` — the same
shape as a shell glob); routes are checked in the order they're listed,
first matching pattern wins, same rule as `targets[].prefix`. Every
`model_routes` entry needs a unique `name` (used as its
stats/log/metrics label, `model:<name>`) and at least one pattern; the
same literal pattern can't appear in two different entries, since the
second would never be reachable.

**Checked before `targets`**, and takes priority over it: if a request's
model matches a `model_routes` entry, that route is used and path-prefix
routing is skipped for that request entirely. A request with no `model`
field, an unparseable body, or a model that matches no configured
pattern simply falls through to `targets`/`--target` exactly as if
`model_routes` didn't exist — this never errors, it's always a
best-effort match. `url`/`urls` (for failover), and
`max_requests_per_minute`/`max_tokens_per_minute` (for a route's own
dedicated rate limits that take precedence over the server-wide ones)
work exactly like their `targets[]` counterparts, including the same
never-retry-on-a-5xx failover safety boundary. `aiproxy validate`
reports a `model routes:` count in its summary.

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

## Dry-run mode for rules

Adding a new `custom_rules` or `path_rules` entry carries real risk: a
regex that's slightly too broad, or a prefix that catches more than
intended, blocks or mangles traffic you didn't mean to touch. Give a
rule `"dry_run": true` to find that out safely first — it's evaluated
against every real request exactly as normal, but instead of actually
blocking or redacting, it only reports what it *would* have done:

```json
{
  "custom_rules": [
    { "name": "candidate-rule", "pattern": "CANDIDATE-[0-9]+", "action": "block", "dry_run": true }
  ],
  "path_rules": [
    { "name": "new-restriction", "prefix": "/beta", "action": "block", "dry_run": true }
  ]
}
```

The request (or response — a `custom_rules` entry is dry-run on both
sides, same as it's scanned on both) is forwarded completely untouched,
as if the rule had never matched, while a would-have match is logged
(`[DRY-RUN BLOCK]` / `[DRY-RUN REDACT]`, gray; or `[RESPONSE DRY-RUN
BLOCK]` / `[RESPONSE DRY-RUN REDACT]` for a response match), counted
separately in `GET /_aiproxy/stats` (`dry_run_blocked`,
`dry_run_redacted`, and their `response_dry_run_*` counterparts, both
overall and per rule in `per_rule`), exposed on the Prometheus endpoint
(`aiproxy_dry_run_blocked_total` and friends, plus rule-labeled
`aiproxy_rule_dry_run_blocked_total`), and — if `webhook_url` is
set — POSTed as its own event (`dry_run_block`, `dry_run_redact`,
`response_dry_run_block`, `response_dry_run_redact`), with `text`
saying "Would have triggered rule" instead of "Triggered rule" so it's
never mistaken for the real thing. A dry-run match never shadows a
different, live rule further down the list — evaluation just continues
past it exactly as if it hadn't matched.

`path_rules[].dry_run` only makes sense combined with `"action":
"block"` — there's nothing to preview for `"allow"`, which never
rejects anything to begin with — so `aiproxy validate` rejects the
combination as a config error. `custom_rules[].dry_run` works with
either `"block"` or `"redact"`. Unlike every other counter in this
project, dry-run activity is never broken down per target — a dry-run
rule's whole point is testing that one rule, not measuring which target
its traffic happened to route to — so it only appears in the overall
totals and the per-rule breakdown.

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
  "token_rate_limited": 0,
  "cache_hits": 5,
  "stale_cache_hits": 1,
  "total_tokens": 3100,
  "response_blocked": 0,
  "response_redacted": 1,
  "dry_run_blocked": 1,
  "dry_run_redacted": 0,
  "response_dry_run_blocked": 0,
  "response_dry_run_redacted": 0,
  "unauthorized": 0,
  "ip_denied": 0,
  "country_denied": 0,
  "anomaly_detected": 1,
  "targets_ejected": 1,
  "targets_recovered": 0,
  "failover": 1,
  "latency": { "count": 42, "sum_seconds": 3.31, "buckets": [ { "le": "0.005", "count": 0 }, { "le": "0.01", "count": 12 }, { "le": "+Inf", "count": 42 } ] },
  "estimated_cost": 0.062,
  "cost_budget": 10,
  "per_target": {
    "/openai": { "allowed": 30, "blocked": 1, "rate_limited": 0, "token_rate_limited": 0, "cache_hits": 5, "total_tokens": 3100, "estimated_cost": 0.062, "failover": 1, "latency": { "count": 30, "sum_seconds": 2.9 } },
    "default": { "allowed": 12, "blocked": 0, "rate_limited": 0, "token_rate_limited": 0, "cache_hits": 0, "total_tokens": 0, "failover": 0, "latency": { "count": 12, "sum_seconds": 0.41 } }
  },
  "per_rule": {
    "aws-access-key": { "blocked": 1, "redacted": 0, "response_blocked": 0, "response_redacted": 0, "dry_run_blocked": 0, "dry_run_redacted": 0, "response_dry_run_blocked": 0, "response_dry_run_redacted": 0 },
    "candidate-rule": { "blocked": 0, "redacted": 0, "response_blocked": 0, "response_redacted": 0, "dry_run_blocked": 1, "dry_run_redacted": 0, "response_dry_run_blocked": 0, "response_dry_run_redacted": 0 }
  },
  "per_client": {
    "default": { "allowed": 12, "blocked": 0, "redacted": 0, "rate_limited": 0, "token_rate_limited": 0, "anomaly_detected": 0, "total_tokens": 0 },
    "team-a": { "allowed": 30, "blocked": 1, "redacted": 0, "rate_limited": 0, "token_rate_limited": 0, "anomaly_detected": 1, "total_tokens": 3100 }
  }
}
```

`estimated_cost` (overall and per target) is included only when
`cost_per_1k_tokens` is set. `per_target` always reflects every target
used so far — unlike the printed shutdown summary, which leaves the
breakdown out entirely for a single-target run, the JSON endpoint stays
structurally the same shape regardless of how many targets are in play,
since that predictability matters more for something meant to be parsed
by a script or dashboard. A [model route](#model-based-routing)'s
traffic appears here too, keyed by `model:<name>` — distinct from any
path prefix's own key, so the two routing mechanisms can never collide
even with overlapping-looking names. `per_rule` breaks the same block/redact
outcomes down by which named rule (built-in, custom, or path) actually
matched — combining its request-side and response-side hits under the
one name, since which target the match happened to route through
doesn't change which rule is responsible for it — so you can see which
rule fires the most (worth checking for false positives) or catches the
most real leaks. The four `dry_run_*`/`response_dry_run_*` fields (see
[dry-run mode](#dry-run-mode-for-rules)) are never broken down by
target — always `0` inside `per_target`, appearing only in the overall
totals and inside `per_rule`. `unauthorized` (see
[authenticating requests](#authenticating-requests-to-the-proxy)),
`ip_denied` (see [restricting access by IP](#restricting-access-by-ip)),
and `country_denied` (see
[GeoIP-based blocking](#geoip-based-blocking)) go further still: never
broken down by target OR by rule, since a rejected request never
resolves either. `token_rate_limited` (see
[token-based rate limiting](#token-based-rate-limiting)) is the opposite
case again — broken down by target and by named client like `rate_limited`,
since which breaker tripped is always about a specific
target/route/key, and tracked as a fully separate counter from it: the
two breakers reject for different reasons. `anomaly_detected` (see
[anomaly-based rate limiting](#anomaly-based-rate-limiting)) is
broken down by client like `token_rate_limited`, but never by
target — which client spiked is independent of which target it
happened to be calling. `cost_budget` (see
[cost budget alerts](#custom-rules-rate-limiting-caching-and-cost-estimation))
is included only when it's set, and — unlike `estimated_cost` — never
repeated inside `per_target`: it's a single whole-proxy-run threshold,
not something each target has its own copy of. `failover` (see
[failover across multiple upstreams](#failover-across-multiple-upstreams))
is the other way around from `unauthorized`: broken down by target like
`allowed`/`blocked`, since a failover is always about one specific
route's own candidate list, not something target-agnostic. `latency`
(see [Prometheus metrics](#prometheus-metrics) for the full histogram
shape and what it measures) is broken down by target too, for the same
reason — `count` and `sum_seconds` alone are enough to compute a mean
latency (`sum_seconds / count * 1000` for milliseconds) without needing
the full `buckets` list. `per_client` (see
[multiple named keys](#multiple-named-keys-with-per-key-stats-and-rate-limits))
breaks down by which named `proxy_api_keys` entry (or `"default"` for
the anonymous `proxy_api_key`) a request was authenticated with, instead
of target or rule — empty entirely unless at least one proxy key is
configured. Any method other than `GET` gets a 405.
Once `proxy_api_key` is set, this endpoint requires it too — a request
missing or failing that check never reaches this handler at all, and
gets a 407 instead. Because the path
is reserved, an upstream that genuinely needs to be reached at
`/_aiproxy/stats` itself cannot be — route it through a different
prefix if that ever comes up.

## Dashboard

```
open http://127.0.0.1:8080/_aiproxy/dashboard
```

`GET /_aiproxy/dashboard` is a fourth reserved, proxy-internal path: a
single, self-contained HTML page — no external stylesheets, scripts, or
fonts, same no-external-framework discipline as the rest of aiproxy —
that polls `GET /_aiproxy/stats` from the browser every 3 seconds and
renders it as a set of summary cards plus per-target/per-rule/per-client
tables, each shown only when the current snapshot actually has data for
it. Nothing here needs its own config flag; it's always reachable, the
same way `/_aiproxy/stats`/`/_aiproxy/metrics` always are.

It's gated by `ip_allow_list`/`ip_deny_list`,
`country_allow_list`/`country_deny_list`, and `proxy_api_key` exactly
like every other reserved path — **with no exception**: the
page's own background fetch of `/_aiproxy/stats` goes through the exact
same check a `curl` request would. In practice this means the dashboard
just works, with zero setup, for the common case of no `proxy_api_key`
configured; once one is set, a plain browser navigation can't attach a
`Proxy-Authorization` header, so the dashboard can't load usable data —
curl or the [Prometheus endpoint](#prometheus-metrics) (whose scrape
config can carry a bearer token natively) remain the answer for that
case. Confirmed against a real browser: an HTTP 407 in particular is
actually intercepted at the network stack itself before it ever reaches
the page's own JavaScript, since browsers reserve that status for their
own configured forward proxy rather than an ordinary origin response —
the dashboard's error banner accounts for this and says so.

## Health check

```
curl http://127.0.0.1:8080/_aiproxy/healthz
```

`GET /_aiproxy/healthz` is a fifth reserved, proxy-internal path, and
the one deliberate exception to how every other reserved path
behaves: it is **never** gated by `ip_allow_list`/`ip_deny_list`,
`country_allow_list`/`country_deny_list`, or `proxy_api_key`, checked
before even those. Every other reserved path
is fully gated because it exposes real operational data (token counts,
rule/client names, cache contents); `/_aiproxy/healthz` exposes nothing
beyond "this process accepted the connection and its HTTP server is
responsive" — the same thing a caller already learns the instant the
TCP connection itself succeeds or fails, auth or no auth. That's also
exactly the plain liveness/readiness signal a container orchestrator
needs, and orchestrators generally can't attach a `Proxy-Authorization`
header or get themselves IP-allow-listed without real friction — gating
this path would make health checks either impossible or require
punching an orchestrator-shaped hole in `ip_allow_list`, which is
strictly worse.

Always responds `200 OK` with `{"status":"ok"}` — it never depends on
`--target`, a `model_routes` upstream, or any other configured
dependency being reachable; that's what [failover](#failover-across-multiple-upstreams)
and the [rate limiter](#custom-rules-rate-limiting-caching-and-cost-estimation)
exist to handle gracefully, not something aiproxy's own liveness should
flap on. GET-only (405 otherwise), never forwarded upstream, and never
counted in stats or logged — health probes fire far more often than
anyone would want in a log stream.

A Kubernetes probe needs no changes to the container image at all,
since the kubelet makes the HTTP call itself from outside the
container:

```yaml
livenessProbe:
  httpGet:
    path: /_aiproxy/healthz
    port: 8080
readinessProbe:
  httpGet:
    path: /_aiproxy/healthz
    port: 8080
```

A Docker Compose/Swarm `HEALTHCHECK`, by contrast, runs *inside* the
container — and the [published image](#installing) is built on
`distroless/static-debian12:nonroot`, deliberately with no shell and no
`curl`/`wget`, for the smallest attack surface a proxy that handles
secrets can have. `HEALTHCHECK` isn't set in the image for that reason;
if you need a container-internal check, either run an external monitor
against the published port, or build your own image on a base with an
HTTP client available.

## Prometheus metrics

The same counters are also available at `GET /_aiproxy/metrics` in
Prometheus's text exposition format, for scraping instead of polling
`/_aiproxy/stats`:

```
aiproxy_requests_allowed_total{target="default"} 42
aiproxy_requests_blocked_total{target="default"} 1
aiproxy_requests_redacted_total{target="default"} 0
aiproxy_requests_rate_limited_total{target="default"} 0
aiproxy_requests_token_rate_limited_total{target="default"} 0
aiproxy_cache_hits_total{target="default"} 5
aiproxy_stale_cache_hits_total{target="default"} 1
aiproxy_tokens_used_total{target="default"} 3100
aiproxy_responses_blocked_total{target="default"} 0
aiproxy_responses_redacted_total{target="default"} 1
aiproxy_failover_total{target="default"} 0
aiproxy_failover_total{target="/openai"} 1
aiproxy_estimated_cost{target="default"} 0.062
aiproxy_rule_blocked_total{rule="aws-access-key"} 1
aiproxy_rule_redacted_total{rule="aws-access-key"} 0
aiproxy_rule_response_blocked_total{rule="aws-access-key"} 0
aiproxy_rule_response_redacted_total{rule="aws-access-key"} 0
aiproxy_rule_response_redacted_total{rule="openai-api-key"} 1
aiproxy_rule_dry_run_blocked_total{rule="candidate-rule"} 1
aiproxy_rule_dry_run_redacted_total{rule="candidate-rule"} 0
aiproxy_dry_run_blocked_total 1
aiproxy_dry_run_redacted_total 0
aiproxy_dry_run_response_blocked_total 0
aiproxy_dry_run_response_redacted_total 0
aiproxy_unauthorized_total 0
aiproxy_ip_denied_total 0
aiproxy_country_denied_total 0
aiproxy_anomaly_detected_total 1
aiproxy_targets_ejected_total 1
aiproxy_targets_recovered_total 0
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.005"} 0
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.01"} 12
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.025"} 30
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.05"} 40
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.1"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.25"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="0.5"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="1"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="2.5"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="5"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="10"} 42
aiproxy_upstream_latency_seconds_bucket{target="default",le="+Inf"} 42
aiproxy_upstream_latency_seconds_sum{target="default"} 3.31
aiproxy_upstream_latency_seconds_count{target="default"} 42
aiproxy_client_allowed_total{client="team-a"} 40
aiproxy_client_blocked_total{client="team-a"} 1
aiproxy_client_redacted_total{client="team-a"} 0
aiproxy_client_rate_limited_total{client="team-a"} 0
aiproxy_client_token_rate_limited_total{client="team-a"} 0
aiproxy_client_anomaly_detected_total{client="team-a"} 0
aiproxy_client_tokens_used_total{client="team-a"} 3100
aiproxy_client_estimated_cost{client="team-a"} 0.093
aiproxy_cost_budget 10
```

(`# HELP`/`# TYPE` lines omitted above for brevity — the real response
has them.) Every target seen so far gets its own `target="..."` series,
always, even in a single-target run — a scrape needs the same shape
every time, unlike the shutdown summary's noise-avoiding suppression.
`aiproxy_estimated_cost` is included only when `cost_per_1k_tokens` is
set, same as the JSON endpoint's `estimated_cost`.
`aiproxy_requests_token_rate_limited_total`/`aiproxy_client_token_rate_limited_total`
(see [token-based rate limiting](#token-based-rate-limiting)) mirror
their `rate_limited` counterparts exactly — labeled the same way, just
counting the token-based breaker's rejections instead, as a fully
separate series. The `aiproxy_rule_*`
series mirror `per_rule` from the JSON endpoint: one `rule="<name>"`
series per rule that has ever matched, for every rule seen so far — not
tied to any target label, since a rule's identity doesn't depend on
which target the request routed to. The four `aiproxy_dry_run_*_total`
series (see [dry-run mode](#dry-run-mode-for-rules)) get their own
rule-labeled `aiproxy_rule_dry_run_*_total{rule="..."}` counterparts,
but are themselves unlabeled — dry-run activity is never broken down by
target. `aiproxy_unauthorized_total` is unlabeled too, and has no
rule-labeled counterpart at all — a rejected request never resolves a
target or a rule to label it with. `aiproxy_ip_denied_total`/
`aiproxy_country_denied_total` (see
[restricting access by IP](#restricting-access-by-ip) and
[GeoIP-based blocking](#geoip-based-blocking)) are unlabeled the same
way, for the same reason. `aiproxy_anomaly_detected_total` (see
[anomaly-based rate limiting](#anomaly-based-rate-limiting)) is
unlabeled too, but unlike those two it *does* have a client-labeled
counterpart, `aiproxy_client_anomaly_detected_total{client="..."}`
(alongside the other `aiproxy_client_*` series above) — which caller
spiked is meaningful in a way which IP/country was denied isn't, since
neither of those checks has resolved a caller identity yet.
`aiproxy_failover_total` is the other
way around — labeled `target="..."` like the very first series above,
not unlabeled — since a failover is always about one specific route's
own candidate list; every target seen so far gets a series here too,
`0` for one that has never needed to fail over.

`aiproxy_upstream_latency_seconds` is a genuine Prometheus histogram
(`_bucket`/`_sum`/`_count`, not a plain counter), labeled `target="..."`
like `aiproxy_failover_total` — it measures how long each successful
forwarded request took, from the first candidate attempt to the
response that actually came back. A single-URL target just times its
one attempt; a [failover](#failover-across-multiple-upstreams) target's
timer starts before the very first (unreachable) candidate, so the time
spent retrying is counted as real latency rather than hidden — a target
that's failing over a lot will show up here as slow even if the
candidate that finally answers is fast. Buckets use Prometheus's own
default boundaries (5ms up to 10s) and are cumulative, so
`histogram_quantile(0.95, rate(aiproxy_upstream_latency_seconds_bucket[5m]))`
works out of the box for a p95 latency panel. A request the rule engine
blocks or redacts outright never reaches the upstream, so it's never
timed; the same numbers (`count`, `sum_seconds`, and the full bucket
list) are also in `/_aiproxy/stats`' `latency` field, both at the top
level and inside each `per_target` entry, for polling instead of
scraping. `aiproxy_cost_budget` is a gauge, not
a counter — the configured `cost_budget` threshold itself, included only
when it's set — and unlabeled for a different reason than the series
above: a single whole-proxy-run value, not something with a per-target
or per-rule breakdown to begin with.

`aiproxy_client_*` mirrors `per_client` from the JSON endpoint (see
[multiple named keys](#multiple-named-keys-with-per-key-stats-and-rate-limits)):
one `client="<name>"` series per key that has ever been used to
authenticate — `"default"` for the anonymous `proxy_api_key`, a named
`proxy_api_keys` entry's own name otherwise — present only once at least
one proxy key is actually configured. `aiproxy_client_estimated_cost` is
included only when `cost_per_1k_tokens` is also set, same condition as
the unlabeled `aiproxy_estimated_cost`.

Once `proxy_api_key` is set, a
scrape has to send it back the same way any other request does (see
[authenticating requests](#authenticating-requests-to-the-proxy)) — a
Prometheus `scrape_configs` entry's `authorization: { type: Bearer,
credentials: ... }` does exactly that. Point Prometheus at it with:

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

## Isolating the admin surface on its own port

By default, `GET /_aiproxy/stats`, `/_aiproxy/metrics`,
`/_aiproxy/dashboard`, and `POST /_aiproxy/cache/clear` all live on the
same listener as the actual proxy traffic (`--addr`). `--admin-addr`
moves all four onto a second, independent listener instead:

```
aiproxy start --target https://api.openai.com \
  --addr 0.0.0.0:8080 --admin-addr 127.0.0.1:9090
```

Once set, `--addr` stops serving those four paths entirely — a request
for one of them there gets a plain 404, never silently forwarded
upstream as if it were an ordinary route, since "reserved path" always
meant exactly that. They're only reachable on `--admin-addr` now,
gated by exactly the same `ip_allow_list`/`ip_deny_list`,
`country_allow_list`/`country_deny_list`, and `proxy_api_key` checks
as before — moving *where* the admin surface is reachable from doesn't
change *what's* required to reach it. That matters in particular if
`--admin-addr` itself ever ends up bound more broadly than intended
(`0.0.0.0` instead of `127.0.0.1`, say): the existing auth still stands
between it and the world, rather than the isolation being the only
thing protecting it.

[`/_aiproxy/healthz`](#health-check) is the one exception — it stays
reachable on `--addr` unconditionally either way, since an
orchestrator's liveness/readiness probe targets the same port the
service actually listens on, and moving it would break that for zero
security benefit (it's the one reserved path with nothing worth
protecting in the first place). It's also served on `--admin-addr`, for
an operator who'd rather probe the admin listener instead.

The typical motivation is keeping a public-facing proxy port and a
private observability port on genuinely different network exposure —
`--addr` on a public interface or load balancer, `--admin-addr` bound
to `127.0.0.1` or a private/VPC-only interface for Prometheus, the
dashboard, and stats polling, so the admin surface never shares the
public port's attack surface at all, defense-in-depth on top of its
existing auth rather than instead of it. `--admin-addr` reuses whatever
TLS configuration is already active (`--tls-cert`/`--tls-key`, see
[Serving over TLS](#serving-over-tls)) rather than needing its own
certificate — both listeners end up on equal footing, plain HTTP or
both HTTPS. It must be a different address than `--addr` (rejected at
startup otherwise — there's no isolation in binding the same address
twice) and, like `--tls-cert`/`--tls-key`/`--audit-log-key-file`, is
CLI-only and not hot-reloadable via SIGHUP: binding a second listener
is a process-level operation a live config swap was never meant to
cover. Empty/absent (the default) keeps everything on `--addr` alone,
completely unchanged from before this flag existed.

## Cross-origin requests (CORS)

A browser-based client calling aiproxy directly from its own page's
JavaScript (`fetch()`, not a server-side call) needs aiproxy to answer
CORS — otherwise the browser's own same-origin policy blocks the page
from reading the response, or even sending it in the first place for
anything beyond a "simple" request. `cors_allowed_origins` turns this
on:

```json
{
  "cors_allowed_origins": ["https://app.example.com"],
  "cors_allowed_methods": ["GET", "POST", "OPTIONS"],
  "cors_allowed_headers": ["Content-Type", "X-Api-Key"],
  "cors_allow_credentials": true,
  "cors_max_age_seconds": 600
}
```

`cors_allowed_origins` is the only required field — everything else is
optional and only meaningful alongside it. `"*"` matches any origin;
otherwise list exact `scheme://host[:port]` origins. Whichever origin a
request actually carries, aiproxy always echoes back that *specific*
value in `Access-Control-Allow-Origin` — never the literal `"*"` string,
even when `"*"` is what matched. That's both simpler (one code path
instead of a separate credentials-aware branch) and the only spec-legal
option once `cors_allow_credentials` is set: a literal `*` is forbidden
alongside `Access-Control-Allow-Credentials: true`.

A browser that's about to send anything beyond a simple GET/POST first
sends a **preflight** — an `OPTIONS` request carrying
`Access-Control-Request-Method` — to ask permission before the real
request goes out. aiproxy answers it directly with `204 No Content`
and the relevant `Access-Control-Allow-*` headers, before rules, rate
limiting, `proxy_api_key` authentication, or forwarding ever run: a
preflight never carries the browser's own credentials for the real
request that follows it (browsers never attach them to an `OPTIONS`
preflight), so gating it behind those checks would make CORS unusable
for any authenticated aiproxy setup. `cors_allowed_methods` defaults to
`GET, POST, PUT, PATCH, DELETE, OPTIONS` when left unset.
`cors_allowed_headers`, left unset, defaults to reflecting back
whatever the browser's own preflight actually asked for
(`Access-Control-Request-Headers`) rather than a hardcoded allowlist —
deliberately, so an incomplete manually-typed list can never end up
silently breaking `Authorization`/`Proxy-Authorization`/`X-Api-Key` for
an operator who forgot to include it; CORS exists to protect a server
from a malicious *page*, not the other way around.
`cors_max_age_seconds`, if set, lets the browser cache a preflight's
answer instead of repeating it before every real request.

The CORS header is added to *every* response this feature applies to —
including one a rule blocked, the rate limiter rejected, or
`proxy_api_key` auth refused — so a browser-based client's own error
handling can actually see why a call failed instead of just an opaque,
generic CORS failure masking the real reason. It's applied identically
on both `--addr` and [`--admin-addr`](#isolating-the-admin-surface-on-its-own-port).
Empty/absent `cors_allowed_origins` (the default) disables CORS
handling entirely — the exact behavior aiproxy had before this feature
existed, and still the right choice for a purely server-to-server
setup with no browser-based caller.

## Webhook alerts

Stats and metrics are pull-based — something has to go and look at them.
Set `webhook_url` to get pushed a real-time alert instead, the moment a
rule matches — on a request going out, a
[response](#scanning-responses-too) coming back, the
[rate limiter](#custom-rules-rate-limiting-caching-and-cost-estimation)
or [token-based rate limiter](#token-based-rate-limiting) tripping, a
[dry-run](#dry-run-mode-for-rules) rule matching, a request
denied by [ip_allow_list/ip_deny_list](#restricting-access-by-ip) or
[country_allow_list/country_deny_list](#geoip-based-blocking), or
failing [proxy authentication](#authenticating-requests-to-the-proxy),
the running cost crossing [cost_budget](#custom-rules-rate-limiting-caching-and-cost-estimation),
a [named client](#anomaly-based-rate-limiting) spiking well past its own
recent baseline, or a [failover](#failover-across-multiple-upstreams) to
the next candidate target:

```json
{
  "webhook_url": "https://hooks.slack.com/services/T00/B00/XXXXXXXXXXXXXXXXXXXXXXXX"
}
```

Every alertable event — `block`, `redact`, `response_block`,
`response_redact`, `rate_limited`, `token_rate_limited`, `ip_denied`,
`country_denied`, `anomaly_detected`, `unauthorized`, `dry_run_block`,
`dry_run_redact`, `response_dry_run_block`, `response_dry_run_redact`,
`budget_exceeded`, `failover`, `target_ejected`, `target_recovered`, or
`config_changed` — POSTs this JSON body to that URL:

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

A `token_rate_limited` alert — fired the moment
[the token-based breaker](#token-based-rate-limiting) rejects a request —
is [`rate_limited`](#custom-rules-rate-limiting-caching-and-cost-estimation)'s
counterpart, tracked as a fully separate event since the two breakers
trip for different reasons; likewise carries an empty `rule`:

```json
{
  "text": "[TOKEN_RATE_LIMITED] POST /v1/messages - Token rate limit exceeded",
  "event": "token_rate_limited",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "time": "2026-01-01T12:00:00Z"
}
```

An `anomaly_detected` alert — fired by
[anomaly_multiplier](#anomaly-based-rate-limiting) (including when
`anomaly_dry_run` is set — an alert still fires for what *would* have
been rejected) — likewise carries an empty `rule`, plus a `client`
field (the flagged named proxy key) and `rate`/`baseline` fields no
other event has: the client's current-window request count, and the
established baseline it was compared against:

```json
{
  "text": "[ANOMALY_DETECTED] POST /v1/messages - client team-a: 500 requests this minute vs. baseline 8.2",
  "event": "anomaly_detected",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "client": "team-a",
  "rate": 500,
  "baseline": 8.2,
  "time": "2026-01-01T12:00:00Z"
}
```

A `target_ejected` alert — fired by
[target_ejection_threshold](#automatically-deprioritizing-a-failing-candidate)
— has no `method`/`url`/`rule` at all: the transition isn't tied to any
one client request, just a `target` field naming the affected candidate
URL. `target_recovered` looks identical but for the event name and
text:

```json
{
  "text": "[TARGET EJECTED] https://backup.example.com temporarily deprioritized after repeated failures",
  "event": "target_ejected",
  "method": "",
  "url": "",
  "rule": "",
  "target": "https://backup.example.com",
  "time": "2026-01-01T12:00:00Z"
}
```

A `config_changed` alert — fired by a
[SIGHUP reload](#seeing-exactly-what-a-reload-changed) that actually
changed something — likewise has no `method`/`url`/`rule`: a config
reload isn't tied to any one client request either, and the whole diff
summary already lives in `text`:

```json
{
  "text": "aiproxy: config reloaded from aiproxy.json: max_requests_per_minute: 60 -> 100",
  "event": "config_changed",
  "method": "",
  "url": "",
  "rule": "",
  "time": "2026-01-01T12:00:00Z"
}
```

An `unauthorized` alert — someone hitting the proxy without a valid
`Proxy-Authorization`, worth knowing about in real time the same way —
likewise carries an empty `rule`, and never echoes the configured
`proxy_api_key` back in `text`:

```json
{
  "text": "[UNAUTHORIZED] POST /v1/messages - Missing or invalid Proxy-Authorization",
  "event": "unauthorized",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "time": "2026-01-01T12:00:00Z"
}
```

An `ip_denied` alert — fired by [ip_allow_list/ip_deny_list](#restricting-access-by-ip),
checked even before `unauthorized` — likewise carries an empty `rule`,
plus a `remote_ip` field no other event has: the denied request's own
TCP peer address:

```json
{
  "text": "[IP_DENIED] POST /v1/messages - 203.0.113.7 not in ip_allow_list, or in ip_deny_list",
  "event": "ip_denied",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "remote_ip": "203.0.113.7",
  "time": "2026-01-01T12:00:00Z"
}
```

A `country_denied` alert — fired by
[country_allow_list/country_deny_list](#geoip-based-blocking), checked
right after `ip_denied` — likewise carries an empty `rule` and a
`remote_ip`, plus a `country` field no other event has: the resolved
country code the request was denied for (empty if it couldn't be
resolved at all — still a denial):

```json
{
  "text": "[COUNTRY_DENIED] POST /v1/messages - 203.0.113.7 (KP) not in country_allow_list, or in country_deny_list",
  "event": "country_denied",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "remote_ip": "203.0.113.7",
  "country": "KP",
  "time": "2026-01-01T12:00:00Z"
}
```

A `budget_exceeded` alert — fired once the running total cost reaches or
passes `cost_budget` — likewise carries an empty `rule`, plus `cost` and
`budget` fields no other event has: the cost at the moment it fired, and
the threshold it crossed. It fires exactly once for the life of the
running process, not on every request past the threshold:

```json
{
  "text": "[BUDGET_EXCEEDED] POST /v1/messages - Estimated cost 10.4000 exceeds budget 10.0000",
  "event": "budget_exceeded",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "time": "2026-01-01T12:00:00Z",
  "cost": 10.4,
  "budget": 10
}
```

A named key's own [per-key `cost_budget`](#per-key-cost-budgets) fires
the same `budget_exceeded` event, independent of the server-wide one,
distinguished only by an added `client` field naming which key crossed
it (absent — same as every other event — for the server-wide budget):

```json
{
  "text": "[BUDGET_EXCEEDED] POST /v1/messages - client team-a: estimated cost 25.1000 exceeds budget 25.0000",
  "event": "budget_exceeded",
  "method": "POST",
  "url": "/v1/messages",
  "rule": "",
  "client": "team-a",
  "time": "2026-01-01T12:00:00Z",
  "cost": 25.1,
  "budget": 25
}
```

A `failover` alert — fired the moment a target's candidate URL turns out
to be unreachable and the request moves on to the next one — likewise
carries an empty `rule`, plus `failed_target` and `next_target` fields
no other event has:

```json
{
  "text": "[FAILOVER] POST /openai/v1/chat/completions - https://api.openai.com unreachable, trying https://backup.example.com",
  "event": "failover",
  "method": "POST",
  "url": "/openai/v1/chat/completions",
  "rule": "",
  "time": "2026-01-01T12:00:00Z",
  "failed_target": "https://api.openai.com",
  "next_target": "https://backup.example.com"
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
`targets[].url`/`targets[].urls`, `webhook_url` accepts plain `http` as well as `https`
(it still has to be a well-formed URL with a host) — a webhook payload
never carries a secret, only a method/url/rule name, so a local or
internal-network receiver with no TLS in front of it is a perfectly
reasonable target. It's hot-reloadable via
[SIGHUP](#reloading-config-without-restarting) like everything else in
this section. Neither the startup notice nor `aiproxy validate`'s
summary ever print the URL itself — a webhook URL, Slack's especially,
typically embeds a bearer credential directly in its path, so it gets
the same treatment as every other secret aiproxy handles.

### Multiple webhook destinations and per-event routing

`webhook_url` is one destination for every event. Set `webhooks` instead
(or alongside it) to send different events to different places — a
budget alert to one Slack channel, everything else to another, say:

```json
{
  "webhook_url": "https://hooks.slack.com/services/T00/B00/GENERAL",
  "webhooks": [
    {
      "url": "https://hooks.slack.com/services/T00/B00/BUDGET-ALERTS",
      "events": ["budget_exceeded"]
    }
  ]
}
```

Each `webhooks` entry has a `url` (validated exactly like `webhook_url`
— any http or https URL with a host) and an optional `events` list.
Omit `events` and that destination is a catch-all, notified of
everything, exactly like `webhook_url` itself; give it a list — any
combination of `block`, `redact`, `response_block`, `response_redact`,
`rate_limited`, `unauthorized`, `dry_run_block`, `dry_run_redact`,
`response_dry_run_block`, `response_dry_run_redact`, `budget_exceeded`,
or `failover` — and it only fires for those. `aiproxy validate` rejects
a name outside that set, the same way it rejects an unrecognized
`builtin_rule_actions` key, so a typo never just silently never matches
anything. `webhook_url` (if set) keeps its original, unfiltered
behavior regardless of what's in `webhooks` — the two aren't mutually
exclusive, and `webhooks` works fine entirely on its own with
`webhook_url` left unset too, if every destination should be filtered.

Every matching destination is POSTed the same JSON payload,
independently, on its own goroutine — a slow or unreachable destination
never delays another, or the client's request. A delivery failure is
still logged as an internal error, labeled by which destination failed
(`webhook_url`, or `webhooks[N]`) so multiple destinations stay
distinguishable in the log — never by the URL itself, same discipline
as everywhere else. The startup notice and `aiproxy validate`'s summary
report only a count (`additional webhook destinations: 2`), never the
destination URLs.

## Validating a config file

```
aiproxy validate --config aiproxy.json
```

Checks `aiproxy.json` for problems without starting the proxy: every
`custom_rules` pattern must compile, every `targets` entry needs a
well-formed, unique prefix and exactly one of a valid HTTPS `url` or a
non-empty `urls` list of them, every `webhooks` entry needs a
well-formed `url` and, if `events` is given, every name in it must be
one aiproxy actually fires, every `proxy_api_keys` entry needs a
non-empty, unique `name` (never `"default"`) and a non-empty, unique
`key`, `log_file` (if set) must actually be possible to open, every
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
