# aiproxy

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

- `--target` (required): the HTTPS URL to forward allowed requests to.
- `--addr`: local address to listen on (default `127.0.0.1:8080`).
- `--config`: path to a JSON config file for custom rules and/or a rate
  limit (default: `aiproxy.json` in the working directory, if present).

Point your client at `http://127.0.0.1:8080` instead of the real API.
Allowed requests are logged in green (`[ALLOW] POST /endpoint`); blocked
ones in bright red (`[BLOCK] POST /endpoint - Triggered rule: <name>`);
requests rejected by the rate limiter in yellow (`[CIRCUIT BREAKER]
POST /endpoint - Rate limit exceeded`); responses served from the local
cache in purple (`[CACHE HIT] POST /endpoint`); and, whenever a JSON
response carries a `usage.total_tokens` field (as LLM APIs typically do),
a blue usage line (`[USAGE] POST /endpoint - Tokens used: <n>`). The
value that matched a rule is never written to the log — only the rule's
name.

## Custom rules, rate limiting, and caching

Drop an `aiproxy.json` file in the working directory (or point `--config`
at one) to add your own body-content rules on top of the built-in AWS,
OpenAI, and GitHub token checks, cap how many requests the proxy forwards
per minute — a local circuit breaker against runaway/looping clients —
and/or cache responses to disk to save time and API costs on repeated
calls:

```json
{
  "custom_rules": [
    { "name": "mitt-företag-hemlighet", "pattern": "SECRET_[0-9]+" }
  ],
  "max_requests_per_minute": 60,
  "cache_enabled": true
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

## Installing

No GitHub Releases exist yet, so for now clone the repo and run the
installer — it detects your OS/architecture, builds aiproxy from source,
and installs it to `/usr/local/bin` (override with `AIPROXY_INSTALL_DIR`):

```
git clone https://github.com/aleksanderbernacki12-byte/aiproxy && cd aiproxy
./install.sh
```

Once install.sh fetches prebuilt binaries directly from GitHub Releases
instead of building locally, installing will be a single command:

```
curl -fsSL https://raw.githubusercontent.com/aleksanderbernacki12-byte/aiproxy/main/install.sh | sh
```

## Building from source

```
make build      # current platform
make build-all  # macOS (arm64 + amd64), Linux (amd64), Windows (amd64)
```
