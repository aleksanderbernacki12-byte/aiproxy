# Phase 3C: Per-Request Config Snapshot — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A request sees exactly one configuration from start to finish, and reload never closes a resource under a writer.

**Architecture:** `ReloadConfig` takes a typed `RuntimeConfig`. `ServeHTTP` takes one `*requestConfig` snapshot (single `s.mu.RLock`) and threads it through helpers and, via `requestContextInfo.config`, through `Rewrite`, `failoverTransport`, `bufferResponse`, `streamResponse`, `recordUsage` and `checkReplayPolicy`. The log file is swapped, closed and written under `logFileMu`.

**Tech Stack:** Go 1.27 stdlib. Spec: `docs/superpowers/specs/2026-09-27-security-remediation-phase3c-design.md`. Branch: `security-phase3c`.

Each task: failing test first where behavior changes, minimal implementation, `go test ./internal/proxy/...`, then `gofmt -l internal && go vet ./... && go test -race ./internal/...` before commit, one commit per task.

---

### Task 1: Typed `RuntimeConfig`

**Files:** `internal/proxy/proxy.go` (`ReloadConfig`), `internal/cli/cli.go:772`, test call sites in `internal/proxy/{proxy,coalesce,idempotency,semanticcache}_test.go`.

- [ ] Add, next to `ReloadConfig`:

```go
// RuntimeConfig is everything ReloadConfig replaces. Each field sets
// the Server field of the same name; Routes and ModelRoutes replace the
// routing tables. A zero field means that setting is unset.
type RuntimeConfig struct {
	Engine                 *rules.Engine
	Limiter                *limiter.Limiter
	TokenLimiter           *limiter.TokenLimiter
	Cache                  *cache.Cache
	CostPer1KTokens        float64
	CostBudget             float64
	CostBudgetHardStop     bool
	MaxBodyBytes           int64
	WebhookURL             *url.URL
	Webhooks               []WebhookTarget
	ProxyAPIKey            string
	ProxyAPIKeys           []ProxyKey
	AdminAPIKey            string
	AdminAPIKeys           []ProxyKey
	LogFile                *os.File
	Routes                 []Route
	ModelRoutes            []ModelRoute
	IPAllowList            []*net.IPNet
	IPDenyList             []*net.IPNet
	GeoIPTable             *geoip.Table
	CountryAllowList       []string
	CountryDenyList        []string
	AnomalyDetector        *anomaly.Registry
	AnomalyDryRun          bool
	UpstreamTransport      *http.Transport
	UpstreamTotalTimeout   time.Duration
	TargetBreaker          *breaker.Registry
	CORS                   *CORSConfig
	HealthCheckInterval    time.Duration
	HealthCheckPath        string
	TargetCostRates        map[string]float64
	IPLimiter              *iplimiter.Registry
	CacheTTL               time.Duration
	TargetCacheTTL         map[string]time.Duration
	TargetCacheEnabled     map[string]bool
	TargetShadowURL        map[string]*url.URL
	TargetShadowSampleRate map[string]float64
	Idempotency            *idempotency.Registry
	Coalescer              *coalesce.Group
	SemanticIndex          *semcache.Index
	SemanticCacheThreshold float64
}
```

- [ ] Change the signature to `func (s *Server) ReloadConfig(cfg RuntimeConfig)` and the body to read `cfg.X` for each former parameter (same assignments, same order).
- [ ] Convert call sites mechanically with a script that maps the 41 positional arguments, in the old parameter order, to `proxy.RuntimeConfig{Field: arg, ...}` and drops zero-valued ones (`nil`, `0`, `""`, `false`). In `cli.go` the call becomes `server.ReloadConfig(proxy.RuntimeConfig{Engine: lc.engine, ... , Routes: routes, ModelRoutes: modelRoutes})`.
- [ ] `go build ./... && go vet ./... && go test ./internal/proxy/ ./internal/cli/` — all existing reload tests pass unchanged in behavior.
- [ ] Commit: `refactor(proxy): take a typed RuntimeConfig in ReloadConfig`.

### Task 2: Log file hand-over under `logFileMu`

**Files:** `internal/proxy/proxy.go` (`appendToLogFile`, `ReloadConfig`), test in `internal/proxy/reloadsnapshot_test.go` (new, `package proxy_test`).

- [ ] Test `TestReload_LogWritesNeverHitAClosedFile`: server with `LogFile` = file 0 and `Logger` = `log.New(&errBuf, "", 0)` (a mutex-guarded buffer); 4 goroutines call `srv.LogEvent("tick", "x")` 500 times each while the main goroutine performs 50 reloads, each with a freshly opened file i (keep all handles/paths). After all: `errBuf` contains no "file already closed"; the sum of JSON lines across all files equals 2000.
- [ ] Run: fails (a write races the close and logs an error, or lines are lost).
- [ ] Implement: in `appendToLogFile`, take `s.logFileMu` first, then read the file with `s.mu.RLock(); f := s.LogFile; s.mu.RUnlock()`. In `ReloadConfig`, lock `s.logFileMu` around the whole swap (`s.logFileMu.Lock()` before `s.mu.Lock()`, close the old file before `s.logFileMu.Unlock()`). Lock order everywhere: `logFileMu` then `mu`.
- [ ] Run with `-race -count=5`: pass. `TestServer_ReloadConfig_ReopensLogFileAndClosesOldHandle` still passes.
- [ ] Commit: `fix(proxy): swap and close the log file under logFileMu`.

### Task 3: Snapshot type and reload-mid-request test

**Files:** new `internal/proxy/snapshot.go`, `internal/proxy/reloadsnapshot_test.go`.

- [ ] Test `TestReload_InFlightRequestKeepsItsConfig`: upstream handler signals `entered` then blocks on `release`, answers `200 {"ok":true}`. Server: `Engine` = Allow, `Idempotency` = registry A. Send `POST /v1/x` with `Idempotency-Key: k1` in a goroutine; wait `entered`; `ReloadConfig` with `Engine` = default Block engine, `Idempotency` = registry B, same `UpstreamTransport`; close `release`. Assert: in-flight response is 200 with body `{"ok":true}`; registry A has a completed entry for the key (a second request against a server whose `Idempotency` is A replays it — check via `A.Claim` returning the replay outcome); registry B has no entry; a new request after reload gets 403.
- [ ] Run: fails (response evaluated by the Block engine and/or stored in B).
- [ ] Create `snapshot.go`:

```go
package proxy

// requestConfig is the configuration one proxied request uses from start
// to finish, copied from Server under a single lock by snapshot so a
// concurrent ReloadConfig can never hand one request two configurations
// (review finding #14).
type requestConfig struct {
	engine                 *rules.Engine
	limiter                *limiter.Limiter
	tokenLimiter           *limiter.TokenLimiter
	cache                  *cache.Cache
	costPer1KTokens        float64
	costBudget             float64
	costBudgetHardStop     bool
	maxBodyBytes           int64
	maxResponseBodyBytes   int64
	proxyAPIKey            string
	proxyAPIKeys           []ProxyKey
	routes                 []route
	modelRoutes            []modelRoute
	ipAllowList            []*net.IPNet
	ipDenyList             []*net.IPNet
	geoIPTable             *geoip.Table
	countryAllowList       []string
	countryDenyList        []string
	anomalyDetector        *anomaly.Registry
	anomalyDryRun          bool
	upstreamTransport      *http.Transport
	upstreamTotalTimeout   time.Duration
	targetBreaker          *breaker.Registry
	cors                   *CORSConfig
	targetCostRates        map[string]float64
	ipLimiter              *iplimiter.Registry
	cacheTTL               time.Duration
	targetCacheTTL         map[string]time.Duration
	targetCacheEnabled     map[string]bool
	targetShadowURL        map[string]*url.URL
	targetShadowSampleRate map[string]float64
	idempotency            *idempotency.Registry
	coalescer              *coalesce.Group
	semanticIndex          *semcache.Index
	semanticCacheThreshold float64
}

func (s *Server) snapshot() *requestConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return &requestConfig{ /* one line per field, from the Server field */ }
}

// configFor returns the snapshot a request carries, or a fresh one for
// callers (mostly tests) that build a requestContextInfo themselves.
func (s *Server) configFor(reqCtx requestContextInfo) *requestConfig {
	if reqCtx.config != nil {
		return reqCtx.config
	}
	return s.snapshot()
}
```

  Move the derived-value logic of the existing getters onto `*requestConfig` methods with the same results: `costRates()`, `shadowTarget(target)`, `maxBody()` (the `<= 0` default of `getMaxBodyBytes`), `cacheEnabledForTarget(target)`, `resolveCacheTTL(target)`. `maxResponseBodyBytes` is copied from what `getMaxResponseBodyBytes` returns.
- [ ] Add `config *requestConfig` to `requestContextInfo`.
- [ ] Commit the failing test together with Task 4 (the test only passes once threading is complete).

### Task 4: Thread the snapshot through the request path

**Files:** `internal/proxy/proxy.go`, `internal/proxy/logurl.go` (unchanged: log masking keeps the current engine).

- [ ] In `ServeHTTP`, right after the reserved-admin-path branch, `cfg := s.snapshot()`; set `reqCtx.config = cfg` where `requestContextInfo` is built (before `context.WithValue` at the current line ~3807).
- [ ] Replace in `ServeHTTP` every `s.getMaxBodyBytes()`, `s.getIdempotency()`, `s.getCache()`, `s.getSemanticCacheThreshold()`, `s.getSemanticIndex()`, `s.getCoalescer()`, `s.getEngine()`, `s.getCostBudgetHardStop()`, `s.getCostRates()`, `s.getCostBudget()`, `s.getCostPer1KTokens()`, `s.getAnomalyConfig()`, `s.getShadowTarget(...)` with the `cfg` equivalent.
- [ ] Give request-path helpers a `cfg *requestConfig` first parameter and read from it: `resolveRoute`, `resolveModelRoute`, `cacheEnabledForTarget`/`resolveCacheTTL` (now `cfg` methods), `checkIPAccess`, `checkCountryAccess`, `checkProxyAuth`, `checkNetworkAccess` (admin callers pass `s.snapshot()`), `checkReplayPolicy`.
- [ ] In `bufferResponse`, `streamResponse`, `recordUsage`: `cfg := s.configFor(reqCtx)` at the top, replace their getter calls. In `failoverTransport.RoundTrip`: `cfg := t.server.configFor(reqCtx)`, use `cfg.upstreamTransport`, `cfg.upstreamTotalTimeout`, `cfg.targetBreaker`.
- [ ] Getters no longer called anywhere are deleted; the ones background/admin code still uses (`getHealthCheckConfig`, `getIPLimiter`, `getIdempotency` for sweeps, `getUpstreamConfig` for probes/shadow, `getCache` for cache clear, `getCostRates`/`getCostBudget` for stats/metrics/summary, `getWebhooks`/`getWebhookURL`, `getAdminAPIKeys`, `getEngine` for log masking) stay.
- [ ] Check nothing on the request path still reads a reloadable field directly:
  `awk` listing of `s.get*`/`s.routes`/`s.Limiter` call sites (as in the plan survey) shows only background/admin functions.
- [ ] `go test -race ./internal/...`: `TestReload_InFlightRequestKeepsItsConfig` passes, everything else green.
- [ ] Commit: `fix(proxy): give each request one config snapshot`.

### Task 5: Concurrency stress test, docs, verification

- [ ] Test `TestReload_ConcurrentWithTrafficAndCacheClear` (`reloadsnapshot_test.go`): cache enabled, admin enabled; 8 goroutines send 100 requests each (half cacheable GETs, half POSTs with idempotency keys); one goroutine reloads 50 times with a new cache and registry each time; one goroutine calls admin cache clear 50 times. Every response is 200; `go test -race` reports nothing.
- [ ] README: in the reload section, state that in-flight requests finish on the configuration they started with and that the log file switches atomically.
- [ ] `gofmt -l internal && go vet ./... && go test -race ./...` green.
- [ ] Commit: `test(proxy): reload under concurrent traffic and cache clear` and `docs: describe per-request config snapshot`.
