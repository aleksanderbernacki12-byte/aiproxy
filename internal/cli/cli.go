// Package cli implements aiproxy's terminal commands. It wires the proxy
// and rules packages together; it holds no networking or security logic
// of its own.
package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"aiproxy/internal/anomaly"
	"aiproxy/internal/auditlog"
	"aiproxy/internal/breaker"
	"aiproxy/internal/cache"
	"aiproxy/internal/config"
	"aiproxy/internal/geoip"
	"aiproxy/internal/iplimiter"
	"aiproxy/internal/limiter"
	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// defaultConfigPath is where aiproxy looks for custom rules when --config
// is not given: aiproxy.json in the current working directory.
const defaultConfigPath = "aiproxy.json"

// Default body regex rules, compiled once at package init so the cost of
// compiling them is never paid per request.
var (
	awsAccessKeyPattern    = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	openAIAPIKeyPattern    = regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)
	githubTokenPattern     = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)
	anthropicAPIKeyPattern = regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)
	privateKeyPattern      = regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----`)
	slackTokenPattern      = regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`)
	stripeAPIKeyPattern    = regexp.MustCompile(`sk_live_[0-9A-Za-z]{24,}`)
	googleAPIKeyPattern    = regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)
	npmAccessTokenPattern  = regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)
	jwtPattern             = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
)

// Execute parses args and runs the requested subcommand, writing output
// to stdout/stderr, and returns a process exit code.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "start":
		return runStart(args[1:], stdout, stderr)
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	case "verify-log":
		return runVerifyLog(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "aiproxy: unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:8080", "address for the proxy to listen on")
	adminAddr := fs.String("admin-addr", "", "address for a second listener serving only the admin surface (GET /_aiproxy/stats, /_aiproxy/metrics, /_aiproxy/dashboard, POST /_aiproxy/cache/clear), gated by the same proxy_api_key/IP/GeoIP checks as -addr; when set, -addr stops serving those paths entirely (404). /_aiproxy/healthz stays reachable on both. Empty (default) keeps everything on -addr")
	target := fs.String("target", "", "HTTPS URL to forward requests to (required)")
	configPath := fs.String("config", "", "path to a JSON config file (custom rules, rate limit, cache, cost estimation, extra target routes; default: aiproxy.json in the working directory, if present)")
	logFormat := fs.String("log-format", "text", `log output format: "text" (colored, human-readable) or "json" (one JSON object per line, safe to pipe into a log aggregator)`)
	tlsCert := fs.String("tls-cert", "", "path to a PEM certificate file — combined with -tls-key, makes the proxy terminate TLS itself instead of listening on plain HTTP")
	tlsKey := fs.String("tls-key", "", "path to a PEM private key file — see -tls-cert")
	auditLogKeyFile := fs.String("audit-log-key-file", "", "path to a secret key file — when set, every line appended to log_file is HMAC-chained so later tampering is detectable with `aiproxy verify-log`; requires log_file to be configured")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	var proxyLogFormat proxy.LogFormat
	switch *logFormat {
	case "text":
		proxyLogFormat = proxy.LogFormatText
	case "json":
		proxyLogFormat = proxy.LogFormatJSON
	default:
		fmt.Fprintf(stderr, "aiproxy: -log-format must be \"text\" or \"json\", got %q\n", *logFormat)
		return 2
	}

	if (*tlsCert == "") != (*tlsKey == "") {
		fmt.Fprintln(stderr, "aiproxy: -tls-cert and -tls-key must be set together, or not at all")
		return 2
	}

	if *adminAddr != "" && *adminAddr == *addr {
		fmt.Fprintln(stderr, "aiproxy: -admin-addr must be different from -addr (there's no isolation in binding the same address twice)")
		return 2
	}

	targetURL, err := parseTarget(*target)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 2
	}

	cfg, loadedFrom, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 2
	}

	logFilePath := ""
	if cfg != nil {
		logFilePath = cfg.LogFile
	}
	if *auditLogKeyFile != "" && logFilePath == "" {
		fmt.Fprintln(stderr, "aiproxy: -audit-log-key-file requires log_file to be set in the config (there's nothing to chain otherwise)")
		return 2
	}

	var auditChain *auditlog.Chain
	if *auditLogKeyFile != "" {
		key, err := auditlog.ReadKeyFile(*auditLogKeyFile)
		if err != nil {
			fmt.Fprintf(stderr, "aiproxy: %v\n", err)
			return 1
		}
		prevHash, err := auditlog.RecoverPrevHash(logFilePath)
		if err != nil {
			fmt.Fprintf(stderr, "aiproxy: %v\n", err)
			return 1
		}
		auditChain = auditlog.NewChain(key, prevHash)
	}

	lc, errs := buildLiveConfig(cfg)
	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		log.Fatal(strings.Join(msgs, "\n"))
	}

	server := proxy.New(*addr, targetURL, lc.engine)
	server.LogFormat = proxyLogFormat
	if proxyLogFormat == proxy.LogFormatJSON {
		// The JSON payload already carries its own "time" field; a
		// prepended timestamp prefix would break every line's JSON.
		server.Logger = log.New(os.Stderr, "", 0)
	}
	server.Limiter = lc.limiter
	server.TokenLimiter = lc.tokenLimiter
	server.Cache = lc.cache
	server.CacheTTL = lc.cacheTTL
	server.TargetCacheTTL = lc.targetCacheTTL
	server.TargetCacheEnabled = lc.targetCacheEnabled
	server.CostPer1KTokens = lc.cost
	server.CostBudget = lc.costBudget
	server.MaxBodyBytes = lc.maxBodyBytes
	server.WebhookURL = lc.webhookURL
	server.Webhooks = lc.webhooks
	server.ProxyAPIKey = lc.proxyAPIKey
	server.ProxyAPIKeys = lc.proxyAPIKeys
	server.LogFile = lc.logFile
	server.IPAllowList = lc.ipAllowList
	server.IPDenyList = lc.ipDenyList
	server.GeoIPTable = lc.geoIPTable
	server.CountryAllowList = lc.countryAllowList
	server.CountryDenyList = lc.countryDenyList
	server.AnomalyDetector = lc.anomalyDetector
	server.AnomalyDryRun = lc.anomalyDryRun
	server.UpstreamTransport = lc.upstreamTransport
	server.UpstreamTotalTimeout = lc.upstreamTotalTimeout
	server.TargetBreaker = lc.targetBreaker
	server.CORS = lc.cors
	server.HealthCheckInterval = lc.healthCheckInterval
	server.HealthCheckPath = lc.healthCheckPath
	server.TargetCostRates = lc.targetCostRates
	server.IPLimiter = lc.ipLimiter
	server.TLSCertFile = *tlsCert
	server.TLSKeyFile = *tlsKey
	server.AuditChain = auditChain
	server.AdminAddr = *adminAddr
	for _, r := range lc.routes {
		server.AddRoute(r.prefix, r.targets, r.weights, r.limiter, r.tokenLimiter)
	}
	for _, r := range lc.modelRoutes {
		server.AddModelRoute(r.name, r.models, r.targets, r.weights, r.limiter, r.tokenLimiter)
	}

	if cfg != nil {
		if len(cfg.CustomRules) > 0 {
			fmt.Fprintf(stdout, "loaded %d custom rule(s) from %s\n", len(cfg.CustomRules), loadedFrom)
		}
		for _, cr := range cfg.CustomRules {
			if cr.DryRun {
				fmt.Fprintf(stdout, "custom rule: %s (dry-run — logged, never enforced)\n", cr.Name)
			}
			if len(cr.Targets) > 0 || len(cr.Keys) > 0 {
				fmt.Fprintf(stdout, "custom rule: %s scoped to targets=%v keys=%v\n", cr.Name, cr.Targets, cr.Keys)
			}
		}
		for _, r := range cfg.PathRules {
			if r.DryRun {
				fmt.Fprintf(stdout, "path rule: %s %s (dry-run — logged, never enforced)\n", r.Prefix, r.Action)
			} else {
				fmt.Fprintf(stdout, "path rule: %s %s\n", r.Prefix, r.Action)
			}
		}
		if cfg.MaxRequestsPerMinute > 0 {
			fmt.Fprintf(stdout, "circuit breaker: %d requests/minute\n", cfg.MaxRequestsPerMinute)
		}
		if cfg.MaxTokensPerMinute > 0 {
			fmt.Fprintf(stdout, "token circuit breaker: %d tokens/minute\n", cfg.MaxTokensPerMinute)
		}
		if cfg.MaxRequestsPerMinutePerIP > 0 {
			fmt.Fprintf(stdout, "per-IP circuit breaker: %d requests/minute per caller IP\n", cfg.MaxRequestsPerMinutePerIP)
		}
		if cfg.CacheEnabled {
			if cfg.CacheTTLSeconds > 0 {
				fmt.Fprintf(stdout, "response cache: enabled (%s/, ttl %ds)\n", cache.DirName, cfg.CacheTTLSeconds)
			} else {
				fmt.Fprintf(stdout, "response cache: enabled (%s/, no ttl)\n", cache.DirName)
			}
			if cfg.CacheMaxSizeBytes > 0 {
				fmt.Fprintf(stdout, "response cache: size-capped at %d bytes (LRU eviction)\n", cfg.CacheMaxSizeBytes)
			}
		}
		if len(lc.targetCacheTTL) > 0 || len(lc.targetCacheEnabled) > 0 {
			overriddenLabels := make(map[string]bool, len(lc.targetCacheTTL)+len(lc.targetCacheEnabled))
			for label := range lc.targetCacheTTL {
				overriddenLabels[label] = true
			}
			for label := range lc.targetCacheEnabled {
				overriddenLabels[label] = true
			}
			fmt.Fprintf(stdout, "per-target cache overrides: %d\n", len(overriddenLabels))
		}
		if cfg.CostPer1KTokens > 0 {
			fmt.Fprintf(stdout, "cost estimation: %g per 1K tokens\n", cfg.CostPer1KTokens)
		}
		if len(lc.targetCostRates) > 0 {
			fmt.Fprintf(stdout, "per-target cost overrides: %d\n", len(lc.targetCostRates))
		}
		if cfg.CostBudget > 0 {
			fmt.Fprintf(stdout, "cost budget: %g (alerts once, on/after crossing)\n", cfg.CostBudget)
		}
		if cfg.MaxBodyBytes > 0 {
			fmt.Fprintf(stdout, "max request body size: %d bytes\n", cfg.MaxBodyBytes)
		}
		if lc.webhookURL != nil {
			// Deliberately never prints the URL itself: a webhook URL
			// (a Slack incoming webhook, in particular) typically embeds
			// a bearer credential directly in its path, so it gets the
			// same treatment as every other secret aiproxy handles —
			// never written to a log or the terminal.
			fmt.Fprintln(stdout, "webhook alerts: enabled (on block/redact/rate_limited/token_rate_limited/unauthorized/dry-run/budget_exceeded)")
		}
		if len(lc.webhooks) > 0 {
			// Same discipline as the webhook_url notice above: counts
			// only, never the destination URLs themselves.
			fmt.Fprintf(stdout, "additional webhook destinations: %d (event-filtered)\n", len(lc.webhooks))
		}
		if len(lc.ipAllowList) > 0 {
			// Not a secret like a webhook URL or a proxy key — printed
			// in full, same as a route's destination URL.
			fmt.Fprintf(stdout, "IP allow list: %s\n", strings.Join(formatIPNets(lc.ipAllowList), ", "))
		}
		if len(lc.ipDenyList) > 0 {
			fmt.Fprintf(stdout, "IP deny list: %s\n", strings.Join(formatIPNets(lc.ipDenyList), ", "))
		}
		if lc.geoIPTable != nil {
			fmt.Fprintf(stdout, "GeoIP ranges loaded: %d\n", lc.geoIPTable.Len())
		}
		if len(lc.countryAllowList) > 0 {
			fmt.Fprintf(stdout, "country allow list: %s\n", strings.Join(lc.countryAllowList, ", "))
		}
		if len(lc.countryDenyList) > 0 {
			fmt.Fprintf(stdout, "country deny list: %s\n", strings.Join(lc.countryDenyList, ", "))
		}
		if lc.anomalyDetector != nil {
			if lc.anomalyDryRun {
				fmt.Fprintf(stdout, "anomaly detection: %gx baseline (dry-run — logged, never enforced)\n", cfg.AnomalyMultiplier)
			} else {
				fmt.Fprintf(stdout, "anomaly detection: %gx baseline\n", cfg.AnomalyMultiplier)
			}
		}
		if cfg.UpstreamResponseTimeoutSeconds > 0 {
			fmt.Fprintf(stdout, "upstream response timeout: %s\n", timeoutDisplay(cfg.UpstreamResponseTimeoutSeconds))
		}
		if cfg.UpstreamTotalTimeoutSeconds > 0 {
			fmt.Fprintf(stdout, "upstream total timeout: %s\n", timeoutDisplay(cfg.UpstreamTotalTimeoutSeconds))
		}
		if lc.targetBreaker != nil {
			fmt.Fprintf(stdout, "target ejection: after %d consecutive failures, %ds cooldown\n", cfg.TargetEjectionThreshold, cfg.TargetEjectionCooldownSeconds)
		}
		if lc.cors != nil {
			fmt.Fprintf(stdout, "CORS: enabled for %s\n", strings.Join(cfg.CORSAllowedOrigins, ", "))
		}
		if lc.healthCheckInterval > 0 {
			fmt.Fprintf(stdout, "target health checks: every %s%s\n", lc.healthCheckInterval, healthCheckPathDisplay(lc.healthCheckPath))
		}
		if lc.proxyAPIKey != "" {
			// Deliberately never prints the key itself, same discipline
			// as the webhook URL above.
			fmt.Fprintln(stdout, "proxy authentication: required (Proxy-Authorization: Bearer <key>)")
		}
		if len(lc.proxyAPIKeys) > 0 {
			// Names identify a key in stats/logs and aren't secret, but
			// the keys themselves get the same treatment as the
			// anonymous one above — counts and names only.
			names := make([]string, len(lc.proxyAPIKeys))
			for i, k := range lc.proxyAPIKeys {
				names[i] = k.Name
			}
			fmt.Fprintf(stdout, "additional named proxy keys: %d (%s)\n", len(lc.proxyAPIKeys), strings.Join(names, ", "))
		}
		if cfg.LogFile != "" {
			fmt.Fprintf(stdout, "log file: %s (JSON lines, reopened on SIGHUP)\n", cfg.LogFile)
		}
		if auditChain != nil {
			fmt.Fprintln(stdout, "audit log signing: enabled (HMAC-chained, verify with `aiproxy verify-log`)")
		}
		for _, r := range lc.routes {
			dest := formatTargetsForDisplay(r.targets)
			if r.weights != nil {
				dest = formatWeightedTargetsForDisplay(r.targets, r.weights)
			}
			if limits := formatRateLimitsForDisplay(r.maxRequestsPerMinute, r.maxTokensPerMinute); limits != "" {
				fmt.Fprintf(stdout, "route: %s -> %s (rate limit: %s)\n", r.prefix, dest, limits)
			} else {
				fmt.Fprintf(stdout, "route: %s -> %s\n", r.prefix, dest)
			}
		}
		for _, r := range lc.modelRoutes {
			dest := formatTargetsForDisplay(r.targets)
			if r.weights != nil {
				dest = formatWeightedTargetsForDisplay(r.targets, r.weights)
			}
			models := strings.Join(r.models, ", ")
			if limits := formatRateLimitsForDisplay(r.maxRequestsPerMinute, r.maxTokensPerMinute); limits != "" {
				fmt.Fprintf(stdout, "model route: %s (%s) -> %s (rate limit: %s)\n", r.name, models, dest, limits)
			} else {
				fmt.Fprintf(stdout, "model route: %s (%s) -> %s\n", r.name, models, dest)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startReloadOnSIGHUP(ctx, server, *configPath, cfg)

	scheme := "http"
	if *tlsCert != "" {
		scheme = "https"
	}
	fmt.Fprintf(stdout, "aiproxy listening on %s://%s, forwarding to %s\n", scheme, *addr, targetURL)
	if *adminAddr != "" {
		fmt.Fprintf(stdout, "admin surface (stats/metrics/dashboard/cache-clear) listening separately on %s://%s\n", scheme, *adminAddr)
	}
	if err := server.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}
	return 0
}

// startReloadOnSIGHUP starts a goroutine that re-reads the config file at
// configPath and applies it to server every time the process receives
// SIGHUP, until ctx is done. A reload that finds any problem — a bad
// regex, a bad target, a cache directory that can't be created, or the
// config file itself failing to load — logs the problem and leaves
// server's current configuration completely untouched: a bad edit
// followed by a SIGHUP must never blank out a running proxy's rules or
// crash it, only fail to apply.
// startReloadOnSIGHUP wires SIGHUP to reloadConfig, threading the
// currently-live config forward through successive reloads (in prevCfg,
// updated after each call) purely so each one can report exactly what
// changed relative to the reload before it — see diffConfig. initialCfg
// is the config runStart already loaded at cold start, the correct
// baseline for the very first SIGHUP this process ever receives.
func startReloadOnSIGHUP(ctx context.Context, server *proxy.Server, configPath string, initialCfg *config.Config) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	prevCfg := initialCfg
	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				prevCfg = reloadConfig(server, configPath, prevCfg)
			}
		}
	}()
}

// reloadConfig re-reads configPath and, if it's valid, swaps it into
// server — the exact same construction path a cold start uses (see
// buildLiveConfig), so a reload can never produce something a cold
// start couldn't. Returns the config that's actually live in server
// once this call returns: prevCfg unchanged on any failure (the
// previous config, and only it, is still what's running), or the newly
// loaded one on success — the caller (startReloadOnSIGHUP) threads this
// back in as prevCfg for the *next* reload, so a chain of reloads always
// diffs against what's truly running, not just what was last attempted.
func reloadConfig(server *proxy.Server, configPath string, prevCfg *config.Config) *config.Config {
	cfg, loadedFrom, err := resolveConfig(configPath)
	if err != nil {
		server.LogEvent("reload_error", fmt.Sprintf("aiproxy: reload failed: %v", err))
		return prevCfg
	}

	lc, errs := buildLiveConfig(cfg)
	if len(errs) > 0 {
		if lc.logFile != nil {
			// buildLiveConfig already opened a fresh handle before some
			// other field failed validation; the reload is being
			// discarded entirely, so this one would otherwise never be
			// closed by anything.
			lc.logFile.Close()
		}
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		server.LogEvent("reload_error", fmt.Sprintf(
			"aiproxy: reload failed, keeping previous config (%d problem(s)): %s",
			len(errs), strings.Join(msgs, "; "),
		))
		return prevCfg
	}

	routes := make([]proxy.Route, len(lc.routes))
	for i, r := range lc.routes {
		routes[i] = proxy.Route{Prefix: r.prefix, Targets: r.targets, Weights: r.weights, Limiter: r.limiter, TokenLimiter: r.tokenLimiter}
	}
	modelRoutes := make([]proxy.ModelRoute, len(lc.modelRoutes))
	for i, r := range lc.modelRoutes {
		modelRoutes[i] = proxy.ModelRoute{Name: r.name, Models: r.models, Targets: r.targets, Weights: r.weights, Limiter: r.limiter, TokenLimiter: r.tokenLimiter}
	}
	server.ReloadConfig(lc.engine, lc.limiter, lc.cache, lc.cost, lc.costBudget, lc.maxBodyBytes, lc.webhookURL, lc.webhooks, lc.proxyAPIKey, lc.proxyAPIKeys, lc.logFile, routes, modelRoutes, lc.ipAllowList, lc.ipDenyList, lc.tokenLimiter, lc.geoIPTable, lc.countryAllowList, lc.countryDenyList, lc.anomalyDetector, lc.anomalyDryRun, lc.upstreamTransport, lc.upstreamTotalTimeout, lc.targetBreaker, lc.cors, lc.healthCheckInterval, lc.healthCheckPath, lc.targetCostRates, lc.ipLimiter, lc.cacheTTL, lc.targetCacheTTL, lc.targetCacheEnabled)

	label := loadedFrom
	if label == "" {
		label = "built-in rules only (no config file)"
	}

	changes := diffConfig(prevCfg, cfg)
	if len(changes) == 0 {
		server.LogEvent("reload", fmt.Sprintf("aiproxy: reloaded config from %s (no changes)", label))
		return cfg
	}
	diffSummary := summarizeConfigDiff(changes)
	server.LogEvent("reload", fmt.Sprintf("aiproxy: reloaded config from %s: %s", label, diffSummary))
	server.NotifyEvent("config_changed", fmt.Sprintf("aiproxy: config reloaded from %s: %s", label, diffSummary))
	return cfg
}

// liveConfig holds every piece of a Server's configuration that can be
// rebuilt from an aiproxy.json: everything runStart wires in at startup,
// and everything a SIGHUP reload replaces via Server.ReloadConfig.
type liveConfig struct {
	engine           *rules.Engine
	limiter          *limiter.Limiter
	tokenLimiter     *limiter.TokenLimiter
	cache            *cache.Cache
	cost             float64
	costBudget       float64
	maxBodyBytes     int64
	webhookURL       *url.URL
	webhooks         []proxy.WebhookTarget
	proxyAPIKey      string
	proxyAPIKeys     []proxy.ProxyKey
	logFile          *os.File
	routes           []targetRoute
	modelRoutes      []modelRoute
	ipAllowList      []*net.IPNet
	ipDenyList       []*net.IPNet
	geoIPTable       *geoip.Table
	countryAllowList []string
	countryDenyList  []string
	anomalyDetector  *anomaly.Registry
	anomalyDryRun    bool

	upstreamTransport    *http.Transport
	upstreamTotalTimeout time.Duration

	targetBreaker *breaker.Registry

	cors *proxy.CORSConfig

	healthCheckInterval time.Duration
	healthCheckPath     string

	targetCostRates map[string]float64

	ipLimiter *iplimiter.Registry

	cacheTTL           time.Duration
	targetCacheTTL     map[string]time.Duration
	targetCacheEnabled map[string]bool
}

// buildLiveConfig builds a liveConfig from cfg, which may be nil (no
// config file at all, producing just the built-in rules with everything
// else disabled) — the same construction path for both a cold start and
// a reload, so a reload can never produce something a cold start
// couldn't. Every problem found (a bad regex, a bad target, a cache
// directory that can't be created) is collected and returned together
// rather than stopping at the first; the caller decides whether that's
// fatal (a cold start) or just means keeping whatever is already running
// (a reload).
func buildLiveConfig(cfg *config.Config) (*liveConfig, []error) {
	engine, errs := buildEngine(cfg)
	lc := &liveConfig{engine: engine, upstreamTransport: proxy.NewUpstreamTransport(0)}
	if cfg == nil {
		return lc, errs
	}

	if cfg.MaxRequestsPerMinute > 0 {
		lc.limiter = limiter.New(cfg.MaxRequestsPerMinute, time.Minute)
	}
	if cfg.MaxTokensPerMinute > 0 {
		lc.tokenLimiter = limiter.NewTokenLimiter(cfg.MaxTokensPerMinute, time.Minute)
	}
	if cfg.MaxRequestsPerMinutePerIP < 0 {
		errs = append(errs, fmt.Errorf("max_requests_per_minute_per_ip: %d must not be negative", cfg.MaxRequestsPerMinutePerIP))
	} else if cfg.MaxRequestsPerMinutePerIP > 0 {
		lc.ipLimiter = iplimiter.NewRegistry(cfg.MaxRequestsPerMinutePerIP, time.Minute)
	}

	if cfg.CacheEnabled {
		c, err := cache.New()
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: %w", err))
		} else {
			c.MaxSizeBytes = cfg.CacheMaxSizeBytes
			lc.cache = c
			lc.cacheTTL = time.Duration(cfg.CacheTTLSeconds) * time.Second
		}
	}

	lc.cost = cfg.CostPer1KTokens
	lc.costBudget = cfg.CostBudget
	lc.maxBodyBytes = cfg.MaxBodyBytes

	if cfg.WebhookURL != "" {
		webhookURL, err := parseWebhookURL(cfg.WebhookURL)
		if err != nil {
			errs = append(errs, fmt.Errorf("webhook_url: %w", err))
		} else {
			lc.webhookURL = webhookURL
		}
	}

	webhooks, webhookErrs := compileWebhookTargets(cfg.Webhooks)
	errs = append(errs, webhookErrs...)
	lc.webhooks = webhooks

	lc.proxyAPIKey = cfg.ProxyAPIKey

	proxyAPIKeys, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
	errs = append(errs, proxyKeyErrs...)
	lc.proxyAPIKeys = proxyAPIKeys

	if cfg.LogFile != "" {
		logFile, err := openLogFile(cfg.LogFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			lc.logFile = logFile
		}
	}

	routes, routeErrs := compileTargetRoutes(cfg.Targets, cfg.CacheEnabled)
	errs = append(errs, routeErrs...)
	lc.routes = routes

	modelRoutes, modelRouteErrs := compileModelRoutes(cfg.ModelRoutes, cfg.CacheEnabled)
	errs = append(errs, modelRouteErrs...)
	lc.modelRoutes = modelRoutes

	// Built from the already-compiled routes/model routes, keyed by the
	// exact same target label stats/logs/Prometheus already use for
	// each one (a targets[].prefix, or "model:<name>") — see
	// proxy.Server.TargetCostRates. Only overrides actually set (> 0)
	// are included; every other label simply falls back to the
	// top-level cost_per_1k_tokens, unchanged from before this field
	// existed.
	targetCostRates := make(map[string]float64)
	for _, r := range lc.routes {
		if r.costPer1KTokens > 0 {
			targetCostRates[r.prefix] = r.costPer1KTokens
		}
	}
	for _, r := range lc.modelRoutes {
		if r.costPer1KTokens > 0 {
			targetCostRates["model:"+r.name] = r.costPer1KTokens
		}
	}
	if len(targetCostRates) > 0 {
		lc.targetCostRates = targetCostRates
	}

	// Built the same way as targetCostRates, just above — see
	// proxy.Server.TargetCacheTTL/TargetCacheEnabled. A target's own
	// cache_ttl_seconds is only included when actually set (> 0); its
	// own cache_enabled is only included when explicitly set at all
	// (nil means "no override," not "override to false").
	targetCacheTTL := make(map[string]time.Duration)
	targetCacheEnabled := make(map[string]bool)
	addCacheOverride := func(label string, enabled *bool, ttlSeconds int) {
		if enabled != nil {
			targetCacheEnabled[label] = *enabled
		}
		if ttlSeconds > 0 {
			targetCacheTTL[label] = time.Duration(ttlSeconds) * time.Second
		}
	}
	for _, r := range lc.routes {
		addCacheOverride(r.prefix, r.cacheEnabled, r.cacheTTLSeconds)
	}
	for _, r := range lc.modelRoutes {
		addCacheOverride("model:"+r.name, r.cacheEnabled, r.cacheTTLSeconds)
	}
	if len(targetCacheTTL) > 0 {
		lc.targetCacheTTL = targetCacheTTL
	}
	if len(targetCacheEnabled) > 0 {
		lc.targetCacheEnabled = targetCacheEnabled
	}

	ipAllowList, allowErrs := compileIPList("ip_allow_list", cfg.IPAllowList)
	errs = append(errs, allowErrs...)
	lc.ipAllowList = ipAllowList

	ipDenyList, denyErrs := compileIPList("ip_deny_list", cfg.IPDenyList)
	errs = append(errs, denyErrs...)
	lc.ipDenyList = ipDenyList

	if (len(cfg.CountryAllowList) > 0 || len(cfg.CountryDenyList) > 0) && cfg.GeoIPRangesFile == "" {
		errs = append(errs, fmt.Errorf("country_allow_list/country_deny_list requires geoip_ranges_file to be set (there's nothing to resolve a request's country from otherwise)"))
	}
	if cfg.GeoIPRangesFile != "" {
		table, err := geoip.Load(cfg.GeoIPRangesFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			lc.geoIPTable = table
		}
	}

	countryAllowList, countryAllowErrs := compileCountryList("country_allow_list", cfg.CountryAllowList)
	errs = append(errs, countryAllowErrs...)
	lc.countryAllowList = countryAllowList

	countryDenyList, countryDenyErrs := compileCountryList("country_deny_list", cfg.CountryDenyList)
	errs = append(errs, countryDenyErrs...)
	lc.countryDenyList = countryDenyList

	if cfg.AnomalyMultiplier < 0 {
		errs = append(errs, fmt.Errorf("anomaly_multiplier: %g must not be negative", cfg.AnomalyMultiplier))
	} else if cfg.AnomalyMultiplier > 0 {
		lc.anomalyDetector = anomaly.NewRegistry(cfg.AnomalyMultiplier, anomaly.DefaultWindow)
	}
	if cfg.AnomalyDryRun && cfg.AnomalyMultiplier <= 0 {
		errs = append(errs, fmt.Errorf("anomaly_dry_run requires anomaly_multiplier to be set (there's nothing to dry-run otherwise)"))
	}
	lc.anomalyDryRun = cfg.AnomalyDryRun

	if cfg.UpstreamResponseTimeoutSeconds < 0 {
		errs = append(errs, fmt.Errorf("upstream_response_timeout_seconds: %d must not be negative", cfg.UpstreamResponseTimeoutSeconds))
	} else if cfg.UpstreamResponseTimeoutSeconds > 0 {
		lc.upstreamTransport = proxy.NewUpstreamTransport(time.Duration(cfg.UpstreamResponseTimeoutSeconds) * time.Second)
	}
	if cfg.UpstreamTotalTimeoutSeconds < 0 {
		errs = append(errs, fmt.Errorf("upstream_total_timeout_seconds: %d must not be negative", cfg.UpstreamTotalTimeoutSeconds))
	}
	lc.upstreamTotalTimeout = time.Duration(cfg.UpstreamTotalTimeoutSeconds) * time.Second

	if cfg.TargetEjectionThreshold < 0 {
		errs = append(errs, fmt.Errorf("target_ejection_threshold: %d must not be negative", cfg.TargetEjectionThreshold))
	}
	if cfg.TargetEjectionCooldownSeconds < 0 {
		errs = append(errs, fmt.Errorf("target_ejection_cooldown_seconds: %d must not be negative", cfg.TargetEjectionCooldownSeconds))
	}
	if cfg.TargetEjectionThreshold > 0 && cfg.TargetEjectionCooldownSeconds <= 0 {
		errs = append(errs, fmt.Errorf("target_ejection_threshold requires target_ejection_cooldown_seconds to be set (there's nothing to time the cooldown with otherwise)"))
	}
	if cfg.TargetEjectionCooldownSeconds > 0 && cfg.TargetEjectionThreshold <= 0 {
		errs = append(errs, fmt.Errorf("target_ejection_cooldown_seconds requires target_ejection_threshold to be set (there's no breaker for it to time)"))
	}
	if cfg.TargetEjectionThreshold > 0 && cfg.TargetEjectionCooldownSeconds > 0 {
		lc.targetBreaker = breaker.NewRegistry(cfg.TargetEjectionThreshold, time.Duration(cfg.TargetEjectionCooldownSeconds)*time.Second)
	}

	if cfg.CORSMaxAgeSeconds < 0 {
		errs = append(errs, fmt.Errorf("cors_max_age_seconds: %d must not be negative", cfg.CORSMaxAgeSeconds))
	}
	if len(cfg.CORSAllowedOrigins) == 0 {
		switch {
		case len(cfg.CORSAllowedMethods) > 0:
			errs = append(errs, fmt.Errorf("cors_allowed_methods requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)"))
		case len(cfg.CORSAllowedHeaders) > 0:
			errs = append(errs, fmt.Errorf("cors_allowed_headers requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)"))
		case cfg.CORSAllowCredentials:
			errs = append(errs, fmt.Errorf("cors_allow_credentials requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)"))
		case cfg.CORSMaxAgeSeconds > 0:
			errs = append(errs, fmt.Errorf("cors_max_age_seconds requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)"))
		}
	} else {
		lc.cors = &proxy.CORSConfig{
			AllowedOrigins:   cfg.CORSAllowedOrigins,
			AllowedMethods:   cfg.CORSAllowedMethods,
			AllowedHeaders:   cfg.CORSAllowedHeaders,
			AllowCredentials: cfg.CORSAllowCredentials,
			MaxAgeSeconds:    cfg.CORSMaxAgeSeconds,
		}
	}

	if cfg.TargetHealthCheckIntervalSeconds < 0 {
		errs = append(errs, fmt.Errorf("target_health_check_interval_seconds: %d must not be negative", cfg.TargetHealthCheckIntervalSeconds))
	}
	if cfg.TargetHealthCheckIntervalSeconds > 0 && cfg.TargetEjectionThreshold <= 0 {
		errs = append(errs, fmt.Errorf("target_health_check_interval_seconds requires target_ejection_threshold/target_ejection_cooldown_seconds to be set (there's no breaker for a health check to report into otherwise)"))
	}
	if cfg.TargetHealthCheckPath != "" && cfg.TargetHealthCheckIntervalSeconds <= 0 {
		errs = append(errs, fmt.Errorf("target_health_check_path requires target_health_check_interval_seconds to be set (there's nothing to probe otherwise)"))
	}
	lc.healthCheckInterval = time.Duration(cfg.TargetHealthCheckIntervalSeconds) * time.Second
	lc.healthCheckPath = cfg.TargetHealthCheckPath

	return lc, errs
}

// compileCountryList validates and normalizes a config file's
// country_allow_list or country_deny_list entries: each must be a
// 2-letter ISO 3166-1 alpha-2 code (case-insensitive, normalized to
// uppercase) — same per-entry indexed error style as compileIPList.
func compileCountryList(fieldName string, entries []string) ([]string, []error) {
	compiled := make([]string, 0, len(entries))
	var errs []error
	for i, raw := range entries {
		code := strings.ToUpper(strings.TrimSpace(raw))
		if !geoip.ValidCountryCode(code) {
			errs = append(errs, fmt.Errorf("%s[%d]: %q is not a 2-letter country code", fieldName, i, raw))
			continue
		}
		compiled = append(compiled, code)
	}
	return compiled, errs
}

// compileIPList parses and validates a config file's ip_allow_list or
// ip_deny_list entries into net.IPNet values for Server.IPAllowList/
// Server.IPDenyList. Each entry is either CIDR notation ("10.0.0.0/8")
// or a bare IP address ("192.168.1.5"), normalized to that address's
// full-width CIDR (/32 for IPv4, /128 for IPv6) — the common,
// unsurprising shorthand for "just this one address." fieldName names
// the config field in error messages ("ip_allow_list" or
// "ip_deny_list"). Problems are collected and returned rather than
// stopping at the first one, same pattern as every other compile*
// helper in this file.
func compileIPList(fieldName string, entries []string) ([]*net.IPNet, []error) {
	compiled := make([]*net.IPNet, 0, len(entries))
	var errs []error
	for i, raw := range entries {
		cidr := raw
		if !strings.Contains(raw, "/") {
			ip := net.ParseIP(raw)
			if ip == nil {
				errs = append(errs, fmt.Errorf("%s[%d]: %q is not a valid IP address or CIDR range", fieldName, i, raw))
				continue
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			cidr = fmt.Sprintf("%s/%d", raw, bits)
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s[%d]: %q is not a valid IP address or CIDR range", fieldName, i, raw))
			continue
		}
		compiled = append(compiled, ipNet)
	}
	return compiled, errs
}

// openLogFile opens path in append mode, creating it if it doesn't
// exist, for Config.LogFile. Called fresh on every cold start and every
// reload — see ReloadConfig's doc comment for why an unconditional
// reopen (rather than only when the path actually changed) is what
// makes SIGHUP-driven external log rotation work.
func openLogFile(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("log_file: %w", err)
	}
	return f, nil
}

// builtinRules lists the name and pattern of each of aiproxy's built-in
// secret-blocking rules, in the order buildEngine adds them to the
// engine.
var builtinRules = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"aws-access-key", awsAccessKeyPattern},
	{"openai-api-key", openAIAPIKeyPattern},
	{"github-token", githubTokenPattern},
	{"anthropic-api-key", anthropicAPIKeyPattern},
	{"private-key", privateKeyPattern},
	{"slack-token", slackTokenPattern},
	{"stripe-api-key", stripeAPIKeyPattern},
	{"google-api-key", googleAPIKeyPattern},
	{"npm-access-token", npmAccessTokenPattern},
	{"jwt", jwtPattern},
}

// builtinRuleNames returns every built-in rule's name, in the same
// order as builtinRules — used to list valid names in a config error
// message without that list drifting out of sync with builtinRules
// itself.
func builtinRuleNames() []string {
	names := make([]string, len(builtinRules))
	for i, b := range builtinRules {
		names[i] = b.name
	}
	return names
}

// resolveBuiltinRuleActions turns a config file's builtin_rule_actions
// map into a rule name -> Action lookup plus a set of rule names turned
// off entirely, defaulting every built-in rule not mentioned to its
// long-standing rules.Block behavior. "off" is accepted here and only
// here — never by parseRuleAction, so a custom_rules entry can't be set
// to "off" (there's no need: omitting a custom rule from the list
// already does that) — since it's the only way to fully disable a
// built-in rule, which can't otherwise be removed from the list the way
// a custom rule can. It reports three kinds of config mistakes as
// errors, collecting all of them rather than stopping at the first: an
// action string that is neither "block", "redact", nor "off"; and a key
// that doesn't match any real built-in rule name (almost always a
// typo).
func resolveBuiltinRuleActions(overrides map[string]string) (actions map[string]rules.Action, off map[string]bool, errs []error) {
	actions = make(map[string]rules.Action, len(builtinRules))
	names := make(map[string]bool, len(builtinRules))
	for _, b := range builtinRules {
		actions[b.name] = rules.Block
		names[b.name] = true
	}

	off = make(map[string]bool)
	for name, raw := range overrides {
		if !names[name] {
			errs = append(errs, fmt.Errorf("Fatal error: builtin_rule_actions: %q is not a built-in rule (valid names: %s)", name, strings.Join(builtinRuleNames(), ", ")))
			continue
		}
		if raw == "off" {
			off[name] = true
			continue
		}
		action, err := parseRuleAction(raw)
		if err != nil {
			// Not parseRuleAction's own error message: "off" is valid
			// here but not for parseRuleAction's other caller
			// (custom_rules[].action), so its message can't mention it.
			errs = append(errs, fmt.Errorf("Fatal error: Invalid action for built-in rule %s: must be \"block\", \"redact\", or \"off\", got %q", name, raw))
			continue
		}
		actions[name] = action
	}
	return actions, off, errs
}

// buildEngine constructs the rule engine used to evaluate every request:
// every built-in secret-blocking rule in builtinRules not turned off
// (each block or redact otherwise, depending on cfg.BuiltinRuleActions),
// plus any path_rules and custom_rules from cfg. Engine.Evaluate always
// checks path rules before any body rule regardless of the order they
// were added in, so a path_rules "allow" entry exempts a matching
// request from custom_rules too, not just the built-ins. cfg may be
// nil (no config file at all), in which case only the built-ins apply,
// all blocking.
func buildEngine(cfg *config.Config) (*rules.Engine, []error) {
	engine := rules.NewEngine(rules.Allow)

	var overrides map[string]string
	if cfg != nil {
		overrides = cfg.BuiltinRuleActions
	}
	actions, off, errs := resolveBuiltinRuleActions(overrides)
	for _, b := range builtinRules {
		if off[b.name] {
			continue
		}
		engine.AddBodyRegexRule(rules.BodyRegexRule{
			Name:    b.name,
			Pattern: b.pattern,
			Action:  actions[b.name],
		})
	}

	if cfg == nil {
		return engine, errs
	}

	pathRules, pErrs := compilePathRules(cfg.PathRules)
	for _, r := range pathRules {
		engine.AddRule(r)
	}
	errs = append(errs, pErrs...)

	customRules, cErrs := compileCustomRules(cfg.CustomRules, validTargetLabels(cfg), validKeyLabels(cfg))
	for _, r := range customRules {
		engine.AddBodyRegexRule(r)
	}
	errs = append(errs, cErrs...)
	return engine, errs
}

// compilePathRules validates and parses each path_rules entry from the
// config file. A prefix must be non-empty, start with "/", and be
// distinct from every other path rule's prefix (a duplicate would only
// ever be reached via the first, dead configuration otherwise); action
// must be exactly "block" or "allow"; dry_run, if set, requires action
// "block" — there is nothing to preview for "allow", which never
// rejects anything to begin with. Problems are collected and returned
// rather than stopping at the first one — the caller decides whether
// that's fatal (runStart) or just a reported problem (runValidate).
func compilePathRules(pathRules []config.PathRule) ([]rules.Rule, []error) {
	compiled := make([]rules.Rule, 0, len(pathRules))
	var errs []error
	seenPrefixes := make(map[string]bool, len(pathRules))
	for _, p := range pathRules {
		if p.Prefix == "" || !strings.HasPrefix(p.Prefix, "/") {
			errs = append(errs, fmt.Errorf("Fatal error: path_rules: prefix %q must be non-empty and start with \"/\"", p.Prefix))
			continue
		}
		if seenPrefixes[p.Prefix] {
			errs = append(errs, fmt.Errorf("Fatal error: path_rules: duplicate prefix %q (only the first entry with a given prefix is ever reachable)", p.Prefix))
			continue
		}
		seenPrefixes[p.Prefix] = true

		action, err := parsePathRuleAction(p.Action)
		if err != nil {
			errs = append(errs, fmt.Errorf("Fatal error: Invalid action for path rule %s: %w", p.Name, err))
			continue
		}
		if p.DryRun && action != rules.Block {
			errs = append(errs, fmt.Errorf("Fatal error: path_rules: %s: dry_run requires action \"block\" (nothing to preview for \"allow\")", p.Name))
			continue
		}

		compiled = append(compiled, rules.Rule{Name: p.Name, PathPrefix: p.Prefix, Action: action, DryRun: p.DryRun})
	}
	return compiled, errs
}

// parsePathRuleAction parses a path_rules entry's action field: "block"
// or "allow". Unlike parseRuleAction (custom_rules[].action), there is
// no default for an absent/empty value — block and allow are opposite
// intents, so silently choosing one could surprise the user in a way
// that matters.
func parsePathRuleAction(raw string) (rules.Action, error) {
	switch raw {
	case "block":
		return rules.Block, nil
	case "allow":
		return rules.Allow, nil
	default:
		return 0, fmt.Errorf("must be \"block\" or \"allow\", got %q", raw)
	}
}

// runValidate checks a config file for problems without starting the
// proxy: every custom_rules pattern must compile, every targets and
// path_rules entry must have a well-formed, unique prefix (and, for
// path_rules, a valid action), and the numeric fields must be sane. It
// never calls log.Fatal or otherwise aborts the process — reporting
// every problem it finds and returning a non-zero exit code is the
// whole point, as opposed to runStart, which treats the same problems
// as fatal.
func runValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "path to the JSON config file to validate (default: aiproxy.json in the working directory)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, loadedFrom, err := resolveConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}
	if cfg == nil {
		fmt.Fprintln(stdout, "no config file found — aiproxy would run with just the built-in secret-blocking rules. Nothing to validate.")
		return 0
	}

	var problems []string

	_, ruleErrs := compileCustomRules(cfg.CustomRules, validTargetLabels(cfg), validKeyLabels(cfg))
	for _, e := range ruleErrs {
		// compileCustomRules' errors are pre-formatted for runStart's
		// log.Fatal, which validate never calls; drop that "Fatal
		// error: " framing so the report reads as a list of problems,
		// not a list of things that supposedly just crashed.
		problems = append(problems, strings.TrimPrefix(e.Error(), "Fatal error: "))
	}

	_, routeErrs := compileTargetRoutes(cfg.Targets, cfg.CacheEnabled)
	for _, e := range routeErrs {
		problems = append(problems, e.Error())
	}

	_, modelRouteErrs := compileModelRoutes(cfg.ModelRoutes, cfg.CacheEnabled)
	for _, e := range modelRouteErrs {
		problems = append(problems, e.Error())
	}

	_, ipAllowErrs := compileIPList("ip_allow_list", cfg.IPAllowList)
	for _, e := range ipAllowErrs {
		problems = append(problems, e.Error())
	}
	_, ipDenyErrs := compileIPList("ip_deny_list", cfg.IPDenyList)
	for _, e := range ipDenyErrs {
		problems = append(problems, e.Error())
	}

	if (len(cfg.CountryAllowList) > 0 || len(cfg.CountryDenyList) > 0) && cfg.GeoIPRangesFile == "" {
		problems = append(problems, "country_allow_list/country_deny_list requires geoip_ranges_file to be set (there's nothing to resolve a request's country from otherwise)")
	}
	if cfg.GeoIPRangesFile != "" {
		if _, err := geoip.Load(cfg.GeoIPRangesFile); err != nil {
			problems = append(problems, err.Error())
		}
	}
	_, countryAllowErrs := compileCountryList("country_allow_list", cfg.CountryAllowList)
	for _, e := range countryAllowErrs {
		problems = append(problems, e.Error())
	}
	_, countryDenyErrs := compileCountryList("country_deny_list", cfg.CountryDenyList)
	for _, e := range countryDenyErrs {
		problems = append(problems, e.Error())
	}

	if cfg.AnomalyMultiplier < 0 {
		problems = append(problems, fmt.Sprintf("anomaly_multiplier: %g must not be negative", cfg.AnomalyMultiplier))
	}
	if cfg.AnomalyDryRun && cfg.AnomalyMultiplier <= 0 {
		problems = append(problems, "anomaly_dry_run requires anomaly_multiplier to be set (there's nothing to dry-run otherwise)")
	}

	if cfg.UpstreamResponseTimeoutSeconds < 0 {
		problems = append(problems, fmt.Sprintf("upstream_response_timeout_seconds: %d must not be negative", cfg.UpstreamResponseTimeoutSeconds))
	}
	if cfg.UpstreamTotalTimeoutSeconds < 0 {
		problems = append(problems, fmt.Sprintf("upstream_total_timeout_seconds: %d must not be negative", cfg.UpstreamTotalTimeoutSeconds))
	}

	if cfg.TargetEjectionThreshold < 0 {
		problems = append(problems, fmt.Sprintf("target_ejection_threshold: %d must not be negative", cfg.TargetEjectionThreshold))
	}
	if cfg.TargetEjectionCooldownSeconds < 0 {
		problems = append(problems, fmt.Sprintf("target_ejection_cooldown_seconds: %d must not be negative", cfg.TargetEjectionCooldownSeconds))
	}
	if cfg.TargetEjectionThreshold > 0 && cfg.TargetEjectionCooldownSeconds <= 0 {
		problems = append(problems, "target_ejection_threshold requires target_ejection_cooldown_seconds to be set (there's nothing to time the cooldown with otherwise)")
	}
	if cfg.TargetEjectionCooldownSeconds > 0 && cfg.TargetEjectionThreshold <= 0 {
		problems = append(problems, "target_ejection_cooldown_seconds requires target_ejection_threshold to be set (there's no breaker for it to time)")
	}

	if cfg.CORSMaxAgeSeconds < 0 {
		problems = append(problems, fmt.Sprintf("cors_max_age_seconds: %d must not be negative", cfg.CORSMaxAgeSeconds))
	}
	if len(cfg.CORSAllowedOrigins) == 0 {
		switch {
		case len(cfg.CORSAllowedMethods) > 0:
			problems = append(problems, "cors_allowed_methods requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)")
		case len(cfg.CORSAllowedHeaders) > 0:
			problems = append(problems, "cors_allowed_headers requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)")
		case cfg.CORSAllowCredentials:
			problems = append(problems, "cors_allow_credentials requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)")
		case cfg.CORSMaxAgeSeconds > 0:
			problems = append(problems, "cors_max_age_seconds requires cors_allowed_origins to be set (there's nothing to answer a preflight for otherwise)")
		}
	}

	if cfg.TargetHealthCheckIntervalSeconds < 0 {
		problems = append(problems, fmt.Sprintf("target_health_check_interval_seconds: %d must not be negative", cfg.TargetHealthCheckIntervalSeconds))
	}
	if cfg.TargetHealthCheckIntervalSeconds > 0 && cfg.TargetEjectionThreshold <= 0 {
		problems = append(problems, "target_health_check_interval_seconds requires target_ejection_threshold/target_ejection_cooldown_seconds to be set (there's no breaker for a health check to report into otherwise)")
	}
	if cfg.TargetHealthCheckPath != "" && cfg.TargetHealthCheckIntervalSeconds <= 0 {
		problems = append(problems, "target_health_check_path requires target_health_check_interval_seconds to be set (there's nothing to probe otherwise)")
	}

	_, pathRuleErrs := compilePathRules(cfg.PathRules)
	for _, e := range pathRuleErrs {
		problems = append(problems, strings.TrimPrefix(e.Error(), "Fatal error: "))
	}

	_, _, builtinErrs := resolveBuiltinRuleActions(cfg.BuiltinRuleActions)
	for _, e := range builtinErrs {
		problems = append(problems, strings.TrimPrefix(e.Error(), "Fatal error: "))
	}

	if cfg.MaxRequestsPerMinute < 0 {
		problems = append(problems, fmt.Sprintf("max_requests_per_minute: %d must not be negative", cfg.MaxRequestsPerMinute))
	}
	if cfg.MaxTokensPerMinute < 0 {
		problems = append(problems, fmt.Sprintf("max_tokens_per_minute: %d must not be negative", cfg.MaxTokensPerMinute))
	}
	if cfg.MaxRequestsPerMinutePerIP < 0 {
		problems = append(problems, fmt.Sprintf("max_requests_per_minute_per_ip: %d must not be negative", cfg.MaxRequestsPerMinutePerIP))
	}
	if cfg.CostPer1KTokens < 0 {
		problems = append(problems, fmt.Sprintf("cost_per_1k_tokens: %g must not be negative", cfg.CostPer1KTokens))
	}
	if cfg.CostBudget < 0 {
		problems = append(problems, fmt.Sprintf("cost_budget: %g must not be negative", cfg.CostBudget))
	}
	if cfg.CostBudget > 0 && cfg.CostPer1KTokens <= 0 {
		problems = append(problems, "cost_budget requires cost_per_1k_tokens to be set (there's no rate to price tokens at otherwise)")
	}
	if cfg.MaxBodyBytes < 0 {
		problems = append(problems, fmt.Sprintf("max_body_size_bytes: %d must not be negative", cfg.MaxBodyBytes))
	}
	if cfg.CacheTTLSeconds < 0 {
		problems = append(problems, fmt.Sprintf("cache_ttl_seconds: %d must not be negative", cfg.CacheTTLSeconds))
	}
	if cfg.CacheTTLSeconds > 0 && !cfg.CacheEnabled {
		problems = append(problems, "cache_ttl_seconds requires cache_enabled to be set (there's nothing to expire otherwise)")
	}
	if cfg.CacheMaxSizeBytes < 0 {
		problems = append(problems, fmt.Sprintf("cache_max_size_bytes: %d must not be negative", cfg.CacheMaxSizeBytes))
	}
	if cfg.CacheMaxSizeBytes > 0 && !cfg.CacheEnabled {
		problems = append(problems, "cache_max_size_bytes requires cache_enabled to be set (there's nothing to cap otherwise)")
	}
	if cfg.WebhookURL != "" {
		if _, err := parseWebhookURL(cfg.WebhookURL); err != nil {
			problems = append(problems, fmt.Sprintf("webhook_url: %v", err))
		}
	}
	_, webhookErrs := compileWebhookTargets(cfg.Webhooks)
	for _, e := range webhookErrs {
		problems = append(problems, e.Error())
	}
	_, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys, cfg.CostPer1KTokens)
	for _, e := range proxyKeyErrs {
		problems = append(problems, e.Error())
	}
	if cfg.LogFile != "" {
		if f, err := openLogFile(cfg.LogFile); err != nil {
			problems = append(problems, err.Error())
		} else {
			f.Close()
		}
	}

	if len(problems) > 0 {
		fmt.Fprintf(stderr, "aiproxy: %s has %d problem(s):\n", loadedFrom, len(problems))
		for _, p := range problems {
			fmt.Fprintf(stderr, "  - %s\n", p)
		}
		return 1
	}

	fmt.Fprintf(stdout, "%s is valid.\n", loadedFrom)
	fmt.Fprintf(stdout, "  custom rules:            %d\n", len(cfg.CustomRules))
	fmt.Fprintf(stdout, "  target routes:           %d\n", len(cfg.Targets))
	fmt.Fprintf(stdout, "  routes with failover:    %d\n", countFailoverTargets(cfg))
	fmt.Fprintf(stdout, "  model routes:            %d\n", len(cfg.ModelRoutes))
	fmt.Fprintf(stdout, "  max requests per minute: %d\n", cfg.MaxRequestsPerMinute)
	fmt.Fprintf(stdout, "  max tokens per minute:   %d\n", cfg.MaxTokensPerMinute)
	fmt.Fprintf(stdout, "  max requests/min per IP: %d\n", cfg.MaxRequestsPerMinutePerIP)
	fmt.Fprintf(stdout, "  cache enabled:           %v\n", cfg.CacheEnabled)
	fmt.Fprintf(stdout, "  cache ttl:               %s\n", cacheTTLDisplay(cfg.CacheTTLSeconds))
	fmt.Fprintf(stdout, "  cache max size:          %s\n", cacheMaxSizeDisplay(cfg.CacheMaxSizeBytes))
	fmt.Fprintf(stdout, "  per-target cache overrides: %d\n", countCacheOverrides(cfg))
	fmt.Fprintf(stdout, "  cost per 1K tokens:      %g\n", cfg.CostPer1KTokens)
	fmt.Fprintf(stdout, "  cost budget:             %g\n", cfg.CostBudget)
	fmt.Fprintf(stdout, "  built-in rule overrides: %d\n", len(cfg.BuiltinRuleActions))
	fmt.Fprintf(stdout, "  max request body size:   %d bytes\n", effectiveMaxBodyBytes(cfg.MaxBodyBytes))
	fmt.Fprintf(stdout, "  webhook alerts:          %v\n", cfg.WebhookURL != "")
	fmt.Fprintf(stdout, "  additional webhooks:     %d\n", len(cfg.Webhooks))
	fmt.Fprintf(stdout, "  path rules:              %d\n", len(cfg.PathRules))
	fmt.Fprintf(stdout, "  rules in dry-run:        %d\n", countDryRunRules(cfg))
	fmt.Fprintf(stdout, "  proxy authentication:    %v\n", cfg.ProxyAPIKey != "")
	fmt.Fprintf(stdout, "  additional proxy keys:   %d\n", len(cfg.ProxyAPIKeys))
	fmt.Fprintf(stdout, "  IP allow list entries:   %d\n", len(cfg.IPAllowList))
	fmt.Fprintf(stdout, "  IP deny list entries:    %d\n", len(cfg.IPDenyList))
	fmt.Fprintf(stdout, "  GeoIP ranges file:       %s\n", geoIPRangesFileDisplay(cfg.GeoIPRangesFile))
	fmt.Fprintf(stdout, "  country allow list:      %d\n", len(cfg.CountryAllowList))
	fmt.Fprintf(stdout, "  country deny list:       %d\n", len(cfg.CountryDenyList))
	fmt.Fprintf(stdout, "  anomaly detection:       %s\n", anomalyDisplay(cfg.AnomalyMultiplier, cfg.AnomalyDryRun))
	fmt.Fprintf(stdout, "  upstream response timeout: %s\n", timeoutDisplay(cfg.UpstreamResponseTimeoutSeconds))
	fmt.Fprintf(stdout, "  upstream total timeout:    %s\n", timeoutDisplay(cfg.UpstreamTotalTimeoutSeconds))
	fmt.Fprintf(stdout, "  target ejection:         %s\n", targetEjectionDisplay(cfg.TargetEjectionThreshold, cfg.TargetEjectionCooldownSeconds))
	fmt.Fprintf(stdout, "  CORS:                    %s\n", corsDisplay(cfg.CORSAllowedOrigins))
	fmt.Fprintf(stdout, "  target health checks:    %s\n", targetHealthCheckDisplay(cfg.TargetHealthCheckIntervalSeconds, cfg.TargetHealthCheckPath))
	fmt.Fprintf(stdout, "  log file:                %s\n", logFileDisplay(cfg.LogFile))
	return 0
}

// targetHealthCheckDisplay renders target_health_check_interval_seconds/
// target_health_check_path for the validate summary.
func targetHealthCheckDisplay(intervalSeconds int, path string) string {
	if intervalSeconds <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("every %s%s", (time.Duration(intervalSeconds) * time.Second).String(), healthCheckPathDisplay(path))
}

// corsDisplay renders cors_allowed_origins for the validate summary.
func corsDisplay(origins []string) string {
	if len(origins) == 0 {
		return "disabled"
	}
	return strings.Join(origins, ", ")
}

// targetEjectionDisplay renders target_ejection_threshold/
// target_ejection_cooldown_seconds for the validate summary.
func targetEjectionDisplay(threshold, cooldownSeconds int) string {
	if threshold <= 0 {
		return "disabled"
	}
	return fmt.Sprintf("after %d consecutive failures, %ds cooldown", threshold, cooldownSeconds)
}

// healthCheckPathDisplay renders target_health_check_path as a
// trailing " (probing <path>)" clause, or "" when it's unset — a
// health check probes each candidate's own configured URL unchanged
// in that case, so there's nothing distinct worth naming.
func healthCheckPathDisplay(path string) string {
	if path == "" {
		return ""
	}
	return fmt.Sprintf(" (probing %s)", path)
}

// timeoutDisplay renders an upstream_response_timeout_seconds/
// upstream_total_timeout_seconds value for the validate summary:
// "unlimited" for the default/absent zero, otherwise the resolved
// duration in the same shape a user would type it back in.
func timeoutDisplay(seconds int) string {
	if seconds <= 0 {
		return "unlimited"
	}
	return (time.Duration(seconds) * time.Second).String()
}

// geoIPRangesFileDisplay renders geoip_ranges_file for the validate
// summary — a file path isn't a secret, same reasoning as
// logFileDisplay, so it's shown in full rather than masked.
func geoIPRangesFileDisplay(path string) string {
	if path == "" {
		return "disabled"
	}
	return path
}

// anomalyDisplay renders anomaly_multiplier/anomaly_dry_run for the
// validate summary.
func anomalyDisplay(multiplier float64, dryRun bool) string {
	if multiplier <= 0 {
		return "disabled"
	}
	if dryRun {
		return fmt.Sprintf("%gx baseline (dry-run)", multiplier)
	}
	return fmt.Sprintf("%gx baseline", multiplier)
}

// runVerifyLog checks that an audit-signed log file's HMAC chain is
// intact end to end: every line's hash matches its content and the
// line before it, exactly what Chain.Wrap computed when aiproxy wrote
// it with the same key (-audit-log-key-file at `aiproxy start`). It
// takes no -config: verifying a log file has nothing to do with
// whichever config produced it, only the key it was signed with.
func runVerifyLog(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-log", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("audit-log-key-file", "", "path to the same key file passed to `aiproxy start -audit-log-key-file` when the log was written (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: aiproxy verify-log -audit-log-key-file <path> <log-file>")
		return 2
	}
	if *keyFile == "" {
		fmt.Fprintln(stderr, "aiproxy: -audit-log-key-file is required")
		return 2
	}

	key, err := auditlog.ReadKeyFile(*keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}

	path := fs.Arg(0)
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}
	defer f.Close()

	result, err := auditlog.Verify(f, key)
	if err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}
	if result.Broken != 0 {
		fmt.Fprintf(stderr, "aiproxy: %s: chain broken at line %d: %v\n", path, result.Broken, result.Err)
		fmt.Fprintf(stderr, "  %d line(s) before it verified OK\n", result.Broken-1)
		return 1
	}
	fmt.Fprintf(stdout, "%s: OK — %d chained line(s) verified\n", path, result.Lines)
	return 0
}

// logFileDisplay renders log_file for the validate summary — unlike
// webhook_url and proxy_api_key, a file path isn't a secret, so it's
// shown in full rather than masked to a bare true/false.
func logFileDisplay(path string) string {
	if path == "" {
		return "disabled"
	}
	return path
}

// cacheTTLDisplay renders cache_ttl_seconds for the validate summary —
// not a secret like webhook_url/proxy_api_key, so shown in full.
func cacheTTLDisplay(seconds int) string {
	if seconds <= 0 {
		return "none (entries never expire on their own)"
	}
	return fmt.Sprintf("%ds", seconds)
}

// countCacheOverrides counts how many distinct targets/model_routes set
// their own cache_enabled and/or cache_ttl_seconds, for the validate
// summary — mirrors exactly how buildLiveConfig itself decides which
// labels get an entry in Server.TargetCacheTTL/TargetCacheEnabled.
func countCacheOverrides(cfg *config.Config) int {
	n := 0
	for _, t := range cfg.Targets {
		if t.CacheEnabled != nil || t.CacheTTLSeconds > 0 {
			n++
		}
	}
	for _, r := range cfg.ModelRoutes {
		if r.CacheEnabled != nil || r.CacheTTLSeconds > 0 {
			n++
		}
	}
	return n
}

// cacheMaxSizeDisplay renders cache_max_size_bytes for the validate
// summary, same reasoning as cacheTTLDisplay.
func cacheMaxSizeDisplay(bytes int64) string {
	if bytes <= 0 {
		return "unbounded"
	}
	return fmt.Sprintf("%d bytes", bytes)
}

// countFailoverTargets counts every targets entry configured with more
// than one urls candidate — a single-URL target (whether via url or a
// one-element urls) has nothing to fail over to.
func countFailoverTargets(cfg *config.Config) int {
	n := 0
	for _, t := range cfg.Targets {
		if len(t.URLs) > 1 {
			n++
		}
	}
	return n
}

// countDryRunRules counts every custom_rules and path_rules entry with
// dry_run set — rules that are actively configured but not actually
// enforcing anything yet.
func countDryRunRules(cfg *config.Config) int {
	n := 0
	for _, cr := range cfg.CustomRules {
		if cr.DryRun {
			n++
		}
	}
	for _, r := range cfg.PathRules {
		if r.DryRun {
			n++
		}
	}
	return n
}

// effectiveMaxBodyBytes reports what max_body_size_bytes actually
// resolves to once the proxy applies its own zero-or-negative fallback
// (proxy.DefaultMaxBodyBytes) — used so "aiproxy validate" reports the
// real limit that would apply, not just the raw, possibly-absent config
// value.
func effectiveMaxBodyBytes(configured int64) int64 {
	if configured <= 0 {
		return proxy.DefaultMaxBodyBytes
	}
	return configured
}

// resolveConfig resolves the config file to use (either the explicit
// --config path, or the default aiproxy.json in the working directory)
// and loads it.
//
// When --config is not given and aiproxy.json simply isn't present, that
// is not an error: it just means nothing is configured, and a nil Config
// is returned. An explicitly requested --config path that is missing or
// invalid is a hard error.
func resolveConfig(configPath string) (*config.Config, string, error) {
	explicit := configPath != ""
	if !explicit {
		configPath = defaultConfigPath
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("loading config: %w", err)
	}
	return cfg, configPath, nil
}

// compileCustomRules compiles each custom_rules entry from the config
// file into a BodyRegexRule. Compilation happens once here, at startup,
// never per request. Unlike the trusted, hardcoded built-in patterns
// (compiled with regexp.MustCompile), a custom pattern comes from a file
// a user can mistype, so compilation failures are collected and returned
// rather than panicking — it's up to the caller whether that's fatal
// (runStart) or just a reported problem (runValidate). validTargets and
// validKeys (see validTargetLabels/validKeyLabels) are the complete set
// of target/key labels this config actually resolves requests to —
// every entry in a rule's own Targets/Keys must be one of them, the same
// "reject an unrecognized name rather than silently compiling a rule
// that never matches" rigor resolveBuiltinRuleActions already applies to
// builtin_rule_actions.
func compileCustomRules(customRules []config.CustomRule, validTargets, validKeys map[string]bool) ([]rules.BodyRegexRule, []error) {
	compiled := make([]rules.BodyRegexRule, 0, len(customRules))
	var errs []error
	for _, cr := range customRules {
		pattern, err := regexp.Compile(cr.Pattern)
		if err != nil {
			errs = append(errs, fmt.Errorf("Fatal error: Invalid regex pattern in custom rule %s: %w", cr.Name, err))
			continue
		}

		action, err := parseRuleAction(cr.Action)
		if err != nil {
			errs = append(errs, fmt.Errorf("Fatal error: Invalid action in custom rule %s: %w", cr.Name, err))
			continue
		}

		invalid := false
		for _, t := range cr.Targets {
			if !validTargets[t] {
				errs = append(errs, fmt.Errorf("Fatal error: custom rule %s: targets: %q is not a known target (valid: \"default\", a configured targets[].prefix, or \"model:<name>\" for a configured model_routes[] entry)", cr.Name, t))
				invalid = true
			}
		}
		for _, k := range cr.Keys {
			if !validKeys[k] {
				errs = append(errs, fmt.Errorf("Fatal error: custom rule %s: keys: %q is not a known proxy key (valid: \"default\" when proxy_api_key is set, or a configured proxy_api_keys[].name)", cr.Name, k))
				invalid = true
			}
		}
		if invalid {
			continue
		}

		compiled = append(compiled, rules.BodyRegexRule{
			Name:    cr.Name,
			Pattern: pattern,
			Action:  action,
			DryRun:  cr.DryRun,
			Targets: cr.Targets,
			Keys:    cr.Keys,
		})
	}
	return compiled, errs
}

// validTargetLabels returns every target label a custom_rules entry's
// Targets field may reference — the exact labels resolveRoute and
// resolveModelRoute attach to a request for stats/logs/Prometheus (see
// proxy.Server.resolveRoute): "default" for the fallback --target
// (always valid, since a default target always exists), each configured
// targets[] entry's own Prefix, and "model:<name>" for each configured
// model_routes[] entry.
func validTargetLabels(cfg *config.Config) map[string]bool {
	labels := map[string]bool{"default": true}
	if cfg == nil {
		return labels
	}
	for _, t := range cfg.Targets {
		labels[t.Prefix] = true
	}
	for _, r := range cfg.ModelRoutes {
		labels["model:"+r.Name] = true
	}
	return labels
}

// validKeyLabels returns every key label a custom_rules entry's Keys
// field may reference — the exact labels checkProxyAuth attaches to a
// request (see proxy.clientAuth.label): "default" for the anonymous
// top-level proxy_api_key (only when it's actually set — there's no
// "default" caller to scope to otherwise) and each configured
// proxy_api_keys[] entry's own Name.
func validKeyLabels(cfg *config.Config) map[string]bool {
	labels := make(map[string]bool)
	if cfg == nil {
		return labels
	}
	if cfg.ProxyAPIKey != "" {
		labels["default"] = true
	}
	for _, k := range cfg.ProxyAPIKeys {
		labels[k.Name] = true
	}
	return labels
}

// parseRuleAction parses a custom_rules entry's action field: "" (absent)
// and "block" both mean rules.Block, the long-standing default; "redact"
// means rules.Redact. Anything else is a config mistake.
func parseRuleAction(raw string) (rules.Action, error) {
	switch raw {
	case "", "block":
		return rules.Block, nil
	case "redact":
		return rules.Redact, nil
	default:
		return 0, fmt.Errorf("must be \"block\" or \"redact\", got %q", raw)
	}
}

// parseTarget validates the --target flag and normalizes it to an HTTPS
// URL the proxy can forward to.
func parseTarget(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("-target is required")
	}
	u, err := parseHTTPSURL(raw)
	if err != nil {
		return nil, fmt.Errorf("-target %w", err)
	}
	return u, nil
}

// parseHTTPSURL validates raw as an upstream URL: defaulting to https
// when no scheme is given, and requiring the result to use https with a
// host. Shared by parseTarget (the --target flag) and
// compileTargetRoutes (each entry in the config file's targets list).
func parseHTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("is not a valid URL: %w", err)
	}
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("must use https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("must include a host")
	}
	return u, nil
}

// parseWebhookURL validates the config file's webhook_url: unlike
// parseHTTPSURL (used for --target and targets[].url, which always
// reach a real upstream API and so are always required to be https),
// this accepts plain http too — a webhook alert only ever carries a
// method/url/rule name, never a secret, and a common real use is a local
// or internal-network receiver (a dev script, an internal relay) with no
// TLS in front of it at all.
func parseWebhookURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("must include a host")
	}
	return u, nil
}

// webhookEventNames is the full set of event names a webhook can ever be
// notified with — see proxy.notifyWebhook, notifyBudgetWebhook, and
// notifyFailoverWebhook — used to validate a webhooks[].events entry in
// the config file. Kept here, next to parseWebhookURL, rather than in
// the proxy package: this is purely a config-validation concern, and the
// proxy package never needs to enumerate its own event names back to
// itself.
var webhookEventNames = map[string]bool{
	"block":                   true,
	"redact":                  true,
	"rate_limited":            true,
	"token_rate_limited":      true,
	"unauthorized":            true,
	"response_block":          true,
	"response_redact":         true,
	"dry_run_block":           true,
	"dry_run_redact":          true,
	"response_dry_run_block":  true,
	"response_dry_run_redact": true,
	"budget_exceeded":         true,
	"failover":                true,
	"ip_denied":               true,
	"country_denied":          true,
	"anomaly_detected":        true,
	"target_ejected":          true,
	"target_recovered":        true,
	"config_changed":          true,
}

// compileWebhookTargets validates and resolves the config file's
// webhooks list into proxy.WebhookTarget values, ready for
// Server.Webhooks. Every entry's url is validated the same way
// webhook_url is (parseWebhookURL); every name in an entry's events, if
// given, must be a recognized event name — same discipline as
// builtin_rule_actions rejecting an unrecognized rule name, so a typo'd
// event name fails validation instead of silently never matching
// anything. Problems from every entry are collected together, same
// pattern as every other compile* helper in this file.
func compileWebhookTargets(targets []config.WebhookTarget) ([]proxy.WebhookTarget, []error) {
	var errs []error
	compiled := make([]proxy.WebhookTarget, 0, len(targets))
	for i, t := range targets {
		u, err := parseWebhookURL(t.URL)
		if err != nil {
			errs = append(errs, fmt.Errorf("webhooks[%d].url: %w", i, err))
			continue
		}
		for _, event := range t.Events {
			if !webhookEventNames[event] {
				errs = append(errs, fmt.Errorf("webhooks[%d].events: %q is not a recognized event name", i, event))
			}
		}
		compiled = append(compiled, proxy.WebhookTarget{URL: u, Events: t.Events})
	}
	return compiled, errs
}

// targetRoute is one compiled entry from the config file's targets list,
// ready to be added to a proxy.Server via AddRoute. targets is always
// non-empty; more than one entry means the route fails over across them
// in the configured order (see proxy.Server's failoverTransport).
// limiter is nil unless the entry set its own max_requests_per_minute
// override.
type targetRoute struct {
	prefix               string
	targets              []*url.URL
	weights              []int
	maxRequestsPerMinute int
	limiter              *limiter.Limiter
	maxTokensPerMinute   int
	tokenLimiter         *limiter.TokenLimiter
	costPer1KTokens      float64
	cacheEnabled         *bool
	cacheTTLSeconds      int
}

// formatTargetsForDisplay renders a targetRoute's candidate list for the
// startup notice: just the one URL for the overwhelmingly common
// single-candidate case (identical to the plain %s output before
// failover existed), or the full ordered chain, joined by " -> ", when
// there's more than one.
func formatTargetsForDisplay(targets []*url.URL) string {
	if len(targets) == 1 {
		return targets[0].String()
	}
	strs := make([]string, len(targets))
	for i, u := range targets {
		strs[i] = u.String()
	}
	return strings.Join(strs, " -> ")
}

// formatWeightedTargetsForDisplay is formatTargetsForDisplay's
// counterpart for a weighted route — used instead whenever weights is
// non-nil, showing each candidate's own configured share rather than
// the " -> " failover-chain arrow, since a weighted split isn't an
// ordered fallback chain the way a plain multi-candidate route is.
func formatWeightedTargetsForDisplay(targets []*url.URL, weights []int) string {
	strs := make([]string, len(targets))
	for i, u := range targets {
		strs[i] = fmt.Sprintf("%s (%d)", u.String(), weights[i])
	}
	return strings.Join(strs, " | ")
}

// formatRateLimitsForDisplay renders a route/model route's own
// request-count and token-based rate limit overrides, if any, for the
// startup notice — "%d requests/minute", "%d tokens/minute", or both
// joined with ", " when the entry sets both independently. Returns ""
// when neither is set, so the caller can fall back to printing no
// "(rate limit: ...)" suffix at all, same as before token-based limits
// existed.
func formatRateLimitsForDisplay(maxRequestsPerMinute, maxTokensPerMinute int) string {
	var parts []string
	if maxRequestsPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d requests/minute", maxRequestsPerMinute))
	}
	if maxTokensPerMinute > 0 {
		parts = append(parts, fmt.Sprintf("%d tokens/minute", maxTokensPerMinute))
	}
	return strings.Join(parts, ", ")
}

// formatIPNets renders a compiled IP allow/deny list for the startup
// notice and the validate summary.
func formatIPNets(nets []*net.IPNet) []string {
	strs := make([]string, len(nets))
	for i, n := range nets {
		strs[i] = n.String()
	}
	return strs
}

// compileTargetRoutes validates and parses each targets entry from the
// config file. A prefix must be non-empty, start with "/", and be
// distinct from every other entry's prefix; each entry's URL(s) must
// pass the same https validation as --target (see compileTargetURLs);
// max_requests_per_minute, if set, must not be negative. Problems are
// collected and returned rather than stopping at the first one — the
// caller decides whether that's fatal (runStart) or just a reported
// problem (runValidate).
func compileTargetRoutes(targets []config.Target, globalCacheEnabled bool) ([]targetRoute, []error) {
	compiled := make([]targetRoute, 0, len(targets))
	var errs []error
	seenPrefixes := make(map[string]bool, len(targets))
	for _, t := range targets {
		if t.Prefix == "" || !strings.HasPrefix(t.Prefix, "/") {
			errs = append(errs, fmt.Errorf("targets: prefix %q must be non-empty and start with \"/\"", t.Prefix))
			continue
		}
		if seenPrefixes[t.Prefix] {
			errs = append(errs, fmt.Errorf("targets: duplicate prefix %q (only the first entry with a given prefix is ever reachable)", t.Prefix))
			continue
		}
		seenPrefixes[t.Prefix] = true

		urls, weights, urlErrs := compileURLCandidates(fmt.Sprintf("targets: prefix %q", t.Prefix), t.URL, t.URLs, t.WeightedURLs)
		if len(urlErrs) > 0 {
			errs = append(errs, urlErrs...)
			continue
		}

		if t.MaxRequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: max_requests_per_minute %d must not be negative", t.Prefix, t.MaxRequestsPerMinute))
			continue
		}
		if t.MaxTokensPerMinute < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: max_tokens_per_minute %d must not be negative", t.Prefix, t.MaxTokensPerMinute))
			continue
		}
		if t.CostPer1KTokens < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: cost_per_1k_tokens %g must not be negative", t.Prefix, t.CostPer1KTokens))
			continue
		}
		if t.CacheTTLSeconds < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: cache_ttl_seconds %d must not be negative", t.Prefix, t.CacheTTLSeconds))
			continue
		}
		targetWantsCache := (t.CacheEnabled != nil && *t.CacheEnabled) || t.CacheTTLSeconds > 0
		if targetWantsCache && !globalCacheEnabled {
			errs = append(errs, fmt.Errorf("targets: prefix %q: cache_enabled/cache_ttl_seconds requires the top-level cache_enabled to be set (there's no cache for a target override to apply to otherwise)", t.Prefix))
			continue
		}

		tr := targetRoute{prefix: t.Prefix, targets: urls, weights: weights, maxRequestsPerMinute: t.MaxRequestsPerMinute, maxTokensPerMinute: t.MaxTokensPerMinute, costPer1KTokens: t.CostPer1KTokens, cacheEnabled: t.CacheEnabled, cacheTTLSeconds: t.CacheTTLSeconds}
		if t.MaxRequestsPerMinute > 0 {
			tr.limiter = limiter.New(t.MaxRequestsPerMinute, time.Minute)
		}
		if t.MaxTokensPerMinute > 0 {
			tr.tokenLimiter = limiter.NewTokenLimiter(t.MaxTokensPerMinute, time.Minute)
		}
		compiled = append(compiled, tr)
	}
	return compiled, errs
}

// compileURLCandidates resolves an entry's url/urls fields into an
// ordered, non-empty list of upstream URLs. Exactly one of the two must
// be set — url for a single upstream (the original, still-supported
// shape), urls for an ordered failover list — and every URL, from
// either field, must pass the same https validation as --target.
// label prefixes every error message (e.g. `targets: prefix "/foo"`,
// `model_routes: "anthropic"`) so the caller's own identity is clear
// without this helper needing to know which kind of route it's for.
// Shared by compileTargetRoutes and compileModelRoutes.
// compileURLCandidates resolves an entry's url/urls/weighted_urls
// fields into an ordered, non-empty list of upstream URLs — exactly
// one of the three must be set. weights is nil unless weighted_urls
// was the one actually set, in which case it's the same length as the
// returned URL list, weights[i] being urls[i]'s own configured Weight
// — see config.WeightedURL.
func compileURLCandidates(label, rawURL string, rawURLs []string, rawWeightedURLs []config.WeightedURL) (urls []*url.URL, weights []int, errs []error) {
	set := 0
	if rawURL != "" {
		set++
	}
	if len(rawURLs) > 0 {
		set++
	}
	if len(rawWeightedURLs) > 0 {
		set++
	}
	if set > 1 {
		return nil, nil, []error{fmt.Errorf("%s: url, urls, and weighted_urls are mutually exclusive — set exactly one", label)}
	}
	if set == 0 {
		return nil, nil, []error{fmt.Errorf("%s: must set one of url, urls, or weighted_urls", label)}
	}

	if rawURL != "" {
		u, err := parseHTTPSURL(rawURL)
		if err != nil {
			return nil, nil, []error{fmt.Errorf("%s: url %w", label, err)}
		}
		return []*url.URL{u}, nil, nil
	}

	if len(rawWeightedURLs) > 0 {
		urls := make([]*url.URL, 0, len(rawWeightedURLs))
		weights := make([]int, 0, len(rawWeightedURLs))
		var errs []error
		for i, wu := range rawWeightedURLs {
			u, err := parseHTTPSURL(wu.URL)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: weighted_urls[%d] %w", label, i, err))
				continue
			}
			if wu.Weight <= 0 {
				errs = append(errs, fmt.Errorf("%s: weighted_urls[%d]: weight %d must be positive", label, i, wu.Weight))
				continue
			}
			urls = append(urls, u)
			weights = append(weights, wu.Weight)
		}
		if len(errs) > 0 {
			return nil, nil, errs
		}
		return urls, weights, nil
	}

	urls = make([]*url.URL, 0, len(rawURLs))
	for i, raw := range rawURLs {
		u, err := parseHTTPSURL(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: urls[%d] %w", label, i, err))
			continue
		}
		urls = append(urls, u)
	}
	if len(errs) > 0 {
		return nil, nil, errs
	}
	return urls, nil, nil
}

// compileModelRoutes validates and parses each model_routes entry from
// the config file. name must be non-empty and unique; models must be a
// non-empty list of syntactically valid path.Match glob patterns, and
// no single literal pattern string may repeat across two different
// routes (a duplicate would leave the second entry unreachable for that
// exact model name, since routes are checked in order and the first
// match wins) — the same "duplicate makes an entry dead" reasoning as
// compileTargetRoutes' prefix check, just at the level of one pattern
// instead of the whole entry. url/urls and max_requests_per_minute are
// validated exactly like a targets entry. Problems are collected and
// returned rather than stopping at the first one — the caller decides
// whether that's fatal (runStart) or just a reported problem
// (runValidate).
func compileModelRoutes(routes []config.ModelRoute, globalCacheEnabled bool) ([]modelRoute, []error) {
	compiled := make([]modelRoute, 0, len(routes))
	var errs []error
	seenNames := make(map[string]bool, len(routes))
	seenPatterns := make(map[string]bool)
	for _, r := range routes {
		if r.Name == "" {
			errs = append(errs, fmt.Errorf("model_routes: name must not be empty"))
			continue
		}
		if seenNames[r.Name] {
			errs = append(errs, fmt.Errorf("model_routes: duplicate name %q (stats would merge under one label)", r.Name))
			continue
		}
		seenNames[r.Name] = true

		if len(r.Models) == 0 {
			errs = append(errs, fmt.Errorf("model_routes: %q: models must list at least one pattern", r.Name))
			continue
		}
		validPatterns := true
		for _, pattern := range r.Models {
			if pattern == "" {
				errs = append(errs, fmt.Errorf("model_routes: %q: models entries must not be empty", r.Name))
				validPatterns = false
				continue
			}
			if _, err := path.Match(pattern, ""); err != nil {
				errs = append(errs, fmt.Errorf("model_routes: %q: models: %q is not a valid glob pattern: %w", r.Name, pattern, err))
				validPatterns = false
				continue
			}
			if seenPatterns[pattern] {
				errs = append(errs, fmt.Errorf("model_routes: %q: models: pattern %q duplicates an earlier route's (it would never be reached, since the earlier route is checked first)", r.Name, pattern))
				validPatterns = false
				continue
			}
			seenPatterns[pattern] = true
		}
		if !validPatterns {
			continue
		}

		urls, weights, urlErrs := compileURLCandidates(fmt.Sprintf("model_routes: %q", r.Name), r.URL, r.URLs, r.WeightedURLs)
		if len(urlErrs) > 0 {
			errs = append(errs, urlErrs...)
			continue
		}

		if r.MaxRequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("model_routes: %q: max_requests_per_minute %d must not be negative", r.Name, r.MaxRequestsPerMinute))
			continue
		}
		if r.MaxTokensPerMinute < 0 {
			errs = append(errs, fmt.Errorf("model_routes: %q: max_tokens_per_minute %d must not be negative", r.Name, r.MaxTokensPerMinute))
			continue
		}
		if r.CostPer1KTokens < 0 {
			errs = append(errs, fmt.Errorf("model_routes: %q: cost_per_1k_tokens %g must not be negative", r.Name, r.CostPer1KTokens))
			continue
		}
		if r.CacheTTLSeconds < 0 {
			errs = append(errs, fmt.Errorf("model_routes: %q: cache_ttl_seconds %d must not be negative", r.Name, r.CacheTTLSeconds))
			continue
		}
		routeWantsCache := (r.CacheEnabled != nil && *r.CacheEnabled) || r.CacheTTLSeconds > 0
		if routeWantsCache && !globalCacheEnabled {
			errs = append(errs, fmt.Errorf("model_routes: %q: cache_enabled/cache_ttl_seconds requires the top-level cache_enabled to be set (there's no cache for a route override to apply to otherwise)", r.Name))
			continue
		}

		mr := modelRoute{name: r.Name, models: r.Models, targets: urls, weights: weights, maxRequestsPerMinute: r.MaxRequestsPerMinute, maxTokensPerMinute: r.MaxTokensPerMinute, costPer1KTokens: r.CostPer1KTokens, cacheEnabled: r.CacheEnabled, cacheTTLSeconds: r.CacheTTLSeconds}
		if r.MaxRequestsPerMinute > 0 {
			mr.limiter = limiter.New(r.MaxRequestsPerMinute, time.Minute)
		}
		if r.MaxTokensPerMinute > 0 {
			mr.tokenLimiter = limiter.NewTokenLimiter(r.MaxTokensPerMinute, time.Minute)
		}
		compiled = append(compiled, mr)
	}
	return compiled, errs
}

// modelRoute is one compiled entry from the config file's model_routes
// list, ready to be added to a proxy.Server via AddModelRoute — the
// content-based-routing counterpart to targetRoute. limiter is nil
// unless the entry set its own max_requests_per_minute override.
type modelRoute struct {
	name                 string
	models               []string
	targets              []*url.URL
	weights              []int
	maxRequestsPerMinute int
	limiter              *limiter.Limiter
	maxTokensPerMinute   int
	tokenLimiter         *limiter.TokenLimiter
	costPer1KTokens      float64
	cacheEnabled         *bool
	cacheTTLSeconds      int
}

// compileProxyAPIKeys validates and resolves the config file's
// proxy_api_keys list into proxy.ProxyKey values, ready for
// Server.ProxyAPIKeys — same shape and rigor as compileTargetRoutes:
// every entry needs a non-empty, unique name (it's the stats/log
// attribution label, so a collision would silently merge two different
// callers' numbers together — "default" is reserved for the anonymous
// top-level proxy_api_key, so it's rejected here too) and a non-empty,
// unique key; max_requests_per_minute, if set, must not be negative and
// compiles into that key's own dedicated limiter, checked instead of
// whatever route/global limiter would otherwise apply for that caller.
func compileProxyAPIKeys(entries []config.ProxyAPIKeyEntry, costPer1KTokens float64) ([]proxy.ProxyKey, []error) {
	compiled := make([]proxy.ProxyKey, 0, len(entries))
	var errs []error
	seenNames := make(map[string]bool, len(entries))
	seenKeys := make(map[string]bool, len(entries))
	for _, e := range entries {
		if e.Name == "" {
			errs = append(errs, fmt.Errorf("proxy_api_keys: name must not be empty"))
			continue
		}
		if e.Name == "default" {
			errs = append(errs, fmt.Errorf("proxy_api_keys: name %q is reserved for the anonymous top-level proxy_api_key", e.Name))
			continue
		}
		if seenNames[e.Name] {
			errs = append(errs, fmt.Errorf("proxy_api_keys: duplicate name %q (stats would merge under one label)", e.Name))
			continue
		}
		seenNames[e.Name] = true

		if e.Key == "" {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: key must not be empty", e.Name))
			continue
		}
		if seenKeys[e.Key] {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: key duplicates an earlier entry's (whichever is checked first would silently claim every request)", e.Name))
			continue
		}
		seenKeys[e.Key] = true

		if e.MaxRequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: max_requests_per_minute %d must not be negative", e.Name, e.MaxRequestsPerMinute))
			continue
		}
		if e.MaxTokensPerMinute < 0 {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: max_tokens_per_minute %d must not be negative", e.Name, e.MaxTokensPerMinute))
			continue
		}

		if e.CostBudget < 0 {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: cost_budget %g must not be negative", e.Name, e.CostBudget))
			continue
		}
		if e.CostBudget > 0 && costPer1KTokens <= 0 {
			errs = append(errs, fmt.Errorf("proxy_api_keys: %q: cost_budget requires the top-level cost_per_1k_tokens to be set (there's no rate to price tokens at otherwise)", e.Name))
			continue
		}

		pk := proxy.ProxyKey{Name: e.Name, Key: e.Key, CostBudget: e.CostBudget}
		if e.MaxRequestsPerMinute > 0 {
			pk.Limiter = limiter.New(e.MaxRequestsPerMinute, time.Minute)
		}
		if e.MaxTokensPerMinute > 0 {
			pk.TokenLimiter = limiter.NewTokenLimiter(e.MaxTokensPerMinute, time.Minute)
		}
		compiled = append(compiled, pk)
	}
	return compiled, errs
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aiproxy <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  start        start the proxy server")
	fmt.Fprintln(w, "  validate     check a config file for problems without starting the proxy")
	fmt.Fprintln(w, "  verify-log   verify an audit-signed log file's HMAC chain is intact")
	fmt.Fprintln(w, "  help         show this help text")
}
