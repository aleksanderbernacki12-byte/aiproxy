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
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"aiproxy/internal/cache"
	"aiproxy/internal/config"
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
	awsAccessKeyPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}`)
	openAIAPIKeyPattern = regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`)
	githubTokenPattern  = regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`)
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
	target := fs.String("target", "", "HTTPS URL to forward requests to (required)")
	configPath := fs.String("config", "", "path to a JSON config file (custom rules, rate limit, cache, cost estimation, extra target routes; default: aiproxy.json in the working directory, if present)")
	logFormat := fs.String("log-format", "text", `log output format: "text" (colored, human-readable) or "json" (one JSON object per line, safe to pipe into a log aggregator)`)
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
	server.Cache = lc.cache
	server.CostPer1KTokens = lc.cost
	for _, r := range lc.routes {
		server.AddRoute(r.prefix, r.target, r.limiter)
	}

	if cfg != nil {
		if len(cfg.CustomRules) > 0 {
			fmt.Fprintf(stdout, "loaded %d custom rule(s) from %s\n", len(cfg.CustomRules), loadedFrom)
		}
		if cfg.MaxRequestsPerMinute > 0 {
			fmt.Fprintf(stdout, "circuit breaker: %d requests/minute\n", cfg.MaxRequestsPerMinute)
		}
		if cfg.CacheEnabled {
			fmt.Fprintf(stdout, "response cache: enabled (%s/)\n", cache.DirName)
		}
		if cfg.CostPer1KTokens > 0 {
			fmt.Fprintf(stdout, "cost estimation: %g per 1K tokens\n", cfg.CostPer1KTokens)
		}
		for _, r := range lc.routes {
			if r.maxRequestsPerMinute > 0 {
				fmt.Fprintf(stdout, "route: %s -> %s (rate limit: %d requests/minute)\n", r.prefix, r.target, r.maxRequestsPerMinute)
			} else {
				fmt.Fprintf(stdout, "route: %s -> %s\n", r.prefix, r.target)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startReloadOnSIGHUP(ctx, server, *configPath)

	fmt.Fprintf(stdout, "aiproxy listening on %s, forwarding to %s\n", *addr, targetURL)
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
func startReloadOnSIGHUP(ctx context.Context, server *proxy.Server, configPath string) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	go func() {
		defer signal.Stop(hup)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				reloadConfig(server, configPath)
			}
		}
	}()
}

func reloadConfig(server *proxy.Server, configPath string) {
	cfg, loadedFrom, err := resolveConfig(configPath)
	if err != nil {
		server.LogEvent("reload_error", fmt.Sprintf("aiproxy: reload failed: %v", err))
		return
	}

	lc, errs := buildLiveConfig(cfg)
	if len(errs) > 0 {
		msgs := make([]string, len(errs))
		for i, e := range errs {
			msgs[i] = e.Error()
		}
		server.LogEvent("reload_error", fmt.Sprintf(
			"aiproxy: reload failed, keeping previous config (%d problem(s)): %s",
			len(errs), strings.Join(msgs, "; "),
		))
		return
	}

	routes := make([]proxy.Route, len(lc.routes))
	for i, r := range lc.routes {
		routes[i] = proxy.Route{Prefix: r.prefix, Target: r.target, Limiter: r.limiter}
	}
	server.ReloadConfig(lc.engine, lc.limiter, lc.cache, lc.cost, routes)

	label := loadedFrom
	if label == "" {
		label = "built-in rules only (no config file)"
	}
	server.LogEvent("reload", fmt.Sprintf("aiproxy: reloaded config from %s", label))
}

// liveConfig holds every piece of a Server's configuration that can be
// rebuilt from an aiproxy.json: everything runStart wires in at startup,
// and everything a SIGHUP reload replaces via Server.ReloadConfig.
type liveConfig struct {
	engine  *rules.Engine
	limiter *limiter.Limiter
	cache   *cache.Cache
	cost    float64
	routes  []targetRoute
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
	lc := &liveConfig{engine: engine}
	if cfg == nil {
		return lc, errs
	}

	if cfg.MaxRequestsPerMinute > 0 {
		lc.limiter = limiter.New(cfg.MaxRequestsPerMinute, time.Minute)
	}

	if cfg.CacheEnabled {
		c, err := cache.New()
		if err != nil {
			errs = append(errs, fmt.Errorf("cache: %w", err))
		} else {
			lc.cache = c
		}
	}

	lc.cost = cfg.CostPer1KTokens

	routes, routeErrs := compileTargetRoutes(cfg.Targets)
	errs = append(errs, routeErrs...)
	lc.routes = routes

	return lc, errs
}

// buildEngine constructs the rule engine used to evaluate every request:
// the three built-in secret-blocking rules, plus any custom rules from
// cfg. cfg may be nil (no config file at all), in which case only the
// built-ins apply.
func buildEngine(cfg *config.Config) (*rules.Engine, []error) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: awsAccessKeyPattern,
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: openAIAPIKeyPattern,
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "github-token",
		Pattern: githubTokenPattern,
		Action:  rules.Block,
	})
	if cfg == nil {
		return engine, nil
	}

	customRules, errs := compileCustomRules(cfg.CustomRules)
	for _, r := range customRules {
		engine.AddBodyRegexRule(r)
	}
	return engine, errs
}

// runValidate checks a config file for problems without starting the
// proxy: every custom_rules pattern must compile, every targets entry
// must have a well-formed, unique prefix and a valid https url, and the
// numeric fields must be sane. It never calls log.Fatal or otherwise
// aborts the process — reporting every problem it finds and returning a
// non-zero exit code is the whole point, as opposed to runStart, which
// treats the same problems as fatal.
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

	_, ruleErrs := compileCustomRules(cfg.CustomRules)
	for _, e := range ruleErrs {
		// compileCustomRules' errors are pre-formatted for runStart's
		// log.Fatal, which validate never calls; drop that "Fatal
		// error: " framing so the report reads as a list of problems,
		// not a list of things that supposedly just crashed.
		problems = append(problems, strings.TrimPrefix(e.Error(), "Fatal error: "))
	}

	_, routeErrs := compileTargetRoutes(cfg.Targets)
	for _, e := range routeErrs {
		problems = append(problems, e.Error())
	}

	if cfg.MaxRequestsPerMinute < 0 {
		problems = append(problems, fmt.Sprintf("max_requests_per_minute: %d must not be negative", cfg.MaxRequestsPerMinute))
	}
	if cfg.CostPer1KTokens < 0 {
		problems = append(problems, fmt.Sprintf("cost_per_1k_tokens: %g must not be negative", cfg.CostPer1KTokens))
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
	fmt.Fprintf(stdout, "  max requests per minute: %d\n", cfg.MaxRequestsPerMinute)
	fmt.Fprintf(stdout, "  cache enabled:           %v\n", cfg.CacheEnabled)
	fmt.Fprintf(stdout, "  cost per 1K tokens:      %g\n", cfg.CostPer1KTokens)
	return 0
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
// (runStart) or just a reported problem (runValidate).
func compileCustomRules(customRules []config.CustomRule) ([]rules.BodyRegexRule, []error) {
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

		compiled = append(compiled, rules.BodyRegexRule{
			Name:    cr.Name,
			Pattern: pattern,
			Action:  action,
		})
	}
	return compiled, errs
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

// targetRoute is one compiled entry from the config file's targets list,
// ready to be added to a proxy.Server via AddRoute. limiter is nil
// unless the entry set its own max_requests_per_minute override.
type targetRoute struct {
	prefix               string
	target               *url.URL
	maxRequestsPerMinute int
	limiter              *limiter.Limiter
}

// compileTargetRoutes validates and parses each targets entry from the
// config file. A prefix must be non-empty, start with "/", and be
// distinct from every other entry's prefix; a URL must pass the same
// https validation as --target; max_requests_per_minute, if set, must
// not be negative. Problems are collected and returned rather than
// stopping at the first one — the caller decides whether that's fatal
// (runStart) or just a reported problem (runValidate).
func compileTargetRoutes(targets []config.Target) ([]targetRoute, []error) {
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

		u, err := parseHTTPSURL(t.URL)
		if err != nil {
			errs = append(errs, fmt.Errorf("targets: prefix %q: url %w", t.Prefix, err))
			continue
		}

		if t.MaxRequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: max_requests_per_minute %d must not be negative", t.Prefix, t.MaxRequestsPerMinute))
			continue
		}

		tr := targetRoute{prefix: t.Prefix, target: u, maxRequestsPerMinute: t.MaxRequestsPerMinute}
		if t.MaxRequestsPerMinute > 0 {
			tr.limiter = limiter.New(t.MaxRequestsPerMinute, time.Minute)
		}
		compiled = append(compiled, tr)
	}
	return compiled, errs
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aiproxy <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  start      start the proxy server")
	fmt.Fprintln(w, "  validate   check a config file for problems without starting the proxy")
	fmt.Fprintln(w, "  help       show this help text")
}
