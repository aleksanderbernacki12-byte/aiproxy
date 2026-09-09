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
	server.CostBudget = lc.costBudget
	server.MaxBodyBytes = lc.maxBodyBytes
	server.WebhookURL = lc.webhookURL
	server.Webhooks = lc.webhooks
	server.ProxyAPIKey = lc.proxyAPIKey
	server.ProxyAPIKeys = lc.proxyAPIKeys
	server.LogFile = lc.logFile
	for _, r := range lc.routes {
		server.AddRoute(r.prefix, r.targets, r.limiter)
	}

	if cfg != nil {
		if len(cfg.CustomRules) > 0 {
			fmt.Fprintf(stdout, "loaded %d custom rule(s) from %s\n", len(cfg.CustomRules), loadedFrom)
		}
		for _, cr := range cfg.CustomRules {
			if cr.DryRun {
				fmt.Fprintf(stdout, "custom rule: %s (dry-run — logged, never enforced)\n", cr.Name)
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
		if cfg.CacheEnabled {
			if cfg.CacheTTLSeconds > 0 {
				fmt.Fprintf(stdout, "response cache: enabled (%s/, ttl %ds)\n", cache.DirName, cfg.CacheTTLSeconds)
			} else {
				fmt.Fprintf(stdout, "response cache: enabled (%s/, no ttl)\n", cache.DirName)
			}
		}
		if cfg.CostPer1KTokens > 0 {
			fmt.Fprintf(stdout, "cost estimation: %g per 1K tokens\n", cfg.CostPer1KTokens)
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
			fmt.Fprintln(stdout, "webhook alerts: enabled (on block/redact/rate_limited/unauthorized/dry-run/budget_exceeded)")
		}
		if len(lc.webhooks) > 0 {
			// Same discipline as the webhook_url notice above: counts
			// only, never the destination URLs themselves.
			fmt.Fprintf(stdout, "additional webhook destinations: %d (event-filtered)\n", len(lc.webhooks))
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
		for _, r := range lc.routes {
			dest := formatTargetsForDisplay(r.targets)
			if r.maxRequestsPerMinute > 0 {
				fmt.Fprintf(stdout, "route: %s -> %s (rate limit: %d requests/minute)\n", r.prefix, dest, r.maxRequestsPerMinute)
			} else {
				fmt.Fprintf(stdout, "route: %s -> %s\n", r.prefix, dest)
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
		return
	}

	routes := make([]proxy.Route, len(lc.routes))
	for i, r := range lc.routes {
		routes[i] = proxy.Route{Prefix: r.prefix, Targets: r.targets, Limiter: r.limiter}
	}
	server.ReloadConfig(lc.engine, lc.limiter, lc.cache, lc.cost, lc.costBudget, lc.maxBodyBytes, lc.webhookURL, lc.webhooks, lc.proxyAPIKey, lc.proxyAPIKeys, lc.logFile, routes)

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
	engine       *rules.Engine
	limiter      *limiter.Limiter
	cache        *cache.Cache
	cost         float64
	costBudget   float64
	maxBodyBytes int64
	webhookURL   *url.URL
	webhooks     []proxy.WebhookTarget
	proxyAPIKey  string
	proxyAPIKeys []proxy.ProxyKey
	logFile      *os.File
	routes       []targetRoute
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
			c.TTL = time.Duration(cfg.CacheTTLSeconds) * time.Second
			lc.cache = c
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

	proxyAPIKeys, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys)
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

	routes, routeErrs := compileTargetRoutes(cfg.Targets)
	errs = append(errs, routeErrs...)
	lc.routes = routes

	return lc, errs
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

	customRules, cErrs := compileCustomRules(cfg.CustomRules)
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
	if cfg.WebhookURL != "" {
		if _, err := parseWebhookURL(cfg.WebhookURL); err != nil {
			problems = append(problems, fmt.Sprintf("webhook_url: %v", err))
		}
	}
	_, webhookErrs := compileWebhookTargets(cfg.Webhooks)
	for _, e := range webhookErrs {
		problems = append(problems, e.Error())
	}
	_, proxyKeyErrs := compileProxyAPIKeys(cfg.ProxyAPIKeys)
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
	fmt.Fprintf(stdout, "  max requests per minute: %d\n", cfg.MaxRequestsPerMinute)
	fmt.Fprintf(stdout, "  cache enabled:           %v\n", cfg.CacheEnabled)
	fmt.Fprintf(stdout, "  cache ttl:               %s\n", cacheTTLDisplay(cfg.CacheTTLSeconds))
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
	fmt.Fprintf(stdout, "  log file:                %s\n", logFileDisplay(cfg.LogFile))
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
			DryRun:  cr.DryRun,
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
	"unauthorized":            true,
	"response_block":          true,
	"response_redact":         true,
	"dry_run_block":           true,
	"dry_run_redact":          true,
	"response_dry_run_block":  true,
	"response_dry_run_redact": true,
	"budget_exceeded":         true,
	"failover":                true,
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
	maxRequestsPerMinute int
	limiter              *limiter.Limiter
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

// compileTargetRoutes validates and parses each targets entry from the
// config file. A prefix must be non-empty, start with "/", and be
// distinct from every other entry's prefix; each entry's URL(s) must
// pass the same https validation as --target (see compileTargetURLs);
// max_requests_per_minute, if set, must not be negative. Problems are
// collected and returned rather than stopping at the first one — the
// caller decides whether that's fatal (runStart) or just a reported
// problem (runValidate).
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

		urls, urlErrs := compileTargetURLs(t.Prefix, t)
		if len(urlErrs) > 0 {
			errs = append(errs, urlErrs...)
			continue
		}

		if t.MaxRequestsPerMinute < 0 {
			errs = append(errs, fmt.Errorf("targets: prefix %q: max_requests_per_minute %d must not be negative", t.Prefix, t.MaxRequestsPerMinute))
			continue
		}

		tr := targetRoute{prefix: t.Prefix, targets: urls, maxRequestsPerMinute: t.MaxRequestsPerMinute}
		if t.MaxRequestsPerMinute > 0 {
			tr.limiter = limiter.New(t.MaxRequestsPerMinute, time.Minute)
		}
		compiled = append(compiled, tr)
	}
	return compiled, errs
}

// compileTargetURLs resolves one targets entry's url/urls fields into an
// ordered, non-empty list of upstream URLs. Exactly one of the two must
// be set — url for a single upstream (the original, still-supported
// shape), urls for an ordered failover list — and every URL, from
// either field, must pass the same https validation as --target.
func compileTargetURLs(prefix string, t config.Target) ([]*url.URL, []error) {
	if t.URL != "" && len(t.URLs) > 0 {
		return nil, []error{fmt.Errorf("targets: prefix %q: url and urls are mutually exclusive — set exactly one", prefix)}
	}
	if t.URL == "" && len(t.URLs) == 0 {
		return nil, []error{fmt.Errorf("targets: prefix %q: must set one of url or urls", prefix)}
	}

	if t.URL != "" {
		u, err := parseHTTPSURL(t.URL)
		if err != nil {
			return nil, []error{fmt.Errorf("targets: prefix %q: url %w", prefix, err)}
		}
		return []*url.URL{u}, nil
	}

	urls := make([]*url.URL, 0, len(t.URLs))
	var errs []error
	for i, raw := range t.URLs {
		u, err := parseHTTPSURL(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("targets: prefix %q: urls[%d] %w", prefix, i, err))
			continue
		}
		urls = append(urls, u)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	return urls, nil
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
func compileProxyAPIKeys(entries []config.ProxyAPIKeyEntry) ([]proxy.ProxyKey, []error) {
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

		pk := proxy.ProxyKey{Name: e.Name, Key: e.Key}
		if e.MaxRequestsPerMinute > 0 {
			pk.Limiter = limiter.New(e.MaxRequestsPerMinute, time.Minute)
		}
		compiled = append(compiled, pk)
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
