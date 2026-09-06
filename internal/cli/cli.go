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
	if err := fs.Parse(args); err != nil {
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

	server := proxy.New(*addr, targetURL, engine)

	if cfg != nil {
		customRules := compileCustomRules(cfg.CustomRules)
		for _, r := range customRules {
			engine.AddBodyRegexRule(r)
		}
		if len(customRules) > 0 {
			fmt.Fprintf(stdout, "loaded %d custom rule(s) from %s\n", len(customRules), loadedFrom)
		}

		if cfg.MaxRequestsPerMinute > 0 {
			server.Limiter = limiter.New(cfg.MaxRequestsPerMinute, time.Minute)
			fmt.Fprintf(stdout, "circuit breaker: %d requests/minute\n", cfg.MaxRequestsPerMinute)
		}

		if cfg.CacheEnabled {
			c, err := cache.New()
			if err != nil {
				fmt.Fprintf(stderr, "aiproxy: %v\n", err)
				return 2
			}
			server.Cache = c
			fmt.Fprintf(stdout, "response cache: enabled (%s/)\n", cache.DirName)
		}

		if cfg.CostPer1KTokens > 0 {
			server.CostPer1KTokens = cfg.CostPer1KTokens
			fmt.Fprintf(stdout, "cost estimation: %g per 1K tokens\n", cfg.CostPer1KTokens)
		}

		if len(cfg.Targets) > 0 {
			routes, err := compileTargetRoutes(cfg.Targets)
			if err != nil {
				fmt.Fprintf(stderr, "aiproxy: %v\n", err)
				return 2
			}
			for _, r := range routes {
				server.AddRoute(r.prefix, r.target)
				fmt.Fprintf(stdout, "route: %s -> %s\n", r.prefix, r.target)
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(stdout, "aiproxy listening on %s, forwarding to %s\n", *addr, targetURL)
	if err := server.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(stderr, "aiproxy: %v\n", err)
		return 1
	}
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
// a user can mistype, so a pattern that fails to compile exits the
// process via log.Fatalf with a readable message rather than panicking.
func compileCustomRules(customRules []config.CustomRule) []rules.BodyRegexRule {
	compiled := make([]rules.BodyRegexRule, 0, len(customRules))
	for _, cr := range customRules {
		pattern, err := regexp.Compile(cr.Pattern)
		if err != nil {
			log.Fatalf("Fatal error: Invalid regex pattern in custom rule %s: %v", cr.Name, err)
		}
		compiled = append(compiled, rules.BodyRegexRule{
			Name:    cr.Name,
			Pattern: pattern,
			Action:  rules.Block,
		})
	}
	return compiled
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
// ready to be added to a proxy.Server via AddRoute.
type targetRoute struct {
	prefix string
	target *url.URL
}

// compileTargetRoutes validates and parses each targets entry from the
// config file. A prefix must be non-empty and start with "/"; a URL must
// pass the same https validation as --target. Any error here is a hard
// failure — an unresolvable extra route is exactly the kind of thing
// that should stop the proxy at startup, not fail silently later on the
// first request that happens to hit it.
func compileTargetRoutes(targets []config.Target) ([]targetRoute, error) {
	compiled := make([]targetRoute, 0, len(targets))
	for _, t := range targets {
		if t.Prefix == "" || !strings.HasPrefix(t.Prefix, "/") {
			return nil, fmt.Errorf("targets: prefix %q must be non-empty and start with \"/\"", t.Prefix)
		}
		u, err := parseHTTPSURL(t.URL)
		if err != nil {
			return nil, fmt.Errorf("targets: prefix %q: url %w", t.Prefix, err)
		}
		compiled = append(compiled, targetRoute{prefix: t.Prefix, target: u})
	}
	return compiled, nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aiproxy <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  start   start the proxy server")
	fmt.Fprintln(w, "  help    show this help text")
}
