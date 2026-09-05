// Package config reads aiproxy's on-disk JSON configuration. It only
// turns a config file into plain Go structs using the standard library's
// encoding/json — it knows nothing about regexes, rules, or the proxy,
// so it stays testable and reusable independently of how its data ends
// up being used.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// CustomRule is one user-defined rule as it appears in the config file,
// before its pattern has been compiled.
type CustomRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}

// Config is the top-level shape of aiproxy.json.
type Config struct {
	CustomRules []CustomRule `json:"custom_rules"`

	// MaxRequestsPerMinute caps how many requests the proxy's circuit
	// breaker allows per minute. Zero (the default when the field is
	// absent) means the rate limiter is disabled.
	MaxRequestsPerMinute int `json:"max_requests_per_minute"`

	// CacheEnabled turns on the proxy's local on-disk response cache.
	// False (the default when the field is absent) means the cache is
	// disabled.
	CacheEnabled bool `json:"cache_enabled"`
}

// Load reads and parses the config file at path. If the file does not
// exist, the returned error satisfies os.IsNotExist so callers can treat
// a missing config file as "nothing configured" rather than fatal.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return &cfg, nil
}
