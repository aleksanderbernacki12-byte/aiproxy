package proxy

import (
	"net"
	"net/http"
	"net/url"
	"time"

	"aiproxy/internal/anomaly"
	"aiproxy/internal/breaker"
	"aiproxy/internal/cache"
	"aiproxy/internal/coalesce"
	"aiproxy/internal/geoip"
	"aiproxy/internal/idempotency"
	"aiproxy/internal/iplimiter"
	"aiproxy/internal/limiter"
	"aiproxy/internal/rules"
	"aiproxy/internal/semcache"
	"aiproxy/internal/stats"
)

// requestConfig is the configuration one proxied request uses from start
// to finish, copied from Server under a single lock by snapshot, so a
// concurrent ReloadConfig can never hand one request two configurations
// (review finding #14): the engine that evaluates the request also
// evaluates its response, and an idempotency key is completed in the
// registry it was claimed in.
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
	maxBodyBytes := s.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}
	return &requestConfig{
		engine:                 s.Engine,
		limiter:                s.Limiter,
		tokenLimiter:           s.TokenLimiter,
		cache:                  s.Cache,
		costPer1KTokens:        s.CostPer1KTokens,
		costBudget:             s.CostBudget,
		costBudgetHardStop:     s.CostBudgetHardStop,
		maxBodyBytes:           maxBodyBytes,
		maxResponseBodyBytes:   s.getMaxResponseBodyBytes(),
		proxyAPIKey:            s.ProxyAPIKey,
		proxyAPIKeys:           s.ProxyAPIKeys,
		routes:                 s.routes,
		modelRoutes:            s.modelRoutes,
		ipAllowList:            s.IPAllowList,
		ipDenyList:             s.IPDenyList,
		geoIPTable:             s.GeoIPTable,
		countryAllowList:       s.CountryAllowList,
		countryDenyList:        s.CountryDenyList,
		anomalyDetector:        s.AnomalyDetector,
		anomalyDryRun:          s.AnomalyDryRun,
		upstreamTransport:      s.UpstreamTransport,
		upstreamTotalTimeout:   s.UpstreamTotalTimeout,
		targetBreaker:          s.TargetBreaker,
		cors:                   s.CORS,
		targetCostRates:        s.TargetCostRates,
		ipLimiter:              s.IPLimiter,
		cacheTTL:               s.CacheTTL,
		targetCacheTTL:         s.TargetCacheTTL,
		targetCacheEnabled:     s.TargetCacheEnabled,
		targetShadowURL:        s.TargetShadowURL,
		targetShadowSampleRate: s.TargetShadowSampleRate,
		idempotency:            s.Idempotency,
		coalescer:              s.Coalescer,
		semanticIndex:          s.SemanticIndex,
		semanticCacheThreshold: s.SemanticCacheThreshold,
	}
}

// configFor returns the snapshot a request carries, or a fresh one for
// callers (mostly tests) that build a requestContextInfo themselves.
func (s *Server) configFor(reqCtx requestContextInfo) *requestConfig {
	if reqCtx.config != nil {
		return reqCtx.config
	}
	return s.snapshot()
}

// costRates combines costPer1KTokens and targetCostRates, so a cost can
// resolve a specific target's own rate with the default as fallback.
func (c *requestConfig) costRates() stats.CostRates {
	return stats.CostRates{Default: c.costPer1KTokens, PerTarget: c.targetCostRates}
}

// cacheEnabledForTarget reports whether target's responses may be
// cached: its own TargetCacheEnabled override if it has one, otherwise
// whether a cache exists at all. An override can only narrow, never
// enable a target when there is no cache.
func (c *requestConfig) cacheEnabledForTarget(target string) bool {
	if enabled, ok := c.targetCacheEnabled[target]; ok {
		return enabled && c.cache != nil
	}
	return c.cache != nil
}

// resolveCacheTTL returns target's own TargetCacheTTL override if it has
// one, otherwise the server-wide CacheTTL.
func (c *requestConfig) resolveCacheTTL(target string) time.Duration {
	if ttl, ok := c.targetCacheTTL[target]; ok {
		return ttl
	}
	return c.cacheTTL
}

// shadowTarget returns target's shadow destination and sample rate; ok
// is false when target has none. A shadow URL without a sample rate
// defaults to 1.0 (see config.Target.ShadowSampleRate).
func (c *requestConfig) shadowTarget(target string) (shadowURL *url.URL, sampleRate float64, ok bool) {
	u, ok := c.targetShadowURL[target]
	if !ok {
		return nil, 0, false
	}
	rate, hasRate := c.targetShadowSampleRate[target]
	if !hasRate {
		rate = 1.0
	}
	return u, rate, true
}
