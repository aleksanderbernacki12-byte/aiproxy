package cli

import (
	"strings"
	"testing"

	"aiproxy/internal/config"
)

// TestBuildLiveConfig_AdminAPIKeysCompileSeparatelyFromProxyKeys proves
// admin_api_key/admin_api_keys compile into their own liveConfig fields
// independently of proxy_api_key/proxy_api_keys — configuring both at
// once must not merge, drop, or cross-contaminate either side.
func TestBuildLiveConfig_AdminAPIKeysCompileSeparatelyFromProxyKeys(t *testing.T) {
	cfg := &config.Config{
		ProxyAPIKey:  "client-secret",
		ProxyAPIKeys: []config.ProxyAPIKeyEntry{{Name: "team-a", Key: "team-a-secret"}},
		AdminAPIKey:  "admin-secret",
		AdminAPIKeys: []config.ProxyAPIKeyEntry{{Name: "ops", Key: "ops-secret"}},
	}
	lc, errs := buildLiveConfig(cfg)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if lc.proxyAPIKey != "client-secret" {
		t.Fatalf("proxyAPIKey = %q, want %q", lc.proxyAPIKey, "client-secret")
	}
	if len(lc.proxyAPIKeys) != 1 || lc.proxyAPIKeys[0].Name != "team-a" {
		t.Fatalf("proxyAPIKeys = %+v, want one entry named 'team-a'", lc.proxyAPIKeys)
	}
	if lc.adminAPIKey != "admin-secret" {
		t.Fatalf("adminAPIKey = %q, want %q", lc.adminAPIKey, "admin-secret")
	}
	if len(lc.adminAPIKeys) != 1 || lc.adminAPIKeys[0].Name != "ops" {
		t.Fatalf("adminAPIKeys = %+v, want one entry named 'ops'", lc.adminAPIKeys)
	}
}

// TestBuildLiveConfig_RejectsAdminKeySharedWithProxyKey proves a single
// secret value can't be configured as both an ordinary client key and
// an admin key — see checkNoSharedAPIKeys. Without this check, once a
// later task wires up real admin-auth checking, any client holding
// that shared key would also reach the admin surface, silently
// reopening review finding #6.
func TestBuildLiveConfig_RejectsAdminKeySharedWithProxyKey(t *testing.T) {
	cfg := &config.Config{
		ProxyAPIKey: "shared-secret",
		AdminAPIKey: "shared-secret",
	}
	_, errs := buildLiveConfig(cfg)
	if len(errs) == 0 {
		t.Fatalf("expected an error rejecting the shared key value, got none")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "must not share a key value") {
			found = true
		}
	}
	if !found {
		t.Fatalf("errs = %v, want one mentioning the shared key value", errs)
	}
}

// TestCompileAPIKeys_ReservedNameErrorNamesTheRightTopLevelField proves
// the "default" name error names admin_api_key when validating
// admin_api_keys, not a hardcoded "proxy_api_key" — an operator
// debugging an admin_api_keys entry named "default" should not be told
// to look at the wrong top-level field.
func TestCompileAPIKeys_ReservedNameErrorNamesTheRightTopLevelField(t *testing.T) {
	_, errs := compileAPIKeys("admin_api_keys", "admin_api_key", []config.ProxyAPIKeyEntry{{Name: "default", Key: "k"}}, 0)
	if len(errs) != 1 {
		t.Fatalf("len(errs) = %d, want 1: %v", len(errs), errs)
	}
	if !strings.Contains(errs[0].Error(), "admin_api_key") {
		t.Fatalf("error = %q, want it to mention admin_api_key", errs[0].Error())
	}
	if strings.Contains(errs[0].Error(), "proxy_api_key") {
		t.Fatalf("error = %q, must not wrongly mention proxy_api_key", errs[0].Error())
	}
}

// TestBuildLiveConfig_RejectsAdminKeysEntrySharedWithProxyKeysEntry
// proves the same cross-check catches a shared value between a named
// entry in proxy_api_keys and a named entry in admin_api_keys, not just
// the two top-level singular fields.
func TestBuildLiveConfig_RejectsAdminKeysEntrySharedWithProxyKeysEntry(t *testing.T) {
	cfg := &config.Config{
		ProxyAPIKeys: []config.ProxyAPIKeyEntry{{Name: "team-a", Key: "shared-secret"}},
		AdminAPIKeys: []config.ProxyAPIKeyEntry{{Name: "ops", Key: "shared-secret"}},
	}
	_, errs := buildLiveConfig(cfg)
	if len(errs) == 0 {
		t.Fatalf("expected an error rejecting the shared key value, got none")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "must not share a key value") {
			found = true
		}
	}
	if !found {
		t.Fatalf("errs = %v, want one mentioning the shared key value", errs)
	}
}
