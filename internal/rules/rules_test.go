package rules_test

import (
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/rules"
)

func TestEngine_BlocksAWSAccessKeyInBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	// Fake AWS access key, sent as a plaintext body the way it would
	// arrive at the proxy before being forwarded over HTTPS.
	body := []byte(`{"config":"AKIAABCDEFGHIJKLMNOP","note":"fake key for test"}`)

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "aws-access-key")
	}
}

func TestEngine_BlocksOpenAIAPIKeyInBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Block,
	})

	// Fake OpenAI API key, sent as a plaintext body.
	body := []byte(`OPENAI_API_KEY=sk-FAKEKEY1234567890ABCDEFGHIJ`)

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/env",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "openai-api-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "openai-api-key")
	}
}

// TestEngine_RedactsMatchedSecretAndForwards proves a Redact rule
// doesn't block the request: it returns action Redact, and the returned
// body has every occurrence of the matched pattern replaced with a
// placeholder naming the rule — never the original secret.
func TestEngine_RedactsMatchedSecretAndForwards(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	body := []byte(`{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ","other":"sk-ANOTHERFAKEKEY000000000"}`)

	action, ruleName, redactedBody, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/chat",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Redact {
		t.Fatalf("action = %v, want %v", action, rules.Redact)
	}
	if ruleName != "openai-api-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "openai-api-key")
	}
	if strings.Contains(string(redactedBody), "sk-FAKEKEY1234567890ABCDEFGHIJ") ||
		strings.Contains(string(redactedBody), "sk-ANOTHERFAKEKEY000000000") {
		t.Fatalf("redacted body still contains the matched secret: %q", redactedBody)
	}
	wantBody := `{"key":"[REDACTED:openai-api-key]","other":"[REDACTED:openai-api-key]"}`
	if string(redactedBody) != wantBody {
		t.Fatalf("redacted body = %q, want %q", redactedBody, wantBody)
	}
}

// TestEngine_NonMatchingBody_ReturnsBodyUnchanged proves Evaluate hands
// back the exact same body it was given when nothing matched — no
// unexpected copy or mutation for the common allow path.
func TestEngine_NonMatchingBody_ReturnsBodyUnchanged(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	body := []byte(`{"hello":"world"}`)
	action, _, gotBody, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/chat",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q", gotBody, body)
	}
}

// TestEngine_BlocksSecretFoundInHeaderValue proves a rule matches a
// header value the same way it matches the body: a clean body with a
// leaked AWS key sitting in an unrelated header is still blocked.
func TestEngine_BlocksSecretFoundInHeaderValue(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`{"hello":"world"}`),
		Headers: map[string][]string{
			"X-Debug-Info": {"AKIAABCDEFGHIJKLMNOP"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "aws-access-key")
	}
}

// TestEngine_RedactsSecretFoundInHeaderValue proves a Redact rule
// matched in a header rewrites only that header's value, leaving the
// body and every other header untouched.
func TestEngine_RedactsSecretFoundInHeaderValue(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	body := []byte(`{"hello":"world"}`)
	action, ruleName, gotBody, gotHeaders, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/chat",
		Body:   body,
		Headers: map[string][]string{
			"X-Debug-Info": {"sk-FAKEKEY1234567890ABCDEFGHIJ"},
			"X-Other":      {"unrelated-value"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Redact {
		t.Fatalf("action = %v, want %v", action, rules.Redact)
	}
	if ruleName != "openai-api-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "openai-api-key")
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q (the match was in a header, not the body)", gotBody, body)
	}
	wantDebug := []string{"[REDACTED:openai-api-key]"}
	if strings.Join(gotHeaders["X-Debug-Info"], ",") != strings.Join(wantDebug, ",") {
		t.Fatalf("X-Debug-Info header = %v, want %v", gotHeaders["X-Debug-Info"], wantDebug)
	}
	if strings.Join(gotHeaders["X-Other"], ",") != "unrelated-value" {
		t.Fatalf("X-Other header = %v, want unchanged", gotHeaders["X-Other"])
	}
}

// TestEngine_BodyMatchTakesPriorityOverHeaderMatch proves the documented
// evaluation order: a rule matching the body wins even when a different
// header would also match a rule, since body rules are checked first.
func TestEngine_BodyMatchTakesPriorityOverHeaderMatch(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`{"config":"AKIAABCDEFGHIJKLMNOP"}`),
		Headers: map[string][]string{
			"X-Debug-Info": {"sk-FAKEKEY1234567890ABCDEFGHIJ"},
		},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q (the body match, not the header match)", ruleName, "aws-access-key")
	}
}

// TestEngine_NonMatchingHeaders_ReturnsHeadersUnchanged proves Evaluate
// hands back the exact same headers map it was given when nothing in it
// matched — no unexpected copy or mutation for the common allow path.
func TestEngine_NonMatchingHeaders_ReturnsHeadersUnchanged(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	headers := map[string][]string{"X-Debug-Info": {"nothing-interesting-here"}}
	action, ruleName, _, gotHeaders, _, err := engine.Evaluate(rules.Request{
		Method:  "POST",
		URL:     "/upload",
		Body:    []byte(`{"hello":"world"}`),
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if strings.Join(gotHeaders["X-Debug-Info"], ",") != "nothing-interesting-here" {
		t.Fatalf("headers = %v, want unchanged", gotHeaders)
	}
}

// TestEngine_EvaluateResponse_BlocksMatchedSecret proves EvaluateResponse
// matches a response body the same way Evaluate matches a request body.
func TestEngine_EvaluateResponse_BlocksMatchedSecret(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _ := engine.EvaluateResponse([]byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`))
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "aws-access-key")
	}
}

// TestEngine_EvaluateResponse_RedactsMatchedSecret proves a Redact rule
// masks every occurrence in the response body, same as Evaluate does
// for a request body.
func TestEngine_EvaluateResponse_RedactsMatchedSecret(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
	})

	action, ruleName, body, _ := engine.EvaluateResponse([]byte(`{"echo":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`))
	if action != rules.Redact {
		t.Fatalf("action = %v, want %v", action, rules.Redact)
	}
	if ruleName != "openai-api-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "openai-api-key")
	}
	want := `{"echo":"[REDACTED:openai-api-key]"}`
	if string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}

// TestEngine_EvaluateResponse_AllowsCleanBody proves a clean response
// body is returned unchanged with the Allow action and no rule name.
func TestEngine_EvaluateResponse_AllowsCleanBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	body := []byte(`{"echo":"hello"}`)
	action, ruleName, gotBody, _ := engine.EvaluateResponse(body)
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q", gotBody, body)
	}
}

// TestEngine_PathRule_BlocksMatchingPrefixRegardlessOfContent proves a
// path rule blocks every request under its prefix outright — even one
// whose body would otherwise be perfectly clean.
func TestEngine_PathRule_BlocksMatchingPrefixRegardlessOfContent(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "block-admin",
		PathPrefix: "/admin",
		Action:     rules.Block,
	})

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "GET",
		URL:    "/admin/users",
		Body:   []byte(`{"hello":"world"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "block-admin" {
		t.Fatalf("rule = %q, want %q", ruleName, "block-admin")
	}
}

// TestEngine_PathRule_AllowExemptsMatchingPrefixFromContentScanning
// proves an Allow path rule skips body/header scanning entirely for a
// matching request — even one whose body would otherwise be blocked.
func TestEngine_PathRule_AllowExemptsMatchingPrefixFromContentScanning(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "health-check",
		PathPrefix: "/health",
		Action:     rules.Allow,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, gotBody, _, _, err := engine.Evaluate(rules.Request{
		Method: "GET",
		URL:    "/health/status",
		Body:   []byte(`{"note":"AKIAABCDEFGHIJKLMNOP"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v (the path rule must exempt this request from the aws-access-key rule)", action, rules.Allow)
	}
	if ruleName != "health-check" {
		t.Fatalf("rule = %q, want %q", ruleName, "health-check")
	}
	if string(gotBody) != `{"note":"AKIAABCDEFGHIJKLMNOP"}` {
		t.Fatalf("body = %q, want unchanged", gotBody)
	}
}

// TestEngine_PathRule_RedactActionBehavesLikeAllow proves the
// documented Rule behavior: Redact has no matched text to replace on a
// path rule, so it is treated exactly like Allow.
func TestEngine_PathRule_RedactActionBehavesLikeAllow(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "legacy-redact-path-rule",
		PathPrefix: "/legacy",
		Action:     rules.Redact,
	})

	body := []byte(`{"hello":"world"}`)
	action, ruleName, gotBody, _, _, err := engine.Evaluate(rules.Request{
		Method: "GET",
		URL:    "/legacy/x",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if ruleName != "legacy-redact-path-rule" {
		t.Fatalf("rule = %q, want %q", ruleName, "legacy-redact-path-rule")
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q", gotBody, body)
	}
}

// TestEngine_PathRule_NonMatchingPrefixFallsThroughToContentScanning
// proves a path rule that doesn't match the request's path has no
// effect at all: content scanning still applies normally.
func TestEngine_PathRule_NonMatchingPrefixFallsThroughToContentScanning(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "block-admin",
		PathPrefix: "/admin",
		Action:     rules.Block,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`{"config":"AKIAABCDEFGHIJKLMNOP"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q (the path rule doesn't apply to this path)", ruleName, "aws-access-key")
	}
}

func TestEngine_AllowsCleanBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _, _, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   []byte(`{"hello":"world"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
}

// TestEngine_DryRunBodyRule_BlockNeverEnforcedButReported proves a
// DryRun body rule matching Block never actually blocks: the request
// comes back Allow, with the body untouched, but the match is reported
// in the returned []DryRunMatch.
func TestEngine_DryRunBodyRule_BlockNeverEnforcedButReported(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	body := []byte(`{"config":"AKIAABCDEFGHIJKLMNOP"}`)
	action, ruleName, gotBody, _, dryRunHits, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/upload",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v (a dry_run rule must never actually block)", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty (dry-run never becomes the real matched rule)", ruleName)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q", gotBody, body)
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "aws-access-key" || dryRunHits[0].Action != rules.Block {
		t.Fatalf("dryRunHits = %+v, want exactly one {aws-access-key, Block}", dryRunHits)
	}
}

// TestEngine_DryRunBodyRule_RedactNeverEnforcedButReported is the
// Redact counterpart: the secret reaches the returned body unmasked,
// but the would-be redact is still reported.
func TestEngine_DryRunBodyRule_RedactNeverEnforcedButReported(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "openai-api-key",
		Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20,}`),
		Action:  rules.Redact,
		DryRun:  true,
	})

	body := []byte(`{"key":"sk-FAKEKEY1234567890ABCDEFGHIJ"}`)
	action, ruleName, gotBody, _, dryRunHits, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/chat",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v (a dry_run rule must never actually redact)", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged (unmasked) %q", gotBody, body)
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "openai-api-key" || dryRunHits[0].Action != rules.Redact {
		t.Fatalf("dryRunHits = %+v, want exactly one {openai-api-key, Redact}", dryRunHits)
	}
}

// TestEngine_DryRunPathRule_BlockNeverEnforcedButReported is the path
// rule equivalent of TestEngine_DryRunBodyRule_BlockNeverEnforcedButReported.
func TestEngine_DryRunPathRule_BlockNeverEnforcedButReported(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddRule(rules.Rule{
		Name:       "block-admin",
		PathPrefix: "/admin",
		Action:     rules.Block,
		DryRun:     true,
	})

	action, ruleName, _, _, dryRunHits, err := engine.Evaluate(rules.Request{
		Method: "GET",
		URL:    "/admin/users",
		Body:   []byte(`{"hello":"world"}`),
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v (a dry_run path rule must never actually block)", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "block-admin" || dryRunHits[0].Action != rules.Block {
		t.Fatalf("dryRunHits = %+v, want exactly one {block-admin, Block}", dryRunHits)
	}
}

// TestEngine_DryRunHeaderRule_NeverEnforcedButReported proves a DryRun
// body rule matching a header value (not the body) behaves the same
// way: never enforced, but reported.
func TestEngine_DryRunHeaderRule_NeverEnforcedButReported(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	headers := map[string][]string{"X-Debug": {"AKIAABCDEFGHIJKLMNOP"}}
	action, ruleName, _, gotHeaders, dryRunHits, err := engine.Evaluate(rules.Request{
		Method:  "GET",
		URL:     "/x",
		Body:    []byte(`{"hello":"world"}`),
		Headers: headers,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if gotHeaders["X-Debug"][0] != "AKIAABCDEFGHIJKLMNOP" {
		t.Fatalf("headers = %+v, want the header value unchanged", gotHeaders)
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "aws-access-key" {
		t.Fatalf("dryRunHits = %+v, want exactly one {aws-access-key, Block}", dryRunHits)
	}
}

// TestEngine_DryRunRule_EvaluationContinuesToLaterRealRule proves a
// dry-run match never shadows a later, real rule: evaluation continues
// past it exactly as if it hadn't matched, so a subsequent real rule
// still fires normally, in addition to the dry-run hit being reported.
func TestEngine_DryRunRule_EvaluationContinuesToLaterRealRule(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "dry-run-candidate",
		Pattern: regexp.MustCompile(`CANDIDATE-[0-9]+`),
		Action:  rules.Block,
		DryRun:  true,
	})
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	body := []byte(`{"a":"CANDIDATE-123","b":"AKIAABCDEFGHIJKLMNOP"}`)
	action, ruleName, _, _, dryRunHits, err := engine.Evaluate(rules.Request{
		Method: "POST",
		URL:    "/x",
		Body:   body,
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Block {
		t.Fatalf("action = %v, want %v (the real, non-dry-run rule must still enforce)", action, rules.Block)
	}
	if ruleName != "aws-access-key" {
		t.Fatalf("rule = %q, want %q", ruleName, "aws-access-key")
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "dry-run-candidate" {
		t.Fatalf("dryRunHits = %+v, want exactly one {dry-run-candidate, Block}", dryRunHits)
	}
}

// TestEngine_DryRunMatch_DeduplicatedAcrossBodyAndHeader proves a
// dry-run rule that matches in both the body and a header is only
// reported once — a rule either would have fired or it wouldn't; a
// per-occurrence count would just be noise for something that never
// actually takes effect anyway.
func TestEngine_DryRunMatch_DeduplicatedAcrossBodyAndHeader(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	action, _, _, _, dryRunHits, err := engine.Evaluate(rules.Request{
		Method:  "POST",
		URL:     "/x",
		Body:    []byte(`{"a":"AKIAABCDEFGHIJKLMNOP"}`),
		Headers: map[string][]string{"X-Debug": {"AKIAZZZZZZZZZZZZZZZZ"}},
	})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v", action, rules.Allow)
	}
	if len(dryRunHits) != 1 {
		t.Fatalf("dryRunHits = %+v, want exactly one deduplicated entry for aws-access-key", dryRunHits)
	}
}

// TestEngine_EvaluateResponse_DryRunNeverEnforcedButReported proves
// EvaluateResponse gives a dry_run rule the same treatment as Evaluate:
// never actually blocked/redacted, but reported.
func TestEngine_EvaluateResponse_DryRunNeverEnforcedButReported(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
		DryRun:  true,
	})

	body := []byte(`{"echo":"AKIAABCDEFGHIJKLMNOP"}`)
	action, ruleName, gotBody, dryRunHits := engine.EvaluateResponse(body)
	if action != rules.Allow {
		t.Fatalf("action = %v, want %v (a dry_run rule must never actually block a response)", action, rules.Allow)
	}
	if ruleName != "" {
		t.Fatalf("rule = %q, want empty", ruleName)
	}
	if string(gotBody) != string(body) {
		t.Fatalf("body = %q, want unchanged %q", gotBody, body)
	}
	if len(dryRunHits) != 1 || dryRunHits[0].RuleName != "aws-access-key" || dryRunHits[0].Action != rules.Block {
		t.Fatalf("dryRunHits = %+v, want exactly one {aws-access-key, Block}", dryRunHits)
	}
}
