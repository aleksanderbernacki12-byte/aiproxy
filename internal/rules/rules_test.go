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

	action, ruleName, _, _, err := engine.Evaluate(rules.Request{
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

	action, ruleName, _, _, err := engine.Evaluate(rules.Request{
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

	action, ruleName, redactedBody, _, err := engine.Evaluate(rules.Request{
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
	action, _, gotBody, _, err := engine.Evaluate(rules.Request{
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

	action, ruleName, _, _, err := engine.Evaluate(rules.Request{
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
	action, ruleName, gotBody, gotHeaders, err := engine.Evaluate(rules.Request{
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

	action, ruleName, _, _, err := engine.Evaluate(rules.Request{
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
	action, ruleName, _, gotHeaders, err := engine.Evaluate(rules.Request{
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

func TestEngine_AllowsCleanBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, _, err := engine.Evaluate(rules.Request{
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
