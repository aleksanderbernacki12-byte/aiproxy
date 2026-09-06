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

	action, ruleName, _, err := engine.Evaluate(rules.Request{
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

	action, ruleName, _, err := engine.Evaluate(rules.Request{
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

	action, ruleName, redactedBody, err := engine.Evaluate(rules.Request{
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
	action, _, gotBody, err := engine.Evaluate(rules.Request{
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

func TestEngine_AllowsCleanBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, _, err := engine.Evaluate(rules.Request{
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
