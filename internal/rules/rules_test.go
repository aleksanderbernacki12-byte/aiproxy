package rules_test

import (
	"regexp"
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

	action, ruleName, err := engine.Evaluate(rules.Request{
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

	action, ruleName, err := engine.Evaluate(rules.Request{
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

func TestEngine_AllowsCleanBody(t *testing.T) {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{
		Name:    "aws-access-key",
		Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Action:  rules.Block,
	})

	action, ruleName, err := engine.Evaluate(rules.Request{
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
