package rules_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"aiproxy/internal/rules"
)

func jsonEngine(action rules.Action) *rules.Engine {
	engine := rules.NewEngine(rules.Allow)
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "secret-a", Pattern: regexp.MustCompile("SECRET_A"), Action: action})
	return engine
}

func evaluateBody(t *testing.T, engine *rules.Engine, body string) (rules.Action, string) {
	t.Helper()
	action, _, result, _, _, err := engine.Evaluate(rules.Request{Method: "POST", URL: "/chat", Body: []byte(body)})
	if err != nil {
		t.Fatal(err)
	}
	return action, string(result)
}

func TestJSON_EscapedSecretIsBlocked(t *testing.T) {
	for _, body := range []string{
		`{"prompt":"SECRET_\u0041"}`,
		`{"messages":[{"content":"x \u0053ECRET_A y"}]}`,
		`{"SECRET_\u0041":1}`,
	} {
		if action, _ := evaluateBody(t, jsonEngine(rules.Block), body); action != rules.Block {
			t.Errorf("%s: action = %v, want Block", body, action)
		}
	}
	action, _, _, _ := jsonEngine(rules.Block).EvaluateResponse([]byte(`{"answer":"SECRET_\u0041"}`), "", "")
	if action != rules.Block {
		t.Errorf("response: action = %v, want Block", action)
	}
}

func TestJSON_EscapedSecretIsRedactedStructurally(t *testing.T) {
	action, result := evaluateBody(t, jsonEngine(rules.Redact), `{"z":1.50,"prompt":"a SECRET_\u0041 b","a":[1e3,true,null]}`)
	if action != rules.Redact {
		t.Fatalf("action = %v, want Redact", action)
	}
	want := `{"z":1.50,"prompt":"a [REDACTED:secret-a] b","a":[1e3,true,null]}`
	if result != want {
		t.Fatalf("body = %s, want %s", result, want)
	}
	if !json.Valid([]byte(result)) {
		t.Fatalf("redacted body is not valid JSON: %s", result)
	}
}

func TestJSON_NoMatchLeavesBytesIdentical(t *testing.T) {
	body := `{ "prompt" : "hello \u00e9",  "n": 1.0 }`
	action, result := evaluateBody(t, jsonEngine(rules.Redact), body)
	if action != rules.Allow || result != body {
		t.Fatalf("action=%v body=%q, want Allow and identical bytes", action, result)
	}
}

func TestJSON_InvalidJSONIsScannedRawOnly(t *testing.T) {
	action, _ := evaluateBody(t, jsonEngine(rules.Block), `{"prompt":"SECRET_\u0041"`)
	if action != rules.Allow {
		t.Fatalf("action = %v, want Allow for invalid JSON with only an escaped match", action)
	}
}

func TestJSON_NestedStructureSurvivesRewrite(t *testing.T) {
	body := `[{"a":{"b":[{"c":"SECRET_\u0041"},{}],"d":[]},"e":"x"},[],"y"]`
	action, result := evaluateBody(t, jsonEngine(rules.Redact), body)
	want := `[{"a":{"b":[{"c":"[REDACTED:secret-a]"},{}],"d":[]},"e":"x"},[],"y"]`
	if action != rules.Redact || result != want {
		t.Fatalf("action=%v body=%s, want Redact %s", action, result, want)
	}
}
