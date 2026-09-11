package proxy

import "testing"

func TestExtractPromptText_PlainStringContent(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world"}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_ContentBlocksArray(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"text","text":"world"}]}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_MultipleMessagesConcatenated(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hello world"}]}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "be terse hello world" {
		t.Fatalf("text = %q, want %q", text, "be terse hello world")
	}
}

func TestExtractPromptText_TopLevelPromptField(t *testing.T) {
	body := []byte(`{"prompt":"legacy completion prompt"}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "legacy completion prompt" {
		t.Fatalf("text = %q, want %q", text, "legacy completion prompt")
	}
}

func TestExtractPromptText_TopLevelInputField(t *testing.T) {
	body := []byte(`{"input":"some input text"}`)
	text, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "some input text" {
		t.Fatalf("text = %q, want %q", text, "some input text")
	}
}

func TestExtractPromptText_UnrecognizedShapeReturnsFalse(t *testing.T) {
	body := []byte(`{"foo":"bar"}`)
	if _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false for a body with no recognized prompt field")
	}
}

func TestExtractPromptText_InvalidJSONReturnsFalse(t *testing.T) {
	if _, ok := extractPromptText([]byte("not json")); ok {
		t.Fatal("expected ok=false for invalid JSON")
	}
}

func TestExtractPromptText_EmptyContentReturnsFalse(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":""}]}`)
	if _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false when every recognized field is empty")
	}
}
