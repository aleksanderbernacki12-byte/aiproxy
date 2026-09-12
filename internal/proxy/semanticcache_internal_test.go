package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExtractPromptText_PlainStringContent(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world"}]}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_ContentBlocksArray(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"text","text":"world"}]}]}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_MultipleMessagesConcatenated(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"be terse"},{"role":"user","content":"hello world"}]}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "be terse hello world" {
		t.Fatalf("text = %q, want %q", text, "be terse hello world")
	}
}

func TestExtractPromptText_TopLevelPromptField(t *testing.T) {
	body := []byte(`{"prompt":"legacy completion prompt"}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "legacy completion prompt" {
		t.Fatalf("text = %q, want %q", text, "legacy completion prompt")
	}
}

func TestExtractPromptText_TopLevelInputField(t *testing.T) {
	body := []byte(`{"input":"some input text"}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "some input text" {
		t.Fatalf("text = %q, want %q", text, "some input text")
	}
}

func TestExtractPromptText_UnrecognizedShapeReturnsFalse(t *testing.T) {
	body := []byte(`{"foo":"bar"}`)
	if _, _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false for a body with no recognized prompt field")
	}
}

func TestExtractPromptText_InvalidJSONReturnsFalse(t *testing.T) {
	if _, _, ok := extractPromptText([]byte("not json")); ok {
		t.Fatal("expected ok=false for invalid JSON")
	}
}

func TestExtractPromptText_EmptyContentReturnsFalse(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":""}]}`)
	if _, _, ok := extractPromptText(body); ok {
		t.Fatal("expected ok=false when every recognized field is empty")
	}
}

func TestExtractPromptText_ContentBlocksArrayWithBareStringElementSkipsOnlyThatElement(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"},"oops-a-bare-string",{"type":"text","text":"world"}]}]}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_ContentBlockWithWrongTypedTextFieldSkipsOnlyThatElement(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"hello"},{"type":"tool_use","text":123},{"type":"text","text":"world"}]}]}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world" {
		t.Fatalf("text = %q, want %q", text, "hello world")
	}
}

func TestExtractPromptText_MalformedMessagesFieldDoesNotDiscardPrompt(t *testing.T) {
	body := []byte(`{"prompt":"legit text","messages":"not-an-array"}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "legit text" {
		t.Fatalf("text = %q, want %q", text, "legit text")
	}
}

func TestExtractPromptText_NoDoubleSpaceBetweenContentAndInput(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hello world"}],"input":"some input"}`)
	text, _, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if text != "hello world some input" {
		t.Fatalf("text = %q, want %q (no double space)", text, "hello world some input")
	}
}

func TestExtractPromptText_RemainderPreservesNonTextFields(t *testing.T) {
	body := []byte(`{"model":"gpt-4","stream":true,"temperature":0.7,"messages":[{"role":"user","content":"hello"}]}`)
	_, remainder, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected text to be found")
	}
	var decoded map[string]any
	if err := json.Unmarshal(remainder, &decoded); err != nil {
		t.Fatalf("remainder is not valid JSON: %v, %q", err, remainder)
	}
	if decoded["model"] != "gpt-4" {
		t.Fatalf("remainder lost model field: %q", remainder)
	}
	if decoded["stream"] != true {
		t.Fatalf("remainder lost stream field: %q", remainder)
	}
	if decoded["temperature"] != 0.7 {
		t.Fatalf("remainder lost temperature field: %q", remainder)
	}
}

func TestExtractPromptText_RemainderBlanksMessageContentButKeepsRole(t *testing.T) {
	body := []byte(`{"messages":[{"role":"system","content":"secret system prompt"}]}`)
	_, remainder, ok := extractPromptText(body)
	if !ok {
		t.Fatal("expected text to be found")
	}
	if strings.Contains(string(remainder), "secret system prompt") {
		t.Fatalf("remainder leaked message content verbatim: %q", remainder)
	}
	var decoded struct {
		Messages []struct {
			Role string `json:"role"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(remainder, &decoded); err != nil {
		t.Fatalf("remainder is not valid JSON: %v", err)
	}
	if len(decoded.Messages) != 1 || decoded.Messages[0].Role != "system" {
		t.Fatalf("remainder lost message role: %q", remainder)
	}
}

func TestExtractPromptText_DifferentModelProducesDifferentRemainder(t *testing.T) {
	a := []byte(`{"model":"model-a","stream":false,"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"model":"model-b","stream":true,"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different model/stream produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_DifferentToolsProduceDifferentRemainder(t *testing.T) {
	a := []byte(`{"tools":[{"name":"get_weather"}],"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"tools":[{"name":"get_stock_price"}],"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different tool definitions produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_DifferentResponseFormatProducesDifferentRemainder(t *testing.T) {
	a := []byte(`{"response_format":{"type":"text"},"messages":[{"role":"user","content":"same text"}]}`)
	b := []byte(`{"response_format":{"type":"json_object"},"messages":[{"role":"user","content":"same text"}]}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different response_format produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_DifferentImagesInContentBlocksProduceDifferentRemainder(t *testing.T) {
	a := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"what is this"},{"type":"image_url","image_url":{"url":"https://example.com/cat.jpg"}}]}]}`)
	b := []byte(`{"messages":[{"role":"user","content":[{"type":"text","text":"what is this"},{"type":"image_url","image_url":{"url":"https://example.com/dog.jpg"}}]}]}`)
	textA, remainderA, okA := extractPromptText(a)
	textB, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if textA != textB {
		t.Fatalf("expected identical extracted text (only the image differs), got %q vs %q", textA, textB)
	}
	if string(remainderA) == string(remainderB) {
		t.Fatalf("different images produced identical remainders despite identical text: %q", remainderA)
	}
}

func TestExtractPromptText_UnrecognizedContentShapesStayDistinguishable(t *testing.T) {
	a := []byte(`{"messages":[{"role":"user","content":{"weird":"AAA"}}]}`)
	b := []byte(`{"messages":[{"role":"user","content":{"weird":"BBB"}}]}`)
	_, remainderA, _ := extractPromptText(a)
	_, remainderB, _ := extractPromptText(b)
	if string(remainderA) == string(remainderB) {
		t.Fatalf("two different unrecognized content shapes produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_NonStringPromptAndInputStayDistinguishable(t *testing.T) {
	a := []byte(`{"model":"m","prompt":["what is 2+2"],"input":"hi"}`)
	b := []byte(`{"model":"m","prompt":["what is 3+3"],"input":"hi"}`)
	_, remainderA, _ := extractPromptText(a)
	_, remainderB, _ := extractPromptText(b)
	if string(remainderA) == string(remainderB) {
		t.Fatalf("two different non-string prompt values produced identical remainders: %q", remainderA)
	}
}

func TestExtractPromptText_FieldOrderIndependence(t *testing.T) {
	a := []byte(`{"model":"m","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	b := []byte(`{"stream":true,"messages":[{"role":"user","content":"hi"}],"model":"m"}`)
	_, remainderA, okA := extractPromptText(a)
	_, remainderB, okB := extractPromptText(b)
	if !okA || !okB {
		t.Fatal("expected text to be found in both")
	}
	if string(remainderA) != string(remainderB) {
		t.Fatalf("field order affected the remainder: %q vs %q", remainderA, remainderB)
	}
}
