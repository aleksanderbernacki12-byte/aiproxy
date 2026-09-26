package proxy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// lastEventBoundary returns the index just past the last blank line in
// data, or -1 if there is none. Per the WHATWG event-stream grammar a line
// ends with CRLF, LF or CR, and an empty line ends an event. A CR as the
// very last byte may be the first half of a CRLF still in flight, so it
// only ends a line at EOF.
func lastEventBoundary(data []byte, atEOF bool) int {
	boundary := -1
	lineStart := 0
	for index := 0; index < len(data); index++ {
		var terminatorLength int
		switch data[index] {
		case '\n':
			terminatorLength = 1
		case '\r':
			switch {
			case index+1 < len(data) && data[index+1] == '\n':
				terminatorLength = 2
			case index+1 == len(data) && !atEOF:
				return boundary
			default:
				terminatorLength = 1
			}
		default:
			continue
		}
		lineEnd := index + terminatorLength
		if index == lineStart {
			boundary = lineEnd
		}
		lineStart = lineEnd
		index = lineEnd - 1
	}
	return boundary
}

// splitEvents splits a batch that ends at an event boundary (or at EOF)
// into its events, each keeping its own terminating blank line so the
// bytes can be re-emitted unchanged.
func splitEvents(batch []byte) [][]byte {
	var events [][]byte
	for len(batch) > 0 {
		boundary := firstEventBoundary(batch)
		if boundary == -1 {
			events = append(events, batch)
			break
		}
		events = append(events, batch[:boundary])
		batch = batch[boundary:]
	}
	return events
}

// firstEventBoundary is lastEventBoundary's counterpart for the earliest
// blank line, treating the end of data as final.
func firstEventBoundary(data []byte) int {
	lineStart := 0
	for index := 0; index < len(data); index++ {
		var terminatorLength int
		switch data[index] {
		case '\n':
			terminatorLength = 1
		case '\r':
			terminatorLength = 1
			if index+1 < len(data) && data[index+1] == '\n' {
				terminatorLength = 2
			}
		default:
			continue
		}
		lineEnd := index + terminatorLength
		if index == lineStart {
			return lineEnd
		}
		lineStart = lineEnd
		index = lineEnd - 1
	}
	return -1
}

// generatedTextKeys are the JSON fields that carry model output in the
// streaming formats of OpenAI (Chat Completions and Responses), Anthropic
// Messages and Gemini. Only these are reassembled across events, so
// per-event metadata such as ids and model names never splits the text.
var generatedTextKeys = map[string]bool{
	"content": true, "text": true, "delta": true, "partial_json": true,
	"arguments": true, "thinking": true, "reasoning_content": true,
}

// eventText returns the generated text an SSE event carries: the decoded
// string values of generatedTextKeys in its JSON data, in document order.
// A non-JSON data payload other than the "[DONE]" sentinel is returned
// as-is.
func eventText(event []byte) string {
	var data []string
	for _, line := range bytes.FieldsFunc(event, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if value, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			data = append(data, string(bytes.TrimPrefix(value, []byte(" "))))
		}
	}
	payload := strings.Join(data, "\n")
	if payload == "" || payload == "[DONE]" {
		return ""
	}
	if !json.Valid([]byte(payload)) {
		return payload
	}

	type frame struct {
		object    bool
		expectKey bool
		key       string
	}
	var stack []frame
	valueConsumed := func() {
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expectKey = true
		}
	}
	var text strings.Builder
	decoder := json.NewDecoder(strings.NewReader(payload))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch value := token.(type) {
		case json.Delim:
			if value == '{' || value == '[' {
				valueConsumed()
				stack = append(stack, frame{object: value == '{', expectKey: value == '{'})
			} else {
				stack = stack[:len(stack)-1]
			}
		case string:
			if len(stack) > 0 && stack[len(stack)-1].object {
				top := &stack[len(stack)-1]
				if top.expectKey {
					top.key, top.expectKey = value, false
					continue
				}
				if generatedTextKeys[top.key] {
					text.WriteString(value)
				}
			}
			valueConsumed()
		default:
			valueConsumed()
		}
	}
	return text.String()
}
