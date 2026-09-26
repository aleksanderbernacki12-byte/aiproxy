package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// decodedJSONStrings returns every string token (object keys and values)
// in body after JSON unescaping, or ok=false when body is not a single
// valid JSON value. Rules match raw bytes first; this closes the gap where
// an escape such as a backslash-u sequence hides a secret the upstream
// will decode (review finding #5).
func decodedJSONStrings(body []byte) (strs []string, ok bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid(trimmed) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return strs, true
		}
		if err != nil {
			return nil, false
		}
		if value, isString := token.(string); isString {
			strs = append(strs, value)
		}
	}
}

// rewriteJSONStrings re-encodes body with apply run on every decoded
// string token, preserving key order, number literals and structure. It
// reports changed=false (and returns body untouched) when apply changed
// nothing, so unaffected bodies keep their exact original bytes.
func rewriteJSONStrings(body []byte, apply func(string) string) (result []byte, changed bool, err error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	type container struct {
		object bool
		count  int
	}
	var stack []container
	var out bytes.Buffer
	separate := func() {
		if len(stack) == 0 {
			return
		}
		top := &stack[len(stack)-1]
		switch {
		case top.object && top.count%2 == 1:
			out.WriteByte(':')
		case top.count > 0:
			out.WriteByte(',')
		}
		top.count++
	}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return body, false, err
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				separate()
				stack = append(stack, container{object: value == '{'})
			default:
				stack = stack[:len(stack)-1]
			}
			out.WriteByte(byte(value))
		case string:
			separate()
			rewritten := apply(value)
			if rewritten != value {
				changed = true
			}
			encoded, err := marshalJSONString(rewritten)
			if err != nil {
				return body, false, err
			}
			out.Write(encoded)
		case json.Number:
			separate()
			out.WriteString(value.String())
		case bool:
			separate()
			if value {
				out.WriteString("true")
			} else {
				out.WriteString("false")
			}
		case nil:
			separate()
			out.WriteString("null")
		}
	}
	if !changed {
		return body, false, nil
	}
	return out.Bytes(), true, nil
}

func marshalJSONString(value string) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
