package proxy

import (
	"io"
	"regexp"
	"strings"
	"testing"

	"aiproxy/internal/rules"
)

type reviewChunks struct {
	chunks []string
	reads  int
}

func (r *reviewChunks) Read(p []byte) (int, error) {
	r.reads++
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

func (r *reviewChunks) Close() error { return nil }

func TestReview_StreamMustRecognizeCRLFBoundaries(t *testing.T) {
	src := &reviewChunks{chunks: []string{"data: first\r\n\r\n", "data: second\r\n\r\n"}}
	tee := &streamTee{src: src}
	var p [4096]byte
	n, err := tee.Read(p[:])
	if err != nil {
		t.Fatal(err)
	}
	if src.reads != 1 {
		t.Fatalf("first read consumed %d upstream reads including EOF instead of emitting first event: %q", src.reads, p[:n])
	}
}

func TestLastEventBoundary(t *testing.T) {
	cases := []struct {
		name  string
		data  string
		atEOF bool
		want  int
	}{
		{"LF", "data: a\n\ndata: b", false, 9},
		{"CRLF", "data: a\r\n\r\ndata: b", false, 11},
		{"CR", "data: a\r\rdata: b", false, 9},
		{"mixed", "data: a\r\n\ndata: b\n\r\n", false, 20},
		{"last of two", "a\n\nb\n\nc", false, 6},
		{"no boundary", "data: a\ndata: b\n", false, -1},
		{"trailing CR may be half of CRLF", "data: a\r\n\r", false, -1},
		{"trailing CR at EOF is a boundary", "data: a\r\n\r", true, 10},
		{"empty", "", false, -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastEventBoundary([]byte(tc.data), tc.atEOF); got != tc.want {
				t.Fatalf("lastEventBoundary(%q, %v) = %d, want %d", tc.data, tc.atEOF, got, tc.want)
			}
		})
	}
}

func TestStreamTee_CRLFSplitAcrossReadsIsOneBoundary(t *testing.T) {
	src := &reviewChunks{chunks: []string{"data: a\r\n\r", "\ndata: b\r\n\r\n"}}
	tee := &streamTee{src: src}
	out, err := io.ReadAll(tee)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "data: a\r\n\r\ndata: b\r\n\r\n" {
		t.Fatalf("stream bytes changed: %q", out)
	}
}

func holdbackEngine(holdback int, action rules.Action) *rules.Engine {
	engine := rules.NewEngine(rules.Allow)
	engine.StreamHoldbackBytes = holdback
	engine.AddBodyRegexRule(rules.BodyRegexRule{Name: "fake-secret", Pattern: regexp.MustCompile("SECRET_A"), Action: action})
	return engine
}

func TestReview_StreamMustScanReassembledText(t *testing.T) {
	e := rules.NewEngine(rules.Allow)
	e.AddBodyRegexRule(rules.BodyRegexRule{Name: "fake-secret", Pattern: regexp.MustCompile("SECRET_A"), Action: rules.Block})
	src := &reviewChunks{chunks: []string{"data: {\"delta\":\"SECRET_\"}\n\n", "data: {\"delta\":\"A\"}\n\n"}}
	tee := &streamTee{src: src, engine: e}
	b, _ := io.ReadAll(tee)
	tee.Close()
	if !tee.blocked && strings.Contains(string(b), "SECRET_") && strings.Contains(string(b), `"A"`) {
		t.Fatalf("client can assemble SECRET_A from unchecked deltas: %s", b)
	}
}

func TestStreamTee_SplitSecretBlockedBeforeAnyPartIsDelivered(t *testing.T) {
	streams := map[string][]string{
		"openai chat": {
			"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"key SECRET_\"}}]}\n\n",
			"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"A done\"}}]}\n\n",
			"data: [DONE]\n\n",
		},
		"anthropic": {
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"SECR\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"ET_A\"}}\n\n",
		},
	}
	for name, chunks := range streams {
		t.Run(name, func(t *testing.T) {
			var blockedBy string
			tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(64, rules.Block), onBlock: func(rule string) { blockedBy = rule }}
			delivered, err := io.ReadAll(tee)
			if err == nil || blockedBy != "fake-secret" {
				t.Fatalf("stream not blocked: err=%v blockedBy=%q", err, blockedBy)
			}
			if len(delivered) != 0 {
				t.Fatalf("client received part of the secret before the block: %q", delivered)
			}
		})
	}
}

func TestStreamTee_RedactRuleSpanningEventsEndsStream(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"SECRET_\"}\n\n", "data: {\"delta\":\"A\"}\n\n"}
	var blockedBy string
	tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(64, rules.Redact), onBlock: func(rule string) { blockedBy = rule }}
	delivered, _ := io.ReadAll(tee)
	if blockedBy != "fake-secret" || len(delivered) != 0 {
		t.Fatalf("blockedBy=%q delivered=%q, want the stream ended with nothing delivered", blockedBy, delivered)
	}
}

func TestStreamTee_HoldbackZeroReleasesEachEventImmediately(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"SECRET_\"}\n\n", "data: {\"delta\":\"A\"}\n\n"}
	src := &reviewChunks{chunks: chunks}
	tee := &streamTee{src: src, engine: holdbackEngine(0, rules.Block)}
	var p [4096]byte
	n, err := tee.Read(p[:])
	if err != nil || string(p[:n]) != chunks[0] || src.reads != 1 {
		t.Fatalf("first Read = %q, %v after %d upstream reads; want the first event immediately", p[:n], err, src.reads)
	}
}

func TestStreamTee_ShortStreamIsDeliveredCompleteAtEOF(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"hello \"}\n\n", "data: {\"delta\":\"world\"}\n\n", "data: [DONE]\n\n"}
	var completed []byte
	var clean bool
	tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(256, rules.Block), accumulate: true}
	tee.onComplete = func(data, _ []byte, cleanEOF bool) { completed, clean = append([]byte(nil), data...), cleanEOF }
	delivered, err := io.ReadAll(tee)
	tee.Close()
	want := strings.Join(chunks, "")
	if err != nil || string(delivered) != want || string(completed) != want || !clean {
		t.Fatalf("delivered=%q err=%v completed=%q clean=%v", delivered, err, completed, clean)
	}
}

func TestStreamTee_BlockInFinalEventIsNotACleanEOF(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"ok\"}\n\n", "data: {\"delta\":\"SECRET_A\"}"}
	var clean = true
	tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(0, rules.Block)}
	tee.onComplete = func(_, _ []byte, cleanEOF bool) { clean = cleanEOF }
	io.ReadAll(tee)
	tee.Close()
	if clean {
		t.Fatal("a stream blocked in its final event was reported as a clean EOF (it could be cached)")
	}
}

func TestEventText(t *testing.T) {
	cases := map[string]string{
		"data: {\"id\":\"x1\",\"model\":\"m\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n":                  "Hi",
		"event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"Yo\"}}\n\n":               "Yo",
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hey\"}\r\n\r\n":                                 "Hey",
		"data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"G\"}]}}]}\n\n":                                 "G",
		"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"function\":{\"arguments\":\"{\\\"k\\\":1}\"}}]}}]}\n\n": "{\"k\":1}",
		"data: [DONE]\n\n": "",
	}
	for event, want := range cases {
		if got := eventText([]byte(event)); got != want {
			t.Errorf("eventText(%q) = %q, want %q", event, got, want)
		}
	}
}

func TestStreamTee_DoesNotAccumulateWithoutAConsumer(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"a\"}\n\n", "data: {\"delta\":\"b\"}\n\n"}
	tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(0, rules.Block)}
	delivered, err := io.ReadAll(tee)
	if err != nil || string(delivered) != strings.Join(chunks, "") {
		t.Fatalf("delivered=%q err=%v", delivered, err)
	}
	if tee.buf.Len() != 0 {
		t.Fatalf("buf holds %d bytes with no cache/idempotency/coalescing consumer", tee.buf.Len())
	}
}

func TestStreamTee_AccumulationPastLimitIsDroppedButStreamDelivered(t *testing.T) {
	chunks := []string{"data: {\"delta\":\"" + strings.Repeat("a", 100) + "\"}\n\n", "data: {\"delta\":\"b\"}\n\n"}
	var completedLen int
	var complete bool
	tee := &streamTee{src: &reviewChunks{chunks: chunks}, engine: holdbackEngine(0, rules.Block), accumulate: true, accumulateLimit: 64}
	tee.onComplete = func(data, _ []byte, cleanEOF bool) {
		completedLen, complete = len(data), cleanEOF && !tee.accumulationOverflowed
	}
	delivered, err := io.ReadAll(tee)
	tee.Close()
	if err != nil || string(delivered) != strings.Join(chunks, "") {
		t.Fatalf("stream not delivered in full: %q err=%v", delivered, err)
	}
	if completedLen != 0 || complete {
		t.Fatalf("onComplete got %d bytes, complete=%v; want nothing retained and not complete", completedLen, complete)
	}
}
